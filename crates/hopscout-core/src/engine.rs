//! The continuous probe engine.
//!
//! Model: **one persistent thread per hop (TTL)**. Each worker owns its own
//! backend handle and loops — send a probe at its TTL, fold the result into the
//! shared [`Session`], sleep one interval, repeat. Hops are fully independent:
//! a router that times out stalls only its own row, never the hops above it.
//!
//! Path length converges on its own. To reach a destination at TTL `D`, the
//! worker at `D` gets a [`ProbeOutcome::Reply`]; any worker with `ttl > D` would
//! *also* see the destination reply (its TTL never expires), so once any hop
//! reports a reply we shrink a shared `path_len` to the smallest such TTL and
//! workers beyond it go idle. Frontends render `1..=path_len`.

use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::backend::{BackendFactory, ProbeBackend};
use crate::model::{ProbeOutcome, ProbeProtocol, ProbeRequest};
use crate::session::Session;

/// Tunables for a trace.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub target: IpAddr,
    pub max_hops: u8,
    /// Delay between successive probes from the same hop.
    pub interval: Duration,
    /// Per-probe timeout.
    pub timeout: Duration,
    pub payload_size: usize,
    pub protocol: ProbeProtocol,
}

impl EngineConfig {
    pub fn new(target: IpAddr) -> Self {
        Self {
            target,
            max_hops: 30,
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            payload_size: 32,
            protocol: ProbeProtocol::Icmp,
        }
    }
}

/// A running trace. Drop or call [`Engine::stop`] to wind the threads down.
pub struct Engine {
    config: EngineConfig,
    session: Arc<Mutex<Session>>,
    stop: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    path_len: Arc<AtomicU8>,
    workers: Vec<JoinHandle<()>>,
}

impl Engine {
    /// Spawn one probe loop per hop. Backend handles are created up front so a
    /// failure (e.g. ICMP unavailable) surfaces here rather than silently in a
    /// worker thread.
    pub fn start(config: EngineConfig, factory: Arc<dyn BackendFactory>) -> io::Result<Self> {
        let session = Arc::new(Mutex::new(Session {
            target: Some(config.target),
            ..Session::default()
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let paused = Arc::new(AtomicBool::new(false));
        let path_len = Arc::new(AtomicU8::new(config.max_hops));

        let mut workers = Vec::with_capacity(config.max_hops as usize);
        for ttl in 1..=config.max_hops {
            let backend = factory.create()?;
            let ctx = WorkerCtx {
                ttl,
                config: config.clone(),
                session: Arc::clone(&session),
                stop: Arc::clone(&stop),
                paused: Arc::clone(&paused),
                path_len: Arc::clone(&path_len),
            };
            let handle = thread::Builder::new()
                .name(format!("hopscout-hop-{ttl}"))
                .spawn(move || hop_loop(ctx, backend))?;
            workers.push(handle);
        }

        Ok(Self {
            config,
            session,
            stop,
            paused,
            path_len,
            workers,
        })
    }

    /// Shared handle to the live session; clone-on-read for rendering.
    pub fn session(&self) -> Arc<Mutex<Session>> {
        Arc::clone(&self.session)
    }

    /// A consistent snapshot of the session for one render pass.
    pub fn snapshot(&self) -> Session {
        self.session.lock().unwrap().clone()
    }

    pub fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
    }

    pub fn toggle_pause(&self) {
        self.paused.fetch_xor(true, Ordering::Relaxed);
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Clear all accumulated stats and restart path discovery.
    pub fn reset(&self) {
        let mut s = self.session.lock().unwrap();
        let target = s.target;
        *s = Session {
            target,
            ..Session::default()
        };
        self.path_len.store(self.config.max_hops, Ordering::Relaxed);
    }

    /// Signal all workers to stop and join them.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for w in std::mem::take(&mut self.workers) {
            let _ = w.join();
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Best-effort: signal stop so detached workers don't outlive the engine.
        self.stop.store(true, Ordering::Relaxed);
    }
}

struct WorkerCtx {
    ttl: u8,
    config: EngineConfig,
    session: Arc<Mutex<Session>>,
    stop: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    path_len: Arc<AtomicU8>,
}

fn hop_loop(ctx: WorkerCtx, backend: Box<dyn ProbeBackend + Send>) {
    let mut seq = 0u64;
    while !ctx.stop.load(Ordering::Relaxed) {
        let idle = ctx.paused.load(Ordering::Relaxed)
            || ctx.ttl > ctx.path_len.load(Ordering::Relaxed);
        if idle {
            interruptible_sleep(Duration::from_millis(100), &ctx.stop);
            continue;
        }

        let req = ProbeRequest {
            ttl: ctx.ttl,
            seq,
            protocol: ctx.config.protocol,
            payload_size: ctx.config.payload_size,
        };
        seq = seq.wrapping_add(1);

        // Account the send before blocking on the wire so loss math is honest
        // even if we never get a reply.
        ctx.session.lock().unwrap().on_sent(ctx.ttl);

        match backend.probe(req, ctx.config.target, ctx.config.timeout) {
            Ok(resp) => {
                let reached = resp.outcome == ProbeOutcome::Reply;
                if reached {
                    ctx.path_len.fetch_min(ctx.ttl, Ordering::Relaxed);
                }
                let mut s = ctx.session.lock().unwrap();
                s.on_response(&resp);
                if reached {
                    s.note_reached(ctx.ttl);
                }
            }
            Err(_) => {
                // Backend fault (rare): back off briefly rather than hot-loop.
                interruptible_sleep(Duration::from_millis(250), &ctx.stop);
            }
        }

        interruptible_sleep(ctx.config.interval, &ctx.stop);
    }
}

/// Sleep `dur`, but wake early (in <=100 ms chunks) if `stop` is set, so quit is
/// responsive even with a one-second interval.
fn interruptible_sleep(dur: Duration, stop: &AtomicBool) {
    let mut remaining = dur;
    let chunk = Duration::from_millis(100);
    while remaining > Duration::ZERO {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let step = remaining.min(chunk);
        thread::sleep(step);
        remaining -= step;
    }
}
