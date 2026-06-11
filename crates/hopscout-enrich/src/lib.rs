//! Background hop enrichment: reverse DNS (hostnames) and origin ASN / AS-name.
//!
//! Runs on its own thread, polling the shared [`Session`] for hop addresses we
//! haven't looked up yet. Each address is resolved at most once (cached), and
//! all DNS/WHOIS I/O happens with the session lock released — enrichment never
//! stalls the probe engine or the UI.
//!
//! * Reverse DNS uses the system resolver via `dns-lookup` (`getnameinfo`).
//! * Origin ASN uses Team Cymru's WHOIS netcat interface at
//!   `whois.cymru.com:43` — a plain line-based TCP protocol, no async runtime,
//!   and addresses are batched into a single query per round.

mod cymru;
mod geo;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use hopscout_core::Session;

/// Owns the enrichment thread; stops it on drop or via [`EnricherHandle::stop`].
pub struct EnricherHandle {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl EnricherHandle {
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for EnricherHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Spawn the enrichment loop against a live session (with reverse DNS).
pub fn spawn(session: Arc<Mutex<Session>>) -> EnricherHandle {
    spawn_with(session, true)
}

/// Spawn enrichment, choosing whether to do reverse DNS (`dns = false` mirrors
/// MTR's `--no-dns`). ASN + geolocation always run.
pub fn spawn_with(session: Arc<Mutex<Session>>, dns: bool) -> EnricherHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let join = thread::Builder::new()
        .name("hopscout-enrich".to_string())
        .spawn(move || run(session, thread_stop, dns))
        .ok();
    EnricherHandle { stop, join }
}

fn run(session: Arc<Mutex<Session>>, stop: Arc<AtomicBool>, dns: bool) {
    // Addresses we've already resolved (or tried), so we never re-query.
    let mut done: HashSet<IpAddr> = HashSet::new();

    while !stop.load(Ordering::Relaxed) {
        let todo = collect_pending(&session, &done);
        if todo.is_empty() {
            interruptible_sleep(Duration::from_millis(500), &stop);
            continue;
        }

        // Fast path: one batched WHOIS round, written for every address at once
        // so ASNs appear immediately rather than waiting behind reverse DNS.
        let asn = cymru::lookup(&todo);
        if !asn.is_empty() {
            apply_asn(&session, &asn);
        }

        // Batched geolocation for the map view.
        let geo = geo::lookup(&todo);
        if !geo.is_empty() {
            apply_geo(&session, &geo);
        }

        // Slow path: reverse DNS is per-address and can block on hosts with no
        // PTR, so it trickles in without holding up the ASN column.
        for addr in &todo {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            if dns {
                if let Ok(name) = dns_lookup::lookup_addr(addr) {
                    apply_hostname(&session, *addr, name);
                }
            }
            done.insert(*addr);
        }
    }
}

/// Hop primary addresses present in the session but not yet enriched.
fn collect_pending(session: &Arc<Mutex<Session>>, done: &HashSet<IpAddr>) -> Vec<IpAddr> {
    let s = session.lock().unwrap();
    let mut seen = HashSet::new();
    let mut pending = Vec::new();
    for hop in &s.hops {
        if let Some(addr) = hop.primary_addr() {
            if !done.contains(&addr) && seen.insert(addr) {
                pending.push(addr);
            }
        }
    }
    pending
}

/// Write a batch of resolved origins into every matching hop, in one lock.
fn apply_asn(session: &Arc<Mutex<Session>>, asn: &HashMap<IpAddr, cymru::Origin>) {
    let mut s = session.lock().unwrap();
    for hop in &mut s.hops {
        if let Some(addr) = hop.primary_addr() {
            if let Some(o) = asn.get(&addr) {
                hop.meta.asn = Some(o.asn);
                hop.meta.as_name = Some(o.name.clone());
            }
        }
    }
}

/// Write a batch of geolocations into every matching hop, in one lock.
fn apply_geo(session: &Arc<Mutex<Session>>, geo: &HashMap<IpAddr, geo::Geo>) {
    let mut s = session.lock().unwrap();
    for hop in &mut s.hops {
        if let Some(addr) = hop.primary_addr() {
            if let Some(g) = geo.get(&addr) {
                hop.meta.lat = Some(g.lat);
                hop.meta.lon = Some(g.lon);
                hop.meta.city = Some(g.city.clone());
                hop.meta.country = Some(g.country.clone());
            }
        }
    }
}

/// Write a resolved hostname into every hop whose primary address matches.
fn apply_hostname(session: &Arc<Mutex<Session>>, addr: IpAddr, name: String) {
    let mut s = session.lock().unwrap();
    for hop in &mut s.hops {
        if hop.primary_addr() == Some(addr) {
            hop.meta.hostname = Some(name.clone());
        }
    }
}

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
