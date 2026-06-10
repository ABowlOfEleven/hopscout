//! Rung-1 ICMP backend on the Win32 `IcmpSendEcho2` API.
//!
//! `IcmpSendEcho2` is the same mechanism WinMTR uses: it needs no elevation,
//! lets us set the outgoing TTL via `IP_OPTION_INFORMATION`, and hands back the
//! responding router's address plus the round-trip time directly — so we get a
//! full traceroute without crafting raw packets. Its ceiling is that it speaks
//! ICMP only; UDP/TCP modes need the raw-socket backend (rung 2).

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::IpHelper::{
    ICMP_ECHO_REPLY, IP_OPTION_INFORMATION, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2,
};

use hopscout_core::{BackendFactory, ProbeBackend, ProbeOutcome, ProbeRequest, ProbeResponse};

// IP_STATUS codes we care about. Declared locally (rather than imported) so the
// backend is robust against churn in the windows crate's constant names.
const IP_SUCCESS: u32 = 0;
const IP_DEST_NET_UNREACHABLE: u32 = 11002;
const IP_DEST_HOST_UNREACHABLE: u32 = 11003;
const IP_DEST_PROT_UNREACHABLE: u32 = 11004;
const IP_DEST_PORT_UNREACHABLE: u32 = 11005;
const IP_REQ_TIMED_OUT: u32 = 11010;
const IP_TTL_EXPIRED_TRANSIT: u32 = 11013;
const IP_TTL_EXPIRED_REASSEM: u32 = 11014;

/// Unprivileged ICMP probe backend (IPv4). IPv6 arrives with `Icmp6SendEcho2`.
pub struct IcmpBackend {
    handle: HANDLE,
}

// SAFETY: the engine gives each worker thread its own IcmpBackend (created via
// IcmpBackendFactory) and never shares one across threads. The handle is
// process-wide and only ever touched by its single owning thread, so moving the
// backend to that thread is sound. We do NOT implement Sync.
unsafe impl Send for IcmpBackend {}

/// Hands the engine a fresh [`IcmpBackend`] (its own ICMP handle) per hop.
pub struct IcmpBackendFactory;

impl BackendFactory for IcmpBackendFactory {
    fn create(&self) -> io::Result<Box<dyn ProbeBackend + Send>> {
        Ok(Box::new(IcmpBackend::new()?))
    }
}

impl IcmpBackend {
    pub fn new() -> io::Result<Self> {
        // SAFETY: IcmpCreateFile takes no arguments and returns either a valid
        // ICMP handle or a Win32 error we surface.
        let handle = unsafe { IcmpCreateFile() }
            .map_err(|e| io::Error::other(format!("IcmpCreateFile failed: {e}")))?;
        Ok(Self { handle })
    }
}

impl Drop for IcmpBackend {
    fn drop(&mut self) {
        // SAFETY: `handle` was produced by IcmpCreateFile and is closed exactly
        // once, here, at end of life.
        unsafe {
            let _ = IcmpCloseHandle(self.handle);
        }
    }
}

impl ProbeBackend for IcmpBackend {
    fn probe(
        &self,
        req: ProbeRequest,
        dest: IpAddr,
        timeout: Duration,
    ) -> io::Result<ProbeResponse> {
        let IpAddr::V4(v4) = dest else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "rung-1 IcmpBackend is IPv4-only; IPv6 lands with Icmp6SendEcho2",
            ));
        };

        let payload_size = req.payload_size.min(u16::MAX as usize);
        let payload = vec![0x68u8; payload_size]; // 'h' — a recognizable filler

        // A Win32 IPAddr stores the four octets in memory order (low byte =
        // first octet), which is exactly `from_ne_bytes(octets)`.
        let dest_addr = u32::from_ne_bytes(v4.octets());

        let opts = IP_OPTION_INFORMATION {
            Ttl: req.ttl,
            Tos: 0,
            Flags: 0,
            OptionsSize: 0,
            OptionsData: std::ptr::null_mut(),
        };

        // Microsoft requires room for one ICMP_ECHO_REPLY, the echoed payload,
        // and 8 bytes for a possible ICMP error; add slack to be safe.
        let reply_size = size_of::<ICMP_ECHO_REPLY>() + payload_size + 8 + 16;
        let mut reply_buf = vec![0u8; reply_size];

        let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;

        // SAFETY: every pointer references a live, correctly-sized local buffer;
        // `handle` is valid; we pass no event/APC so the call is synchronous and
        // fully drains into `reply_buf` before returning.
        let replies = unsafe {
            IcmpSendEcho2(
                self.handle,
                None,
                None,
                None,
                dest_addr,
                payload.as_ptr() as *const c_void,
                payload_size as u16,
                Some(&opts),
                reply_buf.as_mut_ptr() as *mut c_void,
                reply_size as u32,
                timeout_ms,
            )
        };

        if replies == 0 {
            // Zero replies: timeout (the common case) or a hard send error. For
            // the rung-1 MVP we treat both as a timeout row in the trace.
            return Ok(timeout_response(&req));
        }

        // SAFETY: IcmpSendEcho2 reported >= 1 reply, so at least one
        // ICMP_ECHO_REPLY was written at the start of `reply_buf`. We read it
        // unaligned because `reply_buf` is only byte-aligned.
        let reply: ICMP_ECHO_REPLY =
            unsafe { std::ptr::read_unaligned(reply_buf.as_ptr() as *const ICMP_ECHO_REPLY) };

        let from = Ipv4Addr::from(reply.Address.to_ne_bytes());
        let rtt = Duration::from_millis(reply.RoundTripTime as u64);

        let outcome = match reply.Status {
            IP_SUCCESS => ProbeOutcome::Reply,
            IP_TTL_EXPIRED_TRANSIT | IP_TTL_EXPIRED_REASSEM => ProbeOutcome::TtlExceeded,
            IP_DEST_NET_UNREACHABLE
            | IP_DEST_HOST_UNREACHABLE
            | IP_DEST_PROT_UNREACHABLE
            | IP_DEST_PORT_UNREACHABLE => ProbeOutcome::Unreachable,
            IP_REQ_TIMED_OUT => ProbeOutcome::Timeout,
            _ => ProbeOutcome::Unreachable,
        };

        let (from, rtt) = match outcome {
            ProbeOutcome::Timeout => (None, None),
            _ => (Some(IpAddr::V4(from)), Some(rtt)),
        };

        Ok(ProbeResponse {
            ttl: req.ttl,
            seq: req.seq,
            outcome,
            from,
            rtt,
        })
    }
}

fn timeout_response(req: &ProbeRequest) -> ProbeResponse {
    ProbeResponse {
        ttl: req.ttl,
        seq: req.seq,
        outcome: ProbeOutcome::Timeout,
        from: None,
        rtt: None,
    }
}
