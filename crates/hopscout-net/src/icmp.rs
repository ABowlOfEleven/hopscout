//! Rung-1 ICMP backend on the Win32 `IcmpSendEcho2` / `Icmp6SendEcho2` APIs.
//!
//! These are the same mechanism WinMTR uses: no elevation, the outgoing TTL /
//! hop-limit is set via `IP_OPTION_INFORMATION`, and the responding router's
//! address plus round-trip time come back directly — a full traceroute with no
//! raw packets. The ceiling is ICMP-only; UDP/TCP modes need rung 2.
//!
//! One [`IcmpBackend`] opens both an IPv4 and an IPv6 handle and dispatches in
//! [`IcmpBackend::probe`] on the destination's address family.

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::IpHelper::{
    ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY_LH, IP_OPTION_INFORMATION, Icmp6CreateFile, Icmp6SendEcho2,
    IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2,
};
use windows::Win32::Networking::WinSock::{
    AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6, SOCKADDR_IN6_0,
};

use hopscout_core::{BackendFactory, ProbeBackend, ProbeOutcome, ProbeRequest, ProbeResponse};

// IP_STATUS codes (shared by the v4 and v6 reply structs). Declared locally so
// the backend is robust against churn in the windows crate's constant names.
const IP_SUCCESS: u32 = 0;
const IP_DEST_NET_UNREACHABLE: u32 = 11002;
const IP_DEST_HOST_UNREACHABLE: u32 = 11003;
const IP_DEST_PROT_UNREACHABLE: u32 = 11004;
const IP_DEST_PORT_UNREACHABLE: u32 = 11005;
const IP_REQ_TIMED_OUT: u32 = 11010;
const IP_TTL_EXPIRED_TRANSIT: u32 = 11013;
const IP_TTL_EXPIRED_REASSEM: u32 = 11014;

/// Unprivileged ICMP probe backend for IPv4 and IPv6.
pub struct IcmpBackend {
    v4: HANDLE,
    /// `None` if the host has no IPv6 stack; v6 probes then return `Unsupported`.
    v6: Option<HANDLE>,
}

// SAFETY: the engine gives each worker thread its own IcmpBackend (created via
// IcmpBackendFactory) and never shares one across threads. The handles are
// process-wide and only ever touched by their single owning thread, so moving
// the backend to that thread is sound. We do NOT implement Sync.
unsafe impl Send for IcmpBackend {}

impl IcmpBackend {
    pub fn new() -> io::Result<Self> {
        // SAFETY: IcmpCreateFile takes no arguments and returns a valid handle
        // or a Win32 error we surface.
        let v4 = unsafe { IcmpCreateFile() }
            .map_err(|e| io::Error::other(format!("IcmpCreateFile failed: {e}")))?;
        // IPv6 is best-effort: a host without an IPv6 stack just loses v6 probes.
        // SAFETY: same contract as IcmpCreateFile.
        let v6 = unsafe { Icmp6CreateFile() }.ok();
        Ok(Self { v4, v6 })
    }

    fn probe_v4(
        &self,
        req: ProbeRequest,
        dest: Ipv4Addr,
        timeout: Duration,
    ) -> io::Result<ProbeResponse> {
        let payload_size = req.payload_size.min(u16::MAX as usize);
        let payload = vec![0x68u8; payload_size]; // 'h' filler

        // A Win32 IPAddr stores the four octets in memory order (low byte =
        // first octet), which is exactly `from_ne_bytes(octets)`.
        let dest_addr = u32::from_ne_bytes(dest.octets());
        let opts = ttl_options(req.ttl);

        let reply_size = size_of::<ICMP_ECHO_REPLY>() + payload_size + 8 + 16;
        let mut reply_buf = vec![0u8; reply_size];
        let timeout_ms = clamp_timeout(timeout);

        // SAFETY: every pointer references a live, correctly-sized local buffer;
        // `v4` is valid; no event/APC means the call is synchronous and fully
        // drains into `reply_buf` before returning.
        let replies = unsafe {
            IcmpSendEcho2(
                self.v4,
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
            return Ok(timeout_response(&req));
        }

        // SAFETY: >= 1 reply was written at the start of `reply_buf`; read it
        // unaligned because the buffer is only byte-aligned.
        let reply: ICMP_ECHO_REPLY =
            unsafe { std::ptr::read_unaligned(reply_buf.as_ptr() as *const ICMP_ECHO_REPLY) };

        let from = IpAddr::V4(Ipv4Addr::from(reply.Address.to_ne_bytes()));
        let rtt = Duration::from_millis(reply.RoundTripTime as u64);
        Ok(classify(&req, reply.Status, from, rtt))
    }

    fn probe_v6(
        &self,
        req: ProbeRequest,
        dest: Ipv6Addr,
        timeout: Duration,
    ) -> io::Result<ProbeResponse> {
        let Some(handle) = self.v6 else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "no IPv6 stack available (Icmp6CreateFile failed)",
            ));
        };

        let payload_size = req.payload_size.min(u16::MAX as usize);
        let payload = vec![0x68u8; payload_size];
        let opts = ttl_options(req.ttl); // Ttl field doubles as the hop limit

        let source = sockaddr_in6(Ipv6Addr::UNSPECIFIED);
        let target = sockaddr_in6(dest);

        // Icmp6 wants an 8-byte-aligned reply buffer; a Vec<u64> guarantees it.
        let reply_size = size_of::<ICMPV6_ECHO_REPLY_LH>() + payload_size + 8 + 16;
        let words = reply_size.div_ceil(8);
        let mut reply_buf = vec![0u64; words];
        let reply_bytes = (words * 8) as u32;
        let timeout_ms = clamp_timeout(timeout);

        // SAFETY: source/target/opts/payload/reply_buf are live locals of the
        // right size; `handle` is valid; synchronous (no event/APC).
        let replies = unsafe {
            Icmp6SendEcho2(
                handle,
                None,
                None,
                None,
                &source,
                &target,
                payload.as_ptr() as *const c_void,
                payload_size as u16,
                Some(&opts),
                reply_buf.as_mut_ptr() as *mut c_void,
                reply_bytes,
                timeout_ms,
            )
        };
        if replies == 0 {
            return Ok(timeout_response(&req));
        }

        // SAFETY: >= 1 reply written at the buffer start; read unaligned.
        let reply: ICMPV6_ECHO_REPLY_LH = unsafe {
            std::ptr::read_unaligned(reply_buf.as_ptr() as *const ICMPV6_ECHO_REPLY_LH)
        };

        // `sin6_addr` is a packed [u16; 8] in network order; copy it by value.
        let words: [u16; 8] = reply.Address.sin6_addr;
        let from = IpAddr::V6(ipv6_from_words(words));
        let rtt = Duration::from_millis(reply.RoundTripTime as u64);
        Ok(classify(&req, reply.Status, from, rtt))
    }
}

impl Drop for IcmpBackend {
    fn drop(&mut self) {
        // SAFETY: handles came from Icmp[6]CreateFile and are closed once.
        unsafe {
            let _ = IcmpCloseHandle(self.v4);
            if let Some(v6) = self.v6 {
                let _ = IcmpCloseHandle(v6);
            }
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
        match dest {
            IpAddr::V4(v4) => self.probe_v4(req, v4, timeout),
            IpAddr::V6(v6) => self.probe_v6(req, v6, timeout),
        }
    }
}

/// Discover the path MTU to an IPv4 destination by binary-searching the largest
/// DF-set ICMP echo payload that gets through. Returns the MTU in bytes (payload
/// + 28 for the IPv4 + ICMP headers), or `None` if the host doesn't answer ping.
///
/// Oversized DF probes fail fast (the local stack or a bottleneck router reports
/// "packet too big"), so the search converges quickly except on black-hole paths.
pub fn path_mtu(dest: Ipv4Addr, timeout: Duration) -> io::Result<Option<u16>> {
    const DF: u8 = 0x02; // IP "don't fragment" flag
    const HEADERS: u16 = 28; // 20 (IPv4) + 8 (ICMP)

    // SAFETY: standard ICMP handle, closed before returning.
    let handle = unsafe { IcmpCreateFile() }
        .map_err(|e| io::Error::other(format!("IcmpCreateFile failed: {e}")))?;
    let dest_addr = u32::from_ne_bytes(dest.octets());
    let timeout_ms = clamp_timeout(timeout).min(800); // keep the search snappy

    let echo = |payload: u16| -> bool {
        let buf = vec![0x68u8; payload as usize];
        let opts = IP_OPTION_INFORMATION {
            Ttl: 64,
            Tos: 0,
            Flags: DF,
            OptionsSize: 0,
            OptionsData: std::ptr::null_mut(),
        };
        let reply_size = size_of::<ICMP_ECHO_REPLY>() + payload as usize + 8 + 16;
        let mut reply = vec![0u8; reply_size];
        for _ in 0..2 {
            // SAFETY: live buffers of the declared sizes; synchronous call.
            let n = unsafe {
                IcmpSendEcho2(
                    handle,
                    None,
                    None,
                    None,
                    dest_addr,
                    buf.as_ptr() as *const c_void,
                    payload,
                    Some(&opts),
                    reply.as_mut_ptr() as *mut c_void,
                    reply_size as u32,
                    timeout_ms,
                )
            };
            if n != 0 {
                // SAFETY: at least one reply was written.
                let r: ICMP_ECHO_REPLY =
                    unsafe { std::ptr::read_unaligned(reply.as_ptr() as *const ICMP_ECHO_REPLY) };
                if r.Status == IP_SUCCESS {
                    return true;
                }
            }
        }
        false
    };

    let result = if !echo(0) {
        None // host doesn't answer ping at all
    } else {
        let (mut lo, mut hi) = (0u16, 9000u16 - HEADERS); // search up to jumbo frames
        let mut best = 0u16;
        while lo <= hi {
            let mid = lo + (hi - lo) / 2;
            if echo(mid) {
                best = mid;
                lo = mid + 1;
            } else if mid == 0 {
                break;
            } else {
                hi = mid - 1;
            }
        }
        Some(best + HEADERS)
    };

    // SAFETY: handle came from IcmpCreateFile and is closed once.
    unsafe {
        let _ = IcmpCloseHandle(handle);
    }
    Ok(result)
}

/// Hands the engine a fresh [`IcmpBackend`] (its own handles) per hop.
pub struct IcmpBackendFactory;

impl BackendFactory for IcmpBackendFactory {
    fn create(&self) -> io::Result<Box<dyn ProbeBackend + Send>> {
        Ok(Box::new(IcmpBackend::new()?))
    }
}

fn ttl_options(ttl: u8) -> IP_OPTION_INFORMATION {
    IP_OPTION_INFORMATION {
        Ttl: ttl,
        Tos: 0,
        Flags: 0,
        OptionsSize: 0,
        OptionsData: std::ptr::null_mut(),
    }
}

fn clamp_timeout(timeout: Duration) -> u32 {
    timeout.as_millis().min(u32::MAX as u128) as u32
}

/// Map a raw IP_STATUS plus responder/RTT into a [`ProbeResponse`].
fn classify(req: &ProbeRequest, status: u32, from: IpAddr, rtt: Duration) -> ProbeResponse {
    let outcome = match status {
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
        _ => (Some(from), Some(rtt)),
    };
    ProbeResponse {
        ttl: req.ttl,
        seq: req.seq,
        outcome,
        from,
        rtt,
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

/// Build a `SOCKADDR_IN6` for `addr` (scope 0; global unicast traceroute).
fn sockaddr_in6(addr: Ipv6Addr) -> SOCKADDR_IN6 {
    SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: addr.octets(),
            },
        },
        Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
    }
}

/// Rebuild an `Ipv6Addr` from the packed network-order `[u16; 8]` of
/// `IPV6_ADDRESS_EX`. Each word's in-memory bytes are already network order, so
/// `to_ne_bytes` reconstructs the 16-byte address.
fn ipv6_from_words(words: [u16; 8]) -> Ipv6Addr {
    let mut bytes = [0u8; 16];
    for (i, w) in words.iter().enumerate() {
        let b = w.to_ne_bytes();
        bytes[2 * i] = b[0];
        bytes[2 * i + 1] = b[1];
    }
    Ipv6Addr::from(bytes)
}
