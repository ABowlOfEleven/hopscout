//! Privilege separation: a small elevated **helper** process owns the raw socket
//! / Npcap and serves probes to the unprivileged app over a named pipe.
//!
//! This is the hardening of the self-elevation path ([`crate::relaunch_elevated`]):
//! instead of running the whole app as admin, only the helper is elevated, and
//! it does nothing but craft/send/receive probes. The big surface (UI,
//! enrichment, file I/O, parsing) stays at medium integrity.
//!
//! Wire protocol (one connection per probe worker, so requests never interleave):
//! the client sends a fixed 7-byte **Hello** (proto + dest + port), then a stream
//! of 19-byte **Probe** messages, each answered by a 10-byte **Resp**.
//!
//! Status: message framing is unit-tested; the server/client plumbing compiles.
//! Full cross-elevation operation needs the pipe's security descriptor to admit
//! a medium-integrity client (a NULL-DACL + low-integrity SACL label) — that ACL
//! work, and spawning the helper elevated, are the remaining steps and require an
//! admin host to validate.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::os::windows::io::FromRawHandle;
use std::thread;
use std::time::Duration;

use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::core::PCWSTR;

use hopscout_core::{
    BackendFactory, ProbeBackend, ProbeOutcome, ProbeProtocol, ProbeRequest, ProbeResponse,
};

/// The well-known pipe name. (Per-user/instance naming is a future refinement.)
pub const PIPE_NAME: &str = r"\\.\pipe\hopscout-helper";

const PROTO_UDP: u8 = 1;
const PROTO_TCP: u8 = 2;
const HELLO_LEN: usize = 7;
const PROBE_LEN: usize = 19;
const RESP_LEN: usize = 10;

fn proto_byte(p: ProbeProtocol) -> u8 {
    match p {
        ProbeProtocol::Udp => PROTO_UDP,
        ProbeProtocol::TcpSyn => PROTO_TCP,
        ProbeProtocol::Icmp => 0, // ICMP never goes through the helper
    }
}

fn encode_hello(proto: u8, dest: Ipv4Addr, port: u16) -> [u8; HELLO_LEN] {
    let o = dest.octets();
    let p = port.to_be_bytes();
    [proto, o[0], o[1], o[2], o[3], p[0], p[1]]
}

fn decode_hello(b: &[u8; HELLO_LEN]) -> (u8, Ipv4Addr, u16) {
    (
        b[0],
        Ipv4Addr::new(b[1], b[2], b[3], b[4]),
        u16::from_be_bytes([b[5], b[6]]),
    )
}

fn encode_probe(req: &ProbeRequest, timeout: Duration) -> [u8; PROBE_LEN] {
    let mut b = [0u8; PROBE_LEN];
    b[0] = req.ttl;
    b[1..9].copy_from_slice(&req.seq.to_be_bytes());
    b[9..13].copy_from_slice(&(req.payload_size.min(u32::MAX as usize) as u32).to_be_bytes());
    b[13..15].copy_from_slice(&req.flow_id.to_be_bytes());
    b[15..19].copy_from_slice(&(timeout.as_millis().min(u32::MAX as u128) as u32).to_be_bytes());
    b
}

fn decode_probe(b: &[u8; PROBE_LEN], proto: ProbeProtocol) -> (ProbeRequest, Duration) {
    let req = ProbeRequest {
        ttl: b[0],
        seq: u64::from_be_bytes(b[1..9].try_into().unwrap()),
        payload_size: u32::from_be_bytes(b[9..13].try_into().unwrap()) as usize,
        flow_id: u16::from_be_bytes(b[13..15].try_into().unwrap()),
        protocol: proto,
    };
    let timeout = Duration::from_millis(u32::from_be_bytes(b[15..19].try_into().unwrap()) as u64);
    (req, timeout)
}

fn encode_resp(resp: &ProbeResponse) -> [u8; RESP_LEN] {
    let mut b = [0u8; RESP_LEN];
    b[0] = match resp.outcome {
        ProbeOutcome::Reply => 0,
        ProbeOutcome::TtlExceeded => 1,
        ProbeOutcome::Unreachable => 2,
        ProbeOutcome::Timeout => 3,
    };
    if let Some(IpAddr::V4(v4)) = resp.from {
        b[1] = 4;
        b[2..6].copy_from_slice(&v4.octets());
    }
    let rtt = resp.rtt.map(|d| d.as_millis().min(u32::MAX as u128) as u32).unwrap_or(0);
    b[6..10].copy_from_slice(&rtt.to_be_bytes());
    b
}

fn decode_resp(b: &[u8; RESP_LEN], ttl: u8, seq: u64) -> ProbeResponse {
    let outcome = match b[0] {
        0 => ProbeOutcome::Reply,
        1 => ProbeOutcome::TtlExceeded,
        2 => ProbeOutcome::Unreachable,
        _ => ProbeOutcome::Timeout,
    };
    let from = (b[1] == 4).then(|| IpAddr::V4(Ipv4Addr::new(b[2], b[3], b[4], b[5])));
    let rtt_ms = u32::from_be_bytes(b[6..10].try_into().unwrap());
    // RTT presence follows the outcome (everything but a timeout has one), so the
    // decoder doesn't depend on the from-address byte.
    let rtt = (!matches!(outcome, ProbeOutcome::Timeout))
        .then(|| Duration::from_millis(rtt_ms as u64));
    ProbeResponse { ttl, seq, outcome, from, rtt }
}

// ---------------------------------------------------------------------------
// Client side — used by the unprivileged app in place of the raw backends.
// ---------------------------------------------------------------------------

/// A probe backend that proxies each probe to the elevated helper over the pipe.
pub struct HelperBackend {
    pipe: File,
}

impl ProbeBackend for HelperBackend {
    fn probe(
        &self,
        req: ProbeRequest,
        _dest: IpAddr,
        timeout: Duration,
    ) -> io::Result<ProbeResponse> {
        // `&File` implements Read+Write, so &self is enough (one conn per worker).
        let mut pipe = &self.pipe;
        pipe.write_all(&encode_probe(&req, timeout))?;
        let mut resp = [0u8; RESP_LEN];
        pipe.read_exact(&mut resp)?;
        Ok(decode_resp(&resp, req.ttl, req.seq))
    }
}

/// Opens a fresh helper connection per hop worker.
pub struct HelperBackendFactory {
    proto: ProbeProtocol,
    dest: Ipv4Addr,
    port: u16,
}

impl HelperBackendFactory {
    pub fn new(proto: ProbeProtocol, dest: Ipv4Addr, port: u16) -> Self {
        Self { proto, dest, port }
    }
}

impl BackendFactory for HelperBackendFactory {
    fn create(&self) -> io::Result<Box<dyn ProbeBackend + Send>> {
        let pipe = OpenOptions::new().read(true).write(true).open(PIPE_NAME)?;
        let mut p = &pipe;
        p.write_all(&encode_hello(proto_byte(self.proto), self.dest, self.port))?;
        Ok(Box::new(HelperBackend { pipe }))
    }
}

// ---------------------------------------------------------------------------
// Server side — run by the elevated helper binary.
// ---------------------------------------------------------------------------

/// Serve helper connections forever. Each connection gets its own privileged
/// backend; runs in the (elevated) helper process.
pub fn serve() -> io::Result<()> {
    loop {
        let handle = create_pipe_instance()?;
        // Block until a client connects to this instance.
        // SAFETY: handle is a valid pipe instance we just created.
        unsafe {
            let _ = ConnectNamedPipe(handle, None);
        }
        // SAFETY: take ownership of the pipe handle as a File for byte I/O.
        let file = unsafe { File::from_raw_handle(handle.0) };
        thread::spawn(move || {
            let _ = handle_connection(file);
        });
    }
}

fn handle_connection(mut file: File) -> io::Result<()> {
    let mut hello = [0u8; HELLO_LEN];
    file.read_exact(&mut hello)?;
    let (proto_b, dest, port) = decode_hello(&hello);
    let proto = match proto_b {
        PROTO_UDP => ProbeProtocol::Udp,
        PROTO_TCP => ProbeProtocol::TcpSyn,
        _ => return Ok(()),
    };

    let factory = crate::make_factory(proto, IpAddr::V4(dest), port)
        .map_err(|e| io::Error::other(e.to_string()))?;
    let backend = factory.create()?;
    let dest = IpAddr::V4(dest);

    let mut buf = [0u8; PROBE_LEN];
    while file.read_exact(&mut buf).is_ok() {
        let (req, timeout) = decode_probe(&buf, proto);
        let resp = backend.probe(req, dest, timeout)?;
        file.write_all(&encode_resp(&resp))?;
    }
    Ok(())
}

fn create_pipe_instance() -> io::Result<HANDLE> {
    let name = wide(PIPE_NAME);
    // SAFETY: name is a NUL-terminated wide string; default security attributes.
    // NOTE: cross-elevation requires a NULL-DACL + low-integrity SACL here.
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(name.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            None,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(handle)
}

fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrip() {
        let (p, d, port) = decode_hello(&encode_hello(PROTO_TCP, Ipv4Addr::new(8, 8, 8, 8), 443));
        assert_eq!((p, d, port), (PROTO_TCP, Ipv4Addr::new(8, 8, 8, 8), 443));
    }

    #[test]
    fn probe_roundtrip() {
        let req = ProbeRequest {
            ttl: 7,
            seq: 0xDEAD_BEEF_1234,
            protocol: ProbeProtocol::Udp,
            payload_size: 64,
            flow_id: 3,
        };
        let (r2, t2) = decode_probe(&encode_probe(&req, Duration::from_millis(900)), ProbeProtocol::Udp);
        assert_eq!((r2.ttl, r2.seq, r2.payload_size, r2.flow_id), (7, 0xDEAD_BEEF_1234, 64, 3));
        assert_eq!(t2, Duration::from_millis(900));
    }

    #[test]
    fn resp_roundtrip() {
        let resp = ProbeResponse {
            ttl: 9,
            seq: 5,
            outcome: ProbeOutcome::TtlExceeded,
            from: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))),
            rtt: Some(Duration::from_millis(12)),
        };
        let d = decode_resp(&encode_resp(&resp), 9, 5);
        assert!(matches!(d.outcome, ProbeOutcome::TtlExceeded));
        assert_eq!(d.from, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert_eq!(d.rtt, Some(Duration::from_millis(12)));
    }
}
