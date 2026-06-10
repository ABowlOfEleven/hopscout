//! Rung-2 UDP traceroute backend.
//!
//! Windows blocks crafting raw TCP/UDP, so the classic Unix approach doesn't
//! port — but we don't need it. We *send* UDP datagrams with a custom TTL via an
//! ordinary socket (no elevation to send), and *receive* the resulting ICMP
//! "time exceeded" / "port unreachable" replies on a raw ICMP socket (which
//! needs admin). That raw receive socket is the privileged resource.
//!
//! Raw ICMP sockets see *all* host-bound ICMP, so per-hop sockets would each
//! have to filter everyone else's traffic. Instead one shared [`IcmpReceiver`]
//! owns a single raw socket and a reader thread that demuxes replies to the
//! waiting probe, keyed by the unique UDP destination port we chose for it.

use core::ffi::c_void;
use core::mem::{MaybeUninit, size_of};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::windows::io::AsRawSocket;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};
use windows::Win32::Networking::WinSock::{SOCKET, WSAIoctl};

// Capture all IP traffic on the bound interface so we see ICMP *error* messages
// (time-exceeded / unreachable), which a plain raw ICMP socket does not deliver.
const SIO_RCVALL: u32 = 0x9800_0001;
const RCVALL_ON: u32 = 1;

use hopscout_core::{BackendFactory, ProbeBackend, ProbeOutcome, ProbeRequest, ProbeResponse};

const BASE_PORT: u16 = 33434; // classic traceroute UDP base
const PORT_SPAN: u16 = 4000; // size of the unique-destination-port window

#[derive(Clone, Copy, PartialEq)]
enum IcmpKind {
    TimeExceeded,
    PortUnreachable,
    Unreachable,
}

struct Shared {
    waiters: Mutex<HashMap<u16, SyncSender<(IpAddr, IcmpKind)>>>,
    stop: AtomicBool,
}

/// One raw ICMP socket + reader thread, shared by every hop's backend.
pub struct IcmpReceiver {
    shared: Arc<Shared>,
    next: AtomicU32,
    reader: Mutex<Option<JoinHandle<()>>>,
}

impl IcmpReceiver {
    /// Open the raw socket (fails without admin) and start the reader thread.
    ///
    /// `bind` must be the **specific local interface address** used to reach the
    /// target: a Windows raw ICMP socket bound to `0.0.0.0` does not receive.
    pub fn new(bind: Ipv4Addr) -> io::Result<Arc<Self>> {
        let socket = make_sniffer(bind)?;

        let shared = Arc::new(Shared {
            waiters: Mutex::new(HashMap::new()),
            stop: AtomicBool::new(false),
        });
        let reader_shared = Arc::clone(&shared);
        let reader = thread::Builder::new()
            .name("hopscout-icmp-rx".to_string())
            .spawn(move || reader_loop(socket, reader_shared))?;

        Ok(Arc::new(Self {
            shared,
            next: AtomicU32::new(0),
            reader: Mutex::new(Some(reader)),
        }))
    }

    /// A unique destination port within the correlation window.
    fn alloc_port(&self) -> u16 {
        let n = self.next.fetch_add(1, Ordering::Relaxed);
        BASE_PORT + (n % PORT_SPAN as u32) as u16
    }

    fn register(&self, port: u16) -> Receiver<(IpAddr, IcmpKind)> {
        let (tx, rx) = sync_channel(1);
        self.shared.waiters.lock().unwrap().insert(port, tx);
        rx
    }

    fn unregister(&self, port: u16) {
        self.shared.waiters.lock().unwrap().remove(&port);
    }
}

impl Drop for IcmpReceiver {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.reader.lock().unwrap().take() {
            let _ = j.join();
        }
    }
}

/// Build the rung-2 sniffer socket: raw IPPROTO_IP + `SIO_RCVALL`, bound to the
/// interface. (An IPPROTO_ICMP socket doesn't deliver inbound ICMP errors.)
/// This is the operation that genuinely needs admin.
fn make_sniffer(bind: Ipv4Addr) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(0)))?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    socket.bind(&SocketAddr::from((bind, 0)).into())?;
    enable_rcvall(&socket)?;
    Ok(socket)
}

/// Honest capability probe: can we actually stand up the rung-2 sniffer here?
pub(crate) fn can_sniff(bind: Ipv4Addr) -> bool {
    make_sniffer(bind).is_ok()
}

/// Put the raw socket into promiscuous receive (`SIO_RCVALL`) so inbound ICMP
/// error messages reach us. Requires the socket be bound to an interface IP.
fn enable_rcvall(socket: &Socket) -> io::Result<()> {
    let s = SOCKET(socket.as_raw_socket() as usize);
    let inopt: u32 = RCVALL_ON;
    let mut returned = 0u32;
    // SAFETY: `s` is our live socket; inopt is a 4-byte input; no output buffer.
    let rc = unsafe {
        WSAIoctl(
            s,
            SIO_RCVALL,
            Some(&inopt as *const _ as *const c_void),
            size_of::<u32>() as u32,
            None,
            0,
            &mut returned,
            None,
            None,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn reader_loop(socket: Socket, shared: Arc<Shared>) {
    let debug = std::env::var_os("HOPSCOUT_DEBUG").is_some();
    let mut seen = 0u64;
    let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
    while !shared.stop.load(Ordering::Relaxed) {
        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue, // timeout / transient — re-check stop and loop
        };
        // SAFETY: recv_from initialized the first `n` bytes.
        let bytes = unsafe { core::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };

        if debug {
            seen += 1;
            if seen <= 30 {
                eprintln!("[rx] {n}B proto={} from={:?}", bytes.get(9).copied().unwrap_or(0), from.as_socket());
            }
        }

        let responder = match from.as_socket() {
            Some(SocketAddr::V4(s)) => IpAddr::V4(*s.ip()),
            _ => continue,
        };
        if let Some((kind, port)) = parse_icmp_v4(bytes) {
            if let Some(tx) = shared.waiters.lock().unwrap().get(&port) {
                let _ = tx.try_send((responder, kind));
            }
        }
    }
}

/// Parse a raw IPv4 ICMP datagram, returning the error kind and the original
/// UDP destination port (our correlation key) for time-exceeded / unreachable.
fn parse_icmp_v4(buf: &[u8]) -> Option<(IcmpKind, u16)> {
    if buf.len() < 20 || buf[9] != 1 {
        return None; // not enough bytes, or outer protocol isn't ICMP
    }
    let ihl = ((buf[0] & 0x0f) as usize) * 4;
    let icmp = buf.get(ihl..)?;
    if icmp.len() < 8 {
        return None;
    }
    let kind = match (icmp[0], icmp[1]) {
        (11, _) => IcmpKind::TimeExceeded,
        (3, 3) => IcmpKind::PortUnreachable,
        (3, _) => IcmpKind::Unreachable,
        _ => return None,
    };

    // The original datagram follows the 8-byte ICMP header.
    let inner = icmp.get(8..)?;
    if inner.len() < 20 || inner.get(9).copied()? != 17 {
        return None; // inner protocol must be UDP
    }
    let inner_ihl = ((inner[0] & 0x0f) as usize) * 4;
    let udp = inner.get(inner_ihl..)?;
    if udp.len() < 4 {
        return None;
    }
    let dport = u16::from_be_bytes([udp[2], udp[3]]);
    Some((kind, dport))
}

/// Per-hop UDP probe backend sharing one [`IcmpReceiver`].
pub struct RawUdpBackend {
    rx: Arc<IcmpReceiver>,
}

impl ProbeBackend for RawUdpBackend {
    fn probe(
        &self,
        req: ProbeRequest,
        dest: IpAddr,
        timeout: Duration,
    ) -> io::Result<ProbeResponse> {
        let IpAddr::V4(dst4) = dest else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "rung-2 UDP backend is IPv4-only for now",
            ));
        };

        let port = self.rx.alloc_port();
        let waiter = self.rx.register(port);

        let send = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        send.set_ttl(req.ttl as u32)?;
        let payload = vec![0x40u8; req.payload_size.min(1400)];

        let start = Instant::now();
        let send_result = send.send_to(&payload, (dst4, port));
        if let Err(e) = send_result {
            self.rx.unregister(port);
            return Err(e);
        }

        let outcome = waiter.recv_timeout(timeout);
        self.rx.unregister(port);

        Ok(match outcome {
            Ok((responder, kind)) => {
                let rtt = start.elapsed();
                let outcome = match kind {
                    IcmpKind::TimeExceeded => ProbeOutcome::TtlExceeded,
                    IcmpKind::PortUnreachable => ProbeOutcome::Reply, // destination reached
                    IcmpKind::Unreachable => ProbeOutcome::Unreachable,
                };
                ProbeResponse {
                    ttl: req.ttl,
                    seq: req.seq,
                    outcome,
                    from: Some(responder),
                    rtt: Some(rtt),
                }
            }
            Err(_) => ProbeResponse {
                ttl: req.ttl,
                seq: req.seq,
                outcome: ProbeOutcome::Timeout,
                from: None,
                rtt: None,
            },
        })
    }
}

/// Opens the shared raw receiver once and hands each hop a backend sharing it.
pub struct RawUdpBackendFactory {
    rx: Arc<IcmpReceiver>,
}

impl RawUdpBackendFactory {
    /// `local` is the interface address that routes to the target — see
    /// [`local_ipv4_for`].
    pub fn new(local: Ipv4Addr) -> io::Result<Self> {
        Ok(Self {
            rx: IcmpReceiver::new(local)?,
        })
    }
}

/// Discover the local IPv4 the OS would use to reach `dest`, by connecting a UDP
/// socket (which assigns a source address without sending anything).
pub fn local_ipv4_for(dest: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    probe.connect((dest, 80))?;
    match probe.local_addr()?.ip() {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => Ok(Ipv4Addr::UNSPECIFIED),
    }
}

impl BackendFactory for RawUdpBackendFactory {
    fn create(&self) -> io::Result<Box<dyn ProbeBackend + Send>> {
        Ok(Box::new(RawUdpBackend {
            rx: Arc::clone(&self.rx),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_time_exceeded_udp() {
        // Outer IPv4 (20B, proto=ICMP) | ICMP(type 11) | inner IPv4(20B, proto=UDP) | UDP(dport=33500)
        let mut pkt = vec![0u8; 20 + 8 + 20 + 8];
        pkt[0] = 0x45; // IPv4, IHL=5
        pkt[9] = 1; // ICMP
        pkt[20] = 11; // time exceeded
        pkt[20 + 1] = 0;
        let inner = 20 + 8;
        pkt[inner] = 0x45; // inner IPv4, IHL=5
        pkt[inner + 9] = 17; // UDP
        let udp = inner + 20;
        pkt[udp + 2] = (33500u16 >> 8) as u8;
        pkt[udp + 3] = (33500u16 & 0xff) as u8;

        let (kind, port) = parse_icmp_v4(&pkt).expect("should parse");
        assert!(matches!(kind, IcmpKind::TimeExceeded));
        assert_eq!(port, 33500);
    }
}
