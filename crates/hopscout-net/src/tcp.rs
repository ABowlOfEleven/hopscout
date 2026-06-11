//! Rung-3 TCP-SYN traceroute via Npcap layer-2 injection.
//!
//! Sends a crafted TCP SYN at each TTL and watches for the ICMP time-exceeded
//! (intermediate hops) or the SYN-ACK/RST (destination). The 4-tuple is held
//! constant so ECMP load balancers keep the path stable (Paris-style); probes
//! are correlated instead by a unique IP id echoed back inside the ICMP error.
//!
//! Requires Npcap installed (loaded at runtime) and, in practice, admin to
//! inject. The packet crafting is unit-tested in [`crate::packet`]; the live
//! capture path needs an Npcap host to validate end-to-end.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use hopscout_core::{BackendFactory, ProbeBackend, ProbeOutcome, ProbeRequest, ProbeResponse};

use crate::iface::{self, L2Path};
use crate::npcap::{Capture, Npcap};
use crate::packet::{TcpSyn, ethernet_frame};

struct Shared {
    npcap: Arc<Npcap>,
    l2: L2Path,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    src_port: u16, // held constant (Paris); correlation is by IP id
    ip_id: AtomicU16,
}

/// Opens Npcap once, resolves the L2 path, and hands each hop its own capture.
pub struct NpcapTcpBackendFactory {
    shared: Arc<Shared>,
}

impl NpcapTcpBackendFactory {
    pub fn new(dst_ip: Ipv4Addr, dst_port: u16, src_ip: Ipv4Addr) -> io::Result<Self> {
        let npcap = Arc::new(Npcap::load()?);
        let l2 = iface::resolve(dst_ip, src_ip)?;
        Ok(Self {
            shared: Arc::new(Shared {
                npcap,
                l2,
                src_ip,
                dst_ip,
                dst_port,
                src_port: 50000,
                ip_id: AtomicU16::new(1),
            }),
        })
    }
}

impl BackendFactory for NpcapTcpBackendFactory {
    fn create(&self) -> io::Result<Box<dyn ProbeBackend + Send>> {
        let capture = Capture::open(Arc::clone(&self.shared.npcap), &self.shared.l2.device)?;
        Ok(Box::new(NpcapTcpBackend {
            shared: Arc::clone(&self.shared),
            capture,
        }))
    }
}

pub struct NpcapTcpBackend {
    shared: Arc<Shared>,
    capture: Capture,
}

impl ProbeBackend for NpcapTcpBackend {
    fn probe(
        &self,
        req: ProbeRequest,
        _dest: IpAddr,
        timeout: Duration,
    ) -> io::Result<ProbeResponse> {
        let s = &self.shared;
        let ip_id = s.ip_id.fetch_add(1, Ordering::Relaxed).max(1);

        let syn = TcpSyn {
            src_ip: s.src_ip,
            dst_ip: s.dst_ip,
            src_port: s.src_port,
            dst_port: s.dst_port,
            seq: 0x1000_0000 | ip_id as u32,
            ttl: req.ttl,
            ip_id,
        };
        let frame = ethernet_frame(s.l2.gw_mac, s.l2.src_mac, &syn.build());

        let start = Instant::now();
        self.capture.send(&frame)?;

        let deadline = start + timeout;
        while Instant::now() < deadline {
            let Some(frame) = self.capture.next_frame()? else {
                continue;
            };
            if let Some((outcome, from)) = parse_reply(&frame, ip_id, s) {
                return Ok(ProbeResponse {
                    ttl: req.ttl,
                    seq: req.seq,
                    outcome,
                    from: Some(IpAddr::V4(from)),
                    rtt: Some(start.elapsed()),
                });
            }
        }
        Ok(ProbeResponse {
            ttl: req.ttl,
            seq: req.seq,
            outcome: ProbeOutcome::Timeout,
            from: None,
            rtt: None,
        })
    }
}

/// Match a captured Ethernet frame to our probe (`ip_id`), returning the hop.
fn parse_reply(frame: &[u8], ip_id: u16, s: &Shared) -> Option<(ProbeOutcome, Ipv4Addr)> {
    if frame.len() < 14 + 20 || frame[12] != 0x08 || frame[13] != 0x00 {
        return None; // not an IPv4 Ethernet frame
    }
    let ip = &frame[14..];
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ip.len() < ihl {
        return None;
    }
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);

    match ip[9] {
        1 => {
            // ICMP error: correlate by the IP id echoed in the original header.
            let icmp = ip.get(ihl..)?;
            if icmp.len() < 8 {
                return None;
            }
            let outcome = match icmp[0] {
                11 => ProbeOutcome::TtlExceeded,
                3 => ProbeOutcome::Unreachable,
                _ => return None,
            };
            let inner = icmp.get(8..)?;
            if inner.len() < 6 {
                return None;
            }
            let inner_id = u16::from_be_bytes([inner[4], inner[5]]);
            (inner_id == ip_id).then_some((outcome, src))
        }
        6 => {
            // A SYN-ACK / RST from the destination = reached. The 4-tuple is
            // constant (Paris), so correlate to *this* probe by the ACK number:
            // it echoes our SYN seq + 1, and the seq encodes the probe's IP id.
            if src != s.dst_ip {
                return None;
            }
            let tcp = ip.get(ihl..)?;
            if tcp.len() < 12 {
                return None;
            }
            let dport = u16::from_be_bytes([tcp[2], tcp[3]]);
            let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
            let expected_ack = (0x1000_0000u32 | ip_id as u32).wrapping_add(1);
            (dport == s.src_port && ack == expected_ack).then_some((ProbeOutcome::Reply, src))
        }
        _ => None,
    }
}
