//! Core probe types shared across the engine, both frontends, and the export
//! format.

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Transport used to elicit a TTL-exceeded / reply from each hop.
///
/// Rung-1 (`IcmpSendEcho2`, unprivileged) supports only [`ProbeProtocol::Icmp`].
/// `Udp` and `TcpSyn` arrive with the raw-socket backend behind the elevated
/// probe helper, and let you trace paths that drop ICMP (e.g. to `:443`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeProtocol {
    Icmp,
    Udp,
    TcpSyn,
}

/// One probe to send: a TTL (which hop we're poking) and a sequence number that
/// distinguishes repeated probes to the same hop.
#[derive(Debug, Clone, Copy)]
pub struct ProbeRequest {
    pub ttl: u8,
    pub seq: u64,
    pub protocol: ProbeProtocol,
    pub payload_size: usize,
    /// Which probe flow this belongs to. Backends fold it into the flow tuple
    /// (UDP dest-port band / TCP source port) so distinct flows take distinct
    /// paths through ECMP load balancers — the basis for multipath discovery.
    pub flow_id: u16,
}

/// How a single probe turned out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeOutcome {
    /// Reached the final destination (ICMP echo reply / TCP SYN-ACK).
    Reply,
    /// A router on the path returned "TTL exceeded" — `from` is that hop.
    TtlExceeded,
    /// Destination/host/net/port unreachable.
    Unreachable,
    /// No response within the timeout.
    Timeout,
}

/// A probe response handed back by a [`crate::ProbeBackend`].
#[derive(Debug, Clone)]
pub struct ProbeResponse {
    pub ttl: u8,
    pub seq: u64,
    pub outcome: ProbeOutcome,
    /// The address that responded — `None` on [`ProbeOutcome::Timeout`].
    pub from: Option<IpAddr>,
    /// Round-trip time — `None` on timeout.
    pub rtt: Option<Duration>,
    /// MPLS label stack from the hop's ICMP extension, if any. Only populated by
    /// the raw-socket / Npcap backends (the rung-1 ICMP API hides extensions).
    pub mpls: Vec<MplsLabel>,
}

/// One MPLS label-stack entry, decoded from an ICMP extension (RFC 4950).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MplsLabel {
    /// 20-bit MPLS label.
    pub label: u32,
    /// 3-bit traffic class / experimental bits.
    pub exp: u8,
    /// Bottom-of-stack bit.
    pub bos: bool,
    /// Label TTL.
    pub ttl: u8,
}

impl ProbeResponse {
    /// A response with no MPLS labels (the common case).
    pub fn new(
        ttl: u8,
        seq: u64,
        outcome: ProbeOutcome,
        from: Option<IpAddr>,
        rtt: Option<Duration>,
    ) -> Self {
        Self { ttl, seq, outcome, from, rtt, mpls: Vec::new() }
    }
}
