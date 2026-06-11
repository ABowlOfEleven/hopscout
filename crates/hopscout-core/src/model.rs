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
}
