//! The live model both frontends render: a list of hops, each accumulating
//! addresses, rolling stats, a bounded RTT history (for sparklines), and
//! enrichment (rDNS / ASN) as it arrives.

use std::collections::VecDeque;
use std::net::IpAddr;

use crate::model::{MplsLabel, ProbeResponse};
use crate::stats::HopStat;

/// How many recent samples each hop keeps for sparkline rendering.
pub const HISTORY: usize = 256;

/// Enrichment for a hop address, filled in asynchronously by `hopscout-enrich`.
#[derive(Debug, Clone, Default)]
pub struct HopMeta {
    /// Reverse-DNS name, if one resolved.
    pub hostname: Option<String>,
    /// Origin autonomous system number.
    pub asn: Option<u32>,
    /// Human-readable AS name / org.
    pub as_name: Option<String>,
    /// Approximate geolocation (degrees) for the map view.
    pub lat: Option<f32>,
    pub lon: Option<f32>,
    pub city: Option<String>,
    pub country: Option<String>,
}

/// One hop on the path (one TTL value).
#[derive(Debug, Clone, Default)]
pub struct Hop {
    /// Addresses observed responding at this TTL. More than one means the path
    /// is load-balanced (ECMP) here - the seed of multipath discovery.
    pub addrs: Vec<IpAddr>,
    pub stat: HopStat,
    /// Recent RTTs in ms; `None` marks a lost probe. Bounded to [`HISTORY`].
    pub recent: VecDeque<Option<f32>>,
    /// Enrichment for the primary (first) address.
    pub meta: HopMeta,
    /// Most recent MPLS label stack seen at this hop (empty if none).
    pub mpls: Vec<MplsLabel>,
}

impl Hop {
    fn note_addr(&mut self, addr: IpAddr) {
        if !self.addrs.contains(&addr) {
            self.addrs.push(addr);
        }
    }

    fn push_recent(&mut self, sample: Option<f32>) {
        if self.recent.len() == HISTORY {
            self.recent.pop_front();
        }
        self.recent.push_back(sample);
    }

    /// The address we treat as canonical for display/enrichment.
    pub fn primary_addr(&self) -> Option<IpAddr> {
        self.addrs.first().copied()
    }
}

/// The whole trace state. `hops[i]` is the hop at TTL `i + 1`.
#[derive(Debug, Clone, Default)]
pub struct Session {
    pub target: Option<IpAddr>,
    pub hops: Vec<Hop>,
    /// TTL at which the destination first replied, once known. Frontends render
    /// hops `1..=path_len`; below that we're still discovering.
    pub path_len: Option<u8>,
    /// Per-flow observed path: `paths[flow][ttl-1]` is the last address that flow
    /// saw at that TTL. Distinct flows that diverge reveal multipath; the
    /// topology view draws one polyline per flow.
    pub paths: Vec<Vec<Option<IpAddr>>>,
}

impl Session {
    /// Mutable access to the hop at `ttl`, growing the vector as needed.
    fn hop_mut(&mut self, ttl: u8) -> &mut Hop {
        let idx = (ttl as usize).saturating_sub(1);
        if self.hops.len() <= idx {
            self.hops.resize(idx + 1, Hop::default());
        }
        &mut self.hops[idx]
    }

    /// Record that we emitted a probe at `ttl` (drives the loss denominator).
    pub fn on_sent(&mut self, ttl: u8) {
        self.hop_mut(ttl).stat.record_sent();
    }

    /// Fold a probe response into the session.
    pub fn on_response(&mut self, resp: &ProbeResponse) {
        let hop = self.hop_mut(resp.ttl);
        if let Some(addr) = resp.from {
            hop.note_addr(addr);
        }
        if !resp.mpls.is_empty() {
            hop.mpls = resp.mpls.clone();
        }
        match resp.rtt {
            Some(rtt) => {
                hop.stat.record_rtt(rtt);
                hop.push_recent(Some((rtt.as_secs_f64() * 1000.0) as f32));
            }
            None => hop.push_recent(None),
        }
    }

    /// Note that the destination was reached at `ttl`; converges `path_len` to
    /// the shortest TTL that reaches it.
    pub fn note_reached(&mut self, ttl: u8) {
        self.path_len = Some(self.path_len.map_or(ttl, |p| p.min(ttl)));
    }

    /// Record the address a given `flow` saw at `ttl` (for the topology view).
    pub fn record_path(&mut self, flow: usize, ttl: u8, addr: IpAddr) {
        if self.paths.len() <= flow {
            self.paths.resize(flow + 1, Vec::new());
        }
        let path = &mut self.paths[flow];
        let idx = (ttl as usize).saturating_sub(1);
        if path.len() <= idx {
            path.resize(idx + 1, None);
        }
        path[idx] = Some(addr);
    }

    /// Number of hops worth displaying right now.
    pub fn visible_hops(&self) -> usize {
        match self.path_len {
            Some(p) => (p as usize).min(self.hops.len()),
            None => self.hops.len(),
        }
    }
}
