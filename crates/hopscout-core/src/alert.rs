//! Path-change detection: capture a [`Baseline`] of the path, then report how
//! the live [`Session`] deviates from it — route changes, hops appearing or
//! disappearing, latency regressions, and loss onset. Frontends snapshot a
//! baseline (a key / button) and render the live deviation list.

use std::net::IpAddr;

use crate::session::Session;

/// One way the current path differs from the baseline.
#[derive(Clone, Debug)]
pub enum Alert {
    RouteChanged { ttl: u8, from: IpAddr, to: IpAddr },
    HopAppeared { ttl: u8, addr: IpAddr },
    HopDisappeared { ttl: u8, addr: IpAddr },
    LatencyRegression { ttl: u8, baseline_ms: f64, now_ms: f64 },
    LossOnset { ttl: u8, pct: f64 },
}

impl Alert {
    pub fn ttl(&self) -> u8 {
        match self {
            Alert::RouteChanged { ttl, .. }
            | Alert::HopAppeared { ttl, .. }
            | Alert::HopDisappeared { ttl, .. }
            | Alert::LatencyRegression { ttl, .. }
            | Alert::LossOnset { ttl, .. } => *ttl,
        }
    }

    pub fn message(&self) -> String {
        match self {
            Alert::RouteChanged { ttl, from, to } => {
                format!("hop {ttl}: route changed {from} → {to}")
            }
            Alert::HopAppeared { ttl, addr } => format!("hop {ttl}: new hop {addr}"),
            Alert::HopDisappeared { ttl, addr } => format!("hop {ttl}: hop {addr} disappeared"),
            Alert::LatencyRegression { ttl, baseline_ms, now_ms } => {
                format!("hop {ttl}: latency {baseline_ms:.0} → {now_ms:.0} ms")
            }
            Alert::LossOnset { ttl, pct } => format!("hop {ttl}: loss {pct:.0}%"),
        }
    }
}

/// A captured snapshot of the path: per-TTL primary address and mean RTT.
#[derive(Clone, Default)]
pub struct Baseline {
    hops: Vec<(Option<IpAddr>, Option<f64>)>,
}

impl Baseline {
    /// Capture the current visible path as the baseline.
    pub fn capture(s: &Session) -> Self {
        let hops = (0..s.visible_hops())
            .map(|i| {
                let h = &s.hops[i];
                (h.primary_addr(), h.stat.avg_ms())
            })
            .collect();
        Baseline { hops }
    }

    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    /// Deviations of `s` from the baseline. `lat_factor` (e.g. 1.5) flags a hop
    /// whose mean RTT is now ≥ factor× baseline *and* ≥ 5 ms higher.
    pub fn deviations(&self, s: &Session, lat_factor: f64) -> Vec<Alert> {
        let mut out = Vec::new();
        let n = s.visible_hops().max(self.hops.len());
        for i in 0..n {
            let ttl = (i + 1) as u8;
            let (base_addr, base_ms) = self.hops.get(i).copied().unwrap_or((None, None));
            let cur = s.hops.get(i);
            let cur_addr = cur.and_then(|h| h.primary_addr());

            match (base_addr, cur_addr) {
                (Some(a), Some(b)) if a != b => out.push(Alert::RouteChanged { ttl, from: a, to: b }),
                (None, Some(b)) => out.push(Alert::HopAppeared { ttl, addr: b }),
                (Some(a), None) => out.push(Alert::HopDisappeared { ttl, addr: a }),
                _ => {}
            }

            if let (Some(bm), Some(h)) = (base_ms, cur) {
                if let Some(now) = h.stat.avg_ms() {
                    if now > bm * lat_factor && now - bm > 5.0 {
                        out.push(Alert::LatencyRegression { ttl, baseline_ms: bm, now_ms: now });
                    }
                }
            }

            if let Some(h) = cur {
                let loss = h.stat.loss_pct();
                if loss >= 10.0 {
                    out.push(Alert::LossOnset { ttl, pct: loss });
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProbeOutcome, ProbeResponse};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn hop1(ip: [u8; 4], rtt_ms: u64) -> Session {
        let mut s = Session::default();
        s.on_sent(1);
        s.on_response(&ProbeResponse {
            ttl: 1,
            seq: 0,
            outcome: ProbeOutcome::TtlExceeded,
            from: Some(IpAddr::V4(Ipv4Addr::from(ip))),
            rtt: Some(Duration::from_millis(rtt_ms)),
        });
        s.note_reached(1);
        s
    }

    #[test]
    fn detects_route_change_and_clean_baseline() {
        let base = Baseline::capture(&hop1([10, 0, 0, 1], 5));
        assert!(base.deviations(&hop1([10, 0, 0, 1], 5), 1.5).is_empty());

        let devs = base.deviations(&hop1([10, 0, 0, 2], 5), 1.5);
        assert!(devs.iter().any(|a| matches!(a, Alert::RouteChanged { ttl: 1, .. })));
    }

    #[test]
    fn detects_latency_regression() {
        let base = Baseline::capture(&hop1([10, 0, 0, 1], 10));
        let devs = base.deviations(&hop1([10, 0, 0, 1], 40), 1.5);
        assert!(devs.iter().any(|a| matches!(a, Alert::LatencyRegression { .. })));
    }
}
