//! Per-hop rolling statistics.
//!
//! Everything here is O(1) per probe and bounded in memory — no growing history
//! to sort. Mean and variance use Welford's online algorithm (numerically
//! stable), giving us jitter (RTT standard deviation) for free. Streaming
//! percentiles (t-digest / fixed histogram) land in a later phase; the API is
//! shaped to absorb them without touching callers.

use std::time::Duration;

/// Rolling stats for a single hop. Cheap to clone, cheap to update.
#[derive(Debug, Clone, Default)]
pub struct HopStat {
    sent: u64,
    recv: u64,
    last_ms: Option<f64>,
    best_ms: Option<f64>,
    worst_ms: Option<f64>,
    mean_ms: f64,
    /// Sum of squared deviations from the running mean (Welford's M2).
    m2: f64,
}

impl HopStat {
    /// Count a probe we just emitted toward this hop.
    pub fn record_sent(&mut self) {
        self.sent += 1;
    }

    /// Fold a received round-trip time into the rolling stats.
    pub fn record_rtt(&mut self, rtt: Duration) {
        let ms = rtt.as_secs_f64() * 1000.0;
        self.recv += 1;
        self.last_ms = Some(ms);
        self.best_ms = Some(self.best_ms.map_or(ms, |b| b.min(ms)));
        self.worst_ms = Some(self.worst_ms.map_or(ms, |w| w.max(ms)));

        // Welford online mean/variance.
        let delta = ms - self.mean_ms;
        self.mean_ms += delta / self.recv as f64;
        let delta2 = ms - self.mean_ms;
        self.m2 += delta * delta2;
    }

    pub fn sent(&self) -> u64 {
        self.sent
    }

    pub fn recv(&self) -> u64 {
        self.recv
    }

    /// Packet loss percentage in `0.0..=100.0`.
    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            return 0.0;
        }
        (self.sent - self.recv) as f64 / self.sent as f64 * 100.0
    }

    pub fn last_ms(&self) -> Option<f64> {
        self.last_ms
    }

    pub fn best_ms(&self) -> Option<f64> {
        self.best_ms
    }

    pub fn worst_ms(&self) -> Option<f64> {
        self.worst_ms
    }

    /// Mean RTT in ms, or `None` until the first reply.
    pub fn avg_ms(&self) -> Option<f64> {
        if self.recv == 0 {
            None
        } else {
            Some(self.mean_ms)
        }
    }

    /// Jitter: sample standard deviation of RTT. Needs at least two replies.
    pub fn stddev_ms(&self) -> Option<f64> {
        if self.recv < 2 {
            None
        } else {
            Some((self.m2 / (self.recv - 1) as f64).sqrt())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn welford_matches_naive() {
        let mut s = HopStat::default();
        let samples = [10.0_f64, 12.0, 8.0, 11.0, 9.0];
        for &ms in &samples {
            s.record_sent();
            s.record_rtt(Duration::from_secs_f64(ms / 1000.0));
        }
        let n = samples.len() as f64;
        let mean = samples.iter().sum::<f64>() / n;
        let var = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);

        assert!((s.avg_ms().unwrap() - mean).abs() < 1e-6);
        assert!((s.stddev_ms().unwrap() - var.sqrt()).abs() < 1e-6);
        assert_eq!(s.loss_pct(), 0.0);
    }

    #[test]
    fn loss_is_counted() {
        let mut s = HopStat::default();
        for _ in 0..4 {
            s.record_sent();
        }
        s.record_rtt(Duration::from_millis(5));
        assert_eq!(s.loss_pct(), 75.0);
    }
}
