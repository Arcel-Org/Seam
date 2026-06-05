/// Windowed bandwidth estimator.
///
/// Records delivery-rate samples (bytes/sec) with timestamps and exposes:
///   - `estimate()`   — windowed-max delivery rate (best observed in window)
///   - `percentile()` — p-th percentile delivery rate for jitter/stability analysis
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub struct BandwidthEstimator {
    /// Circular buffer of (delivery_rate bytes/sec, timestamp) samples.
    samples: VecDeque<(f64, Instant)>,
    /// Observation window; samples older than this are evicted.
    window: Duration,
}

impl BandwidthEstimator {
    pub fn new(window: Duration) -> Self {
        Self {
            samples: VecDeque::new(),
            window,
        }
    }

    /// Record a delivery event: `bytes` were acknowledged over `elapsed` time.
    ///
    /// Silently ignores zero-duration intervals to avoid infinite rates.
    pub fn record_delivery(&mut self, bytes: usize, elapsed: Duration) {
        let elapsed_secs = elapsed.as_secs_f64();
        if elapsed_secs <= 0.0 {
            return;
        }
        let rate = bytes as f64 / elapsed_secs;
        let now = Instant::now();
        self.samples.push_back((rate, now));
        // Evict samples outside the window.
        self.evict();
    }

    /// Current bandwidth estimate: maximum delivery rate observed in the window.
    /// Returns 0.0 if no samples are available.
    pub fn estimate(&self) -> f64 {
        self.samples
            .iter()
            .map(|(r, _)| *r)
            .fold(0.0_f64, f64::max)
    }

    /// p-th percentile delivery rate (0.0 ≤ p ≤ 1.0).
    ///
    /// p=0.5 → median, p=0.95 → 95th percentile.
    /// Returns 0.0 if no samples are available.
    pub fn percentile(&self, p: f64) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let mut rates: Vec<f64> = self.samples.iter().map(|(r, _)| *r).collect();
        rates.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let idx = ((rates.len() as f64 - 1.0) * p.clamp(0.0, 1.0)).round() as usize;
        rates[idx.min(rates.len() - 1)]
    }

    /// Number of samples currently in the window.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    fn evict(&mut self) {
        let cutoff = Instant::now() - self.window;
        while let Some(&(_, ts)) = self.samples.front() {
            if ts < cutoff {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }
}

impl Default for BandwidthEstimator {
    fn default() -> Self {
        Self::new(Duration::from_secs(10))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bandwidth_windowed_max() {
        let mut bw = BandwidthEstimator::new(Duration::from_secs(30));
        bw.record_delivery(1000, Duration::from_millis(10)); // 100 KB/s
        bw.record_delivery(1000, Duration::from_millis(5));  // 200 KB/s
        bw.record_delivery(1000, Duration::from_millis(20)); //  50 KB/s

        let est = bw.estimate();
        // Max sample is the 200 KB/s one.
        assert!(
            (est - 200_000.0).abs() < 1.0,
            "windowed max should be ~200_000 bytes/sec, got {est}"
        );
    }

    #[test]
    fn bandwidth_percentile_median() {
        let mut bw = BandwidthEstimator::new(Duration::from_secs(30));
        // Insert 5 samples at known rates: 1, 2, 3, 4, 5 MB/s.
        for mbps in [1_000_000u64, 2_000_000, 3_000_000, 4_000_000, 5_000_000] {
            bw.record_delivery(mbps as usize, Duration::from_secs(1));
        }
        let p50 = bw.percentile(0.5);
        assert!(
            (p50 - 3_000_000.0).abs() < 1.0,
            "p50 should be 3 MB/s, got {p50}"
        );
    }

    #[test]
    fn bandwidth_empty_returns_zero() {
        let bw = BandwidthEstimator::new(Duration::from_secs(10));
        assert_eq!(bw.estimate(), 0.0);
        assert_eq!(bw.percentile(0.5), 0.0);
    }

    #[test]
    fn bandwidth_ignores_zero_elapsed() {
        let mut bw = BandwidthEstimator::new(Duration::from_secs(10));
        bw.record_delivery(1000, Duration::ZERO);
        assert_eq!(bw.sample_count(), 0);
    }
}
