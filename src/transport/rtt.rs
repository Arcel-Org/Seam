/// RFC 6298 EWMA RTT estimator with variance tracking.
///
/// SRTT  = (1 - α) * SRTT + α * rtt_sample      α = 1/8
/// RTTVAR = (1 - β) * RTTVAR + β * |SRTT - rtt_sample|  β = 1/4
/// RTO    = max(SRTT + 4 * RTTVAR, 200ms)
use std::time::{Duration, Instant};

const ALPHA: f64 = 0.125; // 1/8
const BETA: f64 = 0.25; // 1/4
const MIN_RTO: Duration = Duration::from_millis(200);

pub struct RttEstimator {
    /// Smoothed RTT.
    srtt: Duration,
    /// RTT variance.
    rttvar: Duration,
    /// Minimum RTT seen across all samples.
    min_rtt: Duration,
    /// Timestamp of the last update.
    last_updated: Instant,
    /// True once at least one sample has been provided.
    initialized: bool,
}

impl RttEstimator {
    pub fn new() -> Self {
        Self {
            srtt: Duration::from_millis(100),
            rttvar: Duration::from_millis(50),
            min_rtt: Duration::from_secs(u64::MAX),
            last_updated: Instant::now(),
            initialized: false,
        }
    }

    /// Incorporate a new RTT sample.
    ///
    /// On the first call the SRTT is set directly to the sample (RFC 6298 §2.2).
    pub fn update(&mut self, rtt_sample: Duration) {
        self.last_updated = Instant::now();

        // Track minimum across all samples.
        if rtt_sample < self.min_rtt {
            self.min_rtt = rtt_sample;
        }

        if !self.initialized {
            // First measurement: seed SRTT = sample, RTTVAR = sample/2.
            self.srtt = rtt_sample;
            self.rttvar = rtt_sample / 2;
            self.initialized = true;
            return;
        }

        // RTTVAR must be updated before SRTT (uses current SRTT).
        let srtt_us = self.srtt.as_micros() as f64;
        let sample_us = rtt_sample.as_micros() as f64;
        let diff = (srtt_us - sample_us).abs();
        let rttvar_us = self.rttvar.as_micros() as f64;
        let new_rttvar = (1.0 - BETA) * rttvar_us + BETA * diff;
        let new_srtt = (1.0 - ALPHA) * srtt_us + ALPHA * sample_us;

        self.rttvar = Duration::from_micros(new_rttvar.max(1.0) as u64);
        self.srtt = Duration::from_micros(new_srtt.max(1.0) as u64);
    }

    /// Smoothed RTT.
    pub fn srtt(&self) -> Duration {
        self.srtt
    }

    /// Retransmission timeout: max(SRTT + 4 * RTTVAR, 200ms).
    pub fn rto(&self) -> Duration {
        let rto = self.srtt + 4 * self.rttvar;
        rto.max(MIN_RTO)
    }

    /// Minimum RTT observed since creation.
    pub fn min_rtt(&self) -> Duration {
        if self.min_rtt == Duration::from_secs(u64::MAX) {
            self.srtt
        } else {
            self.min_rtt
        }
    }

    /// True if at least one sample has been received.
    pub fn has_sample(&self) -> bool {
        self.initialized
    }

    /// Time since the last RTT sample was recorded.
    pub fn time_since_update(&self) -> Duration {
        self.last_updated.elapsed()
    }
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_first_sample_seeds_srtt() {
        let mut est = RttEstimator::new();
        est.update(Duration::from_millis(20));
        assert_eq!(est.srtt(), Duration::from_millis(20));
        assert_eq!(est.min_rtt(), Duration::from_millis(20));
    }

    #[test]
    fn rtt_converges_within_20_samples() {
        let true_rtt = Duration::from_millis(50);
        let mut est = RttEstimator::new();
        for _ in 0..20 {
            est.update(true_rtt);
        }
        let srtt_ms = est.srtt().as_millis() as f64;
        let true_ms = true_rtt.as_millis() as f64;
        let pct_err = (srtt_ms - true_ms).abs() / true_ms;
        assert!(
            pct_err < 0.10,
            "SRTT {srtt_ms}ms should be within 10% of {true_ms}ms, error={pct_err:.2}"
        );
    }

    #[test]
    fn rtt_rto_floor() {
        let mut est = RttEstimator::new();
        // Tiny RTT — RTO should still be >= 200ms.
        est.update(Duration::from_micros(100));
        assert!(est.rto() >= Duration::from_millis(200));
    }

    #[test]
    fn rtt_tracks_min() {
        let mut est = RttEstimator::new();
        est.update(Duration::from_millis(100));
        est.update(Duration::from_millis(20));
        est.update(Duration::from_millis(80));
        assert_eq!(est.min_rtt(), Duration::from_millis(20));
    }
}
