/// Token-bucket packet pacer.
///
/// Sends packets at `cwnd / srtt` bytes/second instead of bursting the full
/// window at once. This prevents incast and reduces buffer bloat on the path
/// while still achieving full throughput.
///
/// Token refill is *work-conserving*: if no data is queued, unused tokens
/// accumulate up to one burst's worth (`max_burst`) so a sudden send doesn't
/// stall.
use std::time::{Duration, Instant};

/// Default maximum burst: 16 packets × 1400 B.
const DEFAULT_MAX_BURST: u64 = 16 * 1400;
/// Minimum pacing rate: 32 KiB/s (keeps the connection alive on idle paths).
const MIN_RATE_BYTES_PER_SEC: u64 = 32 * 1024;

pub struct Pacer {
    /// Current token bucket fill (bytes).
    tokens: f64,
    /// Token fill rate (bytes/second).
    rate: f64,
    /// Maximum bucket capacity (bytes).
    max_burst: f64,
    last_refill: Instant,
}

impl Pacer {
    pub fn new() -> Self {
        Self {
            tokens: DEFAULT_MAX_BURST as f64,
            rate: MIN_RATE_BYTES_PER_SEC as f64,
            max_burst: DEFAULT_MAX_BURST as f64,
            last_refill: Instant::now(),
        }
    }

    /// Update the pacing rate from the congestion controller state.
    /// `cwnd_bytes` — current congestion window; `srtt` — smoothed RTT.
    pub fn update_rate(&mut self, cwnd_bytes: u64, srtt: Duration) {
        let srtt_secs = srtt.as_secs_f64().max(0.001); // avoid div-by-zero
        let rate = cwnd_bytes as f64 / srtt_secs;
        self.rate = rate.max(MIN_RATE_BYTES_PER_SEC as f64);
        // Max burst: one RTT worth of data (or DEFAULT_MAX_BURST, whichever is larger)
        self.max_burst = (cwnd_bytes as f64).max(DEFAULT_MAX_BURST as f64);
    }

    /// Refill tokens based on elapsed time since last call.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + self.rate * elapsed).min(self.max_burst);
        self.last_refill = now;
    }

    /// Returns how many bytes the caller may send right now (≥ 0).
    pub fn available(&mut self) -> u64 {
        self.refill();
        self.tokens as u64
    }

    /// Consume `bytes` tokens. Call after sending a packet.
    pub fn consume(&mut self, bytes: u64) {
        self.tokens = (self.tokens - bytes as f64).max(0.0);
    }

    /// How long until `bytes` bytes become available (for use in select!/sleep).
    pub fn time_until_available(&mut self, bytes: u64) -> Duration {
        self.refill();
        if self.tokens >= bytes as f64 {
            return Duration::ZERO;
        }
        let deficit = bytes as f64 - self.tokens;
        let secs = deficit / self.rate.max(1.0);
        Duration::from_secs_f64(secs)
    }

    pub fn rate_bytes_per_sec(&self) -> u64 {
        self.rate as u64
    }
}

impl Default for Pacer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_refill_over_time() {
        let mut p = Pacer::new();
        p.update_rate(100_000, Duration::from_millis(10)); // 10 MB/s
        p.tokens = 0.0;
        p.last_refill = Instant::now() - Duration::from_millis(100); // pretend 100ms passed
        let avail = p.available();
        assert!(avail > 0, "tokens should refill");
    }

    #[test]
    fn consume_reduces_tokens() {
        let mut p = Pacer::new();
        let before = p.available();
        p.consume(1400);
        assert!(p.available() <= before);
    }

    #[test]
    fn rate_update_changes_refill_speed() {
        let mut p = Pacer::new();
        p.tokens = 0.0;
        p.update_rate(1_000_000, Duration::from_millis(10)); // 100 MB/s
        p.last_refill = Instant::now() - Duration::from_millis(1);
        let fast = p.available();

        p.tokens = 0.0;
        p.update_rate(10_000, Duration::from_millis(10)); // 1 MB/s
        p.last_refill = Instant::now() - Duration::from_millis(1);
        let slow = p.available();

        assert!(
            fast > slow,
            "faster rate should give more tokens: {fast} vs {slow}"
        );
    }

    #[test]
    fn time_until_available_zero_when_full() {
        let mut p = Pacer::new();
        assert_eq!(p.time_until_available(100), Duration::ZERO);
    }
}
