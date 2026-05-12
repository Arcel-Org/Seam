/// AIMD congestion controller.
///
/// Starts in slow-start (cwnd doubles per RTT until ssthresh), then enters
/// congestion avoidance (cwnd += MSS²/cwnd per ACK). On loss, ssthresh =
/// cwnd/2 and cwnd = ssthresh (fast recovery).
use std::time::{Duration, Instant};

const MSS: u64 = 1400; // max segment size in bytes
const INIT_CWND: u64 = 10 * MSS; // RFC 6928: 10-segment initial window
const MIN_CWND: u64 = 2 * MSS;

pub struct CongestionController {
    cwnd: u64,
    ssthresh: u64,
    bytes_in_flight: u64,
    last_loss: Option<Instant>,
}

impl CongestionController {
    pub fn new() -> Self {
        Self {
            cwnd: INIT_CWND,
            ssthresh: u64::MAX,
            bytes_in_flight: 0,
            last_loss: None,
        }
    }

    /// Returns the number of bytes the caller may send right now.
    pub fn available(&self) -> u64 {
        self.cwnd.saturating_sub(self.bytes_in_flight)
    }

    pub fn cwnd(&self) -> u64 {
        self.cwnd
    }
    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    /// Call when a packet of `bytes` is sent.
    pub fn on_send(&mut self, bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
    }

    /// Call when an ACK for `bytes` arrives, with the measured RTT sample.
    pub fn on_ack(&mut self, bytes: u64, _rtt: Duration) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        if self.cwnd < self.ssthresh {
            // Slow start: increase by one MSS per ACKed segment
            self.cwnd = self.cwnd.saturating_add(bytes).min(self.ssthresh);
        } else {
            // Congestion avoidance: increase by MSS²/cwnd (≈ 1 MSS per RTT)
            let inc = MSS.saturating_mul(bytes) / self.cwnd.max(1);
            self.cwnd = self.cwnd.saturating_add(inc.max(1));
        }
    }

    /// Call on packet loss (retransmit timeout or 3 duplicate ACKs).
    pub fn on_loss(&mut self) {
        // Avoid multiple reductions within one RTT
        let now = Instant::now();
        if let Some(last) = self.last_loss {
            if now.duration_since(last) < Duration::from_millis(200) {
                return;
            }
        }
        self.last_loss = Some(now);
        self.ssthresh = (self.cwnd / 2).max(MIN_CWND);
        self.cwnd = self.ssthresh;
        self.bytes_in_flight = self.bytes_in_flight.min(self.cwnd);
    }

    /// Call on retransmit timeout (more aggressive reduction than fast recovery).
    pub fn on_timeout(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(MIN_CWND);
        self.cwnd = MIN_CWND;
        self.bytes_in_flight = 0; // reset — we have no idea what's in flight
    }
}

impl Default for CongestionController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slow_start_growth() {
        let mut cc = CongestionController::new();
        let initial = cc.cwnd();
        cc.on_send(MSS);
        cc.on_ack(MSS, Duration::from_millis(10));
        assert!(cc.cwnd() > initial, "cwnd should grow in slow start");
    }

    #[test]
    fn test_loss_halves_cwnd() {
        let mut cc = CongestionController::new();
        // Drive into CA
        cc.ssthresh = 5 * MSS;
        cc.cwnd = 10 * MSS;
        cc.on_loss();
        assert_eq!(cc.cwnd(), 5 * MSS);
    }

    #[test]
    fn test_timeout_resets_cwnd() {
        let mut cc = CongestionController::new();
        cc.cwnd = 100 * MSS;
        cc.on_timeout();
        assert_eq!(cc.cwnd(), MIN_CWND);
    }
}
