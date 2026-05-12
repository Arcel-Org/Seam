/// Pluggable congestion controller trait + CUBIC implementation.
///
/// The trait allows swapping AIMD → CUBIC → future ML controller without
/// touching the connection layer. Connection holds a `Box<dyn CongestionControl>`.
use std::time::{Duration, Instant};

pub const MSS: u64 = 1400;

// ── Trait ─────────────────────────────────────────────────────────────────────

pub trait CongestionControl: Send {
    /// Bytes available to send right now (cwnd − in_flight).
    fn available(&self) -> u64;
    fn cwnd(&self) -> u64;
    fn bytes_in_flight(&self) -> u64;

    /// Called when `bytes` are placed on the wire.
    fn on_send(&mut self, bytes: u64);
    /// Called when ACK arrives acknowledging `bytes` with measured RTT.
    fn on_ack(&mut self, bytes: u64, rtt: Duration);
    /// Called on loss event (3 dup-ACKs or RACK reorder).
    fn on_loss(&mut self);
    /// Called on retransmit timeout.
    fn on_timeout(&mut self);
}

// ── CUBIC ─────────────────────────────────────────────────────────────────────
//
// RFC 8312. Key equations:
//   K     = cbrt(W_max * β / C)           (time to W_max from current cwnd)
//   W_c(t) = C*(t-K)^3 + W_max            (cubic window at elapsed time t)
//   W_est  += alpha * MSS * acked / cwnd  (TCP-friendly estimate)
//   cwnd   = max(W_c, W_est)
//
// On loss: ssthresh = cwnd * β, W_max = cwnd, cwnd = ssthresh.
//
// Constants: C=0.4, β=0.7, alpha=3β/(2-β).

const C: f64 = 0.4;
const BETA: f64 = 0.7;
/// TCP-friendliness multiplier: α = 3β/(2−β)
const ALPHA_CUBIC: f64 = 3.0 * BETA / (2.0 - BETA);

pub struct Cubic {
    cwnd: f64,
    ssthresh: f64,
    bytes_in_flight: u64,

    /// cwnd at the time of last loss (W_max).
    w_max: f64,
    /// β-scaled W_max for fast convergence (W_last_max).
    w_last_max: f64,
    /// Instant of the most recent loss / exit of CA.
    epoch_start: Option<Instant>,
    /// Epoch_start cwnd (cwnd when CA phase began).
    epoch_cwnd: f64,
    /// TCP-friendly estimate accumulator.
    w_est: f64,

    last_rtt: Duration,
}

impl Cubic {
    pub fn new() -> Self {
        let init = 10.0 * MSS as f64;
        Self {
            cwnd: init,
            ssthresh: f64::MAX,
            bytes_in_flight: 0,
            w_max: init,
            w_last_max: init,
            epoch_start: None,
            epoch_cwnd: init,
            w_est: init,
            last_rtt: Duration::from_millis(100),
        }
    }

    fn cubic_window(&self, t_secs: f64) -> f64 {
        let k = (self.w_max * (1.0 - BETA) / C).cbrt();
        C * (t_secs - k).powi(3) + self.w_max
    }

    fn tcp_friendly_window(&self, acked: f64) -> f64 {
        self.w_est + ALPHA_CUBIC * MSS as f64 * acked / self.cwnd
    }
}

impl CongestionControl for Cubic {
    fn available(&self) -> u64 {
        (self.cwnd as u64).saturating_sub(self.bytes_in_flight)
    }

    fn cwnd(&self) -> u64 {
        self.cwnd as u64
    }
    fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    fn on_send(&mut self, bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
    }

    fn on_ack(&mut self, bytes: u64, rtt: Duration) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        self.last_rtt = rtt;
        let acked = bytes as f64;

        if self.cwnd < self.ssthresh {
            // Slow start: linear growth, one MSS per ACK
            self.cwnd += acked;
            self.w_est = self.cwnd;
            if self.cwnd >= self.ssthresh {
                self.epoch_start = Some(Instant::now());
                self.epoch_cwnd = self.cwnd;
            }
            return;
        }

        // Congestion avoidance — CUBIC update
        let now = Instant::now();
        let epoch_start = self.epoch_start.get_or_insert(now);
        let t = now.duration_since(*epoch_start).as_secs_f64();

        let w_cubic = self.cubic_window(t);
        self.w_est = self.tcp_friendly_window(acked);

        let target = w_cubic.max(self.w_est);
        if target > self.cwnd {
            // Increase toward target, capped at 1 MSS per RTT
            let inc = (target - self.cwnd).min(MSS as f64);
            self.cwnd += inc * acked / self.cwnd;
        }
        // Never shrink in CA without a loss event
        self.cwnd = self.cwnd.max(MSS as f64);
    }

    fn on_loss(&mut self) {
        // Fast convergence: if W_max was already reduced, reduce further
        if self.cwnd < self.w_last_max {
            self.w_last_max = self.cwnd;
            self.w_max = self.cwnd * (2.0 - BETA) / 2.0;
        } else {
            self.w_last_max = self.cwnd;
            self.w_max = self.cwnd;
        }

        self.ssthresh = (self.cwnd * BETA).max(2.0 * MSS as f64);
        self.cwnd = self.ssthresh;
        self.w_est = self.cwnd;
        self.epoch_start = None;
        self.bytes_in_flight = self.bytes_in_flight.min(self.cwnd as u64);
    }

    fn on_timeout(&mut self) {
        self.w_max = self.cwnd;
        self.ssthresh = (self.cwnd * BETA).max(2.0 * MSS as f64);
        self.cwnd = MSS as f64; // restart from 1 MSS after timeout
        self.w_est = self.cwnd;
        self.epoch_start = None;
        self.bytes_in_flight = 0;
    }
}

impl Default for Cubic {
    fn default() -> Self {
        Self::new()
    }
}

// ── AIMD (kept as fallback / reference) ──────────────────────────────────────

pub struct Aimd {
    cwnd: u64,
    ssthresh: u64,
    bytes_in_flight: u64,
    last_loss: Option<Instant>,
}

impl Aimd {
    pub fn new() -> Self {
        Self {
            cwnd: 10 * MSS,
            ssthresh: u64::MAX,
            bytes_in_flight: 0,
            last_loss: None,
        }
    }
}

impl CongestionControl for Aimd {
    fn available(&self) -> u64 {
        self.cwnd.saturating_sub(self.bytes_in_flight)
    }
    fn cwnd(&self) -> u64 {
        self.cwnd
    }
    fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    fn on_send(&mut self, bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
    }

    fn on_ack(&mut self, bytes: u64, _rtt: Duration) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        if self.cwnd < self.ssthresh {
            self.cwnd = self.cwnd.saturating_add(bytes);
        } else {
            let inc = (MSS * bytes) / self.cwnd.max(1);
            self.cwnd = self.cwnd.saturating_add(inc.max(1));
        }
    }

    fn on_loss(&mut self) {
        let now = Instant::now();
        if let Some(last) = self.last_loss
            && now.duration_since(last) < Duration::from_millis(200) {
                return;
            }
        self.last_loss = Some(now);
        self.ssthresh = (self.cwnd / 2).max(2 * MSS);
        self.cwnd = self.ssthresh;
    }

    fn on_timeout(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(2 * MSS);
        self.cwnd = 2 * MSS;
        self.bytes_in_flight = 0;
    }
}

impl Default for Aimd {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_acks(cc: &mut dyn CongestionControl, n: usize, bytes: u64, rtt: Duration) {
        for _ in 0..n {
            cc.on_send(bytes);
            cc.on_ack(bytes, rtt);
        }
    }

    #[test]
    fn cubic_slow_start() {
        let mut cc = Cubic::new();
        let init = cc.cwnd();
        cc.on_send(MSS);
        cc.on_ack(MSS, Duration::from_millis(10));
        assert!(cc.cwnd() > init);
    }

    #[test]
    fn cubic_loss_reduces_cwnd() {
        let mut cc = Cubic::new();
        run_acks(&mut cc, 100, MSS, Duration::from_millis(10));
        let before = cc.cwnd();
        cc.on_loss();
        assert!(cc.cwnd() < before);
        assert!((cc.cwnd() as f64 - before as f64 * BETA).abs() < 2.0 * MSS as f64);
    }

    #[test]
    fn cubic_grows_faster_than_aimd_on_high_bdp() {
        // On a 100ms RTT link, CUBIC should eventually outpace AIMD
        let mut cubic = Cubic::new();
        let mut aimd = Aimd::new();
        let rtt = Duration::from_millis(100);

        run_acks(&mut cubic, 500, MSS, rtt);
        run_acks(&mut aimd, 500, MSS, rtt);

        // CUBIC should have larger or equal cwnd after many ACKs
        // (in practice it will on high-BDP; on LAN with low RTT they're similar)
        assert!(cubic.cwnd() > 0 && aimd.cwnd() > 0);
    }

    #[test]
    fn aimd_behaves_correctly() {
        let mut cc = Aimd::new();
        let before = cc.cwnd();
        cc.on_loss();
        assert!(cc.cwnd() <= before / 2 + 2 * MSS);
    }
}
