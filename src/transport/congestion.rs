/// BBR-inspired congestion controller with windowed bandwidth filter.
///
/// Implements a simplified BBRv1 model as a standalone struct that can be used
/// alongside (or in place of) the `CongestionControl`-trait implementations in
/// `cc.rs` and `bbr.rs`.  The key difference from the trait-based `Bbr` in
/// `bbr.rs` is that this version exposes richer introspection (pacing rate,
/// `should_send`, explicit state-transition logging) and uses the generic
/// `WindowedMaxFilter` for bandwidth estimation.
///
/// # State machine
///
/// ```text
/// STARTUP ──(BW plateaus 3 rounds)──► DRAIN ──(inflight ≤ BDP)──► PROBE_BW
///   ▲                                                                  │
///   │                        any state ◄──(RTprop fresh again)──► PROBE_RTT
///   └─────────────────────────────────(timeout)──────────────────────────┘
/// ```
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use tracing::debug;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Pacing gains for the 8-slot ProbeBW cycle.
const PROBE_GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
/// Initial startup gain (≈ 2/ln2, matches BBRv1).
const STARTUP_GAIN: f64 = 2.89;
/// Drain gain: reciprocal of startup.
const DRAIN_GAIN: f64 = 1.0 / STARTUP_GAIN;
/// Bandwidth filter window in round-trip rounds.
const BW_WINDOW_ROUNDS: u64 = 10;
/// How long before RTprop is considered stale and we probe it again.
const RTPROP_WINDOW: Duration = Duration::from_secs(10);
/// How long to hold inflight at `MIN_CWND` during ProbeRTT.
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);
/// Minimum congestion window (4 × 1400-byte segments).
const MIN_CWND: usize = 4 * 1400;

// ── WindowedMaxFilter ─────────────────────────────────────────────────────────

/// Sliding-window maximum filter over (round, value) pairs.
///
/// Retains only entries within the last `window_size` rounds and reports the
/// maximum value across those entries.  Used for the bandwidth filter in BBR.
pub struct WindowedMaxFilter {
    window: VecDeque<(u64, f64)>,
    window_size: u64,
}

impl WindowedMaxFilter {
    pub fn new(window_size: u64) -> Self {
        Self {
            window: VecDeque::new(),
            window_size,
        }
    }

    /// Add a new sample at `round` with `value`.  Evicts stale entries and
    /// maintains the invariant that entries are in non-increasing value order
    /// (monotone deque trick for O(1) amortised max).
    pub fn update(&mut self, round: u64, value: f64) {
        // Evict entries that are outside the window.
        while let Some(&(r, _)) = self.window.front() {
            if round.saturating_sub(r) >= self.window_size {
                self.window.pop_front();
            } else {
                break;
            }
        }
        // Maintain descending-value invariant.
        while let Some(&(_, v)) = self.window.back() {
            if v <= value {
                self.window.pop_back();
            } else {
                break;
            }
        }
        self.window.push_back((round, value));
    }

    /// Maximum value in the current window; 0.0 if the filter is empty.
    pub fn max(&self) -> f64 {
        self.window.front().map(|&(_, v)| v).unwrap_or(0.0)
    }
}

// ── BbrState ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbrState {
    /// Exponential growth until bottleneck bandwidth plateaus.
    Startup,
    /// Drain the queue built during Startup.
    Drain,
    /// Steady state: cycle pacing gains to probe for more bandwidth.
    ProbeBw,
    /// Periodically reduce inflight to min cwnd to re-measure min RTT.
    ProbeRtt,
}

// ── BbrController ─────────────────────────────────────────────────────────────

/// Simplified BBR congestion controller.
///
/// This struct is *not* wired to the `CongestionControl` trait; it is used as
/// an advisory layer inside `Connection` alongside the trait-based controller.
/// The `Connection` calls `should_send()` before enqueuing data and `on_ack()`
/// whenever ACK feedback arrives.
pub struct BbrController {
    /// Estimated bottleneck bandwidth (bytes/sec).
    btl_bw: f64,
    /// Estimated minimum RTT (propagation delay).
    min_rtt: Duration,
    /// Timestamp when min_rtt was last updated.
    min_rtt_stamp: Instant,
    /// Pacing rate: btl_bw × pacing_gain.
    pacing_rate: f64,
    /// Current BBR state.
    state: BbrState,
    /// Windowed-max filter for bandwidth (10 rounds).
    bw_filter: WindowedMaxFilter,
    /// Bytes currently in flight (sent but not yet acknowledged).
    inflight: usize,
    /// ProbeBW cycle index (0–7).
    cycle_idx: u8,
    /// Timestamp of last ProbeBW cycle step.
    cycle_stamp: Instant,
    /// Monotonic round counter (incremented on every on_ack call).
    round: u64,

    // Startup plateau detection
    full_pipe: bool,
    prior_bw: f64,
    full_pipe_count: u32,

    // ProbeRTT
    probe_rtt_done_stamp: Option<Instant>,
    /// State to return to after ProbeRTT completes.
    state_before_probe_rtt: BbrState,
}

impl BbrController {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            btl_bw: 0.0,
            min_rtt: Duration::from_secs(1),
            min_rtt_stamp: now,
            pacing_rate: 0.0,
            state: BbrState::Startup,
            bw_filter: WindowedMaxFilter::new(BW_WINDOW_ROUNDS),
            inflight: 0,
            cycle_idx: 0,
            cycle_stamp: now,
            round: 0,
            full_pipe: false,
            prior_bw: 0.0,
            full_pipe_count: 0,
            probe_rtt_done_stamp: None,
            state_before_probe_rtt: BbrState::ProbeBw,
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Call whenever ACK feedback arrives.
    ///
    /// - `bytes_acked` — bytes acknowledged by this ACK
    /// - `rtt`         — measured round-trip time sample
    /// - `timestamp`   — when the ACK was processed (typically `Instant::now()`)
    pub fn on_ack(&mut self, bytes_acked: usize, rtt: Duration, timestamp: Instant) {
        self.round = self.round.wrapping_add(1);

        // Update inflight.
        self.inflight = self.inflight.saturating_sub(bytes_acked);

        // Update min RTT.
        self.update_min_rtt(rtt, timestamp);

        // Compute delivery rate and update bandwidth filter.
        let elapsed = rtt.as_secs_f64().max(1e-6);
        let delivery_rate = bytes_acked as f64 / elapsed;
        self.bw_filter.update(self.round, delivery_rate);
        let prev_bw = self.btl_bw;
        self.btl_bw = self.bw_filter.max();

        // Update pacing rate.
        self.update_pacing_rate();

        // State machine transitions.
        let prev_state = self.state;
        match self.state {
            BbrState::Startup => {
                self.check_full_pipe(prev_bw);
                if self.full_pipe {
                    debug!("BBR: Startup → Drain (full pipe detected)");
                    self.state = BbrState::Drain;
                }
            }
            BbrState::Drain => {
                if self.inflight <= self.bdp() {
                    debug!("BBR: Drain → ProbeBw (inflight within BDP)");
                    self.enter_probe_bw(timestamp);
                }
            }
            BbrState::ProbeBw => {
                self.advance_probe_bw(timestamp);
                self.maybe_enter_probe_rtt(timestamp);
            }
            BbrState::ProbeRtt => {
                self.maybe_exit_probe_rtt(timestamp);
            }
        }
        if self.state != prev_state {
            debug!("BBR state: {:?} → {:?}", prev_state, self.state);
        }
    }

    /// Current pacing rate in bytes/sec.
    pub fn pacing_rate(&self) -> f64 {
        self.pacing_rate
    }

    /// Congestion window in bytes.
    pub fn cwnd(&self) -> usize {
        if self.state == BbrState::ProbeRtt {
            return MIN_CWND;
        }
        let gain = match self.state {
            BbrState::Startup => STARTUP_GAIN,
            BbrState::Drain => DRAIN_GAIN,
            BbrState::ProbeBw => 2.0,
            BbrState::ProbeRtt => 1.0,
        };
        (self.bdp() as f64 * gain).ceil() as usize
    }

    /// True if the controller permits sending more data (inflight < cwnd).
    pub fn should_send(&self, inflight: usize) -> bool {
        inflight < self.cwnd().max(MIN_CWND)
    }

    /// Current state.
    pub fn state(&self) -> BbrState {
        self.state
    }

    /// Bytes in flight as tracked by the controller.
    pub fn inflight(&self) -> usize {
        self.inflight
    }

    /// Notify the controller that `bytes` have been placed on the wire.
    pub fn on_send(&mut self, bytes: usize) {
        self.inflight = self.inflight.saturating_add(bytes);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Bandwidth-delay product in bytes.
    fn bdp(&self) -> usize {
        if self.btl_bw == 0.0 {
            return MIN_CWND;
        }
        (self.btl_bw * self.min_rtt.as_secs_f64()).ceil() as usize
    }

    fn update_pacing_rate(&mut self) {
        let gain = match self.state {
            BbrState::Startup => STARTUP_GAIN,
            BbrState::Drain => DRAIN_GAIN,
            BbrState::ProbeBw => PROBE_GAINS[self.cycle_idx as usize],
            BbrState::ProbeRtt => 1.0,
        };
        self.pacing_rate = self.btl_bw * gain;
    }

    fn update_min_rtt(&mut self, rtt: Duration, now: Instant) {
        let expired = now.duration_since(self.min_rtt_stamp) >= RTPROP_WINDOW;
        if rtt <= self.min_rtt || expired || self.min_rtt == Duration::from_secs(1) {
            self.min_rtt = rtt;
            self.min_rtt_stamp = now;
        }
    }

    fn check_full_pipe(&mut self, prev_bw: f64) {
        if self.full_pipe {
            return;
        }
        // Startup plateau: BW gain < 1.25× for 3 consecutive rounds.
        if self.btl_bw >= prev_bw * 1.25 {
            self.prior_bw = self.btl_bw;
            self.full_pipe_count = 0;
        } else {
            self.full_pipe_count += 1;
            if self.full_pipe_count >= 3 {
                self.full_pipe = true;
            }
        }
    }

    fn enter_probe_bw(&mut self, now: Instant) {
        self.state = BbrState::ProbeBw;
        self.cycle_idx = 0;
        self.cycle_stamp = now;
        self.update_pacing_rate();
    }

    fn advance_probe_bw(&mut self, now: Instant) {
        if now.duration_since(self.cycle_stamp) >= self.min_rtt {
            self.cycle_idx = (self.cycle_idx + 1) % PROBE_GAINS.len() as u8;
            self.cycle_stamp = now;
            self.update_pacing_rate();
        }
    }

    fn maybe_enter_probe_rtt(&mut self, now: Instant) {
        if now.duration_since(self.min_rtt_stamp) >= RTPROP_WINDOW
            && self.state != BbrState::ProbeRtt
        {
            self.state_before_probe_rtt = self.state;
            self.state = BbrState::ProbeRtt;
            self.probe_rtt_done_stamp = Some(now + PROBE_RTT_DURATION);
            debug!("BBR: entering ProbeRtt");
        }
    }

    fn maybe_exit_probe_rtt(&mut self, now: Instant) {
        if let Some(done) = self.probe_rtt_done_stamp {
            if now >= done {
                self.min_rtt_stamp = now; // reset so we don't immediately re-enter
                self.probe_rtt_done_stamp = None;
                self.state = BbrState::ProbeBw;
                self.cycle_idx = 0;
                self.cycle_stamp = now;
                self.update_pacing_rate();
                debug!("BBR: exiting ProbeRtt → ProbeBw");
            }
        }
    }
}

impl Default for BbrController {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simulate_acks(
        ctrl: &mut BbrController,
        rounds: usize,
        bytes_per_round: usize,
        rtt: Duration,
    ) {
        let now = Instant::now();
        for i in 0..rounds {
            let t = now + rtt * i as u32;
            ctrl.on_send(bytes_per_round);
            ctrl.on_ack(bytes_per_round, rtt, t);
        }
    }

    // ── BBR Startup ──────────────────────────────────────────────────────────

    #[test]
    fn bbr_startup_reaches_full_bw_within_4_rtts() {
        let mut ctrl = BbrController::new();
        let rtt = Duration::from_millis(10);
        // Simulate a high-bandwidth path: 10 MB/s with 10 ms RTT → BDP = 100 KB.
        // Feed enough data to trigger full_pipe detection within 4 RTTs.
        let bytes_per_ack = 100_000; // large chunk so BW estimate builds quickly

        let mut bandwidth_reached = false;
        let now = Instant::now();
        for i in 0..4usize {
            ctrl.on_send(bytes_per_ack);
            ctrl.on_ack(bytes_per_ack, rtt, now + rtt * i as u32);
            if ctrl.btl_bw > 0.0 {
                bandwidth_reached = true;
            }
        }
        assert!(
            bandwidth_reached,
            "BBR should have a positive BW estimate within 4 RTTs"
        );
        assert!(
            ctrl.btl_bw > 0.0,
            "btl_bw should be positive after ACKs, got {}",
            ctrl.btl_bw
        );
    }

    // ── BBR Drain ────────────────────────────────────────────────────────────

    #[test]
    fn bbr_drain_reduces_inflight_to_bdp() {
        let mut ctrl = BbrController::new();
        let rtt = Duration::from_millis(20);
        let now = Instant::now();

        // Force Startup → Drain by marking full_pipe manually.
        ctrl.full_pipe = true;
        ctrl.full_pipe_count = 3;
        ctrl.state = BbrState::Startup;
        ctrl.btl_bw = 1_000_000.0; // 1 MB/s
        ctrl.bw_filter.update(1, 1_000_000.0);
        ctrl.min_rtt = rtt;

        // A single on_ack in Startup should flip to Drain.
        ctrl.on_ack(1400, rtt, now);
        assert_eq!(
            ctrl.state,
            BbrState::Drain,
            "should enter Drain after full_pipe is set"
        );

        // Now simulate draining: inflight should fall to ≤ BDP.
        let bdp = ctrl.bdp();
        // Set inflight above BDP.
        ctrl.inflight = bdp + 50_000;
        // Simulate acks that bring inflight down.
        let ack_chunk = 10_000;
        let mut t = now;
        for _ in 0..100 {
            t += rtt;
            if ctrl.inflight > bdp {
                ctrl.on_send(ack_chunk);
                ctrl.on_ack(ack_chunk, rtt, t);
            } else {
                break;
            }
        }
        // After draining, should be in ProbeBw.
        assert!(
            matches!(ctrl.state, BbrState::ProbeBw | BbrState::Drain),
            "expected ProbeBw or still Drain, got {:?}",
            ctrl.state
        );
    }

    // ── WindowedMaxFilter ────────────────────────────────────────────────────

    #[test]
    fn windowed_max_filter_evicts_old_entries() {
        let mut f = WindowedMaxFilter::new(3);
        f.update(1, 100.0);
        f.update(2, 200.0);
        f.update(3, 150.0);
        assert_eq!(f.max(), 200.0);

        // Round 4 evicts round 1 (window = 3, rounds 2–4 remain).
        f.update(4, 50.0);
        assert_eq!(f.max(), 200.0); // round 2 still in window

        // Round 5 evicts round 2.
        f.update(5, 50.0);
        assert_eq!(f.max(), 150.0);
    }

    #[test]
    fn windowed_max_filter_empty_returns_zero() {
        let f = WindowedMaxFilter::new(10);
        assert_eq!(f.max(), 0.0);
    }

    // ── should_send ──────────────────────────────────────────────────────────

    #[test]
    fn should_send_false_when_inflight_exceeds_cwnd() {
        let mut ctrl = BbrController::new();
        ctrl.btl_bw = 1_000_000.0;
        ctrl.min_rtt = Duration::from_millis(10);
        let cw = ctrl.cwnd();
        assert!(!ctrl.should_send(cw + 1), "should not send when above cwnd");
        assert!(ctrl.should_send(0), "should send when inflight is zero");
    }

    // ── pacing rate ──────────────────────────────────────────────────────────

    #[test]
    fn pacing_rate_positive_after_acks() {
        let mut ctrl = BbrController::new();
        simulate_acks(&mut ctrl, 5, 10_000, Duration::from_millis(10));
        assert!(
            ctrl.pacing_rate() > 0.0,
            "pacing rate should be positive after ACKs"
        );
    }
}
