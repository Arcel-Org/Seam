use crate::transport::cc::{CongestionControl, MSS};
/// BBRv1 congestion controller (Cardwell et al., 2016).
///
/// Unlike loss-based CC (AIMD/CUBIC), BBR models the path as a pipe with:
///   • BtlBw  — bottleneck bandwidth (max delivery rate over recent window)
///   • RTprop — min RTT over recent window (path propagation delay)
/// and operates at the BDP (bandwidth-delay product).
///
/// BtlBw × RTprop  ≈ optimal cwnd.
///
/// States:
///   Startup  — fast ramp (gain=2.89, like slow start but in rate-space)
///   Drain    — bleed the queue built in startup (gain=1/2.89)
///   ProbeBW  — normal cruise; rotate 8 gains: 1.25, 0.75, 1, 1, 1, 1, 1, 1
///   ProbeRTT — every 10s, shrink cwnd to 4×MSS for 200ms to re-measure RTprop
///
/// This implementation is a pragmatic, teaching-quality BBRv1. For bulk
/// transfer on modern links it generally beats CUBIC on throughput and
/// latency simultaneously; on highly lossy short-RTT links CUBIC may still
/// win. The pluggable `CongestionControl` trait lets callers A/B at runtime.
use std::time::{Duration, Instant};

const STARTUP_GAIN: f64 = 2.89; // 2/ln(2)
const DRAIN_GAIN: f64 = 1.0 / STARTUP_GAIN;
const PROBE_GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

const BW_WINDOW_RTTS: u32 = 10;
const RTPROP_WINDOW: Duration = Duration::from_secs(10);
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);
const MIN_PIPE_CWND: u64 = 4 * MSS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BbrState {
    Startup,
    Drain,
    ProbeBW,
    ProbeRTT,
}

pub struct Bbr {
    state: BbrState,

    /// Bottleneck bandwidth estimate (bytes/sec).
    btl_bw: f64,
    /// Max BW seen in each of the last N round trips (windowed max filter).
    bw_samples: [f64; BW_WINDOW_RTTS as usize],
    bw_sample_idx: usize,

    /// Minimum RTT over the recent window.
    rtprop: Duration,
    rtprop_stamp: Instant,

    /// Current pacing gain and cwnd gain.
    pacing_gain: f64,
    cwnd_gain: f64,
    probe_cycle_idx: usize,
    cycle_stamp: Instant,

    probe_rtt_done_stamp: Option<Instant>,

    cwnd: u64,
    bytes_in_flight: u64,
    delivered: u64,
    delivered_time: Instant,
    round_count: u32,

    full_pipe: bool,
    prior_bw: f64,
    full_pipe_count: u32,
}

impl Bbr {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            state: BbrState::Startup,
            btl_bw: 0.0,
            bw_samples: [0.0; BW_WINDOW_RTTS as usize],
            bw_sample_idx: 0,
            rtprop: Duration::from_secs(1),
            rtprop_stamp: now,
            pacing_gain: STARTUP_GAIN,
            cwnd_gain: STARTUP_GAIN,
            probe_cycle_idx: 0,
            cycle_stamp: now,
            probe_rtt_done_stamp: None,
            cwnd: 10 * MSS,
            bytes_in_flight: 0,
            delivered: 0,
            delivered_time: now,
            round_count: 0,
            full_pipe: false,
            prior_bw: 0.0,
            full_pipe_count: 0,
        }
    }

    fn update_bw(&mut self, sample: f64) {
        self.bw_samples[self.bw_sample_idx] = sample;
        self.bw_sample_idx = (self.bw_sample_idx + 1) % BW_WINDOW_RTTS as usize;
        self.btl_bw = self.bw_samples.iter().cloned().fold(0.0_f64, f64::max);
    }

    fn update_rtprop(&mut self, rtt: Duration) {
        let now = Instant::now();
        let expired = now.duration_since(self.rtprop_stamp) >= RTPROP_WINDOW;
        if rtt < self.rtprop || expired || self.rtprop == Duration::from_secs(1) {
            self.rtprop = rtt;
            self.rtprop_stamp = now;
        }
    }

    fn target_cwnd(&self, gain: f64) -> u64 {
        let bdp = self.btl_bw * self.rtprop.as_secs_f64();
        ((bdp * gain) as u64).max(MIN_PIPE_CWND)
    }

    fn advance_probe_bw(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.cycle_stamp) >= self.rtprop {
            self.probe_cycle_idx = (self.probe_cycle_idx + 1) % PROBE_GAINS.len();
            self.pacing_gain = PROBE_GAINS[self.probe_cycle_idx];
            self.cwnd_gain = 2.0; // BBR keeps cwnd_gain ≈ 2 in steady state
            self.cycle_stamp = now;
        }
    }

    fn check_full_pipe(&mut self) {
        if self.full_pipe || self.state != BbrState::Startup {
            return;
        }
        // Plateau detection: 3 rounds without 25% BtlBw growth
        if self.btl_bw >= self.prior_bw * 1.25 {
            self.prior_bw = self.btl_bw;
            self.full_pipe_count = 0;
            return;
        }
        self.full_pipe_count += 1;
        if self.full_pipe_count >= 3 {
            self.full_pipe = true;
        }
    }

    fn enter_drain(&mut self) {
        self.state = BbrState::Drain;
        self.pacing_gain = DRAIN_GAIN;
        self.cwnd_gain = STARTUP_GAIN;
    }

    fn enter_probe_bw(&mut self) {
        self.state = BbrState::ProbeBW;
        self.pacing_gain = PROBE_GAINS[0];
        self.cwnd_gain = 2.0;
        self.probe_cycle_idx = 0;
        self.cycle_stamp = Instant::now();
    }

    fn maybe_enter_probe_rtt(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.rtprop_stamp) >= RTPROP_WINDOW
            && self.state != BbrState::ProbeRTT
        {
            self.state = BbrState::ProbeRTT;
            self.probe_rtt_done_stamp = Some(now + PROBE_RTT_DURATION);
        }
    }

    fn maybe_exit_probe_rtt(&mut self) {
        if self.state == BbrState::ProbeRTT
            && let Some(done) = self.probe_rtt_done_stamp
                && Instant::now() >= done {
                    self.rtprop_stamp = Instant::now();
                    self.enter_probe_bw();
                }
    }
}

impl CongestionControl for Bbr {
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

    fn on_ack(&mut self, bytes: u64, rtt: Duration) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        self.delivered = self.delivered.saturating_add(bytes);

        // Measure delivery rate
        let now = Instant::now();
        let interval = now
            .duration_since(self.delivered_time)
            .as_secs_f64()
            .max(0.000_001);
        let sample_bw = bytes as f64 / interval;
        self.update_bw(sample_bw);
        self.delivered_time = now;

        self.update_rtprop(rtt);

        match self.state {
            BbrState::Startup => {
                self.check_full_pipe();
                if self.full_pipe {
                    self.enter_drain();
                }
            }
            BbrState::Drain => {
                if self.bytes_in_flight <= self.target_cwnd(1.0) {
                    self.enter_probe_bw();
                }
            }
            BbrState::ProbeBW => {
                self.advance_probe_bw();
                self.maybe_enter_probe_rtt();
            }
            BbrState::ProbeRTT => {
                self.maybe_exit_probe_rtt();
            }
        }

        // Update cwnd
        if self.state == BbrState::ProbeRTT {
            self.cwnd = MIN_PIPE_CWND;
        } else {
            self.cwnd = self.target_cwnd(self.cwnd_gain);
        }
        self.round_count = self.round_count.wrapping_add(1);
    }

    fn on_loss(&mut self) {
        // BBR ignores loss as a congestion signal (model-based). Optionally
        // shrink bytes_in_flight here — we already subtract on ACK.
        // Cut cwnd by 15% like BBRv2's recovery to handle pathological cases.
        let new_cwnd = (self.cwnd as f64 * 0.85) as u64;
        self.cwnd = new_cwnd.max(MIN_PIPE_CWND);
    }

    fn on_timeout(&mut self) {
        // PTO: conservative — drop to min window, restart from Startup
        self.cwnd = MIN_PIPE_CWND;
        self.bytes_in_flight = 0;
        self.state = BbrState::Startup;
        self.pacing_gain = STARTUP_GAIN;
        self.cwnd_gain = STARTUP_GAIN;
        self.full_pipe = false;
        self.full_pipe_count = 0;
    }
}

impl Default for Bbr {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bbr_starts_in_startup_with_high_gain() {
        let bbr = Bbr::new();
        assert_eq!(bbr.state, BbrState::Startup);
        assert!(bbr.pacing_gain > 2.0);
    }

    #[test]
    fn bbr_tracks_bandwidth_samples() {
        let mut bbr = Bbr::new();
        for _ in 0..5 {
            bbr.on_send(MSS);
            bbr.on_ack(MSS, Duration::from_millis(10));
        }
        assert!(bbr.btl_bw > 0.0);
    }

    #[test]
    fn bbr_cwnd_respects_min() {
        let mut bbr = Bbr::new();
        bbr.on_timeout();
        assert!(bbr.cwnd() >= MIN_PIPE_CWND);
    }

    #[test]
    fn bbr_loss_does_not_collapse_cwnd() {
        let mut bbr = Bbr::new();
        // Grow cwnd via ACKs
        for _ in 0..100 {
            bbr.on_send(MSS);
            bbr.on_ack(MSS, Duration::from_millis(5));
        }
        let before = bbr.cwnd();
        bbr.on_loss();
        // BBR shouldn't halve cwnd on loss like CUBIC
        assert!(bbr.cwnd() as f64 >= before as f64 * 0.8);
    }
}
