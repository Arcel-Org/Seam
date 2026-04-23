/// Connection-level statistics for monitoring and observability.
///
/// Snapshots are cheap (plain data copy). Applications can poll periodically
/// to export to Prometheus / OpenTelemetry / structured logs.
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    // Traffic counters
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,

    // Loss & retransmission
    pub packets_lost: u64,
    pub retransmits: u64,
    pub fec_recovered: u64,
    pub fec_unrecoverable: u64,

    // Congestion + RTT
    pub cwnd_bytes: u64,
    pub bytes_in_flight: u64,
    pub srtt: Duration,
    pub rttvar: Duration,
    pub min_rtt: Duration,
    pub max_rtt: Duration,

    // Streams
    pub streams_opened: u64,
    pub streams_closed: u64,
    pub active_streams: u32,

    // Datagrams (unreliable)
    pub datagrams_sent: u64,
    pub datagrams_recv: u64,
    pub datagrams_dropped: u64,

    // Handshake
    pub handshake_duration_us: u64,
    pub cookie_challenges_issued: u64,
    pub cookie_failures: u64,

    // Path
    pub path_mtu: u32,
    pub current_cc: &'static str, // "cubic", "aimd", "bbr"
}

impl ConnectionStats {
    pub fn new() -> Self { Self::default() }

    /// Update RTT min/max given a new sample.
    pub fn record_rtt(&mut self, rtt: Duration) {
        if self.min_rtt.is_zero() || rtt < self.min_rtt {
            self.min_rtt = rtt;
        }
        if rtt > self.max_rtt {
            self.max_rtt = rtt;
        }
    }

    pub fn loss_rate(&self) -> f32 {
        let total = self.packets_sent.max(1);
        self.packets_lost as f32 / total as f32
    }

    pub fn retransmit_rate(&self) -> f32 {
        let total = self.packets_sent.max(1);
        self.retransmits as f32 / total as f32
    }

    /// Effective goodput (application data) — subtracts retransmits from bytes_sent.
    pub fn goodput_bytes(&self) -> u64 {
        // Rough estimate: each retransmit wastes ~MSS
        let wasted = self.retransmits.saturating_mul(1400);
        self.bytes_sent.saturating_sub(wasted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_min_max_tracking() {
        let mut s = ConnectionStats::new();
        s.record_rtt(Duration::from_millis(20));
        s.record_rtt(Duration::from_millis(10));
        s.record_rtt(Duration::from_millis(50));
        assert_eq!(s.min_rtt, Duration::from_millis(10));
        assert_eq!(s.max_rtt, Duration::from_millis(50));
    }

    #[test]
    fn loss_rate_calc() {
        let mut s = ConnectionStats::new();
        s.packets_sent = 1000;
        s.packets_lost = 25;
        assert!((s.loss_rate() - 0.025).abs() < 1e-4);
    }
}
