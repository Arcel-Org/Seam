use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use bytes::Bytes;

/// An in-flight packet tracked for retransmission.
struct InFlight {
    data: Bytes,
    sent_at: Instant,
    retransmits: u32,
}

/// Selective ARQ retransmission tracker.
/// Tracks unacknowledged packets and schedules retransmission after RTO.
pub struct ArqTracker {
    in_flight: BTreeMap<u64, InFlight>, // keyed by packet number
    rto: Duration,
    srtt_us: u64,
    rttvar_us: u64,
}

impl ArqTracker {
    pub fn new() -> Self {
        Self {
            in_flight: BTreeMap::new(),
            rto: Duration::from_millis(300),
            srtt_us: 0,
            rttvar_us: 0,
        }
    }

    /// Record a packet as sent.
    pub fn on_sent(&mut self, pkt_num: u64, data: Bytes) {
        self.in_flight.insert(pkt_num, InFlight {
            data,
            sent_at: Instant::now(),
            retransmits: 0,
        });
    }

    /// Record receipt of an ACK for `pkt_num`. Updates RTT estimates.
    pub fn on_ack(&mut self, pkt_num: u64) -> Option<Duration> {
        if let Some(pkt) = self.in_flight.remove(&pkt_num) {
            if pkt.retransmits == 0 {
                // Only update RTT on first transmission (Karn's algorithm)
                let rtt = pkt.sent_at.elapsed();
                self.update_rtt(rtt);
                return Some(rtt);
            }
        }
        None
    }

    /// Returns packets that have exceeded RTO and should be retransmitted.
    pub fn drain_expired(&mut self) -> Vec<(u64, Bytes)> {
        let now = Instant::now();
        let rto = self.rto;
        let mut expired = Vec::new();
        for (pkt_num, pkt) in self.in_flight.iter_mut() {
            if now.duration_since(pkt.sent_at) >= rto {
                expired.push((*pkt_num, pkt.data.clone()));
                pkt.sent_at = now;
                pkt.retransmits += 1;
            }
        }
        // Exponential backoff on timeout
        if !expired.is_empty() {
            self.rto = (self.rto * 2).min(Duration::from_secs(60));
        }
        expired
    }

    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    pub fn srtt(&self) -> Duration {
        Duration::from_micros(self.srtt_us)
    }

    fn update_rtt(&mut self, rtt: Duration) {
        let rtt_us = rtt.as_micros() as u64;
        if self.srtt_us == 0 {
            // First measurement
            self.srtt_us = rtt_us;
            self.rttvar_us = rtt_us / 2;
        } else {
            // RFC 6298 SRTT update
            let diff = self.srtt_us.abs_diff(rtt_us);
            self.rttvar_us = (3 * self.rttvar_us / 4) + (diff / 4);
            self.srtt_us = (7 * self.srtt_us / 8) + (rtt_us / 8);
        }
        // RTO = SRTT + 4*RTTVAR, clamped to [200ms, 60s]
        let rto_us = self.srtt_us + 4 * self.rttvar_us;
        self.rto = Duration::from_micros(rto_us)
            .max(Duration::from_millis(200))
            .min(Duration::from_secs(60));
    }
}

impl Default for ArqTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_for_unknown_packet_is_ignored() {
        let mut arq = ArqTracker::new();
        assert_eq!(arq.on_ack(42), None);
    }

    #[test]
    fn ack_for_first_send_updates_rtt_and_clears_in_flight() {
        let mut arq = ArqTracker::new();
        arq.on_sent(1, Bytes::from_static(b"payload"));
        let sent = arq.in_flight.get_mut(&1).unwrap();
        sent.sent_at = Instant::now() - Duration::from_millis(25);

        let rtt = arq.on_ack(1).unwrap();
        assert!(rtt >= Duration::from_millis(1));
        assert_eq!(arq.in_flight_count(), 0);
        assert!(arq.srtt() >= Duration::from_millis(1));
        assert!(arq.rto >= Duration::from_millis(200));
    }

    #[test]
    fn expired_packets_are_retransmitted_and_backoff_applies() {
        let mut arq = ArqTracker::new();
        arq.on_sent(5, Bytes::from_static(b"hello"));
        let initial_rto = arq.rto;
        let sent = arq.in_flight.get_mut(&5).unwrap();
        sent.sent_at = Instant::now() - initial_rto;

        let expired = arq.drain_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, 5);
        assert_eq!(expired[0].1, Bytes::from_static(b"hello"));
        assert_eq!(arq.rto, (initial_rto * 2).min(Duration::from_secs(60)));
        assert_eq!(arq.in_flight.get(&5).unwrap().retransmits, 1);
    }

    #[test]
    fn ack_after_retransmit_does_not_update_rtt() {
        let mut arq = ArqTracker::new();
        arq.on_sent(7, Bytes::from_static(b"rto"));
        let sent = arq.in_flight.get_mut(&7).unwrap();
        sent.sent_at = Instant::now() - arq.rto;

        let _ = arq.drain_expired();
        assert_eq!(arq.on_ack(7), None);
        assert_eq!(arq.srtt(), Duration::from_micros(0));
    }
}
