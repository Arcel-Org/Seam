use bytes::Bytes;
/// RACK-TLP loss detection (RFC 8985).
///
/// RACK ("Recent ACKnowledgment") detects losses based on packet send time
/// rather than packet number. A packet is declared lost if a later-sent
/// packet has been ACKed and this packet's send time is older than the
/// most-recently-ACKed send time minus a small reorder window.
///
/// Over RTO-only loss detection, RACK typically declares losses within
/// ~(1 + 1/4) × RTT instead of the ≥3 × RTT of classic TCP retransmission
/// timeout, cutting tail latencies dramatically.
///
/// Wire-compatible with existing ARQ: the caller just feeds send/ack events.
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// RACK reorder window as a fraction of SRTT.
const RACK_REORDER_FRAC_NUM: u32 = 1;
const RACK_REORDER_FRAC_DEN: u32 = 4; // 1/4 SRTT

pub struct InFlightPacket {
    pub data: Bytes,
    pub sent_at: Instant,
    pub size: u64,
    pub retransmits: u32,
}

pub struct RackTracker {
    /// Packet number → in-flight state
    in_flight: BTreeMap<u64, InFlightPacket>,
    /// Send time of the latest packet that has been ACKed.
    rack_xmit_time: Option<Instant>,
    /// Highest packet number ACKed so far.
    rack_end_seq: u64,
    /// Reorder window duration.
    reorder_window: Duration,

    // RTT state (RFC 6298)
    srtt_us: u64,
    rttvar_us: u64,
    min_rtt: Duration,

    // Stats
    pub losses_detected: u64,
    pub acks_received: u64,
}

impl RackTracker {
    pub fn new() -> Self {
        Self {
            in_flight: BTreeMap::new(),
            rack_xmit_time: None,
            rack_end_seq: 0,
            reorder_window: Duration::from_millis(5), // initial default
            srtt_us: 0,
            rttvar_us: 0,
            min_rtt: Duration::from_secs(1),
            losses_detected: 0,
            acks_received: 0,
        }
    }

    /// Record a packet transmission.
    pub fn on_sent(&mut self, pkt_num: u64, data: Bytes, size: u64) {
        self.in_flight.insert(
            pkt_num,
            InFlightPacket {
                data,
                sent_at: Instant::now(),
                size,
                retransmits: 0,
            },
        );
    }

    /// Record receipt of an ACK. Updates RTT and RACK reference time.
    /// Returns (rtt_sample, packets newly declared lost).
    pub fn on_ack(&mut self, pkt_num: u64) -> (Option<Duration>, Vec<(u64, Bytes, u64)>) {
        self.acks_received = self.acks_received.saturating_add(1);

        let Some(pkt) = self.in_flight.remove(&pkt_num) else {
            return (None, Vec::new());
        };

        let rtt = pkt.sent_at.elapsed();

        // Update RACK reference (only for in-order ACKs)
        if pkt_num >= self.rack_end_seq {
            self.rack_end_seq = pkt_num;
            self.rack_xmit_time = Some(pkt.sent_at);
        }

        // Update RTT samples (Karn's algorithm: skip retransmits)
        let rtt_sample = if pkt.retransmits == 0 {
            self.update_rtt(rtt);
            Some(rtt)
        } else {
            None
        };

        // Recompute reorder window: max(1ms, 1/4 × SRTT)
        if self.srtt_us > 0 {
            let frac_us =
                self.srtt_us * RACK_REORDER_FRAC_NUM as u64 / RACK_REORDER_FRAC_DEN as u64;
            self.reorder_window = Duration::from_micros(frac_us).max(Duration::from_millis(1));
        }

        // Declare lost: any in-flight packet sent more than reorder_window
        // before the latest-ACKed packet's send time.
        let losses = self.detect_losses();
        self.losses_detected = self.losses_detected.saturating_add(losses.len() as u64);

        (rtt_sample, losses)
    }

    /// Returns losses detected purely by timeout (PTO fallback).
    pub fn detect_tail_loss(&mut self, pto: Duration) -> Vec<(u64, Bytes, u64)> {
        let now = Instant::now();
        let mut lost = Vec::new();
        let mut keys_to_remove = Vec::new();

        for (&pn, pkt) in self.in_flight.iter() {
            if now.duration_since(pkt.sent_at) > pto {
                lost.push((pn, pkt.data.clone(), pkt.size));
                keys_to_remove.push(pn);
            }
        }
        for k in keys_to_remove {
            self.in_flight.remove(&k);
        }
        self.losses_detected = self.losses_detected.saturating_add(lost.len() as u64);
        lost
    }

    fn detect_losses(&mut self) -> Vec<(u64, Bytes, u64)> {
        let Some(reference) = self.rack_xmit_time else {
            return Vec::new();
        };
        let threshold = reference.checked_sub(self.reorder_window);
        let Some(threshold) = threshold else {
            return Vec::new();
        };

        let mut lost = Vec::new();
        let mut keys_to_remove = Vec::new();

        for (&pn, pkt) in self.in_flight.iter() {
            if pn < self.rack_end_seq && pkt.sent_at < threshold {
                lost.push((pn, pkt.data.clone(), pkt.size));
                keys_to_remove.push(pn);
            }
        }
        for k in keys_to_remove {
            self.in_flight.remove(&k);
        }
        lost
    }

    fn update_rtt(&mut self, rtt: Duration) {
        if rtt < self.min_rtt || self.min_rtt == Duration::from_secs(1) {
            self.min_rtt = rtt;
        }
        let rtt_us = rtt.as_micros() as u64;
        if self.srtt_us == 0 {
            self.srtt_us = rtt_us;
            self.rttvar_us = rtt_us / 2;
        } else {
            let diff = self.srtt_us.abs_diff(rtt_us);
            self.rttvar_us = (3 * self.rttvar_us / 4) + (diff / 4);
            self.srtt_us = (7 * self.srtt_us / 8) + (rtt_us / 8);
        }
    }

    pub fn srtt(&self) -> Duration {
        Duration::from_micros(self.srtt_us)
    }
    pub fn rttvar(&self) -> Duration {
        Duration::from_micros(self.rttvar_us)
    }
    pub fn min_rtt(&self) -> Duration {
        self.min_rtt
    }
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }
    pub fn in_flight_bytes(&self) -> u64 {
        self.in_flight.values().map(|p| p.size).sum()
    }

    /// Probe Timeout: SRTT + 4·RTTVAR + max_ack_delay, clamped.
    pub fn pto(&self) -> Duration {
        let pto_us = self.srtt_us + 4 * self.rttvar_us + 25_000; // 25ms max_ack_delay
        Duration::from_micros(pto_us.max(200_000)).min(Duration::from_secs(60))
    }
}

impl Default for RackTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_updates_srtt_and_removes_packet() {
        let mut r = RackTracker::new();
        r.on_sent(1, Bytes::from_static(b"x"), 100);
        // Backdate send time by 20ms
        r.in_flight.get_mut(&1).unwrap().sent_at = Instant::now() - Duration::from_millis(20);
        let (rtt, losses) = r.on_ack(1);
        assert!(rtt.is_some());
        assert_eq!(losses.len(), 0);
        assert_eq!(r.in_flight_count(), 0);
        assert!(r.srtt() >= Duration::from_millis(10));
    }

    #[test]
    fn rack_declares_earlier_packet_lost_on_later_ack() {
        let mut r = RackTracker::new();
        // Seed SRTT so reorder_window is meaningful
        r.srtt_us = 20_000; // 20ms
        r.reorder_window = Duration::from_millis(5);

        // Packet 1 sent 30ms ago, packet 2 sent 5ms ago, 2 is ACKed first
        r.on_sent(1, Bytes::from_static(b"old"), 100);
        r.in_flight.get_mut(&1).unwrap().sent_at = Instant::now() - Duration::from_millis(30);

        r.on_sent(2, Bytes::from_static(b"new"), 100);
        r.in_flight.get_mut(&2).unwrap().sent_at = Instant::now() - Duration::from_millis(5);

        let (_rtt, losses) = r.on_ack(2);
        assert_eq!(losses.len(), 1, "packet 1 should be declared lost");
        assert_eq!(losses[0].0, 1);
    }

    #[test]
    fn tail_loss_detected_by_pto() {
        let mut r = RackTracker::new();
        r.on_sent(5, Bytes::from_static(b"tail"), 100);
        r.in_flight.get_mut(&5).unwrap().sent_at = Instant::now() - Duration::from_secs(2);
        let lost = r.detect_tail_loss(Duration::from_millis(500));
        assert_eq!(lost.len(), 1);
    }

    #[test]
    fn pto_at_least_200ms() {
        let r = RackTracker::new();
        assert!(r.pto() >= Duration::from_millis(200));
    }
}
