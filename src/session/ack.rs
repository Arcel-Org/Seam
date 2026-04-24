/// Range-based ACK tracking (QUIC-style, RFC 9000 §19.3).
///
/// Instead of one ACK packet per received packet, we accumulate received
/// packet numbers into *contiguous ranges* and emit a single ACK frame
/// that covers many packets. This cuts ACK overhead from O(N) to O(gaps).
///
/// Wire format of an ACK frame payload:
///   [largest_acked: u64]
///   [ack_delay_us: u64]                microseconds since largest_acked arrived
///   [range_count: u16]                 number of additional (gap, length) pairs
///   [first_range_length: u64]          # of contiguous ACKed pkts descending from largest_acked
///   // for each additional range:
///   [gap: u64]                         # of unacked packets below the previous range
///   [range_length: u64]                # of ACKed packets in this range
///
/// Packet numbers in each range are derived arithmetically:
///   range i end   = range (i-1) start − gap_i − 1
///   range i start = range i end − length_i + 1
use std::collections::BTreeSet;
use std::time::Instant;

pub struct AckRanges {
    /// Set of received packet numbers not yet ACKed on the wire.
    received: BTreeSet<u64>,
    /// When the largest unacked packet was received (for ack_delay).
    largest_received_at: Option<Instant>,
    /// Largest packet number ever received (for ack_delay math).
    largest_received: u64,
    /// If true, an ACK-eliciting packet has arrived since the last ACK
    /// we sent — we owe the peer an ACK.
    ack_pending: bool,
}

impl AckRanges {
    pub fn new() -> Self {
        Self {
            received: BTreeSet::new(),
            largest_received_at: None,
            largest_received: 0,
            ack_pending: false,
        }
    }

    /// Note that packet `pn` was received. If `ack_eliciting`, mark that we
    /// owe an ACK.
    pub fn on_received(&mut self, pn: u64, ack_eliciting: bool) {
        if pn > self.largest_received || self.received.is_empty() {
            self.largest_received = pn;
            self.largest_received_at = Some(Instant::now());
        }
        self.received.insert(pn);
        if ack_eliciting {
            self.ack_pending = true;
        }
    }

    pub fn has_pending_ack(&self) -> bool { self.ack_pending }
    pub fn is_empty(&self) -> bool { self.received.is_empty() }

    /// Build a single ACK frame payload covering the current receive set.
    /// After building, the pending-ACK flag is cleared but the ranges are
    /// retained so re-transmitted ACKs cover them too.
    pub fn build_frame(&mut self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        if self.received.is_empty() {
            out.extend_from_slice(&0u64.to_le_bytes());   // largest_acked
            out.extend_from_slice(&0u64.to_le_bytes());   // ack_delay_us
            out.extend_from_slice(&0u16.to_le_bytes());   // range_count
            out.extend_from_slice(&0u64.to_le_bytes());   // first_range_length
            self.ack_pending = false;
            return out;
        }

        let largest = *self.received.iter().next_back().unwrap();
        let ack_delay_us = self.largest_received_at
            .map(|t| t.elapsed().as_micros() as u64)
            .unwrap_or(0);

        // Walk downward from `largest`, forming contiguous ranges.
        let mut ranges: Vec<(u64, u64)> = Vec::new(); // (start, end) inclusive, end > start
        let mut cur_end = largest;
        let mut cur_start = largest;
        for &pn in self.received.iter().rev().skip(1) {
            if pn + 1 == cur_start {
                cur_start = pn;
            } else {
                ranges.push((cur_start, cur_end));
                cur_end = pn;
                cur_start = pn;
            }
        }
        ranges.push((cur_start, cur_end));

        let first_range_length = ranges[0].1 - ranges[0].0; // ranges[0].1 == largest
        let extra_ranges = &ranges[1..];
        let range_count = extra_ranges.len() as u16;

        out.extend_from_slice(&largest.to_le_bytes());
        out.extend_from_slice(&ack_delay_us.to_le_bytes());
        out.extend_from_slice(&range_count.to_le_bytes());
        out.extend_from_slice(&first_range_length.to_le_bytes());

        let mut prev_start = ranges[0].0;
        for &(start, end) in extra_ranges {
            let gap = prev_start - end - 1; // packets between ranges that are unacked
            let length = end - start;
            out.extend_from_slice(&gap.to_le_bytes());
            out.extend_from_slice(&length.to_le_bytes());
            prev_start = start;
        }

        self.ack_pending = false;
        out
    }

    /// Drop ACKed info older than the given threshold to bound memory.
    pub fn prune_below(&mut self, threshold: u64) {
        self.received = self.received.split_off(&threshold);
    }
}

impl Default for AckRanges {
    fn default() -> Self { Self::new() }
}

/// Parse an ACK frame. Returns a vector of inclusive (start, end) packet-number ranges.
pub fn parse_ack_frame(frame: &[u8]) -> Option<(u64, u64, Vec<(u64, u64)>)> {
    if frame.len() < 8 + 8 + 2 + 8 { return None; }
    let largest = u64::from_le_bytes(frame[0..8].try_into().ok()?);
    let ack_delay_us = u64::from_le_bytes(frame[8..16].try_into().ok()?);
    let range_count = u16::from_le_bytes(frame[16..18].try_into().ok()?) as usize;
    let first_range_len = u64::from_le_bytes(frame[18..26].try_into().ok()?);

    let mut ranges = Vec::with_capacity(1 + range_count);
    let mut cur_end = largest;
    let mut cur_start = largest.saturating_sub(first_range_len);
    ranges.push((cur_start, cur_end));

    let mut off = 26;
    for _ in 0..range_count {
        if frame.len() < off + 16 { return None; }
        let gap = u64::from_le_bytes(frame[off..off + 8].try_into().ok()?);
        let length = u64::from_le_bytes(frame[off + 8..off + 16].try_into().ok()?);
        off += 16;
        cur_end = cur_start.checked_sub(gap + 1)?;
        cur_start = cur_end.checked_sub(length)?;
        ranges.push((cur_start, cur_end));
    }
    Some((largest, ack_delay_us, ranges))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_packet_ack() {
        let mut a = AckRanges::new();
        a.on_received(5, true);
        assert!(a.has_pending_ack());
        let frame = a.build_frame();
        let (largest, _delay, ranges) = parse_ack_frame(&frame).unwrap();
        assert_eq!(largest, 5);
        assert_eq!(ranges, vec![(5, 5)]);
    }

    #[test]
    fn contiguous_range_ack() {
        let mut a = AckRanges::new();
        for pn in 10..=15 { a.on_received(pn, true); }
        let frame = a.build_frame();
        let (largest, _, ranges) = parse_ack_frame(&frame).unwrap();
        assert_eq!(largest, 15);
        assert_eq!(ranges, vec![(10, 15)]);
    }

    #[test]
    fn multi_range_with_gaps() {
        let mut a = AckRanges::new();
        // Received: 1,2,3 (gap 4,5,6) 7 (gap 8) 9,10
        for pn in [1u64, 2, 3, 7, 9, 10] { a.on_received(pn, true); }
        let frame = a.build_frame();
        let (largest, _, ranges) = parse_ack_frame(&frame).unwrap();
        assert_eq!(largest, 10);
        // Ranges descending from largest: [9,10], [7,7], [1,3]
        assert_eq!(ranges, vec![(9, 10), (7, 7), (1, 3)]);
    }

    #[test]
    fn non_eliciting_does_not_set_pending() {
        let mut a = AckRanges::new();
        a.on_received(1, false);
        assert!(!a.has_pending_ack());
        a.on_received(2, true);
        assert!(a.has_pending_ack());
    }

    #[test]
    fn build_frame_clears_pending() {
        let mut a = AckRanges::new();
        a.on_received(1, true);
        assert!(a.has_pending_ack());
        a.build_frame();
        assert!(!a.has_pending_ack());
    }
}
