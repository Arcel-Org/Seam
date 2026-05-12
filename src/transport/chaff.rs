/// Chaff packet scheduler for traffic-analysis resistance.
///
/// Two mechanisms:
/// 1. **Chaff packets**: fake encrypted packets sent at exponentially-distributed
///    intervals (memoryless, observer cannot distinguish bursts from real traffic).
/// 2. **MTU padding**: real packets are padded to the path MTU so all packets
///    look the same size to an observer. Chaff packets use the same padded size.
///
/// Combined, an observer sees a constant-rate stream of fixed-size ciphertexts.
use std::time::{Duration, Instant};

pub const MAX_CHAFF_BYTES: usize = 1400; // padded to path MTU, ≤ this
pub const MIN_CHAFF_BYTES: usize = 16;

/// Target mean inter-chaff interval.
const MEAN_INTERVAL_MS: u64 = 50;

pub struct ChaffScheduler {
    next_send: Instant,
    enabled: bool,
    /// LCG state for jitter generation (no external RNG dependency).
    lcg: u64,
}

impl ChaffScheduler {
    pub fn new() -> Self {
        Self {
            next_send: Instant::now(),
            enabled: false,
            lcg: 0xdeadbeef_cafebabe,
        }
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }
    pub fn disable(&mut self) {
        self.enabled = false;
    }
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn should_send(&self) -> bool {
        self.enabled && Instant::now() >= self.next_send
    }

    pub fn time_until_next(&self) -> Duration {
        if !self.enabled {
            return Duration::MAX;
        }
        self.next_send.saturating_duration_since(Instant::now())
    }

    /// Advance the chaff schedule after a packet is sent.
    /// Uses the send_counter as additional entropy for the LCG.
    pub fn mark_sent(&mut self, send_counter: u64) {
        self.lcg = self
            .lcg
            .wrapping_mul(6364136223846793005)
            .wrapping_add(send_counter.wrapping_add(1));
        let interval = pseudo_exp(self.lcg, MEAN_INTERVAL_MS);
        self.next_send = Instant::now() + Duration::from_millis(interval);
    }

    /// Build a chaff payload of `size` zero bytes (caller encrypts it).
    pub fn payload(seed: u64) -> Vec<u8> {
        let len = MIN_CHAFF_BYTES + (seed as usize % (MAX_CHAFF_BYTES - MIN_CHAFF_BYTES + 1));
        vec![0u8; len]
    }

    /// Pad `payload` with zeros so the encrypted packet fills `path_mtu` bytes.
    ///
    /// APEX packet on wire: 32B header + payload + 16B tag.
    /// Target wire size = path_mtu → payload target = path_mtu - 32 - 16 = path_mtu - 48.
    /// If payload is already larger, return it unchanged.
    pub fn pad_to_mtu(&self, payload: &[u8], path_mtu: usize) -> Vec<u8> {
        let overhead = 32 + 16; // header + AEAD tag
        let target_payload = path_mtu.saturating_sub(overhead);
        if payload.len() >= target_payload {
            return payload.to_vec();
        }
        let mut padded = payload.to_vec();
        padded.resize(target_payload, 0);
        padded
    }

    /// Add timing jitter to a real send: delay up to `max_jitter_ms` milliseconds.
    /// Returns the jitter duration that should be applied before flushing.
    /// Call this on every flush to introduce sub-RTT timing noise.
    pub fn jitter_delay(&mut self) -> Duration {
        if !self.enabled {
            return Duration::ZERO;
        }
        self.lcg = self.lcg.wrapping_mul(6364136223846793005).wrapping_add(1);
        // Jitter ≤ 5ms — small enough not to hurt latency, large enough to blur timing
        let jitter_us = (self.lcg >> 32) as u64 % 5_000;
        Duration::from_micros(jitter_us)
    }
}

/// Approximate exponential distribution using an LCG seed.
/// Returns a value drawn from Exp(1/mean_ms) clamped to [mean/4, mean*4].
fn pseudo_exp(seed: u64, mean_ms: u64) -> u64 {
    let u = (seed >> 33) as f64 / (u32::MAX as f64 + 1.0); // uniform (0,1)
    let sample = -(1.0 - u).ln() * mean_ms as f64;
    (sample as u64).clamp(mean_ms / 4, mean_ms * 4)
}

impl Default for ChaffScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_to_mtu_correct_size() {
        let cs = ChaffScheduler::new();
        let mtu = 1400usize;
        let padded = cs.pad_to_mtu(&[1u8; 100], mtu);
        // Padded payload + 32 header + 16 tag should equal MTU
        assert_eq!(padded.len() + 32 + 16, mtu);
    }

    #[test]
    fn pad_does_not_shrink_large_payload() {
        let cs = ChaffScheduler::new();
        let big = vec![0u8; 2000];
        let out = cs.pad_to_mtu(&big, 1400);
        assert_eq!(out.len(), big.len());
    }

    #[test]
    fn jitter_within_bounds() {
        let mut cs = ChaffScheduler::new();
        cs.enable();
        for _ in 0..100 {
            let j = cs.jitter_delay();
            assert!(j <= Duration::from_millis(5));
        }
    }
}
