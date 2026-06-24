/// Path prober: MTU discovery and keep-alive RTT measurement.
///
/// Sends PathProbe packets at regular intervals and measures one-way RTT
/// from the echo. MTU probing uses binary search between MIN_MTU and MAX_MTU.
///
/// Also tracks consecutive probe timeouts to signal when connection migration
/// should be attempted (see `consecutive_timeouts` and `MIGRATION_THRESHOLD`).
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const MIN_MTU: usize = 1280;
pub const MAX_MTU: usize = 1500;

const PROBE_INTERVAL: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Number of consecutive probe timeouts that triggers connection migration.
pub const MIGRATION_THRESHOLD: u32 = 3;

/// PathProbe payload wire format: probe_id(8) + timestamp_us(8) + padding_to(MTU)
pub const PROBE_HDR: usize = 16;

pub struct PathProber {
    next_probe: Instant,
    pending: HashMap<u64, PendingProbe>,
    next_id: u64,
    pub path_mtu: usize,
    mtu_lo: usize,
    mtu_hi: usize,
    probing_mtu: bool,
    /// Number of consecutive keepalive probe timeouts (resets on any echo received).
    pub consecutive_timeouts: u32,
}

struct PendingProbe {
    sent_at: Instant,
    probe_size: usize,
}

impl PathProber {
    pub fn new() -> Self {
        Self {
            next_probe: Instant::now(),
            pending: HashMap::new(),
            next_id: 0,
            path_mtu: MIN_MTU,
            mtu_lo: MIN_MTU,
            mtu_hi: MAX_MTU,
            probing_mtu: true,
            consecutive_timeouts: 0,
        }
    }

    /// Returns true if it is time to send a path probe.
    pub fn should_probe(&self) -> bool {
        Instant::now() >= self.next_probe
    }

    pub fn time_until_next(&self) -> Duration {
        self.next_probe.saturating_duration_since(Instant::now())
    }

    /// Build a probe payload of the given size (or next MTU candidate).
    /// Returns (probe_id, payload).
    pub fn build_probe(&mut self) -> (u64, Vec<u8>) {
        let probe_size = if self.probing_mtu {
            (self.mtu_lo + self.mtu_hi) / 2
        } else {
            PROBE_HDR
        };

        let id = self.next_id;
        self.next_id += 1;

        let now_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        let mut payload = vec![0u8; probe_size.max(PROBE_HDR)];
        payload[0..8].copy_from_slice(&id.to_le_bytes());
        payload[8..16].copy_from_slice(&now_us.to_le_bytes());
        // Remaining bytes are zero padding for MTU probing

        self.pending.insert(
            id,
            PendingProbe {
                sent_at: Instant::now(),
                probe_size,
            },
        );
        self.next_probe = Instant::now() + PROBE_INTERVAL;
        (id, payload)
    }

    /// Process a PathProbe echo response. Returns measured RTT if valid.
    pub fn on_echo(&mut self, payload: &[u8]) -> Option<Duration> {
        if payload.len() < PROBE_HDR {
            return None;
        }
        let id = u64::from_le_bytes(payload[0..8].try_into().ok()?);

        let probe = self.pending.remove(&id)?;
        let rtt = probe.sent_at.elapsed();

        // Any successful echo resets the consecutive-timeout counter.
        self.consecutive_timeouts = 0;

        // MTU probe succeeded: this size is reachable
        if self.probing_mtu {
            self.mtu_lo = probe.probe_size;
            if self.mtu_hi - self.mtu_lo <= 16 {
                // Converged
                self.path_mtu = self.mtu_lo;
                self.probing_mtu = false;
            }
        }

        Some(rtt)
    }

    /// Expire timed-out probes. Returns true if any MTU probe expired (path smaller than tried).
    /// Also increments `consecutive_timeouts` for keepalive probes that expire.
    pub fn expire_timeouts(&mut self) -> bool {
        let now = Instant::now();
        let mut mtu_loss = false;
        let mut keepalive_loss = false;
        self.pending.retain(|_, p| {
            if now.duration_since(p.sent_at) >= PROBE_TIMEOUT {
                if p.probe_size > PROBE_HDR {
                    mtu_loss = true;
                } else {
                    keepalive_loss = true;
                }
                false
            } else {
                true
            }
        });
        if keepalive_loss {
            self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
        }
        if mtu_loss && self.probing_mtu {
            // Probe at this size failed: search lower half
            self.mtu_hi = (self.mtu_lo + self.mtu_hi) / 2;
        }
        mtu_loss
    }

    /// Returns true if enough consecutive probes have timed out to warrant migration.
    pub fn should_migrate(&self) -> bool {
        self.consecutive_timeouts >= MIGRATION_THRESHOLD
    }

    /// Reset the consecutive timeout counter (called after a successful migration).
    pub fn reset_migration_state(&mut self) {
        self.consecutive_timeouts = 0;
    }
}

impl Default for PathProber {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_probe_uses_midpoint_size_and_increments_id() {
        let mut p = PathProber::new();
        let (id0, payload0) = p.build_probe();
        let expected = (MIN_MTU + MAX_MTU) / 2;
        assert_eq!(id0, 0);
        assert_eq!(payload0.len(), expected);
        assert_eq!(u64::from_le_bytes(payload0[0..8].try_into().unwrap()), id0);

        let (id1, _) = p.build_probe();
        assert_eq!(id1, 1);
    }

    #[test]
    fn on_echo_rejects_short_payload_or_unknown_id() {
        let mut p = PathProber::new();
        assert_eq!(p.on_echo(&[0u8; 8]), None);

        let mut payload = vec![0u8; PROBE_HDR];
        payload[0..8].copy_from_slice(&99u64.to_le_bytes());
        assert_eq!(p.on_echo(&payload), None);
    }

    #[test]
    fn successful_echo_updates_mtu_and_can_finish_probing() {
        let mut p = PathProber::new();
        p.mtu_lo = 1400;
        p.mtu_hi = 1410;
        p.probing_mtu = true;

        let (id, payload) = p.build_probe();
        assert_eq!(id, 0);
        let rtt = p.on_echo(&payload);
        assert!(rtt.is_some());
        assert!(!p.probing_mtu);
        assert_eq!(p.path_mtu, 1405);
    }

    #[test]
    fn expire_timeouts_shrinks_search_window_for_lost_mtu_probe() {
        let mut p = PathProber::new();
        p.pending.insert(
            1,
            PendingProbe {
                sent_at: Instant::now() - PROBE_TIMEOUT,
                probe_size: 1450,
            },
        );
        let old_hi = p.mtu_hi;
        let old_lo = p.mtu_lo;

        let lost = p.expire_timeouts();
        assert!(lost);
        assert!(p.pending.is_empty());
        assert_eq!(p.mtu_hi, (old_lo + old_hi) / 2);
    }

    #[test]
    fn keepalive_probe_uses_header_size_after_mtu_converges() {
        let mut p = PathProber::new();
        p.probing_mtu = false;
        let (_, payload) = p.build_probe();
        assert_eq!(payload.len(), PROBE_HDR);
    }
}
