/// Session-level double ratchet integration.
///
/// Wraps [`crate::crypto::ratchet::DoubleRatchet`] with the higher-level
/// session context: deciding when to trigger epoch rotations, building
/// `RatchetStep` wire frames, and providing a simple encrypt/decrypt API
/// that callers in the session or transport layer can use.
///
/// # Usage
///
/// ```ignore
/// // After handshake:
/// let mut ratchet = SessionRatchet::new(&handshake_hash, is_initiator, RatchetConfig::default());
///
/// // Before sending a packet:
/// let msg_key = ratchet.next_send_key();
/// // ... encrypt with msg_key, then zeroize msg_key ...
///
/// // If ratchet signals an epoch step is needed:
/// if let Some(step_frame) = ratchet.maybe_advance_send() {
///     // send step_frame bytes to peer over the wire
/// }
///
/// // When a RatchetStep frame arrives from peer:
/// ratchet.apply_peer_step_bytes(&frame_bytes)?;
/// ```
use std::time::Duration;
use zeroize::Zeroizing;

use crate::crypto::ratchet::{DoubleRatchet, RatchetStep};
use crate::error::SeamError;

// ──────────────────────────────────────────────────────────────────────────────
// Configuration
// ──────────────────────────────────────────────────────────────────────────────

/// Ratchet configuration, driven by `seam config` keys:
/// - `ratchet_epoch_packets` (default 1000)
/// - `ratchet_epoch_seconds` (default 30)
#[derive(Debug, Clone)]
pub struct RatchetConfig {
    /// Rotate after this many packets in an epoch.
    pub epoch_packet_limit: u64,
    /// Rotate after this many seconds in an epoch.
    pub epoch_time_secs: u64,
}

impl Default for RatchetConfig {
    fn default() -> Self {
        Self {
            epoch_packet_limit: 1000,
            epoch_time_secs: 30,
        }
    }
}

impl RatchetConfig {
    /// Parse from `seam config` key/value pairs.
    /// Returns `Some(true)` if the key was recognised and applied.
    pub fn apply_config_key(&mut self, key: &str, value: &str) -> anyhow::Result<bool> {
        match key {
            "ratchet_epoch_packets" => {
                let n: u64 = value.parse().map_err(|_| {
                    anyhow::anyhow!("ratchet_epoch_packets must be a positive integer")
                })?;
                if n == 0 {
                    anyhow::bail!("ratchet_epoch_packets must be ≥ 1");
                }
                self.epoch_packet_limit = n;
                Ok(true)
            }
            "ratchet_epoch_seconds" => {
                let n: u64 = value.parse().map_err(|_| {
                    anyhow::anyhow!("ratchet_epoch_seconds must be a positive integer")
                })?;
                if n == 0 {
                    anyhow::bail!("ratchet_epoch_seconds must be ≥ 1");
                }
                self.epoch_time_secs = n;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SessionRatchet
// ──────────────────────────────────────────────────────────────────────────────

/// High-level double ratchet handle for a Seam session.
pub struct SessionRatchet {
    inner: DoubleRatchet,
}

impl SessionRatchet {
    /// Initialise from the Noise handshake output hash.
    pub fn new(handshake_hash: &[u8; 32], is_initiator: bool, config: RatchetConfig) -> Self {
        let inner = DoubleRatchet::new_with_limits(
            handshake_hash,
            is_initiator,
            config.epoch_packet_limit,
            Duration::from_secs(config.epoch_time_secs),
        );
        Self { inner }
    }

    /// Return the next per-packet send key.
    ///
    /// The returned `Zeroizing<[u8; 32]>` will zeroize on drop.
    /// Callers MUST NOT clone the raw bytes and store them beyond the lifetime
    /// of the encryption call.
    pub fn next_send_key(&mut self) -> Zeroizing<[u8; 32]> {
        self.inner.next_send_key()
    }

    /// Return the next per-packet recv key for `(epoch, packet_index)`.
    ///
    /// Handles out-of-order delivery via the internal skip window.
    /// Returns `None` if the packet is unretrievable (too old, wrong epoch,
    /// or skip window overflow).
    pub fn next_recv_key(&mut self, epoch: u64, packet_index: u64) -> Option<Zeroizing<[u8; 32]>> {
        self.inner.next_recv_key(epoch, packet_index)
    }

    /// Check whether a DH ratchet step is due (packet limit or time limit reached).
    pub fn should_ratchet(&self) -> bool {
        self.inner.should_ratchet()
    }

    /// If a DH ratchet step is due, perform it and return the encoded
    /// `RatchetStep` frame bytes (40 bytes) to send to the peer.
    ///
    /// Returns `None` if no ratchet step is needed yet.
    pub fn maybe_advance_send(&mut self) -> Option<Vec<u8>> {
        if !self.inner.should_ratchet() {
            return None;
        }
        let step = self.inner.advance_send_ratchet();
        Some(step.encode().to_vec())
    }

    /// Apply a `RatchetStep` received from the peer.
    ///
    /// `frame_bytes` must be exactly 40 bytes (output of `RatchetStep::encode`).
    pub fn apply_peer_step_bytes(&mut self, frame_bytes: &[u8]) -> Result<(), SeamError> {
        let step = RatchetStep::decode(frame_bytes).ok_or(SeamError::ProtocolViolation(
            "malformed RatchetStep frame".into(),
        ))?;
        self.inner.apply_peer_ratchet_step(&step);
        Ok(())
    }

    /// Current send epoch.
    pub fn send_epoch(&self) -> u64 {
        self.inner.send_epoch()
    }

    /// Current recv epoch.
    pub fn recv_epoch(&self) -> u64 {
        self.inner.recv_epoch()
    }

    /// Packets sent in the current epoch.
    pub fn packets_in_epoch(&self) -> u64 {
        self.inner.packets_in_epoch()
    }

    /// Epoch packet limit.
    pub fn epoch_packet_limit(&self) -> u64 {
        self.inner.epoch_packet_limit()
    }

    /// Epoch time limit.
    pub fn epoch_time_limit(&self) -> Duration {
        self.inner.epoch_time_limit()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pair(cfg: RatchetConfig) -> (SessionRatchet, SessionRatchet) {
        let hash = [0x42u8; 32];
        (
            SessionRatchet::new(&hash, true, cfg.clone()),
            SessionRatchet::new(&hash, false, cfg),
        )
    }

    #[test]
    fn test_session_ratchet_send_keys_unique() {
        let (mut alice, _bob) = make_pair(RatchetConfig::default());
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let k = *alice.next_send_key();
            assert!(seen.insert(k), "duplicate send key");
        }
    }

    #[test]
    fn test_session_ratchet_epoch_advance() {
        let cfg = RatchetConfig {
            epoch_packet_limit: 3,
            epoch_time_secs: 3600,
        };
        let (mut alice, _bob) = make_pair(cfg);
        assert_eq!(alice.send_epoch(), 0);

        for _ in 0..3 {
            alice.next_send_key();
        }
        assert!(alice.should_ratchet());
        let frame = alice
            .maybe_advance_send()
            .expect("should produce step frame");
        assert_eq!(frame.len(), 40);
        assert_eq!(alice.send_epoch(), 1);
        assert_eq!(alice.packets_in_epoch(), 0);
    }

    #[test]
    fn test_session_ratchet_config_defaults() {
        let cfg = RatchetConfig::default();
        assert_eq!(cfg.epoch_packet_limit, 1000);
        assert_eq!(cfg.epoch_time_secs, 30);
    }

    #[test]
    fn test_apply_config_key() {
        let mut cfg = RatchetConfig::default();
        assert!(
            cfg.apply_config_key("ratchet_epoch_packets", "500")
                .unwrap()
        );
        assert_eq!(cfg.epoch_packet_limit, 500);
        assert!(cfg.apply_config_key("ratchet_epoch_seconds", "60").unwrap());
        assert_eq!(cfg.epoch_time_secs, 60);
        assert!(!cfg.apply_config_key("unknown_key", "1").unwrap());
    }

    #[test]
    fn test_peer_step_round_trip() {
        let cfg = RatchetConfig {
            epoch_packet_limit: 2,
            epoch_time_secs: 3600,
        };
        let (mut alice, mut bob) = make_pair(cfg);

        // Alice sends 2 packets, triggering a ratchet step
        alice.next_send_key();
        alice.next_send_key();
        assert!(alice.should_ratchet());

        let step_bytes = alice.maybe_advance_send().unwrap();
        assert_eq!(alice.send_epoch(), 1);

        // Bob applies Alice's step
        bob.apply_peer_step_bytes(&step_bytes).unwrap();
        assert_eq!(bob.recv_epoch(), 1);
    }
}
