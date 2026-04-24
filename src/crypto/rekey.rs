/// Traffic-key rotation (KEYUPDATE). Forward secrecy within a session.
///
/// Each epoch has a `traffic_secret`. The next epoch's secret is derived via
/// BLAKE3 KDF:
///   next_secret = BLAKE3_KDF("apex/key-update/v1", current_secret)
/// and new PacketKeys are derived from `next_secret` with the existing KDF.
///
/// The packet header's `flags` byte carries a 1-bit "key phase" indicating
/// which epoch decrypts this packet. Receivers that see the bit flip
/// preemptively derive the next epoch's keys and try decryption with both.
///
/// This module exposes the KDF; integration into the packet encode/decode
/// pipeline can flip between epochs via `KeySchedule::rotate()`.
use crate::crypto::keys::PacketKeys;
use zeroize::Zeroize;

pub struct KeySchedule {
    /// Current traffic secret (one-way KDF chain). Zeroized when replaced.
    current_secret: [u8; 32],
    /// Current derived keys (what encoder/decoder use today).
    pub current: PacketKeys,
    /// Next epoch's derived keys, prepared lazily for fast switch.
    pub next: Option<PacketKeys>,
    /// Monotonic epoch counter; low bit == key_phase flag on wire.
    pub epoch: u64,
}

impl KeySchedule {
    pub fn new(initial_secret: [u8; 32]) -> Self {
        let keys = PacketKeys::derive_from_secret(&initial_secret);
        Self {
            current_secret: initial_secret,
            current: keys,
            next: None,
            epoch: 0,
        }
    }

    pub fn key_phase(&self) -> bool { self.epoch & 1 == 1 }

    /// Prepare (but do not activate) the next epoch's keys.
    pub fn prepare_next(&mut self) {
        if self.next.is_some() { return; }
        let next_secret = blake3::derive_key("apex/key-update/v1", &self.current_secret);
        self.next = Some(PacketKeys::derive_from_secret(&next_secret));
    }

    /// Activate the next epoch. Zeroizes the old secret.
    pub fn rotate(&mut self) {
        self.prepare_next();
        let next_secret = blake3::derive_key("apex/key-update/v1", &self.current_secret);
        self.current_secret.zeroize();
        self.current_secret = next_secret;
        self.current = self.next.take().unwrap_or_else(|| {
            PacketKeys::derive_from_secret(&self.current_secret)
        });
        self.epoch = self.epoch.wrapping_add(1);
    }
}

impl Drop for KeySchedule {
    fn drop(&mut self) {
        self.current_secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_epoch_is_zero() {
        let k = KeySchedule::new([0x42u8; 32]);
        assert_eq!(k.epoch, 0);
        assert_eq!(k.key_phase(), false);
    }

    #[test]
    fn rotate_advances_epoch_and_changes_keys() {
        let mut k = KeySchedule::new([0x42u8; 32]);
        let enc_key_before = k.current.enc_key;
        k.rotate();
        assert_eq!(k.epoch, 1);
        assert_eq!(k.key_phase(), true);
        assert_ne!(k.current.enc_key, enc_key_before, "keys must differ after rotation");
    }

    #[test]
    fn two_rotations_give_three_distinct_keys() {
        let mut k = KeySchedule::new([0x42u8; 32]);
        let k0 = k.current.enc_key;
        k.rotate();
        let k1 = k.current.enc_key;
        k.rotate();
        let k2 = k.current.enc_key;
        assert_ne!(k0, k1);
        assert_ne!(k1, k2);
        assert_ne!(k0, k2);
    }

    #[test]
    fn key_phase_toggles_each_rotation() {
        let mut k = KeySchedule::new([0x01u8; 32]);
        assert_eq!(k.key_phase(), false);
        k.rotate();
        assert_eq!(k.key_phase(), true);
        k.rotate();
        assert_eq!(k.key_phase(), false);
    }

    #[test]
    fn prepare_next_is_idempotent() {
        let mut k = KeySchedule::new([0x01u8; 32]);
        k.prepare_next();
        let peek = k.next.as_ref().unwrap().enc_key;
        k.prepare_next();
        assert_eq!(k.next.as_ref().unwrap().enc_key, peek);
    }
}
