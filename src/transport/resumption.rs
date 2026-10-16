/// 0-RTT session resumption via encrypted session tickets.
///
/// ⚠️  **WEAKER FORWARD SECRECY**: Session tickets store the derived traffic
/// keys. If the server's ticket-encryption key is compromised, past 0-RTT
/// sessions can be decrypted. Use only where latency beats FS requirements.
///
/// Ticket wire format (encrypted with server's ticket key via ChaCha20Poly1305):
///   session_id(8) + keys_c2s(76) + keys_s2c(76) + expiry_unix_secs(8) + nonce(12)
///
/// Both directional key sets are stored (see
/// `HybridSharedSecret::derive_directional_packet_keys` for why a session
/// needs two independent key sets, not one shared between directions).
use crate::{crypto::keys::PacketKeys, error::SeamError};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use rand::{RngCore, rngs::OsRng};
use zeroize::{Zeroize, ZeroizeOnDrop};

const TICKET_PLAINTEXT_LEN: usize = 8 + 76 + 76 + 8; // session_id + keys_c2s + keys_s2c + expiry
const TICKET_LEN: usize = TICKET_PLAINTEXT_LEN + 12 + 16; // + nonce + tag
const TICKET_TTL_SECS: u64 = 24 * 3600; // 24-hour ticket lifetime

pub const WEAKER_FS_WARNING: &str = "WARNING: session tickets weaken forward secrecy — \
     if the server ticket key leaks, past 0-RTT sessions can be decrypted.";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TicketKey {
    key: [u8; 32],
}

impl TicketKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Issue a new session ticket for `session_id` / the session's two
    /// directional key sets.
    pub fn issue(&self, session_id: u64, keys_c2s: &PacketKeys, keys_s2c: &PacketKeys) -> Vec<u8> {
        let expiry = unix_now() + TICKET_TTL_SECS;
        let mut plain = [0u8; TICKET_PLAINTEXT_LEN];
        plain[0..8].copy_from_slice(&session_id.to_le_bytes());
        plain[8..84].copy_from_slice(&keys_c2s.to_bytes());
        plain[84..160].copy_from_slice(&keys_s2c.to_bytes());
        plain[160..168].copy_from_slice(&expiry.to_le_bytes());

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let mut buf = plain.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(&nonce.into(), b"seam-ticket", &mut buf)
            .expect("ticket encrypt");

        let mut out = Vec::with_capacity(TICKET_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&buf);
        out.extend_from_slice(tag.as_slice());
        out
    }

    /// Decrypt and validate a session ticket. Returns (session_id, keys_c2s, keys_s2c).
    pub fn redeem(&self, ticket_bytes: &[u8]) -> Result<(u64, PacketKeys, PacketKeys), SeamError> {
        if ticket_bytes.len() != TICKET_LEN {
            return Err(SeamError::HandshakeFailed("bad ticket length".into()));
        }
        let nonce: [u8; 12] = ticket_bytes[..12]
            .try_into()
            .map_err(|_| SeamError::HandshakeFailed("bad ticket nonce".into()))?;
        let mut ct = ticket_bytes[12..12 + TICKET_PLAINTEXT_LEN + 16].to_vec();

        let cipher = ChaCha20Poly1305::new((&self.key).into());
        cipher
            .decrypt_in_place(&nonce.into(), b"seam-ticket", &mut ct)
            .map_err(|_| SeamError::AuthFailed)?;

        if ct.len() < TICKET_PLAINTEXT_LEN {
            return Err(SeamError::AuthFailed);
        }

        let session_id =
            u64::from_le_bytes(ct[0..8].try_into().map_err(|_| SeamError::AuthFailed)?);
        let keys_c2s = PacketKeys::from_bytes(&ct[8..84]).ok_or(SeamError::AuthFailed)?;
        let keys_s2c = PacketKeys::from_bytes(&ct[84..160]).ok_or(SeamError::AuthFailed)?;
        let expiry =
            u64::from_le_bytes(ct[160..168].try_into().map_err(|_| SeamError::AuthFailed)?);

        if unix_now() >= expiry {
            return Err(SeamError::HandshakeFailed("ticket expired".into()));
        }
        Ok((session_id, keys_c2s, keys_s2c))
    }
}

/// In-memory representation of a redeemed ticket (for the client side).
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionTicket {
    pub session_id: u64,
    pub keys_c2s: PacketKeys,
    pub keys_s2c: PacketKeys,
}

impl SessionTicket {
    pub fn new(session_id: u64, keys_c2s: PacketKeys, keys_s2c: PacketKeys) -> Self {
        Self {
            session_id,
            keys_c2s,
            keys_s2c,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 76 + 76);
        out.extend_from_slice(&self.session_id.to_le_bytes());
        out.extend_from_slice(&self.keys_c2s.to_bytes());
        out.extend_from_slice(&self.keys_s2c.to_bytes());
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() != 8 + 76 + 76 {
            return None;
        }
        let session_id = u64::from_le_bytes(buf[0..8].try_into().ok()?);
        let keys_c2s = PacketKeys::from_bytes(&buf[8..84])?;
        let keys_s2c = PacketKeys::from_bytes(&buf[84..160])?;
        Some(Self {
            session_id,
            keys_c2s,
            keys_s2c,
        })
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_roundtrip() {
        let key = TicketKey::new([0x42u8; 32]);
        let keys_c2s = PacketKeys::derive_from_secret(&[0xBEu8; 32]);
        let keys_s2c = PacketKeys::derive_from_secret(&[0xCFu8; 32]);
        let issued = key.issue(999, &keys_c2s, &keys_s2c);
        let (sid, c2s, s2c) = key.redeem(&issued).unwrap();
        assert_eq!(sid, 999);
        assert_eq!(c2s.enc_key, keys_c2s.enc_key);
        assert_eq!(c2s.hp_key, keys_c2s.hp_key);
        assert_eq!(c2s.nonce_base, keys_c2s.nonce_base);
        assert_eq!(s2c.enc_key, keys_s2c.enc_key);
        assert_eq!(s2c.hp_key, keys_s2c.hp_key);
        assert_eq!(s2c.nonce_base, keys_s2c.nonce_base);
    }

    #[test]
    fn tampered_ticket_rejected() {
        let key = TicketKey::new([0x42u8; 32]);
        let keys = PacketKeys::derive_from_secret(&[0u8; 32]);
        let mut ticket = key.issue(1, &keys, &keys);
        ticket[15] ^= 0xFF; // corrupt ciphertext
        assert!(key.redeem(&ticket).is_err());
    }

    #[test]
    fn issued_tickets_use_fresh_nonces() {
        let key = TicketKey::new([0x42u8; 32]);
        let keys = PacketKeys::derive_from_secret(&[0xBEu8; 32]);
        let t1 = key.issue(7, &keys, &keys);
        let t2 = key.issue(7, &keys, &keys);
        assert_ne!(&t1[..12], &t2[..12]);
    }

    #[test]
    fn session_ticket_serialize() {
        let keys_c2s = PacketKeys::derive_from_secret(&[0x11u8; 32]);
        let keys_s2c = PacketKeys::derive_from_secret(&[0x33u8; 32]);
        let t = SessionTicket::new(7, keys_c2s.clone(), keys_s2c.clone());
        let bytes = t.to_bytes();
        let back = SessionTicket::from_bytes(&bytes).unwrap();
        assert_eq!(back.session_id, 7);
        assert_eq!(back.keys_c2s.enc_key, keys_c2s.enc_key);
        assert_eq!(back.keys_s2c.enc_key, keys_s2c.enc_key);
    }

    #[test]
    fn session_ticket_rejects_trailing_bytes() {
        let keys = PacketKeys::derive_from_secret(&[0x22u8; 32]);
        let t = SessionTicket::new(9, keys.clone(), keys);
        let mut bytes = t.to_bytes();
        bytes.push(0xFF);
        assert!(SessionTicket::from_bytes(&bytes).is_none());
    }
}
