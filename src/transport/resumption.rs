use crate::{crypto::keys::PacketKeys, error::SeamError};
/// 0-RTT session resumption via encrypted session tickets.
///
/// ⚠️  **WEAKER FORWARD SECRECY**: Session tickets store the derived traffic
/// keys. If the server's ticket-encryption key is compromised, past 0-RTT
/// sessions can be decrypted. Use only where latency beats FS requirements.
///
/// Ticket wire format (encrypted with server's ticket key via ChaCha20Poly1305):
///   session_id(8) + packet_keys(76) + expiry_unix_secs(8) + nonce(12)
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use rand::{RngCore, rngs::OsRng};

const TICKET_PLAINTEXT_LEN: usize = 8 + 76 + 8; // session_id + keys + expiry
const TICKET_LEN: usize = TICKET_PLAINTEXT_LEN + 12 + 16; // + nonce + tag
const TICKET_TTL_SECS: u64 = 24 * 3600; // 24-hour ticket lifetime

pub const WEAKER_FS_WARNING: &str = "WARNING: session tickets weaken forward secrecy — \
     if the server ticket key leaks, past 0-RTT sessions can be decrypted.";

#[derive(Clone)]
pub struct TicketKey {
    key: [u8; 32],
}

impl TicketKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Issue a new session ticket for `session_id` / `keys`.
    pub fn issue(&self, session_id: u64, keys: &PacketKeys) -> Vec<u8> {
        let expiry = unix_now() + TICKET_TTL_SECS;
        let mut plain = [0u8; TICKET_PLAINTEXT_LEN];
        plain[0..8].copy_from_slice(&session_id.to_le_bytes());
        plain[8..84].copy_from_slice(&keys.to_bytes());
        plain[84..92].copy_from_slice(&expiry.to_le_bytes());

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

    /// Decrypt and validate a session ticket. Returns (session_id, keys).
    pub fn redeem(&self, ticket_bytes: &[u8]) -> Result<(u64, PacketKeys), SeamError> {
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
        let keys = PacketKeys::from_bytes(&ct[8..84]).ok_or(SeamError::AuthFailed)?;
        let expiry = u64::from_le_bytes(ct[84..92].try_into().map_err(|_| SeamError::AuthFailed)?);

        if unix_now() > expiry {
            return Err(SeamError::HandshakeFailed("ticket expired".into()));
        }
        Ok((session_id, keys))
    }
}

/// In-memory representation of a redeemed ticket (for the client side).
#[derive(Debug, Clone)]
pub struct SessionTicket {
    pub session_id: u64,
    pub keys: PacketKeys,
}

impl SessionTicket {
    pub fn new(session_id: u64, keys: PacketKeys) -> Self {
        Self { session_id, keys }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 76);
        out.extend_from_slice(&self.session_id.to_le_bytes());
        out.extend_from_slice(&self.keys.to_bytes());
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() != 84 {
            return None;
        }
        let session_id = u64::from_le_bytes(buf[0..8].try_into().ok()?);
        let keys = PacketKeys::from_bytes(&buf[8..84])?;
        Some(Self { session_id, keys })
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
        let keys = PacketKeys::derive_from_secret(&[0xBEu8; 32]);
        let issued = key.issue(999, &keys);
        let (sid, redeemed) = key.redeem(&issued).unwrap();
        assert_eq!(sid, 999);
        assert_eq!(redeemed.enc_key, keys.enc_key);
        assert_eq!(redeemed.hp_key, keys.hp_key);
        assert_eq!(redeemed.nonce_base, keys.nonce_base);
    }

    #[test]
    fn tampered_ticket_rejected() {
        let key = TicketKey::new([0x42u8; 32]);
        let keys = PacketKeys::derive_from_secret(&[0u8; 32]);
        let mut ticket = key.issue(1, &keys);
        ticket[15] ^= 0xFF; // corrupt ciphertext
        assert!(key.redeem(&ticket).is_err());
    }

    #[test]
    fn issued_tickets_use_fresh_nonces() {
        let key = TicketKey::new([0x42u8; 32]);
        let keys = PacketKeys::derive_from_secret(&[0xBEu8; 32]);
        let t1 = key.issue(7, &keys);
        let t2 = key.issue(7, &keys);
        assert_ne!(&t1[..12], &t2[..12]);
    }

    #[test]
    fn session_ticket_serialize() {
        let keys = PacketKeys::derive_from_secret(&[0x11u8; 32]);
        let t = SessionTicket::new(7, keys.clone());
        let bytes = t.to_bytes();
        let back = SessionTicket::from_bytes(&bytes).unwrap();
        assert_eq!(back.session_id, 7);
        assert_eq!(back.keys.enc_key, keys.enc_key);
    }

    #[test]
    fn session_ticket_rejects_trailing_bytes() {
        let keys = PacketKeys::derive_from_secret(&[0x22u8; 32]);
        let t = SessionTicket::new(9, keys);
        let mut bytes = t.to_bytes();
        bytes.push(0xFF);
        assert!(SessionTicket::from_bytes(&bytes).is_none());
    }
}
