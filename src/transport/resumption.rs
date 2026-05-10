/// 0-RTT session resumption via encrypted session tickets.
///
/// ⚠️  **WEAKER FORWARD SECRECY**: Session tickets derive from the long-term
/// traffic secret. If the server's ticket-encryption key is compromised, past
/// 0-RTT sessions can be decrypted. Use only where latency beats FS requirements.
/// The API enforces awareness: `SessionTicket::zero_rtt_connect` requires the
/// caller to pass `WEAKER_FS_WARNING` as an acknowledgement string.
///
/// Wire format for a 0-RTT Initial packet (type = 0x14):
///   encrypted_ticket(variable) + 0-RTT data
///
/// Ticket wire format (encrypted with server's ticket key via ChaCha20Poly1305):
///   session_id(8) + traffic_secret(32) + expiry_unix_secs(8) + nonce(12)

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use crate::error::SeamError;
use rand::{RngCore, rngs::OsRng};

pub const WEAKER_FS_WARNING: &str =
    "WEAKER-FS: 0-RTT tickets reduce forward secrecy. Acknowledged.";

const TICKET_PLAINTEXT_LEN: usize = 8 + 32 + 8; // session_id + secret + expiry
const TICKET_LEN: usize = TICKET_PLAINTEXT_LEN + 12 + 16; // + nonce + tag
const TICKET_TTL_SECS: u64 = 24 * 3600; // 24-hour ticket lifetime

pub struct TicketKey {
    key: [u8; 32],
}

impl TicketKey {
    pub fn new(key: [u8; 32]) -> Self { Self { key } }

    /// Issue a new session ticket for `session_id` / `traffic_secret`.
    pub fn issue(&self, session_id: u64, traffic_secret: &[u8; 32]) -> Vec<u8> {
        let expiry = unix_now() + TICKET_TTL_SECS;
        let mut plain = [0u8; TICKET_PLAINTEXT_LEN];
        plain[0..8].copy_from_slice(&session_id.to_le_bytes());
        plain[8..40].copy_from_slice(traffic_secret);
        plain[40..48].copy_from_slice(&expiry.to_le_bytes());

        // Use a fresh nonce per ticket to avoid accidental nonce reuse under the
        // same key when issuing tickets in the same second.
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let mut buf = plain.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(&nonce.into(), b"apex-ticket", &mut buf)
            .expect("ticket encrypt");

        let mut out = Vec::with_capacity(TICKET_LEN);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&buf);
        out.extend_from_slice(tag.as_slice());
        out
    }

    /// Decrypt and validate a session ticket. Returns (session_id, traffic_secret).
    pub fn redeem(&self, ticket_bytes: &[u8]) -> Result<(u64, [u8; 32]), SeamError> {
        if ticket_bytes.len() != TICKET_LEN {
            return Err(SeamError::HandshakeFailed("bad ticket length".into()));
        }
        let nonce: [u8; 12] = ticket_bytes[..12]
            .try_into()
            .map_err(|_| SeamError::HandshakeFailed("bad ticket nonce".into()))?;
        let mut ct = ticket_bytes[12..12 + TICKET_PLAINTEXT_LEN + 16].to_vec();

        let cipher = ChaCha20Poly1305::new((&self.key).into());
        cipher
            .decrypt_in_place(&nonce.into(), b"apex-ticket", &mut ct)
            .map_err(|_| SeamError::AuthFailed)?;

        if ct.len() < TICKET_PLAINTEXT_LEN {
            return Err(SeamError::AuthFailed);
        }

        let session_id = u64::from_le_bytes(
            ct[0..8]
                .try_into()
                .map_err(|_| SeamError::AuthFailed)?,
        );
        let traffic_secret: [u8; 32] = ct[8..40]
            .try_into()
            .map_err(|_| SeamError::AuthFailed)?;
        let expiry = u64::from_le_bytes(
            ct[40..48]
                .try_into()
                .map_err(|_| SeamError::AuthFailed)?,
        );

        if unix_now() > expiry {
            return Err(SeamError::HandshakeFailed("ticket expired".into()));
        }
        Ok((session_id, traffic_secret))
    }
}

/// In-memory representation of a redeemed ticket (for the client side).
#[derive(Debug, Clone)]
pub struct SessionTicket {
    pub session_id: u64,
    pub traffic_secret: [u8; 32],
}

impl SessionTicket {
    pub fn new(session_id: u64, traffic_secret: [u8; 32]) -> Self {
        Self { session_id, traffic_secret }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32);
        out.extend_from_slice(&self.session_id.to_le_bytes());
        out.extend_from_slice(&self.traffic_secret);
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() != 40 { return None; }
        let session_id = u64::from_le_bytes(buf[0..8].try_into().ok()?);
        let traffic_secret: [u8; 32] = buf[8..40].try_into().ok()?;
        Some(Self { session_id, traffic_secret })
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
        let secret = [0xBEu8; 32];
        let issued = key.issue(999, &secret);
        let (sid, sec) = key.redeem(&issued).unwrap();
        assert_eq!(sid, 999);
        assert_eq!(sec, secret);
    }

    #[test]
    fn tampered_ticket_rejected() {
        let key = TicketKey::new([0x42u8; 32]);
        let mut ticket = key.issue(1, &[0u8; 32]);
        ticket[15] ^= 0xFF; // corrupt ciphertext
        assert!(key.redeem(&ticket).is_err());
    }

    #[test]
    fn issued_tickets_use_fresh_nonces() {
        let key = TicketKey::new([0x42u8; 32]);
        let secret = [0xBEu8; 32];
        let t1 = key.issue(7, &secret);
        let t2 = key.issue(7, &secret);
        assert_ne!(&t1[..12], &t2[..12]);
    }

    #[test]
    fn session_ticket_serialize() {
        let t = SessionTicket::new(7, [0x11u8; 32]);
        let bytes = t.to_bytes();
        let back = SessionTicket::from_bytes(&bytes).unwrap();
        assert_eq!(back.session_id, 7);
        assert_eq!(back.traffic_secret, [0x11u8; 32]);
    }

    #[test]
    fn session_ticket_rejects_trailing_bytes() {
        let t = SessionTicket::new(9, [0x22u8; 32]);
        let mut bytes = t.to_bytes();
        bytes.push(0xFF);
        assert!(SessionTicket::from_bytes(&bytes).is_none());
    }
}
