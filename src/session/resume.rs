use blake3::Hasher;
use rand::RngCore;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::SeamError;

const DEFAULT_TTL: u64 = 3600;

/// Wire format: ticket_id(16) + session_secret(32) + created_at(8) + ttl_seconds(8) + peer_identity(32)
const TICKET_BYTES: usize = 16 + 32 + 8 + 8 + 32;

/// Proof-of-possession size: BLAKE3 output over ticket_id + session_secret + nonce
const PROOF_LEN: usize = 32;
/// Nonce size for proof-of-possession
pub const POP_NONCE_LEN: usize = 16;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionTicket {
    pub ticket_id: [u8; 16],
    pub session_secret: Zeroizing<[u8; 32]>,
    pub created_at: u64,
    pub ttl_seconds: u64,
    pub peer_identity: [u8; 32],
}

impl SessionTicket {
    pub fn new(peer_identity: [u8; 32], session_secret: Zeroizing<[u8; 32]>) -> Self {
        let mut ticket_id = [0u8; 16];
        OsRng.fill_bytes(&mut ticket_id);
        Self {
            ticket_id,
            session_secret,
            created_at: unix_now(),
            ttl_seconds: DEFAULT_TTL,
            peer_identity,
        }
    }

    pub fn is_valid(&self) -> bool {
        let now = unix_now();
        now >= self.created_at && now < self.created_at.saturating_add(self.ttl_seconds)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TICKET_BYTES);
        out.extend_from_slice(&self.ticket_id);
        out.extend_from_slice(self.session_secret.as_ref());
        out.extend_from_slice(&self.created_at.to_le_bytes());
        out.extend_from_slice(&self.ttl_seconds.to_le_bytes());
        out.extend_from_slice(&self.peer_identity);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, SeamError> {
        if b.len() != TICKET_BYTES {
            return Err(SeamError::HandshakeFailed(format!(
                "resume ticket: expected {TICKET_BYTES} bytes, got {}",
                b.len()
            )));
        }
        let ticket_id: [u8; 16] = b[0..16]
            .try_into()
            .map_err(|_| SeamError::HandshakeFailed("resume ticket: bad ticket_id".into()))?;
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&b[16..48]);
        let created_at = u64::from_le_bytes(
            b[48..56]
                .try_into()
                .map_err(|_| SeamError::HandshakeFailed("resume ticket: bad created_at".into()))?,
        );
        let ttl_seconds =
            u64::from_le_bytes(b[56..64].try_into().map_err(|_| {
                SeamError::HandshakeFailed("resume ticket: bad ttl_seconds".into())
            })?);
        let peer_identity: [u8; 32] = b[64..96]
            .try_into()
            .map_err(|_| SeamError::HandshakeFailed("resume ticket: bad peer_identity".into()))?;
        Ok(Self {
            ticket_id,
            session_secret: secret,
            created_at,
            ttl_seconds,
            peer_identity,
        })
    }

    /// Derive a BLAKE3-based proof-of-possession over ticket_id + session_secret + nonce.
    /// The nonce is supplied by the caller (from the SvcResume frame) to prevent replay.
    pub fn proof_of_possession(&self, nonce: &[u8; POP_NONCE_LEN]) -> [u8; PROOF_LEN] {
        let mut h = Hasher::new_derive_key("seam/resume-proof/v1");
        h.update(&self.ticket_id);
        h.update(self.session_secret.as_ref());
        h.update(nonce);
        *h.finalize().as_bytes()
    }

    /// Verify a proof-of-possession from the peer.
    pub fn verify_proof(&self, nonce: &[u8; POP_NONCE_LEN], proof: &[u8; PROOF_LEN]) -> bool {
        let expected = self.proof_of_possession(nonce);
        subtle::ConstantTimeEq::ct_eq(expected.as_ref(), proof.as_ref()).into()
    }
}

/// In-memory store of resumption tickets. Expires stale entries on every insert.
pub struct ResumeStore {
    tickets: HashMap<[u8; 16], SessionTicket>,
}

impl ResumeStore {
    pub fn new() -> Self {
        Self {
            tickets: HashMap::new(),
        }
    }

    pub fn store(&mut self, ticket: SessionTicket) {
        self.evict_expired();
        self.tickets.insert(ticket.ticket_id, ticket);
    }

    /// Remove and return the ticket, if present and not yet expired.
    pub fn take(&mut self, ticket_id: &[u8; 16]) -> Option<SessionTicket> {
        let ticket = self.tickets.remove(ticket_id)?;
        if ticket.is_valid() {
            Some(ticket)
        } else {
            None
        }
    }

    pub fn evict_expired(&mut self) {
        self.tickets.retain(|_, t| t.is_valid());
    }
}

impl Default for ResumeStore {
    fn default() -> Self {
        Self::new()
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ticket() -> SessionTicket {
        let mut secret = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(secret.as_mut());
        let peer: [u8; 32] = [0xABu8; 32];
        SessionTicket::new(peer, secret)
    }

    #[test]
    fn ticket_roundtrip() {
        let t = make_ticket();
        let id = t.ticket_id;
        let bytes = t.to_bytes();
        let back = SessionTicket::from_bytes(&bytes).unwrap();
        assert_eq!(back.ticket_id, id);
    }

    #[test]
    fn ticket_is_valid() {
        let t = make_ticket();
        assert!(t.is_valid());
    }

    #[test]
    fn ticket_expired_fails_is_valid() {
        let mut t = make_ticket();
        t.created_at = 0;
        t.ttl_seconds = 1;
        assert!(!t.is_valid());
    }

    #[test]
    fn proof_of_possession_verifies() {
        let t = make_ticket();
        let mut nonce = [0u8; POP_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let proof = t.proof_of_possession(&nonce);
        assert!(t.verify_proof(&nonce, &proof));
    }

    #[test]
    fn wrong_nonce_fails_verification() {
        let t = make_ticket();
        let mut nonce = [0u8; POP_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let proof = t.proof_of_possession(&nonce);
        let mut bad_nonce = nonce;
        bad_nonce[0] ^= 0xFF;
        assert!(!t.verify_proof(&bad_nonce, &proof));
    }

    #[test]
    fn resume_store_take_evicts_expired() {
        let mut store = ResumeStore::new();
        let mut t = make_ticket();
        t.created_at = 0;
        t.ttl_seconds = 1;
        let id = t.ticket_id;
        store.tickets.insert(id, t);
        assert!(store.take(&id).is_none());
    }

    #[test]
    fn resume_store_take_returns_valid() {
        let mut store = ResumeStore::new();
        let t = make_ticket();
        let id = t.ticket_id;
        store.store(t);
        assert!(store.take(&id).is_some());
    }

    #[test]
    fn resume_store_take_consumes() {
        let mut store = ResumeStore::new();
        let t = make_ticket();
        let id = t.ticket_id;
        store.store(t);
        assert!(store.take(&id).is_some());
        assert!(store.take(&id).is_none());
    }
}
