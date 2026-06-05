use crate::{
    crypto::{header::apply_header_protection, keys::PacketKeys, make_cipher},
    error::SeamError,
    packet::{HEADER_LEN, PktType, encode_buf_len},
};
use std::sync::atomic::{AtomicU64, Ordering};

pub struct PacketEncoder {
    keys: PacketKeys,
    session_id: u64,
    next_pkt_num: AtomicU64,
}

impl PacketEncoder {
    pub fn new(keys: PacketKeys, session_id: u64) -> Self {
        Self {
            keys,
            session_id,
            next_pkt_num: AtomicU64::new(0),
        }
    }

    /// Return the packet number that will be used by the *next* call to `encode`.
    /// Useful for recording a pkt_num in the ARQ tracker before encoding.
    pub fn peek_next_pkt_num(&self) -> u64 {
        self.next_pkt_num.load(Ordering::Relaxed)
    }

    /// Encode a packet into `out`. Returns bytes written.
    /// `out` must be at least `encode_buf_len(plaintext.len())` bytes.
    pub fn encode(
        &self,
        pkt_type: PktType,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, SeamError> {
        let needed = encode_buf_len(plaintext.len());
        if out.len() < needed {
            return Err(SeamError::BufferTooSmall {
                need: needed,
                have: out.len(),
            });
        }

        let pkt_num = self.next_pkt_num.fetch_add(1, Ordering::Relaxed);

        // Build plaintext header (32 bytes)
        let mut header = [0u8; HEADER_LEN];
        header[0] = 1; // version
        header[1] = pkt_type as u8;
        // bytes 2-3: flags = 0
        // bytes 4-7: reserved = 0
        header[8..16].copy_from_slice(&self.session_id.to_le_bytes());
        header[16..24].copy_from_slice(&pkt_num.to_le_bytes());
        // bytes 24-31: reserved = 0

        // Copy header and plaintext into output
        out[..HEADER_LEN].copy_from_slice(&header);
        out[HEADER_LEN..HEADER_LEN + plaintext.len()].copy_from_slice(plaintext);

        // Build nonce: nonce_base XOR packet_number (as little-endian u96)
        let mut nonce = self.keys.nonce_base;
        for (n, b) in nonce.iter_mut().zip(pkt_num.to_le_bytes().iter()) {
            *n ^= b;
        }

        // AEAD encrypt in-place (payload region); AAD = plaintext header.
        // We use a Vec for the in-place API, then copy the tag back.
        let cipher = make_cipher(self.keys.cipher_suite, self.keys.enc_key);

        let header_bytes = out[..HEADER_LEN].to_vec(); // AAD
        let mut payload_buf = out[HEADER_LEN..HEADER_LEN + plaintext.len()].to_vec();

        cipher.encrypt_in_place(&nonce, &header_bytes, &mut payload_buf)?;

        // payload_buf now contains ciphertext || tag (16 bytes appended)
        let cipher_len = plaintext.len();
        out[HEADER_LEN..HEADER_LEN + cipher_len].copy_from_slice(&payload_buf[..cipher_len]);
        out[HEADER_LEN + cipher_len..HEADER_LEN + cipher_len + 16]
            .copy_from_slice(&payload_buf[cipher_len..]);

        // Apply header protection using first 16 bytes of ciphertext as sample
        let sample: [u8; 16] = out[HEADER_LEN..HEADER_LEN + 16].try_into().unwrap();
        let mut hdr: [u8; HEADER_LEN] = out[..HEADER_LEN].try_into().unwrap();
        apply_header_protection(&self.keys.hp_key, &mut hdr, &sample);
        out[..HEADER_LEN].copy_from_slice(&hdr);

        Ok(needed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CipherSuite, keys::PacketKeys};
    use std::collections::HashSet;

    /// Nonce collision detection — birthday-paradox safety validation.
    ///
    /// The nonce construction is: nonce = nonce_base XOR pkt_num (96-bit LE).
    /// For a given session key the nonce space is 2^96 values.  We generate
    /// N = 2^20 (~1 million) packets — a realistic long-lived government link
    /// load — and verify that every nonce is unique.
    ///
    /// Birthday-paradox bound: expected collisions ≈ N² / (2 × 2^96) ≈ 2^-57
    /// for N = 2^20, which is negligibly small.  Any collision here would
    /// indicate a defect in the nonce construction (e.g. truncation bug).
    #[test]
    fn nonce_uniqueness_over_1m_packets() {
        let secret = b"nonce-collision-test-32bytes-pad";
        let keys = PacketKeys::derive_from_secret_with_cipher(secret, CipherSuite::ChaCha20Poly1305);
        let nonce_base = keys.nonce_base;

        const N: u64 = 1 << 20; // 1,048,576 packets
        let mut seen: HashSet<[u8; 12]> = HashSet::with_capacity(N as usize);

        for pkt_num in 0..N {
            let mut nonce = nonce_base;
            // XOR with little-endian packet number (same as encoder)
            for (n, b) in nonce.iter_mut().zip(pkt_num.to_le_bytes().iter()) {
                *n ^= b;
            }
            let inserted = seen.insert(nonce);
            assert!(
                inserted,
                "nonce collision detected at packet #{pkt_num} — \
                 nonce construction is broken (nonce={:?})",
                nonce
            );
        }
        // Sanity: all N nonces were unique
        assert_eq!(seen.len(), N as usize);
    }

    /// Cross-session isolation: same packet number but different session IDs
    /// produce different nonces (nonce_base is derived from the session secret
    /// which embeds the session ID via the handshake).
    ///
    /// This test uses two distinct secrets (simulating two sessions) and verifies
    /// their nonce sequences are disjoint over the first 64 K packets.
    #[test]
    fn nonce_uniqueness_across_sessions() {
        let secret_a = b"session-a-secret-32-bytes-paddd!";
        let secret_b = b"session-b-secret-32-bytes-paddd!";
        let keys_a = PacketKeys::derive_from_secret(secret_a);
        let keys_b = PacketKeys::derive_from_secret(secret_b);

        // The nonce bases must differ (BLAKE3 domain separation guarantees this,
        // but we verify explicitly).
        assert_ne!(
            keys_a.nonce_base, keys_b.nonce_base,
            "different traffic secrets must produce different nonce bases"
        );

        const N: u64 = 1 << 16; // 65,536 packets per session

        let nonces_a: HashSet<[u8; 12]> = (0..N)
            .map(|pkt_num| {
                let mut nonce = keys_a.nonce_base;
                for (n, b) in nonce.iter_mut().zip(pkt_num.to_le_bytes().iter()) {
                    *n ^= b;
                }
                nonce
            })
            .collect();

        let nonces_b: HashSet<[u8; 12]> = (0..N)
            .map(|pkt_num| {
                let mut nonce = keys_b.nonce_base;
                for (n, b) in nonce.iter_mut().zip(pkt_num.to_le_bytes().iter()) {
                    *n ^= b;
                }
                nonce
            })
            .collect();

        // The two sessions must not share any nonces.
        let intersection_count = nonces_a.intersection(&nonces_b).count();
        assert_eq!(
            intersection_count, 0,
            "sessions with distinct traffic secrets must not share nonces \
             ({intersection_count} cross-session nonce collisions found)"
        );
    }

    /// Proptest: for any random nonce_base and any pair of distinct packet
    /// numbers, the resulting nonces are distinct.
    ///
    /// Verifies the XOR construction is injective: if pkt_a ≠ pkt_b then
    /// nonce_base XOR pkt_a ≠ nonce_base XOR pkt_b  (by XOR cancellation law).
    #[cfg(test)]
    mod proptest_nonce {
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn xor_nonce_injective(
                base in proptest::array::uniform12(0u8..),
                pkt_a: u64,
                pkt_b: u64,
            ) {
                // Only test distinct packet numbers
                prop_assume!(pkt_a != pkt_b);

                let mut nonce_a = base;
                for (n, b) in nonce_a.iter_mut().zip(pkt_a.to_le_bytes().iter()) {
                    *n ^= b;
                }
                let mut nonce_b = base;
                for (n, b) in nonce_b.iter_mut().zip(pkt_b.to_le_bytes().iter()) {
                    *n ^= b;
                }
                prop_assert_ne!(nonce_a, nonce_b,
                    "XOR nonce construction must be injective: \
                     distinct packet numbers must yield distinct nonces");
            }
        }
    }
}
