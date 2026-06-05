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
