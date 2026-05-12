use crate::{
    crypto::{header::apply_header_protection, keys::PacketKeys, replay::ReplayWindow},
    error::SeamError,
    packet::{HEADER_LEN, MIN_PACKET_LEN, PktType, TAG_LEN},
};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Tag};

pub struct PacketDecoder {
    keys: PacketKeys,
    replay: ReplayWindow,
}

impl PacketDecoder {
    pub fn new(keys: PacketKeys) -> Self {
        Self {
            keys,
            replay: ReplayWindow::new(),
        }
    }

    /// Decode a packet in-place. Returns `(pkt_type, packet_number, plaintext_slice)`.
    /// The buffer is modified: header is unprotected, payload is decrypted.
    pub fn decode<'a>(&mut self, buf: &'a mut [u8]) -> Result<(PktType, u64, &'a [u8]), SeamError> {
        if buf.len() < MIN_PACKET_LEN {
            return Err(SeamError::BufferTooSmall {
                need: MIN_PACKET_LEN,
                have: buf.len(),
            });
        }

        // Remove header protection using first 16 bytes of ciphertext
        let ciphertext_start = HEADER_LEN;
        let sample: &[u8] = &buf[ciphertext_start..ciphertext_start + 16];
        let sample_arr: [u8; 16] = sample.try_into().unwrap();
        let mut header_arr: [u8; HEADER_LEN] = buf[..HEADER_LEN].try_into().unwrap();
        // Pass a slice reference for the header protection function
        apply_header_protection(&self.keys.hp_key, &mut header_arr, &sample_arr);
        buf[..HEADER_LEN].copy_from_slice(&header_arr);

        // Parse header
        let pkt_type = PktType::try_from(buf[1])?;
        let pkt_num = u64::from_le_bytes(buf[16..24].try_into().unwrap());

        // Replay check before decryption
        self.replay.check_and_insert(pkt_num)?;

        // Build nonce
        let mut nonce = self.keys.nonce_base;
        for (n, b) in nonce.iter_mut().zip(pkt_num.to_le_bytes().iter()) {
            *n ^= b;
        }

        // Split buffer: header (AAD) | payload | tag
        let payload_end = buf.len() - TAG_LEN;
        let tag_bytes: [u8; TAG_LEN] = buf[payload_end..].try_into().unwrap();
        let tag = Tag::from(tag_bytes);

        let (header_region, rest) = buf.split_at_mut(HEADER_LEN);
        let payload_region = &mut rest[..payload_end - HEADER_LEN];

        let cipher = ChaCha20Poly1305::new((&self.keys.enc_key).into());
        cipher
            .decrypt_in_place_detached(&nonce.into(), header_region, payload_region, &tag)
            .map_err(|_| SeamError::AuthFailed)?;

        Ok((pkt_type, pkt_num, payload_region))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{encoder::PacketEncoder, keys::PacketKeys};

    fn make_pair() -> (PacketEncoder, PacketDecoder) {
        let secret = b"test-secret-32-bytes-padding-xyz";
        let enc_keys = PacketKeys::derive_from_secret(secret);
        let dec_keys = PacketKeys::derive_from_secret(secret);
        let encoder = PacketEncoder::new(enc_keys, 0xdeadbeef);
        let decoder = PacketDecoder::new(dec_keys);
        (encoder, decoder)
    }

    #[test]
    fn test_roundtrip() {
        let (enc, mut dec) = make_pair();
        let plaintext = b"hello apex protocol";
        let mut buf = vec![0u8; HEADER_LEN + plaintext.len() + TAG_LEN];
        let written = enc.encode(PktType::Data, plaintext, &mut buf).unwrap();
        assert_eq!(written, buf.len());
        let (pkt_type, _pkt_num, decoded) = dec.decode(&mut buf).unwrap();
        assert_eq!(pkt_type, PktType::Data);
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn test_replay_rejected() {
        let (enc, mut dec) = make_pair();
        let mut buf = vec![0u8; HEADER_LEN + 4 + TAG_LEN];
        enc.encode(PktType::Data, b"test", &mut buf).unwrap();
        // First decode succeeds
        let mut buf2 = buf.clone();
        dec.decode(&mut buf).unwrap();
        // Second decode of same packet must fail
        assert!(matches!(dec.decode(&mut buf2), Err(SeamError::Replay(_))));
    }

    #[test]
    fn test_tampered_ciphertext() {
        let (enc, mut dec) = make_pair();
        // Payload must be > 16 bytes so we can tamper past the header-protection sample window.
        let payload = b"tamper-me-payload-long";
        let mut buf = vec![0u8; HEADER_LEN + payload.len() + TAG_LEN];
        enc.encode(PktType::Data, payload, &mut buf).unwrap();
        // Flip a byte in the ciphertext beyond the 16-byte sample (HEADER_LEN + 17).
        buf[HEADER_LEN + 17] ^= 0xFF;
        assert!(matches!(dec.decode(&mut buf), Err(SeamError::AuthFailed)));
    }

    #[test]
    fn test_window_sliding() {
        let secret = b"window-slide-test-32-bytes-paddd";
        let enc_keys = PacketKeys::derive_from_secret(secret);
        let dec_keys = PacketKeys::derive_from_secret(secret);
        let encoder = PacketEncoder::new(enc_keys, 1);
        let mut decoder = PacketDecoder::new(dec_keys);

        // Encode 1030 packets, decoding each one
        for _ in 0..1030 {
            let mut buf = vec![0u8; HEADER_LEN + 4 + TAG_LEN];
            encoder.encode(PktType::Data, b"data", &mut buf).unwrap();
            decoder.decode(&mut buf).unwrap();
        }
    }
}
