use crate::{
    crypto::{
        header::apply_header_protection, keys::PacketKeys, make_cipher, replay::ReplayWindow,
    },
    error::SeamError,
    packet::{HEADER_LEN, MAX_PACKET_LEN, MIN_PACKET_LEN, PktType, TAG_LEN},
};

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
        // Hard-reject oversized frames before touching the AEAD — prevents wasting
        // crypto resources on amplification or malformed packets.
        if buf.len() > MAX_PACKET_LEN {
            return Err(SeamError::PacketTooLarge {
                have: buf.len(),
                max: MAX_PACKET_LEN,
            });
        }
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
        let header_bytes = buf[..HEADER_LEN].to_vec(); // AAD

        // Build ciphertext+tag buffer for in-place decryption
        let mut ct_buf = buf[HEADER_LEN..].to_vec(); // ciphertext || tag

        let cipher = make_cipher(self.keys.cipher_suite, self.keys.enc_key);
        cipher.decrypt_in_place(&nonce, &header_bytes, &mut ct_buf)?;

        // ct_buf now contains plaintext (tag has been stripped)
        let plaintext_len = payload_end - HEADER_LEN;
        buf[HEADER_LEN..payload_end].copy_from_slice(&ct_buf[..plaintext_len]);

        Ok((pkt_type, pkt_num, &buf[HEADER_LEN..payload_end]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CipherSuite, encoder::PacketEncoder, keys::PacketKeys};

    fn make_pair() -> (PacketEncoder, PacketDecoder) {
        make_pair_with_suite(CipherSuite::ChaCha20Poly1305)
    }

    fn make_pair_with_suite(suite: CipherSuite) -> (PacketEncoder, PacketDecoder) {
        let secret = b"test-secret-32-bytes-padding-xyz";
        let enc_keys = PacketKeys::derive_from_secret_with_cipher(secret, suite);
        let dec_keys = PacketKeys::derive_from_secret_with_cipher(secret, suite);
        let encoder = PacketEncoder::new(enc_keys, 0xdeadbeef);
        let decoder = PacketDecoder::new(dec_keys);
        (encoder, decoder)
    }

    #[test]
    fn test_oversized_packet_rejected() {
        let (_, mut dec) = make_pair();
        // A buffer larger than MAX_PACKET_LEN (65535) must be rejected before
        // any AEAD work is attempted.
        let mut oversized = vec![0u8; MAX_PACKET_LEN + 1];
        assert!(matches!(
            dec.decode(&mut oversized),
            Err(SeamError::PacketTooLarge { have, max })
            if have == MAX_PACKET_LEN + 1 && max == MAX_PACKET_LEN
        ));
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
    fn test_roundtrip_aes256gcm() {
        let (enc, mut dec) = make_pair_with_suite(CipherSuite::Aes256Gcm);
        let plaintext = b"hello cnsa 2.0 compliant packet";
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

    /// Packet at exactly the last slot of the window (offset = 1023) must be accepted.
    #[test]
    fn test_window_boundary_last_slot_accepted() {
        let secret = b"boundary-last-slot-32bytes-paddd";
        let enc_keys = PacketKeys::derive_from_secret(secret);
        let dec_keys = PacketKeys::derive_from_secret(secret);
        let encoder = PacketEncoder::new(enc_keys, 0xABCD);
        let mut decoder = PacketDecoder::new(dec_keys);

        // Encode seq 0 to anchor base_seq = 0
        let mut buf0 = vec![0u8; HEADER_LEN + 4 + TAG_LEN];
        encoder.encode(PktType::Data, b"anch", &mut buf0).unwrap();
        decoder.decode(&mut buf0).unwrap();

        // Encode seq 1 through 1022 (skip decoding to leave base_seq = 0)
        for _ in 1..1023 {
            let mut buf = vec![0u8; HEADER_LEN + 4 + TAG_LEN];
            encoder.encode(PktType::Data, b"skip", &mut buf).unwrap();
            // do NOT decode — we only want to advance the encoder counter
            let _ = buf; // suppress unused warning
        }

        // seq 1023 is the last valid slot in the window when base_seq = 0 (offset = 1023 < 1024)
        let mut buf_boundary = vec![0u8; HEADER_LEN + 4 + TAG_LEN];
        encoder
            .encode(PktType::Data, b"bndl", &mut buf_boundary)
            .unwrap();
        // Decode the skipped packets first (1 .. 1022) is impractical here; instead we
        // decode only the boundary packet which requires sliding.  The important assertion
        // is that the decode does NOT return a TooOld / Replay error.
        assert!(
            decoder.decode(&mut buf_boundary).is_ok(),
            "seq 1023 (window boundary) must be accepted"
        );
    }

    /// A packet whose sequence number is exactly one slot past the tail of the current
    /// window (i.e. already evicted by sliding) must be rejected as TooOld.
    #[test]
    fn test_window_boundary_just_outside_rejected() {
        use crate::crypto::replay::ReplayWindow;
        use crate::error::SeamError;

        let mut w = ReplayWindow::new();

        // Accept seq 1023, which is the last valid slot when base_seq = 0.
        w.check_and_insert(1023).unwrap();

        // Now accept seq 1024 — this slides the window so base_seq advances by 1.
        // After the slide, base_seq = 1 and seq 0 falls outside the window.
        w.check_and_insert(1024).unwrap();

        // seq 0 is now below base_seq and must be rejected.
        let result = w.check_and_insert(0);
        assert!(
            matches!(result, Err(SeamError::TooOld(0))),
            "seq 0 just outside window must be TooOld, got {:?}",
            result
        );
    }

    /// A duplicate packet that was already accepted must be rejected as Replay,
    /// even when the packet number sits exactly at the current window boundary.
    #[test]
    fn test_duplicate_at_boundary_rejected() {
        use crate::crypto::replay::ReplayWindow;
        use crate::error::SeamError;

        let mut w = ReplayWindow::new();

        // Accept the packet at the top of the window (offset = 1023).
        w.check_and_insert(1023).unwrap();

        // A second attempt with the same seq must be rejected as Replay.
        let result = w.check_and_insert(1023);
        assert!(
            matches!(result, Err(SeamError::Replay(1023))),
            "duplicate at window boundary must be Replay, got {:?}",
            result
        );
    }
}
