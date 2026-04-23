use chacha20::{ChaCha20, cipher::{KeyIvInit, StreamCipherSeek, StreamCipher}};

/// Apply (or remove — it's symmetric) header protection.
///
/// Samples the first 16 bytes of `ciphertext` to produce a 32-byte mask,
/// then XORs `header` in-place. Call once to protect, call again to unprotect.
pub fn apply_header_protection(hp_key: &[u8; 32], header: &mut [u8; 32], ciphertext: &[u8; 16]) {
    // nonce = first 12 bytes of sample, counter = last 4 bytes of sample
    let nonce: [u8; 12] = ciphertext[..12].try_into().unwrap();
    let counter = u32::from_le_bytes(ciphertext[12..16].try_into().unwrap());

    let mut cipher = ChaCha20::new(hp_key.into(), &nonce.into());
    cipher.seek(counter as u64 * 64); // seek to the block at `counter`
    let mut mask = [0u8; 32];
    cipher.apply_keystream(&mut mask);

    for (h, m) in header.iter_mut().zip(mask.iter()) {
        *h ^= m;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_protection_is_symmetric() {
        let hp_key = [7u8; 32];
        let sample = [3u8; 16];
        let mut header = [1u8; 32];
        let original = header;

        apply_header_protection(&hp_key, &mut header, &sample);
        assert_ne!(header, original);
        apply_header_protection(&hp_key, &mut header, &sample);
        assert_eq!(header, original);
    }

    #[test]
    fn changing_sample_changes_mask() {
        let hp_key = [9u8; 32];
        let mut a = [0xAAu8; 32];
        let mut b = [0xAAu8; 32];
        apply_header_protection(&hp_key, &mut a, &[1u8; 16]);
        apply_header_protection(&hp_key, &mut b, &[2u8; 16]);
        assert_ne!(a, b);
    }
}
