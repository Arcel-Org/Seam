use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct PacketKeys {
    pub enc_key: [u8; 32],
    pub hp_key: [u8; 32],
    pub nonce_base: [u8; 12],
}

impl PacketKeys {
    pub fn new(enc_key: [u8; 32], hp_key: [u8; 32], nonce_base: [u8; 12]) -> Self {
        Self {
            enc_key,
            hp_key,
            nonce_base,
        }
    }

    /// Derive all keys from a single 32-byte traffic secret using BLAKE3.
    pub fn derive_from_secret(secret: &[u8]) -> Self {
        let enc_key: [u8; 32] = blake3::derive_key("apex/payload-encryption/v1", secret);
        let hp_key: [u8; 32] = blake3::derive_key("apex/header-protection/v1", secret);
        let nb_full: [u8; 32] = blake3::derive_key("apex/nonce-base/v1", secret);
        let mut nonce_base = [0u8; 12];
        nonce_base.copy_from_slice(&nb_full[..12]);
        Self {
            enc_key,
            hp_key,
            nonce_base,
        }
    }
}
