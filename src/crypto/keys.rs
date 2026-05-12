use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop, Clone, Debug)]
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

    /// Serialise to 76 bytes: enc_key(32) + hp_key(32) + nonce_base(12).
    pub fn to_bytes(&self) -> [u8; 76] {
        let mut out = [0u8; 76];
        out[0..32].copy_from_slice(&self.enc_key);
        out[32..64].copy_from_slice(&self.hp_key);
        out[64..76].copy_from_slice(&self.nonce_base);
        out
    }

    /// Deserialise from 76 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 76 {
            return None;
        }
        Some(Self {
            enc_key: bytes[0..32].try_into().ok()?,
            hp_key: bytes[32..64].try_into().ok()?,
            nonce_base: bytes[64..76].try_into().ok()?,
        })
    }
}
