use crate::crypto::keys::PacketKeys;
use pqcrypto_kyber::kyber768::{
    self, Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Long-term identity key pair (X25519 + Kyber768 / ML-KEM-768).
pub struct IdentityKeypair {
    pub x25519_secret: StaticSecret,
    pub x25519_public: X25519Public,
    pub kem_pk: KemPublicKey,
    pub kem_sk: KemSecretKey,
}

impl IdentityKeypair {
    pub fn generate() -> Self {
        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519Public::from(&x25519_secret);
        let (kem_pk, kem_sk) = kyber768::keypair();
        Self {
            x25519_secret,
            x25519_public,
            kem_pk,
            kem_sk,
        }
    }
}

/// Combined shared secret — breaking either X25519 or Kyber alone is insufficient.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSharedSecret {
    data: [u8; 64],
}

impl HybridSharedSecret {
    pub fn new(x25519_bytes: [u8; 32], kem_bytes: [u8; 32]) -> Self {
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(&x25519_bytes);
        data[32..].copy_from_slice(&kem_bytes);
        Self { data }
    }

    pub fn derive_packet_keys(&self, noise_hash: &[u8]) -> PacketKeys {
        let mut ikm = Vec::with_capacity(64 + noise_hash.len());
        ikm.extend_from_slice(&self.data);
        ikm.extend_from_slice(noise_hash);
        PacketKeys::derive_from_secret(&ikm)
    }
}

/// Encapsulate against peer's public key → (ciphertext bytes, 32-byte SS).
pub fn kem_encapsulate(pk: &KemPublicKey) -> (Vec<u8>, [u8; 32]) {
    let (ss, ct) = kyber768::encapsulate(pk);
    let ss_bytes: [u8; 32] = ss.as_bytes().try_into().expect("SS must be 32 bytes");
    (ct.as_bytes().to_vec(), ss_bytes)
}

/// Decapsulate received ciphertext → 32-byte SS.
pub fn kem_decapsulate(sk: &KemSecretKey, ct_bytes: &[u8]) -> Option<[u8; 32]> {
    let ct = KemCiphertext::from_bytes(ct_bytes).ok()?;
    let ss = kyber768::decapsulate(&ct, sk);
    let ss_bytes: [u8; 32] = ss.as_bytes().try_into().ok()?;
    Some(ss_bytes)
}

/// Serialise a KEM public key.
pub fn pk_to_bytes(pk: &KemPublicKey) -> Vec<u8> {
    pk.as_bytes().to_vec()
}

/// Deserialise a KEM public key.
pub fn pk_from_bytes(bytes: &[u8]) -> Option<KemPublicKey> {
    KemPublicKey::from_bytes(bytes).ok()
}
