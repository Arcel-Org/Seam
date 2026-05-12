use crate::crypto::keys::PacketKeys;
use ml_kem::{
    Ciphertext, Decapsulate, DecapsulationKey768, Encapsulate, EncapsulationKey768,
    KeyExport, Kem, MlKem768, Seed,
    array::Array,
};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use std::path::Path;

pub type KemPublicKey = EncapsulationKey768;
pub type KemSecretKey = DecapsulationKey768;

/// Long-term identity key pair (X25519 + ML-KEM-768 / FIPS 203).
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
        let (kem_sk, kem_pk) = MlKem768::generate_keypair();
        Self {
            x25519_secret,
            x25519_public,
            kem_pk,
            kem_sk,
        }
    }

    /// Serialise to bytes with length prefixes.
    /// Format (version 2): version(1) + x25519_sk(32) + kem_sk_len(4) + kem_sk(64) + kem_pk_len(4) + kem_pk(1184)
    pub fn to_bytes(&self) -> Vec<u8> {
        let seed = self.kem_sk.to_seed().expect("seed always present on generated keys");
        let kem_sk_bytes: &[u8] = seed.as_ref();
        let kem_pk_bytes_arr = self.kem_pk.to_bytes();
        let kem_pk_bytes: &[u8] = kem_pk_bytes_arr.as_ref();
        let mut out = Vec::with_capacity(1 + 32 + 8 + kem_sk_bytes.len() + kem_pk_bytes.len());
        out.push(2u8); // version 2: ml-kem seed format
        out.extend_from_slice(&self.x25519_secret.to_bytes());
        out.extend_from_slice(&(kem_sk_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(kem_sk_bytes);
        out.extend_from_slice(&(kem_pk_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(kem_pk_bytes);
        out
    }

    /// Deserialise from bytes (version 2 format only).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 1 + 32 + 8 {
            return None;
        }
        if bytes[0] != 2 {
            return None;
        }
        let x25519_arr: [u8; 32] = bytes[1..33].try_into().ok()?;
        let x25519_secret = StaticSecret::from(x25519_arr);
        let x25519_public = X25519Public::from(&x25519_secret);

        let kem_sk_len = u32::from_be_bytes(bytes[33..37].try_into().ok()?) as usize;
        let kem_sk_end = 37 + kem_sk_len;
        if bytes.len() < kem_sk_end {
            return None;
        }
        let seed: Seed = Array::try_from(&bytes[37..kem_sk_end]).ok()?;
        let kem_sk = DecapsulationKey768::from_seed(seed);

        if bytes.len() < kem_sk_end + 4 {
            return None;
        }
        let kem_pk_len =
            u32::from_be_bytes(bytes[kem_sk_end..kem_sk_end + 4].try_into().ok()?) as usize;
        let kem_pk_end = kem_sk_end + 4 + kem_pk_len;
        if bytes.len() < kem_pk_end {
            return None;
        }
        let pk_arr = Array::try_from(&bytes[kem_sk_end + 4..kem_pk_end]).ok()?;
        let kem_pk = EncapsulationKey768::new(&pk_arr).ok()?;

        Some(Self {
            x25519_secret,
            x25519_public,
            kem_pk,
            kem_sk,
        })
    }

    /// Load an existing identity from `path`, or generate and persist a new one.
    /// On Unix the file is created with 0o600 permissions.
    pub fn load_or_generate(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            let bytes = std::fs::read(path).map_err(|e| anyhow::anyhow!("read identity: {e}"))?;
            Self::from_bytes(&bytes).ok_or_else(|| anyhow::anyhow!("invalid identity file"))
        } else {
            let id = Self::generate();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| anyhow::anyhow!("create identity dir: {e}"))?;
            }
            std::fs::write(path, id.to_bytes())
                .map_err(|e| anyhow::anyhow!("write identity: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(path)?.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(path, perms)?;
            }
            Ok(id)
        }
    }
}

/// Combined shared secret — breaking either X25519 or ML-KEM-768 alone is insufficient.
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
    let (ct, ss) = pk.encapsulate();
    let ct_bytes: Vec<u8> = ct[..].to_vec();
    let ss_bytes: [u8; 32] = ss[..].try_into().expect("SharedKey is 32 bytes");
    (ct_bytes, ss_bytes)
}

/// Decapsulate received ciphertext → 32-byte SS, or None if ciphertext is malformed.
pub fn kem_decapsulate(sk: &KemSecretKey, ct_bytes: &[u8]) -> Option<[u8; 32]> {
    let ct: Ciphertext<MlKem768> = Array::try_from(ct_bytes).ok()?;
    let ss = sk.decapsulate(&ct);
    let ss_bytes: [u8; 32] = ss[..].try_into().ok()?;
    Some(ss_bytes)
}

/// Serialise a KEM public key.
pub fn pk_to_bytes(pk: &KemPublicKey) -> Vec<u8> {
    pk.to_bytes()[..].to_vec()
}

/// Deserialise a KEM public key.
pub fn pk_from_bytes(bytes: &[u8]) -> Option<KemPublicKey> {
    let arr = Array::try_from(bytes).ok()?;
    EncapsulationKey768::new(&arr).ok()
}
