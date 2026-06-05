use crate::crypto::{CipherSuite, keys::PacketKeys};
use fips204::ml_dsa_65::{self, PrivateKey as MlDsaPrivateKey, PublicKey as MlDsaPublicKey};
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use ml_kem::{
    Ciphertext, Decapsulate, DecapsulationKey768, Encapsulate, EncapsulationKey768, Kem, KeyExport,
    MlKem768, Seed, array::Array,
};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use std::path::Path;

pub type KemPublicKey = EncapsulationKey768;
pub type KemSecretKey = DecapsulationKey768;

/// ML-DSA-65 (FIPS 204) signing key sizes.
pub const MLDSA_SK_LEN: usize = ml_dsa_65::SK_LEN; // 4032 bytes
pub const MLDSA_PK_LEN: usize = ml_dsa_65::PK_LEN; // 1952 bytes
pub const MLDSA_SIG_LEN: usize = ml_dsa_65::SIG_LEN; // 3309 bytes

/// Long-term identity key pair:
///   - X25519 (classical key agreement)
///   - ML-KEM-768 / FIPS 203 (post-quantum key encapsulation)
///   - ML-DSA-65 / FIPS 204 (post-quantum identity signature)
pub struct IdentityKeypair {
    // Classical key agreement
    pub x25519_secret: StaticSecret,
    pub x25519_public: X25519Public,
    // Post-quantum key encapsulation (for session key exchange)
    pub kem_pk: KemPublicKey,
    pub kem_sk: KemSecretKey,
    // Post-quantum identity signature (quantum-resistant identity proof)
    pub mldsa_sk: MlDsaPrivateKey,
    pub mldsa_pk: MlDsaPublicKey,
}

impl IdentityKeypair {
    pub fn generate() -> Self {
        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519Public::from(&x25519_secret);
        let (kem_sk, kem_pk) = MlKem768::generate_keypair();
        let (mldsa_pk, mldsa_sk) = ml_dsa_65::KG::try_keygen().expect("ML-DSA-65 keygen failed");
        Self {
            x25519_secret,
            x25519_public,
            kem_pk,
            kem_sk,
            mldsa_sk,
            mldsa_pk,
        }
    }

    /// Serialise to bytes.
    ///
    /// Format (version 3): version(1) + x25519_sk(32)
    ///   + kem_sk_len(4) + kem_sk(64) + kem_pk_len(4) + kem_pk(1184)
    ///   + mldsa_sk(4032) + mldsa_pk(1952)
    pub fn to_bytes(&self) -> Vec<u8> {
        let seed = self
            .kem_sk
            .to_seed()
            .expect("seed always present on generated keys");
        let kem_sk_bytes: &[u8] = seed.as_ref();
        let kem_pk_bytes_arr = self.kem_pk.to_bytes();
        let kem_pk_bytes: &[u8] = kem_pk_bytes_arr.as_ref();

        // Serialise ML-DSA-65 keys (consuming the structs via into_bytes)
        // We need to clone/copy out so we don't move self; we clone via into_bytes on copies.
        let mldsa_sk_bytes: [u8; MLDSA_SK_LEN] = self.mldsa_sk.clone().into_bytes();
        let mldsa_pk_bytes: [u8; MLDSA_PK_LEN] = self.mldsa_pk.clone().into_bytes();

        let mut out = Vec::with_capacity(
            1 + 32 + 8 + kem_sk_bytes.len() + kem_pk_bytes.len() + MLDSA_SK_LEN + MLDSA_PK_LEN,
        );
        out.push(3u8); // version 3: ml-kem seed format + ml-dsa-65
        out.extend_from_slice(&self.x25519_secret.to_bytes());
        out.extend_from_slice(&(kem_sk_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(kem_sk_bytes);
        out.extend_from_slice(&(kem_pk_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(kem_pk_bytes);
        out.extend_from_slice(&mldsa_sk_bytes);
        out.extend_from_slice(&mldsa_pk_bytes);
        out
    }

    /// Deserialise from bytes.
    ///
    /// Supports version 3 (X25519 + ML-KEM-768 + ML-DSA-65).
    /// For version 2 (X25519 + ML-KEM-768 only), generates a new ML-DSA-65 keypair
    /// deterministically from the X25519 secret so that it is stable across upgrades,
    /// and returns the upgraded struct (caller should persist to disk).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 1 {
            return None;
        }
        match bytes[0] {
            3 => Self::from_bytes_v3(bytes),
            2 => Self::from_bytes_v2_upgrade(bytes),
            _ => None,
        }
    }

    fn from_bytes_v3(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 1 + 32 + 8 {
            return None;
        }
        // version byte already checked
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

        // ML-DSA-65 keys follow
        let mldsa_end = kem_pk_end + MLDSA_SK_LEN + MLDSA_PK_LEN;
        if bytes.len() < mldsa_end {
            return None;
        }
        let mldsa_sk_arr: [u8; MLDSA_SK_LEN] = bytes[kem_pk_end..kem_pk_end + MLDSA_SK_LEN]
            .try_into()
            .ok()?;
        let mldsa_pk_arr: [u8; MLDSA_PK_LEN] = bytes[kem_pk_end + MLDSA_SK_LEN..mldsa_end]
            .try_into()
            .ok()?;
        let mldsa_sk = MlDsaPrivateKey::try_from_bytes(mldsa_sk_arr).ok()?;
        let mldsa_pk = MlDsaPublicKey::try_from_bytes(mldsa_pk_arr).ok()?;

        Some(Self {
            x25519_secret,
            x25519_public,
            kem_pk,
            kem_sk,
            mldsa_sk,
            mldsa_pk,
        })
    }

    /// Load a v2 identity (X25519 + ML-KEM-768 only) and augment it with an
    /// ML-DSA-65 keypair derived deterministically from the X25519 secret seed.
    /// The caller is responsible for re-persisting the upgraded identity.
    fn from_bytes_v2_upgrade(bytes: &[u8]) -> Option<Self> {
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

        // Derive ML-DSA-65 keypair deterministically from the x25519 secret.
        // This makes the ML-DSA key stable after v2→v3 upgrade.
        let mldsa_seed: [u8; 32] = blake3::derive_key("seam/mldsa-identity-seed/v1", &x25519_arr);
        let (mldsa_pk, mldsa_sk) = ml_dsa_65::KG::keygen_from_seed(&mldsa_seed);

        Some(Self {
            x25519_secret,
            x25519_public,
            kem_pk,
            kem_sk,
            mldsa_sk,
            mldsa_pk,
        })
    }

    /// Load an existing identity from `path`, or generate and persist a new one.
    ///
    /// If an old v2 identity is found (X25519 + ML-KEM-768 only), it is automatically
    /// upgraded to v3 (adds ML-DSA-65) and re-persisted. The user is warned via stderr.
    /// On Unix the file is created with 0o600 permissions.
    pub fn load_or_generate(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            let bytes = std::fs::read(path).map_err(|e| anyhow::anyhow!("read identity: {e}"))?;
            // Check version byte for migration
            let version = bytes.first().copied().unwrap_or(0);
            let id =
                Self::from_bytes(&bytes).ok_or_else(|| anyhow::anyhow!("invalid identity file"))?;
            if version == 2 {
                eprintln!(
                    "seam: identity key upgraded from v2 (X25519+ML-KEM-768) to v3 \
                     (X25519+ML-KEM-768+ML-DSA-65). Re-saving {}.",
                    path.display()
                );
                std::fs::write(path, id.to_bytes())
                    .map_err(|e| anyhow::anyhow!("write upgraded identity: {e}"))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perms = std::fs::metadata(path)?.permissions();
                    perms.set_mode(0o600);
                    std::fs::set_permissions(path, perms)?;
                }
            }
            Ok(id)
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

    /// Sign a message (typically a BLAKE3 handshake transcript hash) with the ML-DSA-65
    /// signing key. Returns a 3309-byte signature.
    pub fn mldsa_sign(&self, message: &[u8]) -> anyhow::Result<[u8; MLDSA_SIG_LEN]> {
        self.mldsa_sk
            .try_sign(message, b"seam-identity-proof/v1")
            .map_err(|e| anyhow::anyhow!("ML-DSA-65 sign failed: {e}"))
    }

    /// Return the SHA-256 fingerprint of the ML-DSA-65 verify key (hex string, 64 chars).
    pub fn mldsa_fingerprint(&self) -> String {
        use sha2::Digest as _;
        let pk_bytes: [u8; MLDSA_PK_LEN] = self.mldsa_pk.clone().into_bytes();
        let hash = sha2::Sha256::digest(&pk_bytes);
        hex::encode(hash)
    }
}

/// Verify a ML-DSA-65 signature from a peer.
///
/// `pk_bytes` must be exactly `MLDSA_PK_LEN` (1952) bytes.
/// `sig_bytes` must be exactly `MLDSA_SIG_LEN` (3309) bytes.
pub fn mldsa_verify(
    pk_bytes: &[u8; MLDSA_PK_LEN],
    message: &[u8],
    sig_bytes: &[u8; MLDSA_SIG_LEN],
) -> bool {
    let pk = match MlDsaPublicKey::try_from_bytes(*pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    pk.verify(message, sig_bytes, b"seam-identity-proof/v1")
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
        self.derive_packet_keys_with_cipher(noise_hash, CipherSuite::default())
    }

    pub fn derive_packet_keys_with_cipher(
        &self,
        noise_hash: &[u8],
        cipher_suite: CipherSuite,
    ) -> PacketKeys {
        let mut ikm = Vec::with_capacity(64 + noise_hash.len());
        ikm.extend_from_slice(&self.data);
        ikm.extend_from_slice(noise_hash);
        PacketKeys::derive_from_secret_with_cipher(&ikm, cipher_suite)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generate_roundtrip() {
        let id = IdentityKeypair::generate();
        let bytes = id.to_bytes();
        assert_eq!(bytes[0], 3, "version byte must be 3");
        let id2 = IdentityKeypair::from_bytes(&bytes).expect("roundtrip failed");
        assert_eq!(
            id.x25519_public.as_bytes(),
            id2.x25519_public.as_bytes(),
            "x25519 public key must survive roundtrip"
        );
        let mldsa_pk1: [u8; MLDSA_PK_LEN] = id.mldsa_pk.clone().into_bytes();
        let mldsa_pk2: [u8; MLDSA_PK_LEN] = id2.mldsa_pk.clone().into_bytes();
        assert_eq!(
            mldsa_pk1, mldsa_pk2,
            "ML-DSA-65 public key must survive roundtrip"
        );
    }

    #[test]
    fn test_mldsa_sign_verify() {
        let id = IdentityKeypair::generate();
        let message = b"seam-handshake-transcript-hash-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let sig = id.mldsa_sign(message).expect("signing failed");
        let pk_bytes: [u8; MLDSA_PK_LEN] = id.mldsa_pk.clone().into_bytes();
        assert!(
            mldsa_verify(&pk_bytes, message, &sig),
            "ML-DSA-65 signature verification failed"
        );
    }

    #[test]
    fn test_mldsa_sign_wrong_message_fails() {
        let id = IdentityKeypair::generate();
        let message = b"correct-message-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let wrong = b"wrong-message-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let sig = id.mldsa_sign(message).expect("signing failed");
        let pk_bytes: [u8; MLDSA_PK_LEN] = id.mldsa_pk.clone().into_bytes();
        assert!(
            !mldsa_verify(&pk_bytes, wrong, &sig),
            "verify should fail on wrong message"
        );
    }

    #[test]
    fn test_mldsa_fingerprint_deterministic() {
        let id = IdentityKeypair::generate();
        assert_eq!(id.mldsa_fingerprint(), id.mldsa_fingerprint());
        assert_eq!(id.mldsa_fingerprint().len(), 64);
    }
}
