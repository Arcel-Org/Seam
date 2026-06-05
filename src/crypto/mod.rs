pub mod decoder;
pub mod encoder;
pub mod header;
pub mod keys;
pub mod ratchet;
pub mod rekey;
pub mod replay;

pub use rekey::KeySchedule;

use crate::error::SeamError;

// ──────────────────────────────────────────────────────────────────────────────
// CipherSuite
// ──────────────────────────────────────────────────────────────────────────────

/// Selects the AEAD cipher used for packet encryption.
///
/// - `ChaCha20Poly1305` — default, excellent cross-platform performance, no
///   hardware requirement.
/// - `Aes256Gcm` — required by NSA CNSA 2.0 for national security systems and
///   DoD deployments; hardware-accelerated on AES-NI platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CipherSuite {
    /// ChaCha20-Poly1305 (default, cross-platform performance)
    #[default]
    ChaCha20Poly1305,
    /// AES-256-GCM (CNSA 2.0 compliant, required for NSS/DoD)
    Aes256Gcm,
}

impl CipherSuite {
    /// Parse from a CLI/config string (`"chacha20poly1305"` or `"aes256gcm"`).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "chacha20poly1305" | "chacha20-poly1305" => Some(Self::ChaCha20Poly1305),
            "aes256gcm" | "aes-256-gcm" => Some(Self::Aes256Gcm),
            _ => None,
        }
    }

    /// Canonical string representation (matches CLI values).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305 => "chacha20poly1305",
            Self::Aes256Gcm => "aes256gcm",
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// AeadCipher trait
// ──────────────────────────────────────────────────────────────────────────────

/// Unified AEAD interface over ChaCha20-Poly1305 and AES-256-GCM.
///
/// Both ciphers use 32-byte keys, 12-byte nonces and 16-byte tags.
pub trait AeadCipher: Send + Sync {
    /// Encrypt `buffer` in-place, appending the 16-byte authentication tag.
    fn encrypt_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), SeamError>;

    /// Decrypt `buffer` in-place (tag must be the trailing 16 bytes and will
    /// be removed on success).
    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), SeamError>;

    fn key_len() -> usize
    where
        Self: Sized,
    {
        32
    }
    fn nonce_len() -> usize
    where
        Self: Sized,
    {
        12
    }
    fn tag_len() -> usize
    where
        Self: Sized,
    {
        16
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ChaCha20-Poly1305 implementation
// ──────────────────────────────────────────────────────────────────────────────

pub struct ChaCha20Poly1305Cipher {
    key: [u8; 32],
}

impl ChaCha20Poly1305Cipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

impl AeadCipher for ChaCha20Poly1305Cipher {
    fn encrypt_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), SeamError> {
        use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nonce_arr: [u8; 12] = nonce.try_into().map_err(|_| SeamError::AuthFailed)?;
        cipher
            .encrypt_in_place(&nonce_arr.into(), aad, buffer)
            .map_err(|_| SeamError::AuthFailed)
    }

    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), SeamError> {
        use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nonce_arr: [u8; 12] = nonce.try_into().map_err(|_| SeamError::AuthFailed)?;
        cipher
            .decrypt_in_place(&nonce_arr.into(), aad, buffer)
            .map_err(|_| SeamError::AuthFailed)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// AES-256-GCM implementation
// ──────────────────────────────────────────────────────────────────────────────

pub struct Aes256GcmCipher {
    key: [u8; 32],
}

impl Aes256GcmCipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

impl AeadCipher for Aes256GcmCipher {
    fn encrypt_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), SeamError> {
        use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit};
        let cipher = Aes256Gcm::new((&self.key).into());
        let nonce_arr: [u8; 12] = nonce.try_into().map_err(|_| SeamError::AuthFailed)?;
        cipher
            .encrypt_in_place(&nonce_arr.into(), aad, buffer)
            .map_err(|_| SeamError::AuthFailed)
    }

    fn decrypt_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), SeamError> {
        use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit};
        let cipher = Aes256Gcm::new((&self.key).into());
        let nonce_arr: [u8; 12] = nonce.try_into().map_err(|_| SeamError::AuthFailed)?;
        cipher
            .decrypt_in_place(&nonce_arr.into(), aad, buffer)
            .map_err(|_| SeamError::AuthFailed)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Factory helper
// ──────────────────────────────────────────────────────────────────────────────

/// Construct a heap-allocated `AeadCipher` for the given suite and key.
pub fn make_cipher(suite: CipherSuite, key: [u8; 32]) -> Box<dyn AeadCipher> {
    match suite {
        CipherSuite::ChaCha20Poly1305 => Box::new(ChaCha20Poly1305Cipher::new(key)),
        CipherSuite::Aes256Gcm => Box::new(Aes256GcmCipher::new(key)),
    }
}
