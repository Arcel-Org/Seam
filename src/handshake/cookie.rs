use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

/// Stateless server-side cookie. BLAKE3-HMAC of (secret || client_addr || bucket).
/// The server never allocates session state until the client echoes a valid cookie back.
///
/// Verification uses constant-time comparison to avoid leaking cookie prefixes
/// via timing side-channels on hostile networks.
pub struct CookieFactory {
    secret: [u8; 32],
    /// Resolution in seconds — prevents timing attacks while allowing clock drift.
    bucket_secs: u64,
}

impl CookieFactory {
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            secret,
            bucket_secs: 30,
        }
    }

    fn bucket(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now / self.bucket_secs
    }

    /// Generate a cookie for the given client address bytes.
    pub fn generate(&self, client_addr: &[u8]) -> [u8; 32] {
        self.compute(client_addr, self.bucket())
    }

    /// Verify a cookie, accepting current and previous bucket (30s grace window).
    /// Uses `subtle::ConstantTimeEq` — must not short-circuit on mismatch.
    pub fn verify(&self, client_addr: &[u8], cookie: &[u8; 32]) -> bool {
        let b = self.bucket();
        let cur = self.compute(client_addr, b);
        let prev = if b > 0 {
            self.compute(client_addr, b - 1)
        } else {
            [0u8; 32]
        };
        // Always compute both to avoid timing differences between "current valid"
        // and "previous valid" cases.
        let ct_cur = cur.ct_eq(cookie);
        let ct_prev = prev.ct_eq(cookie);
        bool::from(ct_cur | ct_prev)
    }

    fn compute(&self, client_addr: &[u8], bucket: u64) -> [u8; 32] {
        let mut input = Vec::with_capacity(client_addr.len() + 8);
        input.extend_from_slice(client_addr);
        input.extend_from_slice(&bucket.to_le_bytes());
        blake3::keyed_hash(&self.secret, &input).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_roundtrip() {
        let secret = [0x42u8; 32];
        let factory = CookieFactory::new(secret);
        let addr = b"127.0.0.1:9000";
        let cookie = factory.generate(addr);
        assert!(factory.verify(addr, &cookie));
    }

    #[test]
    fn test_wrong_addr_rejected() {
        let factory = CookieFactory::new([0x42u8; 32]);
        let cookie = factory.generate(b"1.2.3.4:5000");
        assert!(!factory.verify(b"5.5.5.5:5000", &cookie));
    }

    #[test]
    fn test_tampered_cookie_rejected() {
        let factory = CookieFactory::new([0x42u8; 32]);
        let mut cookie = factory.generate(b"1.2.3.4:5000");
        cookie[0] ^= 0xFF;
        assert!(!factory.verify(b"1.2.3.4:5000", &cookie));
    }
}
