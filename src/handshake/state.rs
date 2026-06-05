use crate::handshake::hybrid_keys::{KemPublicKey, KemSecretKey, MLDSA_PK_LEN, MLDSA_SIG_LEN};
use crate::{
    crypto::{CipherSuite, keys::PacketKeys},
    error::SeamError,
    handshake::hybrid_keys::{
        HybridSharedSecret, IdentityKeypair, kem_decapsulate, kem_encapsulate, mldsa_verify,
        pk_from_bytes, pk_to_bytes,
    },
};
use snow::Builder;

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Wire tag used to advertise/confirm AES-256-GCM support in handshake payloads.
/// Placed as the last 1 byte of the length-prefixed payload block.
///
/// Encoding (appended after the KEM PK length prefix):
///   byte 0: cipher preference flag
///     0x00 = ChaCha20-Poly1305 only
///     0x01 = AES-256-GCM preferred (also accepts ChaCha20-Poly1305)
const CIPHER_FLAG_CHACHA: u8 = 0x00;
const CIPHER_FLAG_AES: u8 = 0x01;

pub struct HandshakeResult {
    pub session_id: u64,
    pub keys: PacketKeys,
    pub peer_static_pubkey: [u8; 32],
    /// The cipher suite agreed during the handshake.
    pub cipher_suite: CipherSuite,
    /// BLAKE3 hash of the Noise handshake transcript (used for identity proof signing).
    pub handshake_hash: Vec<u8>,
}

/// Post-handshake identity proof message (ML-DSA-65 / FIPS 204).
///
/// Each party sends this immediately after the Noise handshake completes.
/// The signature covers the BLAKE3 handshake transcript hash, binding the
/// ML-DSA-65 identity to the session in a quantum-resistant manner.
///
/// Wire format: mldsa_pk(1952) + signature(3309) = 5261 bytes total.
pub struct IdentityProof {
    /// ML-DSA-65 verify key (1952 bytes).
    pub mldsa_pk: [u8; MLDSA_PK_LEN],
    /// ML-DSA-65 signature over the handshake transcript hash (3309 bytes).
    pub signature: [u8; MLDSA_SIG_LEN],
}

impl IdentityProof {
    /// Serialise to wire bytes (MLDSA_PK_LEN + MLDSA_SIG_LEN = 5261 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MLDSA_PK_LEN + MLDSA_SIG_LEN);
        out.extend_from_slice(&self.mldsa_pk);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Deserialise from wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != MLDSA_PK_LEN + MLDSA_SIG_LEN {
            return None;
        }
        let mldsa_pk: [u8; MLDSA_PK_LEN] = bytes[..MLDSA_PK_LEN].try_into().ok()?;
        let signature: [u8; MLDSA_SIG_LEN] = bytes[MLDSA_PK_LEN..].try_into().ok()?;
        Some(Self { mldsa_pk, signature })
    }

    /// Build an identity proof by signing the handshake transcript hash.
    pub fn sign(id: &IdentityKeypair, handshake_hash: &[u8]) -> Result<Self, SeamError> {
        use fips204::traits::SerDes as _;
        let mldsa_pk: [u8; MLDSA_PK_LEN] = id.mldsa_pk.clone().into_bytes();
        let signature = id
            .mldsa_sign(handshake_hash)
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
        Ok(Self { mldsa_pk, signature })
    }

    /// Verify this identity proof against the handshake transcript hash.
    pub fn verify(&self, handshake_hash: &[u8]) -> bool {
        mldsa_verify(&self.mldsa_pk, handshake_hash, &self.signature)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Client side
// ──────────────────────────────────────────────────────────────────────────────

pub struct ClientHandshake {
    noise: snow::HandshakeState,
    /// The cipher suite the client prefers.
    preferred_cipher: CipherSuite,
}

impl ClientHandshake {
    pub fn new(
        local: &IdentityKeypair,
        server_x25519_static: &[u8; 32],
    ) -> Result<Self, SeamError> {
        Self::new_with_cipher(local, server_x25519_static, CipherSuite::default())
    }

    pub fn new_with_cipher(
        local: &IdentityKeypair,
        server_x25519_static: &[u8; 32],
        preferred_cipher: CipherSuite,
    ) -> Result<Self, SeamError> {
        let noise = Builder::new(NOISE_PATTERN.parse().unwrap())
            .local_private_key(&local.x25519_secret.to_bytes())
            .remote_public_key(server_x25519_static)
            .build_initiator()
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
        Ok(Self {
            noise,
            preferred_cipher,
        })
    }

    /// Msg1 (-> e, es): payload = length-prefixed server KEM public key bytes
    /// followed by a 1-byte cipher flag indicating the client's preference.
    pub fn write_msg1(
        &mut self,
        server_kem_pk: &KemPublicKey,
        out: &mut Vec<u8>,
    ) -> Result<(), SeamError> {
        let pk_bytes = pk_to_bytes(server_kem_pk);
        let cipher_flag = cipher_to_flag(self.preferred_cipher);
        let mut payload = length_prefix(&pk_bytes);
        payload.push(cipher_flag);
        write_noise(&mut self.noise, &payload, out)
    }

    /// Msg2 (<- e, ee, se, s, es): server sends its KEM public key and the
    /// agreed cipher flag.
    pub fn read_msg2(&mut self, msg: &[u8]) -> Result<(KemPublicKey, CipherSuite), SeamError> {
        let payload = read_noise(&mut self.noise, msg)?;
        let (pk_bytes, cipher_flag) = extract_prefix_with_flag(&payload)?;
        let pk = pk_from_bytes(pk_bytes)
            .ok_or_else(|| SeamError::HandshakeFailed("bad KEM PK".into()))?;
        let suite = flag_to_cipher(cipher_flag);
        Ok((pk, suite))
    }

    /// Msg3 (-> s, se): encapsulate against server's KEM PK, write msg3 to `out`, finish.
    pub fn write_msg3_and_finish(
        mut self,
        server_kem_pk: &KemPublicKey,
        agreed_cipher: CipherSuite,
        out: &mut Vec<u8>,
    ) -> Result<HandshakeResult, SeamError> {
        let (ct_bytes, kem_shared) = kem_encapsulate(server_kem_pk);
        let payload = length_prefix(&ct_bytes);

        // Write msg3 first (it's mixed into the transcript hash)
        write_noise(&mut self.noise, &payload, out)?;

        // Capture hash and peer static after writing msg3
        let hash = self.noise.get_handshake_hash().to_vec();
        let peer_static: [u8; 32] = self
            .noise
            .get_remote_static()
            .ok_or_else(|| SeamError::HandshakeFailed("no remote static".into()))?
            .try_into()
            .map_err(|_| SeamError::HandshakeFailed("bad static key length".into()))?;

        finish(hash, peer_static, kem_shared, agreed_cipher)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Server side
// ──────────────────────────────────────────────────────────────────────────────

pub struct ServerHandshake {
    noise: snow::HandshakeState,
    /// Whether this server supports (and prefers) AES-256-GCM.
    preferred_cipher: CipherSuite,
}

impl ServerHandshake {
    pub fn new(local: &IdentityKeypair) -> Result<Self, SeamError> {
        Self::new_with_cipher(local, CipherSuite::default())
    }

    pub fn new_with_cipher(
        local: &IdentityKeypair,
        preferred_cipher: CipherSuite,
    ) -> Result<Self, SeamError> {
        let noise = Builder::new(NOISE_PATTERN.parse().unwrap())
            .local_private_key(&local.x25519_secret.to_bytes())
            .build_responder()
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
        Ok(Self {
            noise,
            preferred_cipher,
        })
    }

    /// Msg1: client sends our KEM PK and its cipher preference.
    /// Returns the cipher suite agreed upon: AES-256-GCM if both sides prefer
    /// it, otherwise ChaCha20-Poly1305.
    pub fn read_msg1(&mut self, msg: &[u8]) -> Result<CipherSuite, SeamError> {
        let mut buf = vec![0u8; 65535];
        let n = self
            .noise
            .read_message(msg, &mut buf)
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
        let payload = &buf[..n];

        // Gracefully handle old clients that don't send the cipher flag.
        let cipher_flag = if payload.len() > 2 {
            // last byte after the KEM PK length prefix block
            let len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
            if payload.len() > 2 + len {
                payload[2 + len]
            } else {
                CIPHER_FLAG_CHACHA
            }
        } else {
            CIPHER_FLAG_CHACHA
        };

        let client_suite = flag_to_cipher(cipher_flag);

        // Negotiate: use AES-256-GCM only if both sides prefer it.
        let agreed = if self.preferred_cipher == CipherSuite::Aes256Gcm
            && client_suite == CipherSuite::Aes256Gcm
        {
            CipherSuite::Aes256Gcm
        } else {
            CipherSuite::ChaCha20Poly1305
        };

        Ok(agreed)
    }

    /// Msg2: we send our KEM public key and the agreed cipher flag.
    pub fn write_msg2(
        &mut self,
        local_kem_pk: &KemPublicKey,
        agreed_cipher: CipherSuite,
        out: &mut Vec<u8>,
    ) -> Result<(), SeamError> {
        let pk_bytes = pk_to_bytes(local_kem_pk);
        let cipher_flag = cipher_to_flag(agreed_cipher);
        let mut payload = length_prefix(&pk_bytes);
        payload.push(cipher_flag);
        write_noise(&mut self.noise, &payload, out)
    }

    /// Msg3: client sends KEM ciphertext; we decapsulate to get the shared secret.
    pub fn read_msg3_and_finish(
        mut self,
        local_kem_sk: &KemSecretKey,
        agreed_cipher: CipherSuite,
        msg3: &[u8],
    ) -> Result<HandshakeResult, SeamError> {
        let payload = read_noise(&mut self.noise, msg3)?;

        let ct_bytes = extract_prefix(&payload)?;
        let kem_shared = kem_decapsulate(local_kem_sk, ct_bytes)
            .ok_or_else(|| SeamError::HandshakeFailed("KEM decapsulation failed".into()))?;

        let hash = self.noise.get_handshake_hash().to_vec();
        let peer_static: [u8; 32] = self
            .noise
            .get_remote_static()
            .ok_or_else(|| SeamError::HandshakeFailed("no remote static".into()))?
            .try_into()
            .map_err(|_| SeamError::HandshakeFailed("bad static key length".into()))?;

        finish(hash, peer_static, kem_shared, agreed_cipher)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ──────────────────────────────────────────────────────────────────────────────

fn finish(
    hash: Vec<u8>,
    peer_static: [u8; 32],
    kem_shared: [u8; 32],
    cipher_suite: CipherSuite,
) -> Result<HandshakeResult, SeamError> {
    let x25519_component = blake3::derive_key("apex/x25519-component/v1", &hash);
    let hybrid = HybridSharedSecret::new(kem_shared, x25519_component);
    let keys = hybrid.derive_packet_keys_with_cipher(&hash, cipher_suite);
    let session_id = u64::from_le_bytes(hash[..8].try_into().unwrap());
    Ok(HandshakeResult {
        session_id,
        keys,
        peer_static_pubkey: peer_static,
        cipher_suite,
        handshake_hash: hash,
    })
}

fn write_noise(
    hs: &mut snow::HandshakeState,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), SeamError> {
    let mut buf = vec![0u8; 65535];
    let n = hs
        .write_message(payload, &mut buf)
        .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
    out.extend_from_slice(&buf[..n]);
    Ok(())
}

fn read_noise(hs: &mut snow::HandshakeState, msg: &[u8]) -> Result<Vec<u8>, SeamError> {
    let mut buf = vec![0u8; 65535];
    let n = hs
        .read_message(msg, &mut buf)
        .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
    Ok(buf[..n].to_vec())
}

fn length_prefix(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + data.len());
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(data);
    out
}

fn extract_prefix(buf: &[u8]) -> Result<&[u8], SeamError> {
    if buf.len() < 2 {
        return Err(SeamError::HandshakeFailed("payload too short".into()));
    }
    let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + len {
        return Err(SeamError::HandshakeFailed("payload truncated".into()));
    }
    Ok(&buf[2..2 + len])
}

/// Like `extract_prefix` but also returns the cipher flag byte that follows.
fn extract_prefix_with_flag(buf: &[u8]) -> Result<(&[u8], u8), SeamError> {
    if buf.len() < 2 {
        return Err(SeamError::HandshakeFailed("payload too short".into()));
    }
    let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + len {
        return Err(SeamError::HandshakeFailed("payload truncated".into()));
    }
    let data = &buf[2..2 + len];
    let flag = if buf.len() > 2 + len {
        buf[2 + len]
    } else {
        CIPHER_FLAG_CHACHA
    };
    Ok((data, flag))
}

fn cipher_to_flag(suite: CipherSuite) -> u8 {
    match suite {
        CipherSuite::ChaCha20Poly1305 => CIPHER_FLAG_CHACHA,
        CipherSuite::Aes256Gcm => CIPHER_FLAG_AES,
    }
}

fn flag_to_cipher(flag: u8) -> CipherSuite {
    if flag == CIPHER_FLAG_AES {
        CipherSuite::Aes256Gcm
    } else {
        CipherSuite::ChaCha20Poly1305
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::hybrid_keys::IdentityKeypair;

    fn run_handshake(
        client_cipher: CipherSuite,
        server_cipher: CipherSuite,
    ) -> (HandshakeResult, HandshakeResult) {
        let client_id = IdentityKeypair::generate();
        let server_id = IdentityKeypair::generate();
        let server_x25519: [u8; 32] = server_id.x25519_public.to_bytes();

        let mut client =
            ClientHandshake::new_with_cipher(&client_id, &server_x25519, client_cipher).unwrap();
        let mut server = ServerHandshake::new_with_cipher(&server_id, server_cipher).unwrap();

        // Msg1: client → server
        let mut msg1 = Vec::new();
        client.write_msg1(&server_id.kem_pk, &mut msg1).unwrap();
        let agreed = server.read_msg1(&msg1).unwrap();

        // Msg2: server → client
        let mut msg2 = Vec::new();
        server
            .write_msg2(&server_id.kem_pk, agreed, &mut msg2)
            .unwrap();
        let (server_kem_pk, client_agreed) = client.read_msg2(&msg2).unwrap();
        assert_eq!(client_agreed, agreed);

        // Msg3: client finishes
        let mut msg3 = Vec::new();
        let client_result = client
            .write_msg3_and_finish(&server_kem_pk, agreed, &mut msg3)
            .unwrap();

        // Server finishes
        let server_result = server
            .read_msg3_and_finish(&server_id.kem_sk, agreed, &msg3)
            .unwrap();

        assert_eq!(client_result.session_id, server_result.session_id);
        (client_result, server_result)
    }

    #[test]
    fn test_full_handshake_chacha() {
        let (c, s) = run_handshake(CipherSuite::ChaCha20Poly1305, CipherSuite::ChaCha20Poly1305);
        assert_eq!(c.cipher_suite, CipherSuite::ChaCha20Poly1305);
        assert_eq!(s.cipher_suite, CipherSuite::ChaCha20Poly1305);
    }

    #[test]
    fn test_full_handshake_aes256gcm() {
        let (c, s) = run_handshake(CipherSuite::Aes256Gcm, CipherSuite::Aes256Gcm);
        assert_eq!(c.cipher_suite, CipherSuite::Aes256Gcm);
        assert_eq!(s.cipher_suite, CipherSuite::Aes256Gcm);
    }

    #[test]
    fn test_cipher_negotiation_fallback() {
        // Client wants AES but server only does ChaCha → agree on ChaCha
        let (c, s) = run_handshake(CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305);
        assert_eq!(c.cipher_suite, CipherSuite::ChaCha20Poly1305);
        assert_eq!(s.cipher_suite, CipherSuite::ChaCha20Poly1305);
    }

    #[test]
    fn test_full_handshake() {
        // Backward-compat alias
        run_handshake(CipherSuite::default(), CipherSuite::default());
    }
}
