use snow::Builder;
use pqcrypto_kyber::kyber768::PublicKey as KemPublicKey;
use crate::{
    crypto::keys::PacketKeys,
    error::SeamError,
    handshake::hybrid_keys::{
        IdentityKeypair, HybridSharedSecret,
        kem_encapsulate, kem_decapsulate,
        pk_to_bytes, pk_from_bytes,
    },
};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

pub struct HandshakeResult {
    pub session_id: u64,
    pub keys: PacketKeys,
    pub peer_static_pubkey: [u8; 32],
}

// ──────────────────────────────────────────────────────────────────────────────
// Client side
// ──────────────────────────────────────────────────────────────────────────────

pub struct ClientHandshake {
    noise: snow::HandshakeState,
}

impl ClientHandshake {
    pub fn new(local: &IdentityKeypair, server_x25519_static: &[u8; 32]) -> Result<Self, SeamError> {
        let noise = Builder::new(NOISE_PATTERN.parse().unwrap())
            .local_private_key(&local.x25519_secret.to_bytes())
            .remote_public_key(server_x25519_static)
            .build_initiator()
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
        Ok(Self { noise })
    }

    /// Msg1 (-> e, es): payload = length-prefixed server KEM public key bytes.
    pub fn write_msg1(&mut self, server_kem_pk: &KemPublicKey, out: &mut Vec<u8>) -> Result<(), SeamError> {
        let pk_bytes = pk_to_bytes(server_kem_pk);
        let payload = length_prefix(&pk_bytes);
        write_noise(&mut self.noise, &payload, out)
    }

    /// Msg2 (<- e, ee, se, s, es): server sends its KEM public key back.
    pub fn read_msg2(&mut self, msg: &[u8]) -> Result<KemPublicKey, SeamError> {
        let payload = read_noise(&mut self.noise, msg)?;
        let pk_bytes = extract_prefix(&payload)?;
        pk_from_bytes(pk_bytes).ok_or_else(|| SeamError::HandshakeFailed("bad KEM PK".into()))
    }

    /// Msg3 (-> s, se): encapsulate against server's KEM PK, write msg3 to `out`, finish.
    pub fn write_msg3_and_finish(
        mut self,
        server_kem_pk: &KemPublicKey,
        out: &mut Vec<u8>,
    ) -> Result<HandshakeResult, SeamError> {
        let (ct_bytes, kem_shared) = kem_encapsulate(server_kem_pk);
        let payload = length_prefix(&ct_bytes);

        // Write msg3 first (it's mixed into the transcript hash)
        write_noise(&mut self.noise, &payload, out)?;

        // Capture hash and peer static after writing msg3
        let hash = self.noise.get_handshake_hash().to_vec();
        let peer_static: [u8; 32] = self.noise.get_remote_static()
            .ok_or_else(|| SeamError::HandshakeFailed("no remote static".into()))?
            .try_into()
            .map_err(|_| SeamError::HandshakeFailed("bad static key length".into()))?;

        finish(hash, peer_static, kem_shared)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Server side
// ──────────────────────────────────────────────────────────────────────────────

pub struct ServerHandshake {
    noise: snow::HandshakeState,
}

impl ServerHandshake {
    pub fn new(local: &IdentityKeypair) -> Result<Self, SeamError> {
        let noise = Builder::new(NOISE_PATTERN.parse().unwrap())
            .local_private_key(&local.x25519_secret.to_bytes())
            .build_responder()
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
        Ok(Self { noise })
    }

    /// Msg1: client sends our KEM PK (just reads it through noise, we ignore the payload).
    pub fn read_msg1(&mut self, msg: &[u8]) -> Result<(), SeamError> {
        let mut buf = vec![0u8; 65535];
        self.noise.read_message(msg, &mut buf)
            .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
        Ok(())
    }

    /// Msg2: we send our KEM public key in the payload so client can encapsulate against it.
    pub fn write_msg2(&mut self, local_kem_pk: &KemPublicKey, out: &mut Vec<u8>) -> Result<(), SeamError> {
        let pk_bytes = pk_to_bytes(local_kem_pk);
        let payload = length_prefix(&pk_bytes);
        write_noise(&mut self.noise, &payload, out)
    }

    /// Msg3: client sends KEM ciphertext; we decapsulate to get the shared secret.
    pub fn read_msg3_and_finish(
        mut self,
        local_kem_sk: &pqcrypto_kyber::kyber768::SecretKey,
        msg3: &[u8],
    ) -> Result<HandshakeResult, SeamError> {
        let payload = read_noise(&mut self.noise, msg3)?;

        let kem_shared = if payload.len() >= 2 {
            match extract_prefix(&payload) {
                Ok(ct_bytes) => kem_decapsulate(local_kem_sk, ct_bytes).unwrap_or([0u8; 32]),
                Err(_) => [0u8; 32],
            }
        } else {
            [0u8; 32]
        };

        let hash = self.noise.get_handshake_hash().to_vec();
        let peer_static: [u8; 32] = self.noise.get_remote_static()
            .ok_or_else(|| SeamError::HandshakeFailed("no remote static".into()))?
            .try_into()
            .map_err(|_| SeamError::HandshakeFailed("bad static key length".into()))?;

        finish(hash, peer_static, kem_shared)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ──────────────────────────────────────────────────────────────────────────────

fn finish(hash: Vec<u8>, peer_static: [u8; 32], kem_shared: [u8; 32]) -> Result<HandshakeResult, SeamError> {
    let x25519_component = blake3::derive_key("apex/x25519-component/v1", &hash);
    let hybrid = HybridSharedSecret::new(kem_shared, x25519_component);
    let keys = hybrid.derive_packet_keys(&hash);
    let session_id = u64::from_le_bytes(hash[..8].try_into().unwrap());
    Ok(HandshakeResult { session_id, keys, peer_static_pubkey: peer_static })
}

fn write_noise(hs: &mut snow::HandshakeState, payload: &[u8], out: &mut Vec<u8>) -> Result<(), SeamError> {
    let mut buf = vec![0u8; 65535];
    let n = hs.write_message(payload, &mut buf)
        .map_err(|e| SeamError::HandshakeFailed(e.to_string()))?;
    out.extend_from_slice(&buf[..n]);
    Ok(())
}

fn read_noise(hs: &mut snow::HandshakeState, msg: &[u8]) -> Result<Vec<u8>, SeamError> {
    let mut buf = vec![0u8; 65535];
    let n = hs.read_message(msg, &mut buf)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::hybrid_keys::IdentityKeypair;

    #[test]
    fn test_full_handshake() {
        let client_id = IdentityKeypair::generate();
        let server_id = IdentityKeypair::generate();
        let server_x25519: [u8; 32] = server_id.x25519_public.to_bytes();

        let mut client = ClientHandshake::new(&client_id, &server_x25519).unwrap();
        let mut server = ServerHandshake::new(&server_id).unwrap();

        // Msg1: client → server
        let mut msg1 = Vec::new();
        client.write_msg1(&server_id.kem_pk, &mut msg1).unwrap();
        server.read_msg1(&msg1).unwrap();

        // Msg2: server → client
        let mut msg2 = Vec::new();
        server.write_msg2(&server_id.kem_pk, &mut msg2).unwrap();
        let server_kem_pk = client.read_msg2(&msg2).unwrap();

        // Msg3: client finishes
        let mut msg3 = Vec::new();
        let client_result = client.write_msg3_and_finish(&server_kem_pk, &mut msg3).unwrap();

        // Server finishes
        let server_result = server.read_msg3_and_finish(&server_id.kem_sk, &msg3).unwrap();

        assert_eq!(client_result.session_id, server_result.session_id);
    }
}
