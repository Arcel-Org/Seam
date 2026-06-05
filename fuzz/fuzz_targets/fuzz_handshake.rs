#![no_main]
//! Fuzz target: feed arbitrary bytes as Noise_XX handshake messages.
//!
//! A malicious peer can inject any byte sequence at any phase of the
//! handshake. The state machine must reject such input with a typed error
//! and never panic or exhibit undefined behaviour.
//!
//! Strategy: use the first byte to pick which handshake phase to exercise,
//! then feed the remainder as the raw message. We test:
//!   - ServerHandshake::read_msg1  (server receives attacker-controlled msg1)
//!   - ClientHandshake::read_msg2  (client receives attacker-controlled msg2)
//!   - ServerHandshake::read_msg3_and_finish (server receives attacker-controlled msg3)

use libfuzzer_sys::fuzz_target;
use seam_protocol::{
    CipherSuite,
    handshake::{ClientHandshake, IdentityKeypair, ServerHandshake},
};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let selector = data[0] % 3;
    let payload = &data[1..];

    match selector {
        // ── Phase 0: server reads msg1 from arbitrary bytes ──────────────────
        0 => {
            let server_id = IdentityKeypair::generate();
            let mut server = match ServerHandshake::new(&server_id) {
                Ok(s) => s,
                Err(_) => return,
            };
            // Must not panic — result (Ok or Err) is irrelevant
            let _ = server.read_msg1(payload);
        }

        // ── Phase 1: client reads msg2 from arbitrary bytes ──────────────────
        1 => {
            let client_id = IdentityKeypair::generate();
            // We need a real server x25519 static key; use a fixed dummy
            let dummy_server = IdentityKeypair::generate();
            let server_x25519: [u8; 32] = dummy_server.x25519_public.to_bytes();
            let mut client =
                match ClientHandshake::new_with_cipher(&client_id, &server_x25519, CipherSuite::ChaCha20Poly1305) {
                    Ok(c) => c,
                    Err(_) => return,
                };
            // We need to have sent msg1 first for the Noise state machine to be
            // ready to receive msg2.  Drive through a real msg1 exchange.
            let mut server = match ServerHandshake::new(&dummy_server) {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut msg1 = Vec::new();
            if client.write_msg1(&dummy_server.kem_pk, &mut msg1).is_err() {
                return;
            }
            if server.read_msg1(&msg1).is_err() {
                return;
            }
            // Now feed fuzz bytes as msg2
            let _ = client.read_msg2(payload);
        }

        // ── Phase 2: server reads msg3 from arbitrary bytes ──────────────────
        _ => {
            let client_id = IdentityKeypair::generate();
            let server_id = IdentityKeypair::generate();
            let server_x25519: [u8; 32] = server_id.x25519_public.to_bytes();

            let mut client = match ClientHandshake::new(&client_id, &server_x25519) {
                Ok(c) => c,
                Err(_) => return,
            };
            let mut server = match ServerHandshake::new(&server_id) {
                Ok(s) => s,
                Err(_) => return,
            };

            // Drive through msg1 + msg2 with real keys
            let mut msg1 = Vec::new();
            if client.write_msg1(&server_id.kem_pk, &mut msg1).is_err() {
                return;
            }
            let agreed = match server.read_msg1(&msg1) {
                Ok(a) => a,
                Err(_) => return,
            };
            let mut msg2 = Vec::new();
            if server.write_msg2(&server_id.kem_pk, agreed, &mut msg2).is_err() {
                return;
            }
            let (_, client_agreed) = match client.read_msg2(&msg2) {
                Ok(r) => r,
                Err(_) => return,
            };
            // Feed fuzz bytes as msg3
            let _ = server.read_msg3_and_finish(&server_id.kem_sk, client_agreed, payload);
        }
    }
});
