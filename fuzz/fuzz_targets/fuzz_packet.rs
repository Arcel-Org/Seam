#![no_main]
//! Fuzz target: feed arbitrary bytes as a complete Seam packet.
//!
//! PacketDecoder must either succeed or return a typed error on any input —
//! no panics, no unwrap failures, no undefined behaviour.
//!
//! We test both cipher suites: the first byte selects the suite so the fuzzer
//! can explore both code paths independently.

use libfuzzer_sys::fuzz_target;
use seam_protocol::{CipherSuite, PacketDecoder, PacketKeys};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // First byte selects cipher suite; remainder is the packet bytes.
    let suite = if data[0] & 1 == 0 {
        CipherSuite::ChaCha20Poly1305
    } else {
        CipherSuite::Aes256Gcm
    };
    let packet = &data[1..];

    let keys = PacketKeys::derive_from_secret_with_cipher(
        b"fuzz-packet-secret-32-bytes-ok!!",
        suite,
    );
    let mut decoder = PacketDecoder::new(keys);
    let mut buf = packet.to_vec();
    // We only require: no panic. The result (Ok or Err) is irrelevant.
    let _ = decoder.decode(&mut buf);
});
