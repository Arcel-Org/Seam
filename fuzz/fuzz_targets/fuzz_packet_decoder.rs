#![no_main]
//! Fuzz target: PacketDecoder must never panic on arbitrary input.
//!
//! A malicious peer can send any byte sequence. The decoder is the first
//! line of defense — it must reject or decode, never crash. We don't care
//! about AEAD authentication passing (it won't without the key); we only
//! require the decoder to handle adversarial input gracefully.

use libfuzzer_sys::fuzz_target;
use apex_protocol::{PacketDecoder, PacketKeys};

fuzz_target!(|data: &[u8]| {
    let keys = PacketKeys::derive_from_secret(b"fuzz-secret-32-bytes-exactly-ok!");
    let mut decoder = PacketDecoder::new(keys);
    let mut buf = data.to_vec();
    // We don't care about the result — only that we don't panic.
    let _ = decoder.decode(&mut buf);
});
