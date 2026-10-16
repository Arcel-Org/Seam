#![no_main]
//! Fuzz target: TicketKey::redeem on arbitrary input.
//!
//! Adversary crafts arbitrary ticket bytes; we must reject without panicking.

use libfuzzer_sys::fuzz_target;
use seam_protocol::transport::TicketKey;

fuzz_target!(|data: &[u8]| {
    let key = TicketKey::new([0x42u8; 32]);
    let _ = key.redeem(data);
});
