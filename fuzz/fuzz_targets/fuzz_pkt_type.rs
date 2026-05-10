#![no_main]
//! Fuzz target: PktType::try_from on arbitrary bytes.
//! Must return Ok for every defined value and Err for every undefined value.

use libfuzzer_sys::fuzz_target;
use seam_protocol::PktType;

fuzz_target!(|data: &[u8]| {
    for &b in data {
        let _ = PktType::try_from(b);
    }
});
