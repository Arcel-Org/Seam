#![no_main]
//! Fuzz target: FecRepairData::from_bytes on arbitrary input.

use libfuzzer_sys::fuzz_target;
use seam_protocol::fec::FecRepairData;

fuzz_target!(|data: &[u8]| {
    if let Some(parsed) = FecRepairData::from_bytes(data) {
        // Roundtrip if it parsed: serialize must not panic and the
        // resulting bytes should re-parse identically.
        let bytes = parsed.to_bytes();
        let reparsed = FecRepairData::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(reparsed.repair_idx, parsed.repair_idx);
        assert_eq!(reparsed.k, parsed.k);
        assert_eq!(reparsed.r, parsed.r);
        assert_eq!(reparsed.padded_len, parsed.padded_len);
    }
});
