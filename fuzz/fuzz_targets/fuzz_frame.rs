#![no_main]
//! Fuzz target: arbitrary bytes into the FEC decoder.
//!
//! The FEC decoder is the first consumer of every repair and source frame that
//! arrives from the network. It must handle adversarial input — truncated
//! headers, impossible k/r values, mismatched group IDs — without panicking.
//!
//! Input layout (inspired by the existing fuzz_fec_decode target but extended):
//!   For each record:
//!     op(1) | ...
//!   op & 0x03 == 0 → add_source:   group_id(4) source_idx(1) k(1) r(1) len(2) data[len]
//!   op & 0x03 == 1 → add_repair:   raw FecRepairData::from_bytes (entire rest of buffer)
//!   op & 0x03 == 2 → parse only:   FecRepairData::from_bytes on rest, roundtrip if Some
//!   op & 0x03 == 3 → new decoder:  reset decoder state, continue parsing remaining bytes
//!
//! Each branch must complete without panicking regardless of input content.

use libfuzzer_sys::fuzz_target;
use seam_protocol::fec::{FecDecoder, FecRepairData};

fuzz_target!(|data: &[u8]| {
    let mut dec = FecDecoder::new();
    let mut cursor = data;

    while !cursor.is_empty() {
        if cursor.len() < 2 {
            break;
        }
        let op = cursor[0] & 0x03;
        let rest = &cursor[1..];

        match op {
            // add_source: group_id(4) source_idx(1) k(1) r(1) len(2) data[len]
            0 => {
                if rest.len() < 9 {
                    break;
                }
                let group_id = u32::from_le_bytes(rest[0..4].try_into().unwrap());
                let source_idx = rest[4];
                let k = rest[5];
                let r = rest[6];
                let len = u16::from_le_bytes([rest[7], rest[8]]) as usize;
                if rest.len() < 9 + len {
                    break;
                }
                let payload = &rest[9..9 + len];
                let _ = dec.add_source(group_id, source_idx, k, r, payload);
                cursor = &rest[9 + len..];
            }

            // add_repair: parse FecRepairData from rest, feed to decoder if valid
            1 => {
                if let Some(rep) = FecRepairData::from_bytes(rest) {
                    let _ = dec.add_repair(&rep);
                }
                // consume the whole remaining buffer for this op
                break;
            }

            // parse-only roundtrip: FecRepairData::from_bytes + to_bytes
            2 => {
                if let Some(parsed) = FecRepairData::from_bytes(rest) {
                    let bytes = parsed.to_bytes();
                    // Re-parse: must succeed and match key fields
                    if let Some(reparsed) = FecRepairData::from_bytes(&bytes) {
                        // Verify structural invariants hold — panic here means a bug
                        assert_eq!(reparsed.repair_idx, parsed.repair_idx);
                        assert_eq!(reparsed.k, parsed.k);
                        assert_eq!(reparsed.r, parsed.r);
                        assert_eq!(reparsed.padded_len, parsed.padded_len);
                    }
                }
                break;
            }

            // Reset decoder, continue parsing
            _ => {
                dec = FecDecoder::new();
                cursor = rest;
            }
        }
    }
});
