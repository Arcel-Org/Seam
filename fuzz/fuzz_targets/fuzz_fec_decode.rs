#![no_main]
//! Fuzz target: FecDecoder must handle arbitrary add_source/add_repair calls
//! without panicking. Data is split into operation records.

use libfuzzer_sys::fuzz_target;
use apex_protocol::fec::{FecDecoder, FecRepairData};

fuzz_target!(|data: &[u8]| {
    let mut dec = FecDecoder::new();
    let mut cursor = data;
    while cursor.len() > 4 {
        let op = cursor[0] & 1;
        let rest = &cursor[1..];
        if op == 0 {
            // add_source: need at least [group_id:4][source_idx][k][r][len:2][data...]
            if rest.len() < 9 { break; }
            let group_id = u32::from_le_bytes(rest[0..4].try_into().unwrap());
            let source_idx = rest[4];
            let k = rest[5];
            let r = rest[6];
            let len = u16::from_le_bytes([rest[7], rest[8]]) as usize;
            if rest.len() < 9 + len { break; }
            let payload = &rest[9..9 + len];
            let _ = dec.add_source(group_id, source_idx, k, r, payload);
            cursor = &rest[9 + len..];
        } else {
            // add_repair: feed to parser
            if let Some(rep) = FecRepairData::from_bytes(rest) {
                let _ = dec.add_repair(&rep);
            }
            break;
        }
    }
});
