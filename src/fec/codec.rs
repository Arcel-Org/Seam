use super::gf;
/// Systematic Reed-Solomon FEC codec over GF(2^8).
///
/// Encoding: [I_k | C] where C is a Cauchy parity matrix.
/// C[i][j] = 1 / (i XOR (r + j)) in GF(2^8).
/// Any k of the k+r rows are linearly independent (MDS).
///
/// Wire format for FecRepair payload:
///   group_id(4) + repair_idx(1) + k(1) + r(1) + padded_len(2) + data
///
/// Wire format for FecSource envelope (prepended when FEC active):
///   group_id(4) + source_idx(1) + k(1) + r(1)
use std::collections::HashMap;

pub const FEC_SOURCE_HDR: usize = 7; // group_id(4) + source_idx(1) + k(1) + r(1)
pub const FEC_REPAIR_HDR: usize = 9; // group_id(4) + repair_idx(1) + k(1) + r(1) + padded_len(2)

/// Cauchy matrix element: C[i][j] = 1 / (i XOR (r + j))
/// i ∈ [0, r), j ∈ [0, k). All (i XOR (r+j)) are distinct and non-zero for
/// small k+r values (guaranteed when k+r ≤ 128).
#[inline]
fn cauchy(i: u8, j: u8, r: u8) -> u8 {
    gf::inv(i ^ (r.wrapping_add(j)))
}

// ── Encoder ──────────────────────────────────────────────────────────────────

pub struct FecEncoder {
    pub group_id: u32,
    k: u8,
    r: u8,
    sources: Vec<Vec<u8>>,
    padded_len: usize,
    source_idx: u8,
}

pub struct FecRepairData {
    pub group_id: u32,
    pub repair_idx: u8,
    pub k: u8,
    pub r: u8,
    pub padded_len: u16,
    pub data: Vec<u8>,
}

impl FecRepairData {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FEC_REPAIR_HDR + self.data.len());
        out.extend_from_slice(&self.group_id.to_le_bytes());
        out.push(self.repair_idx);
        out.push(self.k);
        out.push(self.r);
        out.extend_from_slice(&self.padded_len.to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < FEC_REPAIR_HDR {
            return None;
        }
        let group_id = u32::from_le_bytes(buf[0..4].try_into().ok()?);
        let repair_idx = buf[4];
        let k = buf[5];
        let r = buf[6];
        let padded_len = u16::from_le_bytes(buf[7..9].try_into().ok()?);
        if buf.len() < FEC_REPAIR_HDR + padded_len as usize {
            return None;
        }
        Some(Self {
            group_id,
            repair_idx,
            k,
            r,
            padded_len,
            data: buf[FEC_REPAIR_HDR..FEC_REPAIR_HDR + padded_len as usize].to_vec(),
        })
    }
}

impl FecEncoder {
    pub fn new(group_id: u32, k: u8, r: u8) -> Self {
        Self {
            group_id,
            k,
            r,
            sources: Vec::with_capacity(k as usize),
            padded_len: 0,
            source_idx: 0,
        }
    }

    /// Build the FEC source envelope to prepend to the original payload.
    pub fn source_envelope(&self) -> [u8; FEC_SOURCE_HDR] {
        let mut hdr = [0u8; FEC_SOURCE_HDR];
        hdr[0..4].copy_from_slice(&self.group_id.to_le_bytes());
        hdr[4] = self.source_idx;
        hdr[5] = self.k;
        hdr[6] = self.r;
        hdr
    }

    /// Add a source payload. Returns r repair symbols when k sources accumulated.
    pub fn push_source(&mut self, payload: &[u8]) -> Option<Vec<FecRepairData>> {
        self.padded_len = self.padded_len.max(payload.len());
        self.sources.push(payload.to_vec());
        self.source_idx += 1;

        if self.sources.len() == self.k as usize {
            Some(self.emit_repairs(self.k))
        } else {
            None
        }
    }

    /// Force flush a partial group (end of stream). Returns repairs or None if empty.
    pub fn flush(&mut self) -> Option<Vec<FecRepairData>> {
        if self.sources.is_empty() {
            return None;
        }
        let actual_k = self.sources.len() as u8;
        Some(self.emit_repairs(actual_k))
    }

    fn emit_repairs(&mut self, actual_k: u8) -> Vec<FecRepairData> {
        let len = self.padded_len;
        for s in &mut self.sources {
            s.resize(len, 0);
        }

        let r = self.r;
        let mut repairs = Vec::with_capacity(r as usize);
        for i in 0..r {
            let mut sym = vec![0u8; len];
            for j in 0..actual_k {
                gf::mul_add_slice(&mut sym, &self.sources[j as usize], cauchy(i, j, r));
            }
            repairs.push(FecRepairData {
                group_id: self.group_id,
                repair_idx: i,
                k: actual_k,
                r,
                padded_len: len as u16,
                data: sym,
            });
        }

        self.group_id = self.group_id.wrapping_add(1);
        self.sources.clear();
        self.padded_len = 0;
        self.source_idx = 0;
        repairs
    }
}

// ── Decoder ──────────────────────────────────────────────────────────────────

struct GroupState {
    k: u8,
    r: u8,
    padded_len: usize,
    sources: HashMap<u8, Vec<u8>>,
    repairs: HashMap<u8, Vec<u8>>,
    recovered: bool,
}

impl GroupState {
    fn new(k: u8, r: u8, padded_len: usize) -> Self {
        Self {
            k,
            r,
            padded_len,
            sources: HashMap::new(),
            repairs: HashMap::new(),
            recovered: false,
        }
    }

    fn try_recover(&mut self) -> Option<Vec<(u8, Vec<u8>)>> {
        if self.recovered {
            return None;
        }
        let have_src = self.sources.len() as u8;
        let have_rep = self.repairs.len() as u8;

        if have_src == self.k {
            self.recovered = true;
            return Some(vec![]);
        }
        if have_src + have_rep < self.k {
            return None;
        }

        let k = self.k as usize;
        let r = self.r;
        let len = self.padded_len;

        let missing: Vec<u8> = (0..self.k)
            .filter(|i| !self.sources.contains_key(i))
            .collect();
        let n_missing = missing.len();
        if have_rep < n_missing as u8 {
            return None;
        }

        // Select rows: all available sources + first n_missing repairs.
        let mut avail_rep: Vec<u8> = self.repairs.keys().copied().collect();
        avail_rep.sort();
        avail_rep.truncate(n_missing);

        // Build k×k encoding matrix for selected rows, plus the associated RHS.
        // Source row i has encoding vector = e_i (standard basis), rhs = source[i]
        // Repair row i has encoding vector = cauchy row i, rhs = repair[i]
        let mut mat: Vec<Vec<u8>> = Vec::with_capacity(k);
        let mut rhs: Vec<Vec<u8>> = Vec::with_capacity(k);

        // Fill sources first (in column order so mat → identity is easy to track)
        // We process all k columns in order and gather rows in that order.
        let mut avail_src: Vec<u8> = self.sources.keys().copied().collect();
        avail_src.sort();

        // Build a row for each of the k column indices in order.
        // If source i is available, use identity row. Otherwise use a repair row.
        let mut rep_iter = avail_rep.iter();
        for col in 0..self.k {
            if let Some(src_data) = self.sources.get(&col) {
                let mut row = vec![0u8; k];
                row[col as usize] = 1;
                mat.push(row);
                rhs.push(src_data.clone());
            } else {
                // Take next available repair row for this missing column
                let &ri = rep_iter.next().unwrap();
                let row: Vec<u8> = (0..self.k).map(|j| cauchy(ri, j, r)).collect();
                mat.push(row);
                rhs.push(self.repairs[&ri].clone());
            }
        }

        if !gauss_rhs(&mut mat, &mut rhs, k, len) {
            return None;
        }

        // After elimination mat = I; rhs[i] = source[i] for all i.
        let recovered: Vec<(u8, Vec<u8>)> = missing
            .iter()
            .map(|&mi| (mi, rhs[mi as usize].clone()))
            .collect();

        self.recovered = true;
        Some(recovered)
    }
}

/// Gaussian elimination over GF(2^8). Transforms mat → I, applying same ops to rhs.
fn gauss_rhs(mat: &mut Vec<Vec<u8>>, rhs: &mut Vec<Vec<u8>>, k: usize, rhs_len: usize) -> bool {
    for col in 0..k {
        let pivot = (col..k).find(|&r| mat[r][col] != 0);
        let Some(pivot) = pivot else { return false };
        mat.swap(col, pivot);
        rhs.swap(col, pivot);

        let piv_inv = gf::inv(mat[col][col]);
        for j in 0..k {
            mat[col][j] = gf::mul(mat[col][j], piv_inv);
        }
        for j in 0..rhs_len {
            rhs[col][j] = gf::mul(rhs[col][j], piv_inv);
        }

        for r in 0..k {
            if r == col {
                continue;
            }
            let factor = mat[r][col];
            if factor == 0 {
                continue;
            }
            for j in 0..k {
                let v = gf::mul(factor, mat[col][j]);
                mat[r][j] ^= v;
            }
            let row_c = rhs[col].clone();
            gf::mul_add_slice(&mut rhs[r], &row_c, factor);
        }
    }
    true
}

pub struct FecDecoder {
    groups: HashMap<u32, GroupState>,
}

impl FecDecoder {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
        }
    }

    /// Process an incoming source packet (with FEC source envelope already stripped).
    pub fn add_source(
        &mut self,
        group_id: u32,
        source_idx: u8,
        k: u8,
        r: u8,
        data: &[u8],
    ) -> Option<Vec<(u8, Vec<u8>)>> {
        let group = self
            .groups
            .entry(group_id)
            .or_insert_with(|| GroupState::new(k, r, data.len()));

        group.padded_len = group.padded_len.max(data.len());
        let mut padded = data.to_vec();
        padded.resize(group.padded_len, 0);
        group.sources.insert(source_idx, padded);
        group.try_recover()
    }

    /// Process an incoming repair packet.
    pub fn add_repair(&mut self, repair: &FecRepairData) -> Option<Vec<(u8, Vec<u8>)>> {
        let group = self
            .groups
            .entry(repair.group_id)
            .or_insert_with(|| GroupState::new(repair.k, repair.r, repair.padded_len as usize));

        group.padded_len = group.padded_len.max(repair.padded_len as usize);
        let mut padded = repair.data.clone();
        padded.resize(group.padded_len, 0);
        group.repairs.insert(repair.repair_idx, padded);
        group.try_recover()
    }

    pub fn cleanup_group(&mut self, group_id: u32) {
        self.groups.remove(&group_id);
    }
}

impl Default for FecDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a FEC source envelope from the front of a buffer.
/// Returns (group_id, source_idx, k, r, inner_payload).
pub fn parse_source_envelope(buf: &[u8]) -> Option<(u32, u8, u8, u8, &[u8])> {
    if buf.len() < FEC_SOURCE_HDR {
        return None;
    }
    let group_id = u32::from_le_bytes(buf[0..4].try_into().ok()?);
    let source_idx = buf[4];
    let k = buf[5];
    let r = buf[6];
    Some((group_id, source_idx, k, r, &buf[FEC_SOURCE_HDR..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(seed: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
    }

    fn encode_group(k: u8, r: u8, len: usize) -> (Vec<Vec<u8>>, Vec<FecRepairData>) {
        let mut enc = FecEncoder::new(1, k, r);
        let sources: Vec<Vec<u8>> = (0..k).map(|i| payload(i * 7, len)).collect();
        let mut repairs = None;
        for src in &sources {
            repairs = enc.push_source(src);
        }
        (sources, repairs.unwrap())
    }

    #[test]
    fn test_no_loss() {
        let (_, repairs) = encode_group(4, 2, 100);
        assert_eq!(repairs.len(), 2);
    }

    #[test]
    fn test_single_loss_recovery() {
        let k = 4u8;
        let r = 2u8;
        let (sources, repairs) = encode_group(k, r, 80);
        let mut dec = FecDecoder::new();

        for (i, src) in sources.iter().enumerate() {
            if i == 2 {
                continue;
            }
            dec.add_source(1, i as u8, k, r, src);
        }
        let recovered = dec.add_repair(&repairs[0]).expect("should recover");
        assert_eq!(recovered.len(), 1);
        let (idx, data) = &recovered[0];
        assert_eq!(*idx, 2);
        assert_eq!(&data[..sources[2].len()], sources[2].as_slice());
    }

    #[test]
    fn test_double_loss_recovery() {
        let k = 6u8;
        let r = 3u8;
        let (sources, repairs) = encode_group(k, r, 64);
        let mut dec = FecDecoder::new();

        let gid = repairs[0].group_id;
        for (i, src) in sources.iter().enumerate() {
            if i == 1 || i == 4 {
                continue;
            }
            dec.add_source(gid, i as u8, k, r, src);
        }
        dec.add_repair(&repairs[0]);
        let recovered = dec.add_repair(&repairs[1]).expect("should recover");
        assert_eq!(recovered.len(), 2);
        let rec_map: HashMap<u8, Vec<u8>> = recovered.into_iter().collect();
        assert_eq!(&rec_map[&1][..sources[1].len()], sources[1].as_slice());
        assert_eq!(&rec_map[&4][..sources[4].len()], sources[4].as_slice());
    }

    #[test]
    fn test_partial_group_flush() {
        let mut enc = FecEncoder::new(0, 8, 2);
        for i in 0..3u8 {
            enc.push_source(&payload(i * 5, 50));
        }
        let repairs = enc.flush().expect("flush produces repairs");
        assert_eq!(repairs.len(), 2);
        assert_eq!(repairs[0].k, 3); // actual_k = 3
    }

    #[test]
    fn test_repair_round_trip_serialization() {
        let (_, repairs) = encode_group(4, 2, 32);
        let bytes = repairs[0].to_bytes();
        let parsed = FecRepairData::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.repair_idx, 0);
        assert_eq!(parsed.k, 4);
        assert_eq!(parsed.r, 2);
        assert_eq!(parsed.data, repairs[0].data);
    }
}
