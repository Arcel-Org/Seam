/// GF(2^8) arithmetic using primitive polynomial x^8 + x^4 + x^3 + x^2 + 1.
///
/// EXP/LOG tables give O(1) multiply/divide. Tables are computed at compile time.
const POLY: u16 = 0x11d;

const fn build_tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0usize;
    while i < 255 {
        exp[i] = x as u8;
        exp[i + 255] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= POLY;
        }
        i += 1;
    }
    exp[255] = 1;
    exp[510] = 1;
    (exp, log)
}

const TABLES: ([u8; 512], [u8; 256]) = build_tables();
const EXP: &[u8; 512] = &TABLES.0;
const LOG: &[u8; 256] = &TABLES.1;

#[inline(always)]
pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

#[inline(always)]
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let log_sum = LOG[a as usize] as usize + LOG[b as usize] as usize;
    EXP[log_sum]
}

#[inline(always)]
pub fn div(a: u8, b: u8) -> u8 {
    debug_assert!(b != 0, "GF division by zero");
    if a == 0 {
        return 0;
    }
    let log_diff = LOG[a as usize] as usize + 255 - LOG[b as usize] as usize;
    EXP[log_diff]
}

#[inline(always)]
pub fn inv(a: u8) -> u8 {
    debug_assert!(a != 0, "GF inverse of zero");
    EXP[255 - LOG[a as usize] as usize]
}

/// Multiply a byte slice by a scalar in-place: dst[i] ^= scalar * src[i].
///
/// 8x loop unrolling cuts loop overhead by ~7x on long slices.
/// The compiler typically auto-vectorizes the XOR loop for scalar=1.
pub fn mul_add_slice(dst: &mut [u8], src: &[u8], scalar: u8) {
    debug_assert_eq!(dst.len(), src.len());
    if scalar == 0 {
        return;
    }

    let len = dst.len();
    let chunks = len / 8;
    let rem = len % 8;

    if scalar == 1 {
        // Hot path: pure XOR — compiler can auto-vectorize this
        for i in 0..chunks {
            let b = i * 8;
            dst[b] ^= src[b];
            dst[b + 1] ^= src[b + 1];
            dst[b + 2] ^= src[b + 2];
            dst[b + 3] ^= src[b + 3];
            dst[b + 4] ^= src[b + 4];
            dst[b + 5] ^= src[b + 5];
            dst[b + 6] ^= src[b + 6];
            dst[b + 7] ^= src[b + 7];
        }
        let base = chunks * 8;
        for i in 0..rem {
            dst[base + i] ^= src[base + i];
        }
        return;
    }

    // General path: GF multiply then XOR
    let log_s = LOG[scalar as usize] as usize;
    for i in 0..chunks {
        let b = i * 8;
        dst[b] ^= if src[b] != 0 {
            EXP[log_s + LOG[src[b] as usize] as usize]
        } else {
            0
        };
        dst[b + 1] ^= if src[b + 1] != 0 {
            EXP[log_s + LOG[src[b + 1] as usize] as usize]
        } else {
            0
        };
        dst[b + 2] ^= if src[b + 2] != 0 {
            EXP[log_s + LOG[src[b + 2] as usize] as usize]
        } else {
            0
        };
        dst[b + 3] ^= if src[b + 3] != 0 {
            EXP[log_s + LOG[src[b + 3] as usize] as usize]
        } else {
            0
        };
        dst[b + 4] ^= if src[b + 4] != 0 {
            EXP[log_s + LOG[src[b + 4] as usize] as usize]
        } else {
            0
        };
        dst[b + 5] ^= if src[b + 5] != 0 {
            EXP[log_s + LOG[src[b + 5] as usize] as usize]
        } else {
            0
        };
        dst[b + 6] ^= if src[b + 6] != 0 {
            EXP[log_s + LOG[src[b + 6] as usize] as usize]
        } else {
            0
        };
        dst[b + 7] ^= if src[b + 7] != 0 {
            EXP[log_s + LOG[src[b + 7] as usize] as usize]
        } else {
            0
        };
    }
    let base = chunks * 8;
    for i in 0..rem {
        let s = src[base + i];
        dst[base + i] ^= if s != 0 {
            EXP[log_s + LOG[s as usize] as usize]
        } else {
            0
        };
    }
}

/// Invert a k×k matrix over GF(2^8) in place (Gaussian elimination).
/// Returns false if the matrix is singular.
pub fn invert_matrix(mat: &mut [Vec<u8>], k: usize) -> bool {
    // Augment with identity
    let mut aug: Vec<Vec<u8>> = (0..k)
        .map(|i| {
            let mut row = mat[i].clone();
            row.resize(2 * k, 0);
            row[k + i] = 1;
            row
        })
        .collect();

    for col in 0..k {
        // Find pivot
        let pivot = (col..k).find(|&r| aug[r][col] != 0);
        let Some(pivot) = pivot else { return false };
        aug.swap(col, pivot);

        let pivot_inv = inv(aug[col][col]);
        // Scale pivot row
        for v in aug[col].iter_mut() {
            *v = mul(*v, pivot_inv);
        }
        // Eliminate column
        for r in 0..k {
            if r == col {
                continue;
            }
            let factor = aug[r][col];
            if factor == 0 {
                continue;
            }
            let pivot_row = aug[col].clone();
            for (dst, &src) in aug[r].iter_mut().zip(pivot_row.iter()) {
                *dst ^= mul(factor, src);
            }
        }
    }

    for i in 0..k {
        mat[i] = aug[i][k..].to_vec();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mul_inverse() {
        for a in 1u8..=255 {
            assert_eq!(mul(a, inv(a)), 1, "a={a}");
        }
    }

    #[test]
    fn test_mul_commutative() {
        assert_eq!(mul(3, 7), mul(7, 3));
    }

    #[test]
    fn test_identity() {
        for a in 0u8..=255 {
            assert_eq!(mul(a, 1), a);
            assert_eq!(add(a, a), 0); // characteristic 2
        }
    }
}
