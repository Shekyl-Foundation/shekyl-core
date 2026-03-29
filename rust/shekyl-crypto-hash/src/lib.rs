//! Keccak-256 hashing matching Monero/Shekyl's `cn_fast_hash`.
//!
//! Uses original Keccak padding (0x01), NOT NIST SHA3 padding (0x06).
//! This is consensus-critical: the output must be byte-identical to the
//! C implementation in `src/crypto/keccak.c`.

use tiny_keccak::{Hasher, Keccak};

pub const HASH_SIZE: usize = 32;

pub type Hash = [u8; HASH_SIZE];

/// Compute `cn_fast_hash` -- Keccak-256 with original padding.
///
/// This matches `cn_fast_hash` in `src/crypto/hash.c` which calls
/// `keccak1600` (full 200-byte state absorb) then takes the first 32 bytes.
/// For 32-byte output the rate is 136 bytes (1600 - 2*256 = 1088 bits).
pub fn cn_fast_hash(data: &[u8]) -> Hash {
    let mut keccak = Keccak::v256();
    keccak.update(data);
    let mut out = [0u8; HASH_SIZE];
    keccak.finalize(&mut out);
    out
}

/// Compute Merkle tree hash from a list of 32-byte hashes.
///
/// Matches `tree_hash` in `src/crypto/tree-hash.c`.
pub fn tree_hash(hashes: &[Hash]) -> Hash {
    match hashes.len() {
        0 => [0u8; HASH_SIZE],
        1 => hashes[0],
        2 => {
            let mut buf = [0u8; 2 * HASH_SIZE];
            buf[..HASH_SIZE].copy_from_slice(&hashes[0]);
            buf[HASH_SIZE..].copy_from_slice(&hashes[1]);
            cn_fast_hash(&buf)
        }
        count => {
            let mut cnt = 1usize;
            while cnt * 2 < count {
                cnt *= 2;
            }

            let mut ints = vec![[0u8; HASH_SIZE]; cnt];
            for (dst, src) in ints.iter_mut().zip(hashes[..cnt].iter()) {
                *dst = *src;
            }

            let mut j = cnt;
            while j < count {
                let mut buf = [0u8; 2 * HASH_SIZE];
                buf[..HASH_SIZE].copy_from_slice(&ints[j - cnt]);
                buf[HASH_SIZE..].copy_from_slice(&hashes[j]);
                ints[j - cnt] = cn_fast_hash(&buf);
                j += 1;
            }

            while cnt > 2 {
                cnt /= 2;
                let mut i = 0;
                while i < cnt {
                    let mut buf = [0u8; 2 * HASH_SIZE];
                    buf[..HASH_SIZE].copy_from_slice(&ints[2 * i]);
                    buf[HASH_SIZE..].copy_from_slice(&ints[2 * i + 1]);
                    ints[i] = cn_fast_hash(&buf);
                    i += 1;
                }
            }

            let mut buf = [0u8; 2 * HASH_SIZE];
            buf[..HASH_SIZE].copy_from_slice(&ints[0]);
            buf[HASH_SIZE..].copy_from_slice(&ints[1]);
            cn_fast_hash(&buf)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hash() {
        let h = cn_fast_hash(&[]);
        // Known Keccak-256 of empty input (original padding, NOT SHA3)
        let expected = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
            0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
            0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
            0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
        ];
        assert_eq!(h, expected, "cn_fast_hash of empty input must match Keccak-256");
    }

    #[test]
    fn known_hash() {
        let h = cn_fast_hash(b"Shekyl");
        assert_eq!(h.len(), HASH_SIZE);
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn tree_hash_single() {
        let h = [0xABu8; HASH_SIZE];
        assert_eq!(tree_hash(&[h]), h);
    }

    #[test]
    fn tree_hash_two() {
        let a = cn_fast_hash(b"a");
        let b = cn_fast_hash(b"b");
        let root = tree_hash(&[a, b]);
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&a);
        combined[32..].copy_from_slice(&b);
        assert_eq!(root, cn_fast_hash(&combined));
    }
}
