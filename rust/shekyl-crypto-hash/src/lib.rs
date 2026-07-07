//! Keccak-256 hashing for Shekyl's `cn_fast_hash` primitive.
//!
//! Backed by the audited RustCrypto `sha3` crate (`Keccak256`) — original Keccak
//! padding (0x01), NOT NIST SHA3 padding (0x06). This is consensus-critical: the
//! output must be byte-identical to the C `src/crypto/keccak.c` (the empty-input KAT
//! in `tests` pins exactly that). The byte-identity, not the implementation crate, is
//! what is genesis-locked — `sha3` and the prior `tiny-keccak` both compute the same
//! original-Keccak-256, and standardizing on the RustCrypto crate collapses the
//! codebase onto one audited keccak (shekyl-oxide already uses `sha3`).
//!
//! The `cn_fast_hash` *name* is the inherited CryptoNote consensus-primitive name
//! ("cn" = CryptoNote; the *fast* hash vs. the slow PoW hash), kept for 1:1 source
//! mapping to the C++ daemon; a rule-93 rename to `keccak256` is a tracked follow-up
//! (see `60-no-monero-legacy.mdc`).

#![deny(unsafe_code)]

use sha3::{Digest, Keccak256};

pub const HASH_SIZE: usize = 32;

pub type Hash = [u8; HASH_SIZE];

/// Compute `cn_fast_hash` — Keccak-256 with original padding, via RustCrypto `sha3`.
///
/// Matches `cn_fast_hash` in `src/crypto/hash.c` (keccak1600 absorb, first 32 bytes;
/// rate 136 bytes for 256-bit output). `sha3::Keccak256` is the original Keccak
/// variant (0x01 padding), so this is byte-identical to the prior tiny-keccak impl and
/// to the C++ daemon — verified by the empty-input KAT below and the live coinbase/
/// spend hash KATs in shekyl-wire.
pub fn cn_fast_hash(data: &[u8]) -> Hash {
    Keccak256::digest(data).into()
}

/// Compute `tree_hash_cnt`: largest power of 2 strictly less than count.
/// Equivalent to `tree_hash_cnt` in `src/crypto/tree-hash.c`.
fn tree_hash_cnt(count: usize) -> usize {
    debug_assert!(count >= 3);
    let mut pow = 2usize;
    while pow < count {
        pow <<= 1;
    }
    pow >> 1
}

/// Compute Merkle tree hash from a list of 32-byte hashes.
///
/// Matches `tree_hash` in `src/crypto/tree-hash.c` exactly.
pub fn tree_hash(hashes: &[Hash]) -> Hash {
    let count = hashes.len();
    match count {
        0 => [0u8; HASH_SIZE],
        1 => hashes[0],
        2 => {
            let mut buf = [0u8; 2 * HASH_SIZE];
            buf[..HASH_SIZE].copy_from_slice(&hashes[0]);
            buf[HASH_SIZE..].copy_from_slice(&hashes[1]);
            cn_fast_hash(&buf)
        }
        _ => {
            let mut cnt = tree_hash_cnt(count);
            let mut ints = vec![[0u8; HASH_SIZE]; cnt];

            let skip = 2 * cnt - count;
            ints[..skip].copy_from_slice(&hashes[..skip]);

            let mut i = skip;
            let mut j = skip;
            while j < cnt {
                let mut buf = [0u8; 2 * HASH_SIZE];
                buf[..HASH_SIZE].copy_from_slice(&hashes[i]);
                buf[HASH_SIZE..].copy_from_slice(&hashes[i + 1]);
                ints[j] = cn_fast_hash(&buf);
                i += 2;
                j += 1;
            }
            debug_assert_eq!(i, count);

            while cnt > 2 {
                cnt >>= 1;
                for k in 0..cnt {
                    let mut buf = [0u8; 2 * HASH_SIZE];
                    buf[..HASH_SIZE].copy_from_slice(&ints[2 * k]);
                    buf[HASH_SIZE..].copy_from_slice(&ints[2 * k + 1]);
                    ints[k] = cn_fast_hash(&buf);
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
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];
        assert_eq!(
            h, expected,
            "cn_fast_hash of empty input must match Keccak-256"
        );
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
