// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Consensus hash identities (GENESIS_TX_WIRE_FORMAT.md §11).
//!
//! All hashing is `cn_fast_hash` (keccak-256, original 0x01 padding) via
//! [`shekyl_crypto_hash::cn_fast_hash`] — byte-identical to the C++
//! `cn_fast_hash`. This module owns the cross-cutting [`merkle_root`]; the
//! per-object tx/block hashes live on [`crate::Transaction`] / [`crate::Block`].

use shekyl_crypto_hash::cn_fast_hash;

/// `cn_fast_hash` over the concatenation of fixed 32-byte component hashes —
/// the multi-part tx-hash combiner (§11).
pub(crate) fn hash_concat(parts: &[[u8; 32]]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(parts.len() * 32);
    for part in parts {
        buf.extend_from_slice(part);
    }
    cn_fast_hash(&buf)
}

/// `cn_fast_hash(a ‖ b)` — the pairing step of the Merkle tree-hash.
fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    cn_fast_hash(&buf)
}

/// Monero `tree_hash` over a block's transaction hashes (`tree-hash.c`).
///
/// `None` for an empty tree. One leaf hashes to itself; two pair directly;
/// otherwise the rightmost leaves are paired down to the largest power of two
/// `≤ len`, then paired off to the root.
pub(crate) fn merkle_root(mut leaves: Vec<[u8; 32]>) -> Option<[u8; 32]> {
    match leaves.len() {
        0 => None,
        1 => Some(leaves[0]),
        2 => Some(hash_pair(&leaves[0], &leaves[1])),
        n => {
            let mut high = 4usize;
            while high < n {
                high <<= 1;
            }
            let low = high / 2;
            let overage = n - low;
            // Pair off the rightmost `2 * overage` leaves, leaving exactly `low`
            // (a power of two).
            let tail = leaves.split_off(low - overage);
            for pair in tail.chunks(2) {
                leaves.push(hash_pair(&pair[0], &pair[1]));
            }
            debug_assert_eq!(leaves.len(), low);
            while leaves.len() > 1 {
                let mut next = Vec::with_capacity(leaves.len() / 2);
                for pair in leaves.chunks(2) {
                    next.push(hash_pair(&pair[0], &pair[1]));
                }
                leaves = next;
            }
            Some(leaves[0])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_is_itself() {
        assert_eq!(merkle_root(vec![[7u8; 32]]), Some([7u8; 32]));
    }

    #[test]
    fn two_leaves_pair() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(merkle_root(vec![a, b]), Some(hash_pair(&a, &b)));
    }

    #[test]
    fn empty_is_none() {
        assert_eq!(merkle_root(vec![]), None);
    }
}
