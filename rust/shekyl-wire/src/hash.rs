// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Consensus hash identities (GENESIS_TX_WIRE_FORMAT.md §11).
//!
//! All hashing is original-padding Keccak-256 (`0x01`, NOT SHA3-256's `0x06`) via
//! [`shekyl_crypto_hash::keccak256`] — byte-identical to the C++ daemon's
//! `cn_fast_hash` (the C++ symbol keeps the CryptoNote name). This module owns
//! the cross-cutting [`merkle_root`]; the
//! per-object tx/block hashes live on [`crate::Transaction`] / [`crate::Block`].

use shekyl_crypto_hash::keccak256;

/// `keccak256` over the concatenation of fixed 32-byte component hashes —
/// the multi-part tx-hash combiner (§11).
pub(crate) fn hash_concat(parts: &[[u8; 32]]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(parts.len() * 32);
    for part in parts {
        buf.extend_from_slice(part);
    }
    keccak256(&buf)
}

/// `keccak256(a ‖ b)` — the pairing step of the Merkle tree-hash.
fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(a);
    buf[32..].copy_from_slice(b);
    keccak256(&buf)
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

    /// The 16 tree-hash vectors of the inherited hash suite's
    /// `tests-tree.txt`, copied byte for byte: the expected
    /// root, then the leaves as one hex string of 32-byte hashes. They are
    /// the only vectors for the odd sizes, where the rightmost leaves pair
    /// down to a power of two before the rest; the block header's
    /// transaction tree hash is this function.
    #[test]
    fn merkle_root_matches_every_tree_vector() {
        const VECTORS: &str = include_str!("../tests/vectors/tx_tree_hash.txt");
        let unhex = |text: &str| -> Vec<u8> {
            assert!(text.len() % 2 == 0, "odd-length hex: {text}");
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
                .collect()
        };
        let mut sizes = Vec::new();
        for (line_no, line) in VECTORS.lines().enumerate() {
            let mut fields = line.split_whitespace();
            let (Some(expected), Some(leaves), None) =
                (fields.next(), fields.next(), fields.next())
            else {
                panic!("line {}: not `<root> <leaves>`: {line:?}", line_no + 1);
            };
            let bytes = unhex(leaves);
            assert!(bytes.len() % 32 == 0, "line {}: leaves", line_no + 1);
            let leaves: Vec<[u8; 32]> = bytes
                .chunks(32)
                .map(|c| c.try_into().expect("32 bytes"))
                .collect();
            sizes.push(leaves.len());
            let root = merkle_root(leaves).expect("a vector has a leaf");
            assert_eq!(
                root.to_vec(),
                unhex(expected),
                "line {}: {} leaves",
                line_no + 1,
                sizes[sizes.len() - 1]
            );
        }
        // The subject (rule 47): every size from 1 to 16 leaves, so each
        // odd size and each power-of-two boundary is in the file.
        sizes.sort_unstable();
        assert_eq!(sizes, (1..=16).collect::<Vec<_>>(), "the leaf counts");
    }
}
