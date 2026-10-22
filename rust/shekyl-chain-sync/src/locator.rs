// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A sparse locator, newest first: the 10 newest hashes, then a
//! doubling step, then genesis. At most the wire's locator cap
//! (CS-Q2 step 2).

use shekyl_levin::BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT;
use shekyl_types::BlockHash;

const DENSE: usize = 10;

/// `newest_first` is the chain the request extends, tip at index 0.
/// An empty chain locates the null hash, so a peer can answer with
/// genesis (its parent is null).
pub(crate) fn locator(newest_first: &[BlockHash]) -> Vec<[u8; 32]> {
    let cap = usize::try_from(BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT).unwrap_or(usize::MAX);
    if newest_first.is_empty() {
        return vec![bytes(BlockHash::NULL)];
    }
    let mut out = Vec::new();
    let dense = DENSE.min(newest_first.len());
    for hash in &newest_first[..dense] {
        out.push(bytes(*hash));
    }
    let mut step = 2usize;
    let mut index = dense;
    while index < newest_first.len() && out.len() + 1 < cap {
        out.push(bytes(newest_first[index]));
        index = index.saturating_add(step);
        step = step.saturating_mul(2);
    }
    let genesis = bytes(*newest_first.last().expect("the chain is not empty"));
    if out.last() != Some(&genesis) && out.len() < cap {
        out.push(genesis);
    }
    out
}

fn bytes(hash: BlockHash) -> [u8; 32] {
    *hash.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> BlockHash {
        BlockHash::from_bytes([byte; 32])
    }

    #[test]
    fn a_short_chain_is_the_whole_chain_newest_first() {
        let chain = [hash(3), hash(2), hash(1)];
        let ids = locator(&chain);
        assert_eq!(ids.len(), 3);
        assert_eq!(ids[0], bytes(hash(3)));
        assert_eq!(ids[2], bytes(hash(1)));
    }

    #[test]
    fn an_empty_chain_locates_the_null_hash() {
        let ids = locator(&[]);
        assert_eq!(ids, vec![bytes(BlockHash::NULL)]);
    }

    #[test]
    fn past_the_dense_prefix_the_step_doubles_and_genesis_is_last() {
        let chain: Vec<BlockHash> = (0..20).rev().map(hash).collect();
        let ids = locator(&chain);
        // 10 newest, then index 10, 12, 16 — and genesis, which the
        // doubling has not reached.
        assert_eq!(ids.len(), 14);
        assert_eq!(ids[0], bytes(hash(19)));
        assert_eq!(ids[9], bytes(hash(10)));
        assert_eq!(ids[10], bytes(hash(9)));
        assert_eq!(ids[11], bytes(hash(7)));
        assert_eq!(ids[12], bytes(hash(3)));
        assert_eq!(*ids.last().expect("genesis"), bytes(hash(0)));
    }
}
