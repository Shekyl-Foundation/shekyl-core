// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A sparse locator, newest first: the 10 newest hashes, then a
//! doubling step, then genesis. At most the wire's locator cap
//! (CS-Q2 step 2). The chain is named by height. Only those heights
//! are read.

use shekyl_levin::BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT;
use shekyl_types::{BlockCount, BlockHash, BlockHeight, ChainCount};

const DENSE: u64 = 10;

/// `count` is the block count of the chain the request extends (`H*`).
/// `at` answers one height. An empty chain locates the null hash and
/// does not call `at`, so a peer can answer with genesis.
pub(crate) fn locator<E>(
    count: ChainCount,
    mut at: impl FnMut(BlockHeight) -> Result<Option<BlockHash>, E>,
) -> Result<Vec<[u8; 32]>, E> {
    let Some(tip) = count.tip() else {
        return Ok(vec![bytes(BlockHash::NULL)]);
    };
    let cap = usize::try_from(BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT).unwrap_or(usize::MAX);
    let mut out = Vec::new();
    let mut saw_genesis = false;
    let mut push = |height: BlockHeight, out: &mut Vec<[u8; 32]>| -> Result<(), E> {
        if height.is_zero() {
            saw_genesis = true;
        }
        if let Some(hash) = at(height)? {
            out.push(bytes(hash));
        }
        Ok(())
    };
    let dense = DENSE.min(count.to_raw());
    for index in 0..dense {
        let Some(height) = tip.checked_sub_count(BlockCount::from_raw(index)) else {
            break;
        };
        push(height, &mut out)?;
    }
    let mut step = 2u64;
    let mut index = dense;
    let last = tip.to_raw();
    while index < last && out.len() + 1 < cap {
        let Some(height) = tip.checked_sub_count(BlockCount::from_raw(index)) else {
            break;
        };
        push(height, &mut out)?;
        index = index.saturating_add(step);
        step = step.saturating_mul(2);
    }
    if !saw_genesis && out.len() < cap {
        if let Some(hash) = at(BlockHeight::ZERO)? {
            let encoded = bytes(hash);
            if out.last() != Some(&encoded) {
                out.push(encoded);
            }
        }
    }
    Ok(out)
}

fn bytes(hash: BlockHash) -> [u8; 32] {
    *hash.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_at(height: BlockHeight) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&height.to_raw().to_le_bytes());
        BlockHash::from_bytes(bytes)
    }

    fn asked(count: u64) -> Vec<BlockHeight> {
        let mut asked = Vec::new();
        locator(ChainCount::from_raw(count), |height| {
            asked.push(height);
            Ok::<_, ()>(Some(hash_at(height)))
        })
        .expect("the accessor answers");
        asked
    }

    #[test]
    fn a_short_chain_is_the_whole_chain_newest_first() {
        let mut asked = Vec::new();
        let ids = locator(ChainCount::from_raw(3), |height| {
            asked.push(height);
            Ok::<_, ()>(Some(hash_at(height)))
        })
        .expect("answers");
        assert_eq!(
            asked,
            vec![
                BlockHeight::from_raw(2),
                BlockHeight::from_raw(1),
                BlockHeight::from_raw(0),
            ]
        );
        assert_eq!(ids[0], bytes(hash_at(BlockHeight::from_raw(2))));
        assert_eq!(
            *ids.last().expect("genesis"),
            bytes(hash_at(BlockHeight::ZERO))
        );
    }

    #[test]
    fn an_empty_chain_locates_the_null_hash_without_a_read() {
        let mut reads = 0u32;
        let ids = locator(ChainCount::ZERO, |_| {
            reads += 1;
            Ok::<_, ()>(None)
        })
        .expect("no read");
        assert_eq!(reads, 0);
        assert_eq!(ids, vec![bytes(BlockHash::NULL)]);
    }

    #[test]
    fn past_the_dense_prefix_only_the_doubling_heights_are_read() {
        let asked = asked(20);
        let heights: Vec<u64> = asked.iter().map(|h| h.to_raw()).collect();
        // 19..10, then 9, 7, 3, then genesis 0. Not the heights in between.
        assert_eq!(
            heights,
            vec![19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 7, 3, 0]
        );
    }

    #[test]
    fn a_long_chain_is_read_at_logarithmic_heights() {
        let asked = asked(1_024);
        let reads = asked.len();
        assert!(reads < 40, "reads {reads}, the chain is 1024");
        assert!(reads < 1_024 / 10);
    }
}
