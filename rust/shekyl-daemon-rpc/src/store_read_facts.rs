// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`ChainReadFacts`] over the chain store: a child of
//! [`store_facts`](super), so it shares the fault mapping and the tip read,
//! and holds to the same two rules — one snapshot per call, one source per
//! value.
//!
//! - The alt reads walk the alt table as the store keeps it, in LMDB's
//!   key order (the key-types gate holds the order).
//! - The tree after block `h` is the tree a block at `h + 1` is checked
//!   against: the store's `root_at(h + 1)` and `leaf_count_at(h + 1)`, the
//!   depth derived from the count (`ChainView::depth_at`, `CTW-Q4`). The
//!   tree after the tip and the tree after a named height are the same
//!   read, so `get_curve_tree_info` is `get_curve_tree_checkpoint` at the
//!   tip by construction.
//! - The emission of a range is the supply accumulator's growth across it
//!   (`coins_generated`, CEN-G12's paid reward); its fees are each listed
//!   body's `ct.fee`, read off the recorded transaction.
//! - The longhash is the substrate's, under the seed CEN-D3 names.

use shekyl_chain_rules::{seed_height, AtHeight, ChainView};
use shekyl_chain_store::store::{ReadSnapshot, SnapshotView};
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::{Ct, Transaction};

use super::{count_at, store_fault, tip_of, StoreFacts};
use crate::chain_facts::FactsFault;
use crate::read_facts::{
    AltChainFacts, ChainReadFacts, CoinbaseRange, CoinbaseSum, CurveTreeFacts, PowAt, PowSeed,
};

/// The tree after the block at `after`: the store's state at `after + 1`.
/// `None` when `after` is above the tip.
fn tree_after(
    snap: &ReadSnapshot<'_>,
    after: BlockHeight,
) -> Result<Option<CurveTreeFacts>, FactsFault> {
    let view = SnapshotView::new(snap);
    let Some(next) = after.to_raw().checked_add(1).map(BlockHeight::from_raw) else {
        return Ok(None);
    };
    let root = match view.root_at(next).map_err(store_fault)? {
        AtHeight::Recorded(root) => root,
        AtHeight::AboveTip => return Ok(None),
    };
    // The root, the count and the depth answer from one snapshot: a root
    // recorded at `next` with no count beside it is the store disagreeing
    // with itself.
    let leaf_count = match view.leaf_count_at(next).map_err(store_fault)? {
        AtHeight::Recorded(count) => count,
        AtHeight::AboveTip => return Err(FactsFault::Inconsistent),
    };
    let depth = match view.depth_at(next).map_err(store_fault)? {
        AtHeight::Recorded(depth) => depth,
        AtHeight::AboveTip => return Err(FactsFault::Inconsistent),
    };
    Ok(Some(CurveTreeFacts {
        after,
        root,
        depth,
        leaf_count,
    }))
}

/// The supply accumulator at `height`, a recorded block's.
fn coins_through(snap: &ReadSnapshot<'_>, height: BlockHeight) -> Result<u128, FactsFault> {
    match snap.block_info(height).map_err(store_fault)? {
        AtHeight::Recorded(info) => Ok(u128::from(info.coins_generated.to_raw())),
        AtHeight::AboveTip => Err(FactsFault::Inconsistent),
    }
}

/// The fees the block at `height` lists: each listed body's `ct.fee`, read
/// off the recorded pruned segment (the base carries the fee, so a pruned
/// transaction still has one). A listed hash the store cannot find is the
/// store disagreeing with itself.
fn fees_at(snap: &ReadSnapshot<'_>, height: BlockHeight) -> Result<u128, FactsFault> {
    let block = match snap.block(height).map_err(store_fault)? {
        AtHeight::Recorded(body) => body.block,
        AtHeight::AboveTip => return Err(FactsFault::Inconsistent),
    };
    let mut fees = 0u128;
    for hash in &block.transaction_hashes {
        let Some(record) = snap.tx_record(hash).map_err(store_fault)? else {
            tracing::error!(?hash, %height, "a listed transaction is not in the store");
            return Err(FactsFault::Inconsistent);
        };
        let tx = Transaction::read(&mut record.pruned.as_bytes()).map_err(|error| {
            tracing::error!(%error, ?hash, "a recorded transaction's base does not parse");
            FactsFault::Inconsistent
        })?;
        if let Ct::Fcmp { fee, .. } = tx.ct {
            fees += u128::from(fee);
        }
    }
    Ok(fees)
}

impl ChainReadFacts for StoreFacts {
    fn alt_block_hashes(&self) -> Result<Vec<BlockHash>, FactsFault> {
        let snap = self.snapshot()?;
        tip_of(&snap)?;
        Ok(snap
            .alt_blocks()
            .map_err(store_fault)?
            .into_iter()
            .map(|entry| entry.id)
            .collect())
    }

    fn alternate_chains(&self) -> Result<Vec<AltChainFacts>, FactsFault> {
        let snap = self.snapshot()?;
        tip_of(&snap)?;
        let entries = snap.alt_blocks().map_err(store_fault)?;
        let by_id: std::collections::HashMap<BlockHash, &shekyl_chain_store::codec::AltBlock> =
            entries
                .iter()
                .map(|entry| (entry.id, &entry.block))
                .collect();
        let parents: std::collections::HashSet<BlockHash> = entries
            .iter()
            .map(|entry| entry.block.block().header.previous)
            .collect();
        let mut chains = Vec::new();
        // A tip is an alt block no alt block names as its parent. Each is
        // walked down while its parent is an alt block; the first parent
        // that is not is where the chain leaves the alternatives.
        for tip in entries.iter().filter(|entry| !parents.contains(&entry.id)) {
            let mut blocks = vec![tip.id];
            let mut parent = tip.block.block().header.previous;
            while let Some(below) = by_id.get(&parent) {
                if blocks.len() > entries.len() {
                    // Longer than the table: the parent links loop, which
                    // no chain of hashes does.
                    return Err(FactsFault::Inconsistent);
                }
                blocks.push(parent);
                parent = below.block().header.previous;
            }
            chains.push(AltChainFacts {
                blocks,
                tip_height: tip.block.height(),
                cumulative_difficulty: tip.block.cumulative_difficulty().to_raw(),
                parent,
            });
        }
        Ok(chains)
    }

    fn curve_tree(&self) -> Result<CurveTreeFacts, FactsFault> {
        let snap = self.snapshot()?;
        let (tip, _) = tip_of(&snap)?;
        // The tip's own successor state is the last row connect wrote.
        tree_after(&snap, tip)?.ok_or(FactsFault::Inconsistent)
    }

    fn curve_tree_after(&self, height: BlockHeight) -> Result<Option<CurveTreeFacts>, FactsFault> {
        let snap = self.snapshot()?;
        let (tip, _) = tip_of(&snap)?;
        if height > tip {
            return Ok(None);
        }
        tree_after(&snap, height)?
            .map(Some)
            .ok_or(FactsFault::Inconsistent)
    }

    fn coinbase_sum(&self, start: BlockHeight, count: u64) -> Result<CoinbaseRange, FactsFault> {
        let snap = self.snapshot()?;
        let (tip, _) = tip_of(&snap)?;
        let chain = count_at(tip).to_raw();
        // The C++ handler's bound, as it wrote it: a start at or past the
        // count, or a count larger than the chain. A range that starts
        // inside and runs past the tip is summed through the tip, as its
        // `for_blocks_range` stopped at the table's end.
        if start.to_raw() >= chain || count > chain {
            return Ok(CoinbaseRange::TooLarge);
        }
        let Some(last) = count.checked_sub(1) else {
            return Ok(CoinbaseRange::Summed(CoinbaseSum::default()));
        };
        let end = BlockHeight::from_raw(start.to_raw().saturating_add(last).min(tip.to_raw()));
        let before = match start.to_raw().checked_sub(1) {
            Some(parent) => coins_through(&snap, BlockHeight::from_raw(parent))?,
            None => 0,
        };
        let emission = coins_through(&snap, end)?
            .checked_sub(before)
            .ok_or(FactsFault::Inconsistent)?;
        let mut fees = 0u128;
        for height in start.to_raw()..=end.to_raw() {
            fees += fees_at(&snap, BlockHeight::from_raw(height))?;
        }
        Ok(CoinbaseRange::Summed(CoinbaseSum { emission, fees }))
    }

    fn pow_hash(&self, pow_blob: &[u8], seed: PowSeed) -> Result<PowAt, FactsFault> {
        let seed = match seed {
            PowSeed::Given(seed) => seed,
            PowSeed::AtHeight(height) => match seed_height(height) {
                // Genesis admission: no block 0 yet, the null seed (CEN-D3).
                None => BlockHash::NULL,
                Some(seed_height) => {
                    let snap = self.snapshot()?;
                    let (tip, _) = tip_of(&snap)?;
                    match snap.block_info(seed_height).map_err(store_fault)? {
                        AtHeight::Recorded(info) => info.hash,
                        AtHeight::AboveTip => return Ok(PowAt::SeedAboveTip { seed_height, tip }),
                    }
                }
            },
        };
        Ok(PowAt::Hashed(self.pow.longhash(pow_blob, &seed)?))
    }
}
