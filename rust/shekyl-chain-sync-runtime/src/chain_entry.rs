// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The sync reads the C++ protocol handler still asks for.
//!
//! Chain sync's cutover (CS-5) deletes that caller and the `shekyl_core_*`
//! exports that marshal these functions. The reads stay here, beside
//! [`serve`](crate::serve), which answers 2011 and 2013 and is the
//! responder that replaces this path. This module does not grow a second
//! responder.
//!
//! [`short_history`] is the model's [`locator`](shekyl_chain_sync::locator)
//! over one snapshot. An empty chain locates the null hash and does not
//! read: [`serve`](crate::serve)'s fork walk starts that locator at
//! genesis. [`supplement`] is the 2007 chain entry: the first locator
//! hash this chain holds, then at most
//! [`BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT`](shekyl_levin::BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT)
//! blocks including that one, and the tip's cumulative difficulty.
//!
//! A transaction a peer asks for is not read here. Whether it is shown
//! is the pool's (`shekyl_mempool::resolve_shown`); the marshaller holds
//! one snapshot across that read.

use shekyl_chain_rules::AtHeight;
use shekyl_chain_store::codec::AltBlock;
use shekyl_chain_store::store::{ChainStore, ReadSnapshot, StoreError};
use shekyl_chain_sync::locator;
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_levin::BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT;
use shekyl_types::{BlockCount, BlockHash, BlockHeight, BlockWeight, ChainCount};

/// Why a sync read failed. A store fault passes through. The other two
/// are a chain the count cannot name, and a height the count includes
/// that has no row.
#[derive(Debug)]
pub enum EntryFault {
    /// The store could not be read.
    Store(StoreError),
    /// The recorded tip is the last `BlockHeight`: no chain count names it.
    Uncountable,
    /// `height` is inside the chain count and the snapshot has no row there.
    Gap {
        /// The height that was missing.
        height: BlockHeight,
    },
}

impl From<StoreError> for EntryFault {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// One main-chain block a chain entry carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MainBlock {
    /// The block's identity.
    pub hash: BlockHash,
    /// The block's weight.
    pub weight: BlockWeight,
    /// Cumulative difficulty at this block.
    pub cumulative_difficulty: CumulativeDifficulty,
}

/// A chain entry: the blocks from the split, inclusive, up to the
/// chain-entry limit, and the tip's cumulative difficulty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainSupplement {
    /// Hashes and weights from the split, lowest height first.
    pub blocks: Vec<MainBlock>,
    /// The first shared block.
    pub start: BlockHeight,
    /// The chain's block count.
    pub chain_count: ChainCount,
    /// The tip's cumulative difficulty, whether or not the window reaches it.
    pub tip_cumulative_difficulty: CumulativeDifficulty,
}

/// Where a block sits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockPlace {
    /// On the main chain.
    Main,
    /// Held as an alternative, not on the main chain.
    Alternative,
    /// Not held.
    Absent,
}

/// A block the chain holds, main or alternative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldBlock {
    /// Wire bytes.
    pub wire: Vec<u8>,
    /// Attestation witness. Empty when the block stored none.
    pub witness: Vec<u8>,
    /// An alternative block. A main-chain block is `false`.
    pub alternative: bool,
    /// The block's weight.
    pub weight: BlockWeight,
}

/// The chain's block count. An empty chain is [`ChainCount::ZERO`].
///
/// # Errors
///
/// A store fault, or a tip no chain count can name.
pub fn chain_count(store: &ChainStore) -> Result<ChainCount, EntryFault> {
    let snap = store.begin_read()?;
    chain_count_on(&snap)
}

/// The top block. `None` is an empty chain.
///
/// # Errors
///
/// A store fault, a tip no chain count can name, or a tip the snapshot
/// does not hold.
pub fn chain_top(store: &ChainStore) -> Result<Option<(BlockHeight, BlockHash)>, EntryFault> {
    let snap = store.begin_read()?;
    let count = chain_count_on(&snap)?;
    let Some(height) = count.tip() else {
        return Ok(None);
    };
    let row = require_row(&snap, height)?;
    Ok(Some((height, row.hash)))
}

/// The hash at `height`. `None` is above the tip.
///
/// # Errors
///
/// A store fault.
pub fn hash_at(store: &ChainStore, height: BlockHeight) -> Result<Option<BlockHash>, EntryFault> {
    let snap = store.begin_read()?;
    Ok(row_at(&snap, height)?.map(|row| row.hash))
}

/// Where `id` sits.
///
/// # Errors
///
/// A store fault.
pub fn block_place(store: &ChainStore, id: &BlockHash) -> Result<BlockPlace, EntryFault> {
    let snap = store.begin_read()?;
    if snap.height_of(id)?.is_some() {
        return Ok(BlockPlace::Main);
    }
    if snap.has_alt_block(id)? {
        return Ok(BlockPlace::Alternative);
    }
    Ok(BlockPlace::Absent)
}

/// Cumulative difficulty at `height`. `None` is above the tip.
///
/// # Errors
///
/// A store fault.
pub fn cumulative_difficulty_at(
    store: &ChainStore,
    height: BlockHeight,
) -> Result<Option<CumulativeDifficulty>, EntryFault> {
    let snap = store.begin_read()?;
    Ok(row_at(&snap, height)?.map(|row| row.cumulative_difficulty))
}

/// The short chain history, tip first, and the chain's block count.
///
/// An empty chain is the null hash alone and reads nothing. A height the
/// count includes and the snapshot does not hold fails the read: a hole
/// is not a hash the locator skips.
///
/// # Errors
///
/// A store fault, a tip no chain count can name, or a hole on a height
/// the locator names.
pub fn short_history(store: &ChainStore) -> Result<(ChainCount, Vec<[u8; 32]>), EntryFault> {
    let snap = store.begin_read()?;
    let count = chain_count_on(&snap)?;
    let ids = locator(count, |height| {
        require_row(&snap, height).map(|row| Some(row.hash))
    })?;
    Ok((count, ids))
}

/// The chain entry for `locator_ids` (newest first, genesis last).
///
/// `None` when the locator is empty, the chain is empty, the locator's
/// last hash is not this chain's genesis, or no locator hash is on the
/// main chain. The window starts at the first hash that is, includes
/// that block, and stops at
/// [`BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT`](shekyl_levin::BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT)
/// blocks or the tip, whichever comes first. The difficulty is the tip's.
///
/// # Errors
///
/// A store fault, or a hole inside the window or at the tip.
pub fn supplement(
    store: &ChainStore,
    locator_ids: &[BlockHash],
) -> Result<Option<ChainSupplement>, EntryFault> {
    let snap = store.begin_read()?;
    let count = chain_count_on(&snap)?;
    supplement_span(
        count,
        locator_ids,
        |hash| Ok(snap.height_of(hash)?),
        |height| row_at(&snap, height).map_err(EntryFault::from),
    )
}

/// A block the chain holds. `None` when it holds neither a main-chain
/// block nor an alternative. The witness is the block's own: an
/// alternative's witness is not read off the main chain.
///
/// # Errors
///
/// A store fault, or a main-chain height whose info or blob row is missing.
pub fn held_block(store: &ChainStore, id: &BlockHash) -> Result<Option<HeldBlock>, EntryFault> {
    let snap = store.begin_read()?;
    if let Some(height) = snap.height_of(id)? {
        let wire = match snap.block_blob(height)? {
            AtHeight::Recorded(raw) => raw.into_wire_bytes(),
            AtHeight::AboveTip => return Err(EntryFault::Gap { height }),
        };
        let witness = match snap.attestation_witness_at(height)? {
            AtHeight::Recorded(Some(bytes)) => bytes,
            AtHeight::Recorded(None) | AtHeight::AboveTip => Vec::new(),
        };
        let row = require_row(&snap, height)?;
        return Ok(Some(HeldBlock {
            wire,
            witness,
            alternative: false,
            weight: row.weight,
        }));
    }
    let Some(alt) = snap.alt_block(id)? else {
        return Ok(None);
    };
    Ok(Some(held_alt(&alt)))
}

fn held_alt(alt: &AltBlock) -> HeldBlock {
    HeldBlock {
        wire: alt.block().serialize(),
        witness: alt.attestation_witness().unwrap_or(&[]).to_vec(),
        alternative: true,
        weight: alt.block_weight(),
    }
}

fn chain_count_on(snap: &ReadSnapshot<'_>) -> Result<ChainCount, EntryFault> {
    match snap.tip()?.recorded {
        None => Ok(ChainCount::ZERO),
        Some(tip) => ChainCount::with_tip(tip.height).ok_or(EntryFault::Uncountable),
    }
}

fn row_at(snap: &ReadSnapshot<'_>, height: BlockHeight) -> Result<Option<MainBlock>, StoreError> {
    match snap.block_info(height)? {
        AtHeight::Recorded(info) => Ok(Some(MainBlock {
            hash: info.hash,
            weight: info.weight,
            cumulative_difficulty: info.cumulative_difficulty,
        })),
        AtHeight::AboveTip => Ok(None),
    }
}

fn require_row(snap: &ReadSnapshot<'_>, height: BlockHeight) -> Result<MainBlock, EntryFault> {
    row_at(snap, height)?.ok_or(EntryFault::Gap { height })
}

/// How many blocks a chain entry carries from `start` on a chain of
/// `count`: the blocks still ahead, capped at the chain-entry limit.
fn window_len(count: ChainCount, start: BlockHeight) -> u64 {
    count
        .to_raw()
        .saturating_sub(start.to_raw())
        .min(BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT)
}

/// The chain entry, apart from the store. `height_of` is the main-chain
/// height of a hash (`None` when the main chain does not hold it). `at`
/// is the block at a height (`None` above the tip).
fn supplement_span<E>(
    count: ChainCount,
    locator_ids: &[BlockHash],
    mut height_of: impl FnMut(&BlockHash) -> Result<Option<BlockHeight>, E>,
    mut at: impl FnMut(BlockHeight) -> Result<Option<MainBlock>, E>,
) -> Result<Option<ChainSupplement>, E>
where
    E: From<EntryFault>,
{
    if count == ChainCount::ZERO || locator_ids.is_empty() {
        return Ok(None);
    }
    let Some(genesis) = at(BlockHeight::ZERO)? else {
        return Err(EntryFault::Gap {
            height: BlockHeight::ZERO,
        }
        .into());
    };
    match locator_ids.last() {
        Some(last) if *last == genesis.hash => {}
        _ => return Ok(None),
    }
    let mut start = None;
    for hash in locator_ids {
        if let Some(height) = height_of(hash)? {
            if !count.has_block(height) {
                return Err(EntryFault::Gap { height }.into());
            }
            start = Some(height);
            break;
        }
    }
    let Some(start) = start else {
        return Ok(None);
    };
    let span = window_len(count, start);
    let mut blocks = Vec::with_capacity(usize::try_from(span).unwrap_or(0));
    for offset in 0..span {
        let Some(height) = start.checked_add(BlockCount::from_raw(offset)) else {
            return Err(EntryFault::Uncountable.into());
        };
        let Some(row) = at(height)? else {
            return Err(EntryFault::Gap { height }.into());
        };
        blocks.push(row);
    }
    let Some(tip) = count.tip() else {
        return Ok(None);
    };
    let Some(tip_row) = at(tip)? else {
        return Err(EntryFault::Gap { height: tip }.into());
    };
    Ok(Some(ChainSupplement {
        blocks,
        start,
        chain_count: count,
        tip_cumulative_difficulty: tip_row.cumulative_difficulty,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_of(height: u64) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&height.to_le_bytes());
        BlockHash::from_bytes(bytes)
    }

    fn row(height: u64) -> MainBlock {
        MainBlock {
            hash: hash_of(height),
            weight: BlockWeight::from_raw(1_000 + height),
            cumulative_difficulty: CumulativeDifficulty::from_raw(u128::from(height) + 1),
        }
    }

    fn table(count: u64) -> Vec<MainBlock> {
        (0..count).map(row).collect()
    }

    fn answer(
        rows: &[MainBlock],
        locator_ids: &[BlockHash],
    ) -> Result<Option<ChainSupplement>, EntryFault> {
        let count = ChainCount::from_raw(u64::try_from(rows.len()).unwrap_or(0));
        supplement_span(
            count,
            locator_ids,
            |hash| {
                Ok(rows
                    .iter()
                    .position(|row| row.hash == *hash)
                    .map(|index| BlockHeight::from_raw(u64::try_from(index).unwrap_or(0))))
            },
            |height| {
                let index = usize::try_from(height.to_raw()).unwrap_or(usize::MAX);
                Ok(rows.get(index).copied())
            },
        )
    }

    #[test]
    fn the_first_shared_hash_starts_the_window_and_includes_itself() {
        let rows = table(20);
        let locator_ids = vec![hash_of(99), hash_of(4), hash_of(1), rows[0].hash];
        let answer = answer(&rows, &locator_ids).expect("reads").expect("shared");
        assert_eq!(answer.start, BlockHeight::from_raw(4));
        assert_eq!(answer.blocks.len(), 16);
        assert_eq!(answer.blocks[0].hash, hash_of(4));
        assert_eq!(answer.blocks.last().expect("tip").hash, hash_of(19));
        assert_eq!(
            answer.tip_cumulative_difficulty,
            rows[19].cumulative_difficulty
        );
    }

    #[test]
    fn a_window_stops_at_the_chain_entry_limit_and_keeps_the_tip_difficulty() {
        let count = BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT + 50;
        let rows = table(count);
        let locator_ids = vec![hash_of(10), rows[0].hash];
        let answer = answer(&rows, &locator_ids).expect("reads").expect("shared");
        assert_eq!(
            u64::try_from(answer.blocks.len()).expect("fits"),
            BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT
        );
        assert_eq!(answer.blocks[0].hash, hash_of(10));
        let tip = usize::try_from(count - 1).expect("fits");
        assert_eq!(
            answer.tip_cumulative_difficulty,
            rows[tip].cumulative_difficulty
        );
        assert_ne!(
            answer.blocks.last().expect("end of the window").hash,
            rows[tip].hash
        );
    }

    #[test]
    fn a_locator_that_does_not_end_at_genesis_is_not_a_chain_entry() {
        let rows = table(8);
        let missing_genesis = vec![hash_of(3), hash_of(1)];
        assert!(answer(&rows, &missing_genesis).expect("reads").is_none());
        assert!(answer(&rows, &[]).expect("reads").is_none());
        assert!(answer(&[], &[hash_of(0)]).expect("reads").is_none());
    }

    #[test]
    fn an_unknown_prefix_that_ends_at_genesis_starts_there() {
        let rows = table(4);
        let locator_ids = vec![hash_of(90), rows[0].hash];
        let answer = answer(&rows, &locator_ids)
            .expect("reads")
            .expect("genesis");
        assert_eq!(answer.start, BlockHeight::ZERO);
        assert_eq!(answer.blocks.len(), 4);
    }
}
