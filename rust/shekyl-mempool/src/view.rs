// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`PoolView`]: the chain as the pool door judges against it — the chain's
//! answers, with the pool's spent key images added (`E5-Q1`;
//! `DRS_E5_POOL_ALT_PRUNE.md` §2.2).
//!
//! Under FCMP++ a pool transaction's outputs are not in the tree, so the
//! pool adds nothing a rule can read except the key images its entries
//! spend. [`ChainView::has_key_image`] is therefore chain ∨ pool — CEN-M6
//! (spent on the chain) and CEN-M7 (spent by a pool entry) are one read,
//! judged by the validator's own CEN-I7 — and every other read is the
//! inner view's, unchanged. The decorator has exactly one override; a
//! second one would be the pool teaching a rule something the chain does
//! not hold.
//!
//! It never implements `connect`'s view type: a verdict judged over it
//! cannot be connected (`tests/trybuild/`, the negative control).

use std::collections::BTreeMap;

use shekyl_chain_rules::{AtHeight, ChainView, HeaderRecord, HeaderView, Tip};
use shekyl_types::{KeyImage, TxHash};

/// The key images the pool's entries spend, each with the entry that
/// spends it — CEN-M7's conflict map. One spender per key image: the door
/// refuses a second (the decorator answers "spent"), so the map never
/// holds a conflict.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyImages {
    spent_by: BTreeMap<KeyImage, TxHash>,
}

impl KeyImages {
    /// The entry spending `key_image`, if one does.
    #[must_use]
    pub fn spender(&self, key_image: &KeyImage) -> Option<TxHash> {
        self.spent_by.get(key_image).copied()
    }

    /// Whether a pool entry spends `key_image`.
    #[must_use]
    pub fn contains(&self, key_image: &KeyImage) -> bool {
        self.spent_by.contains_key(key_image)
    }

    /// How many key images the pool's entries spend.
    #[must_use]
    pub fn len(&self) -> usize {
        self.spent_by.len()
    }

    /// Whether no entry spends any.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spent_by.is_empty()
    }

    /// Record that `txid` spends every key image in `key_images`. The door
    /// calls this only after the chain's `Ok`, so none is held.
    pub(crate) fn insert(&mut self, txid: TxHash, key_images: impl IntoIterator<Item = KeyImage>) {
        for key_image in key_images {
            let previous = self.spent_by.insert(key_image, txid);
            debug_assert!(
                previous.is_none(),
                "the door admitted a second spender of one key image"
            );
        }
    }

    /// Forget the key images `txid` spent — it left the pool.
    pub(crate) fn remove(&mut self, txid: &TxHash, key_images: impl IntoIterator<Item = KeyImage>) {
        for key_image in key_images {
            if self.spent_by.get(&key_image) == Some(txid) {
                self.spent_by.remove(&key_image);
            }
        }
    }
}

/// The chain `V`, with the pool's spent key images added to
/// [`ChainView::has_key_image`]. Every other read is `V`'s.
#[derive(Clone, Copy, Debug)]
pub struct PoolView<'v, V> {
    chain: &'v V,
    pool: &'v KeyImages,
}

impl<'v, V> PoolView<'v, V> {
    /// The chain `chain` as seen by a transaction the pool holding `pool`
    /// is judging.
    #[must_use]
    pub const fn new(chain: &'v V, pool: &'v KeyImages) -> Self {
        Self { chain, pool }
    }
}

impl<'id, V: HeaderView<'id>> HeaderView<'id> for PoolView<'_, V> {
    type Fault = V::Fault;

    fn tip(&self) -> Result<Option<Tip>, Self::Fault> {
        self.chain.tip()
    }

    fn header_at(
        &self,
        height: shekyl_types::BlockHeight,
    ) -> Result<AtHeight<HeaderRecord>, Self::Fault> {
        self.chain.header_at(height)
    }
}

impl<'id, V: ChainView<'id>> ChainView<'id> for PoolView<'_, V> {
    /// Spent on the chain (CEN-M6) **or** by a pool entry (CEN-M7) — the
    /// one override. The pool is asked first: it is in memory, and a key
    /// image it holds is refused whatever the chain says.
    fn has_key_image(&self, key_image: &KeyImage) -> Result<bool, Self::Fault> {
        if self.pool.contains(key_image) {
            return Ok(true);
        }
        self.chain.has_key_image(key_image)
    }

    fn block_at(
        &self,
        height: shekyl_types::BlockHeight,
    ) -> Result<AtHeight<shekyl_chain_rules::RecordedBlock>, Self::Fault> {
        self.chain.block_at(height)
    }

    fn height_of(
        &self,
        hash: &shekyl_types::BlockHash,
    ) -> Result<Option<shekyl_types::BlockHeight>, Self::Fault> {
        self.chain.height_of(hash)
    }

    fn root_at(
        &self,
        height: shekyl_types::BlockHeight,
    ) -> Result<AtHeight<shekyl_types::CurveTreeRoot>, Self::Fault> {
        self.chain.root_at(height)
    }

    fn tree_frontier(&self) -> Result<shekyl_chain_rules::TreeFrontier, Self::Fault> {
        self.chain.tree_frontier()
    }

    fn leaf_count_at(
        &self,
        height: shekyl_types::BlockHeight,
    ) -> Result<AtHeight<u64>, Self::Fault> {
        self.chain.leaf_count_at(height)
    }

    fn outputs_at(
        &self,
        height: shekyl_types::BlockHeight,
    ) -> Result<AtHeight<shekyl_chain_rules::BlockOutputs>, Self::Fault> {
        self.chain.outputs_at(height)
    }

    fn depth_at(&self, height: shekyl_types::BlockHeight) -> Result<AtHeight<u8>, Self::Fault> {
        self.chain.depth_at(height)
    }

    fn weights_window(
        &self,
        end: shekyl_types::BlockHeight,
        at_most: shekyl_types::BlockCount,
    ) -> Result<AtHeight<Vec<shekyl_chain_rules::RecordedWeights>>, Self::Fault> {
        self.chain.weights_window(end, at_most)
    }

    fn has_transaction(&self, hash: &TxHash) -> Result<bool, Self::Fault> {
        self.chain.has_transaction(hash)
    }

    fn total_burned(&self) -> Result<shekyl_units::AtomicUnits, Self::Fault> {
        self.chain.total_burned()
    }

    fn long_term_effective_median_at(
        &self,
        height: shekyl_types::BlockHeight,
    ) -> Result<AtHeight<shekyl_types::LongTermWeight>, Self::Fault> {
        self.chain.long_term_effective_median_at(height)
    }

    fn burned_through(
        &self,
        height: shekyl_types::BlockHeight,
    ) -> Result<AtHeight<shekyl_units::AtomicUnits>, Self::Fault> {
        self.chain.burned_through(height)
    }

    shekyl_chain_rules::archival_reads!(delegate chain);
}

#[cfg(test)]
#[path = "view_tests.rs"]
mod view_tests;
