// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one stub view the brand fixtures share: an empty chain, implementing
//! [`HeaderView`] and [`ChainView`] for every `'id`, over `Stub<T>`.
//!
//! `T` is the brand. [`View`] is `Stub<Brand<'id>>` — invariant in `'id`
//! through the `fn(&'id ()) -> &'id ()` phantom, one brand per
//! [`with_view`] call, as the store's `write` brands its `BatchView`.
//! [`Evil`] is `Stub<()>`: no brand, one type, a `ChainView` for every
//! `'id` — the view that merely borrows the lifetime.
//!
//! One impl, included by `#[path]` from each fixture. When `ChainView` grows
//! a read, this file grows one method; the fixtures' `.stderr` snapshots
//! then still name only the error at `connect`. A stub that fell behind the
//! trait would put `E0046` in every snapshot instead, and the suite would
//! be red — which is the point of the suite over an inline `compile_fail`
//! doctest, whose verdict cannot tell "fails at `connect`" from "fails at
//! the impl" (`validate.rs`, 2026-10-10).

#![allow(dead_code)]

use core::convert::Infallible;
use core::marker::PhantomData;
use std::collections::BTreeMap;

use shekyl_chain_rules::{
    AtHeight, BlockOutputs, ChainValid, ChainView, HeaderRecord, HeaderView, RecordedBlock,
    RecordedWeights, SlashLogFloor, StructurallyValid, Tip, TreeFrontier,
};
use shekyl_types::archival::{
    BondRecord, IndexedDraw, IssuedDigest, PassCount, RMarket, ServedShard, SettlementRow,
    SigmaWorkMilli, SlashLogEntry,
};
use shekyl_types::{
    BlockCount, BlockHash, BlockHeight, CurveTreeRoot, KeyImage, PCanonicalId, SettlementEpoch,
    ShardId, TxHash,
};
use shekyl_units::AtomicUnits;

/// An empty chain, whatever `T` says about its brand.
pub struct Stub<T>(pub T);

/// Branded by `'id`, invariantly.
pub struct Brand<'id>(PhantomData<fn(&'id ()) -> &'id ()>);

/// The branded view: one brand per [`with_view`] call.
pub type View<'id> = Stub<Brand<'id>>;

/// The unbranded view: one type, a `ChainView` for every `'id`.
pub type Evil = Stub<()>;

/// Each call brands a fresh view, as the store's `write` does.
pub fn with_view<R>(f: impl for<'id> FnOnce(View<'id>) -> R) -> R {
    f(Stub(Brand(PhantomData)))
}

/// The store's `connect`: the verdict must carry *this* view's brand and
/// *this* view's type.
pub fn connect<'id>(_view: &View<'id>, _valid: ChainValid<'id, View<'id>>) {}

/// A candidate the stage would accept. Never called: the fixtures are
/// compiled, not run.
pub fn formed() -> StructurallyValid {
    unimplemented!("the brand fixtures are compiled, not run")
}

impl<'id, T> HeaderView<'id> for Stub<T> {
    type Fault = Infallible;
    fn tip(&self) -> Result<Option<Tip>, Infallible> {
        Ok(None)
    }
    fn header_at(&self, _: BlockHeight) -> Result<AtHeight<HeaderRecord>, Infallible> {
        Ok(AtHeight::AboveTip)
    }
}

impl<'id, T> ChainView<'id> for Stub<T> {
    fn has_key_image(&self, _: &KeyImage) -> Result<bool, Infallible> {
        Ok(false)
    }
    fn block_at(&self, _: BlockHeight) -> Result<AtHeight<RecordedBlock>, Infallible> {
        Ok(AtHeight::AboveTip)
    }
    fn height_of(&self, _: &BlockHash) -> Result<Option<BlockHeight>, Infallible> {
        Ok(None)
    }
    fn root_at(&self, _: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Infallible> {
        Ok(AtHeight::AboveTip)
    }
    fn tree_frontier(&self) -> Result<TreeFrontier, Infallible> {
        Ok(TreeFrontier::EMPTY)
    }
    fn leaf_count_at(&self, _: BlockHeight) -> Result<AtHeight<u64>, Infallible> {
        Ok(AtHeight::AboveTip)
    }
    fn outputs_at(&self, _: BlockHeight) -> Result<AtHeight<BlockOutputs>, Infallible> {
        Ok(AtHeight::AboveTip)
    }
    fn weights_window(
        &self,
        _: BlockHeight,
        _: BlockCount,
    ) -> Result<AtHeight<Vec<RecordedWeights>>, Infallible> {
        Ok(AtHeight::AboveTip)
    }
    fn has_transaction(&self, _: &TxHash) -> Result<bool, Infallible> {
        Ok(false)
    }
    fn total_burned(&self) -> Result<AtomicUnits, Infallible> {
        Ok(AtomicUnits::ZERO)
    }
    fn bond_record(&self, _: &PCanonicalId) -> Result<Option<BondRecord>, Infallible> {
        Ok(None)
    }
    fn slash_log_after(
        &self,
        _: &PCanonicalId,
        _: BlockHeight,
        _: SlashLogFloor,
    ) -> Result<Vec<SlashLogEntry>, Infallible> {
        Ok(Vec::new())
    }
    fn last_served_epoch(
        &self,
        _: &PCanonicalId,
        _: ShardId,
    ) -> Result<Option<SettlementEpoch>, Infallible> {
        Ok(None)
    }
    fn served_shards(&self, _: &PCanonicalId) -> Result<Vec<ServedShard>, Infallible> {
        Ok(Vec::new())
    }
    fn pass_count(
        &self,
        _: &PCanonicalId,
        _: ShardId,
        _: SettlementEpoch,
    ) -> Result<PassCount, Infallible> {
        Ok(PassCount::ZERO)
    }
    fn r_market(&self, _: ShardId, _: SettlementEpoch) -> Result<Option<RMarket>, Infallible> {
        Ok(None)
    }
    fn sigma_work(&self, _: SettlementEpoch) -> Result<Option<SigmaWorkMilli>, Infallible> {
        Ok(None)
    }
    fn budget(&self, _: SettlementEpoch) -> Result<Option<AtomicUnits>, Infallible> {
        Ok(None)
    }
    fn last_settled_slash_epoch(&self) -> Result<Option<SettlementEpoch>, Infallible> {
        Ok(None)
    }
    fn bond_records(&self) -> Result<Vec<(PCanonicalId, BondRecord)>, Infallible> {
        Ok(Vec::new())
    }
    fn slash_applied(
        &self,
        _: &PCanonicalId,
        _: ShardId,
        _: SettlementEpoch,
    ) -> Result<bool, Infallible> {
        Ok(false)
    }
    fn budget_accruing(&self, _: SettlementEpoch) -> Result<Option<AtomicUnits>, Infallible> {
        Ok(None)
    }
    fn settlement_row(
        &self,
        _: &PCanonicalId,
        _: ShardId,
        _: SettlementEpoch,
    ) -> Result<Option<SettlementRow>, Infallible> {
        Ok(None)
    }
    fn issued_draws(&self, _: SettlementEpoch) -> Result<Vec<IndexedDraw>, Infallible> {
        Ok(Vec::new())
    }
    fn issued_digest(&self, _: SettlementEpoch) -> Result<IssuedDigest, Infallible> {
        Ok(IssuedDigest::ZERO)
    }
    fn served_at(
        &self,
        _: &PCanonicalId,
        _: &[SettlementEpoch],
    ) -> Result<BTreeMap<SettlementEpoch, Vec<ShardId>>, Infallible> {
        Ok(BTreeMap::new())
    }
}
