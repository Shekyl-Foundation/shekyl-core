// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one judge-and-record step of a connect.
//!
//! [`Apply`](super::Apply) and the staged admitting connect
//! ([`ApplyAdmitting`](super::bundles::ApplyAdmitting)) both hold a source's
//! height to the chain, run `validate_with_memo`, and record what connected.
//! The live path then calls `connect`. The admitting path, which is in
//! flight for 4b, calls `connect_admitting`. Neither keeps a second copy of
//! the height claim, the refusal, or the bookkeeping.

use shekyl_chain_rules::{
    validate_with_memo, ArchivalDelta, CenRow, ChainValid, DrawableMemo, HeaderView, PaidEmission,
    RuleSet, StructurallyValid, Verdict, Weights,
};
use shekyl_chain_store::store::{BatchView, WriteBatch};
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot};

use super::{Applied, RunFault};
use crate::schedule::ChainRules;

/// What a connected block contributes to [`Applied`], taken off the verdict
/// before `connect` moves it.
pub(super) struct ConnectedFacts {
    hash: BlockHash,
    root_after: CurveTreeRoot,
    weights: Weights,
    emission: PaidEmission,
    archival: ArchivalDelta,
}

/// A block `validate_with_memo` accepted and this batch has not connected yet.
pub(super) struct Judged<'b, 'id> {
    pub(super) height: BlockHeight,
    pub(super) valid: ChainValid<'id, BatchView<'b, 'id>>,
    pub(super) rule_set: RuleSet,
    pub(super) facts: ConnectedFacts,
}

impl Judged<'_, '_> {
    /// The census rows this verdict exercised.
    pub(super) fn exercised(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.valid.coverage().iter().map(CenRow::as_str)
    }
}

/// Hold `claimed` to the height this batch connects at, and judge `formed`.
///
/// `Ok(None)` is a refusal, recorded on `applied`: this run of blocks stops
/// there and the writer stays up. A fault is the writer's. `Ok(Some)` is a
/// block the caller connects, then [`record_connected`].
///
/// The height is the store's to say, not the source's: the rule set in
/// force and the row the block is recorded under are both keyed by the
/// height the chain connects at, which is `tip + 1` on this view. The
/// source's height is bookkeeping; where the two disagree the source is
/// wrong about the chain, and that is a driver defect surfaced before
/// anything is judged under the wrong schedule. The parent's hash is
/// CEN-A2's operand inside `validate`, not a second copy of this height
/// check.
pub(super) fn judge_connecting<'b, 'id>(
    applied: &mut Applied,
    batch: &'b WriteBatch<'b, 'id>,
    rules: ChainRules,
    trust: &shekyl_chain_rules::Trust,
    memo: &mut DrawableMemo,
    claimed: BlockHeight,
    formed: Verdict<StructurallyValid>,
) -> Result<Option<Judged<'b, 'id>>, RunFault> {
    let view = batch.chain_view();
    let (height, _) = super::connecting(view.tip()?)?;
    if claimed != height {
        return Err(RunFault::HeightClaim {
            claimed,
            connecting: height,
        });
    }
    let formed = match formed {
        Ok(formed) => formed,
        Err(refused) => {
            applied.refused = Some((height, refused));
            return Ok(None);
        }
    };
    let rule_set = rules.in_force(height);
    let valid = match validate_with_memo(formed, &view, &rule_set, trust, Some(memo)) {
        Ok(Ok(valid)) => valid,
        Ok(Err(refused)) => {
            applied.refused = Some((height, refused));
            return Ok(None);
        }
        Err(fault) => return Err(super::validate_fault(batch, height, fault)),
    };
    let facts = ConnectedFacts {
        hash: valid.block().hash(),
        root_after: valid.block().root_after(),
        weights: *valid.block().weights(),
        emission: *valid.block().emission(),
        archival: valid.block().archival().clone(),
    };
    Ok(Some(Judged {
        height,
        valid,
        rule_set,
        facts,
    }))
}

/// Record a block that this batch has connected.
pub(super) fn record_connected(applied: &mut Applied, height: BlockHeight, facts: ConnectedFacts) {
    applied.connected.push((height, facts.hash));
    applied.roots.push((height, facts.root_after));
    applied.weights.push((height, facts.weights));
    applied.emission.push((height, facts.emission));
    applied.archival.push((height, facts.archival));
}
