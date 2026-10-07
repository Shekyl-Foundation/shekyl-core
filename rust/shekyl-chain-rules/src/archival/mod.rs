// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The archival transition — what connecting a block does to the archival
//! market's state, derived by the verdict and carried to the store as an
//! [`ArchivalDelta`]. DRS-E4 (`DRS_E4_ARCHIVAL_WRITER.md` §3.1 `ARW-Q1`,
//! §3.2 phase 2 and phase 9, §3.5–§3.7).
//!
//! # The store computes nothing
//!
//! `ARW-Q1` ruled that the values this module produces — a bond record's
//! post-image, a slash, an epoch's `r_market` and `Σwork` — are consensus
//! facts with reach (they price the next bond post, refuse the next claim,
//! decide the next serve credit), and a value with that reach is carried by
//! the authority over validity. So `validate` reads the archival state it
//! needs off [`ChainView`], runs the retention crate's folds, and the
//! [`ChainValid`](crate::ChainValid) it mints carries the delta. The store
//! writes each part through its handle and holds **no archival
//! arithmetic**: `connect` does not know what a slash is, only that a
//! record is replaced and a set gains a member.
//!
//! The type enforces the ruling. Every field of [`ArchivalDelta`] and its
//! one constructor are private to this module, so **a delta the validator
//! did not produce cannot be spelled** — not refused at a boundary,
//! unrepresentable. The doctests on the type are the pin.
//!
//! # The C++ is the template, not the text
//!
//! `db_lmdb.cpp`'s connect hooks (`add_transaction`'s three vin arms,
//! `process_archival_slash_at_height`, `process_archival_epoch_close_at_height`)
//! are what this module reproduces, and where the Rust differs it is
//! because the design says so:
//!
//! - **Refusals, not aborts.** The C++ hooks are verify-backstops that
//!   `throw` (CEN-L7: "fatal verify-backstops"). Here a post the folds
//!   refuse — a debit that is not the record's total, a claim for an epoch
//!   already claimed, a serve credit for a persona with no bond — refuses
//!   the *block* under CEN-L7 at the offending input's locus. The record is
//!   fine; the block is not. What the folds say about the *record* — a
//!   `bonded_total` that is not its floor, two open intervals — is
//!   [`Corrupt::BondRecordInvariant`]: bytes no conforming store holds,
//!   and the verdict halts rather than write over them.
//! - **The count operand.** The C++ hooks take `prev_height + 1`, the block
//!   **count** after this block connects, and every schedule test is
//!   written against it: an epoch's slashes fold when
//!   `count > deadline(E)`; an epoch closes when
//!   `schedule.close_due_at_height(count)`; the close's
//!   `close_block_height` is `count`. This module keeps that convention
//!   and names it `count` (= `connecting + 1`) so a reader does not mistake
//!   it for the connecting height. The retention crate's own docs sometimes
//!   say "connecting"; the operand is the count.
//! - **The schedule is the rule set's** (`ARW-15`). Every epoch boundary is
//!   read off `RuleSet::settlement_schedule()` — the
//!   `shekyl_archival_retention::SettlementSchedule` the set in force
//!   carries — never off the process-latched free functions
//!   (`settlement_epoch_at_height`, …), which are the daemon's and the
//!   FFI's entry points. The validator reads no environment; a chain
//!   captured under a shortened regtest epoch replays under a Fakechain
//!   set naming that epoch, in any process.
//! - **Zero is a value** (`ARW-Q4`, §3.6). The close writes an `RMarket`
//!   for **every closed shard**, zeros included; the C++ skipped zeros on
//!   the same screen it wrote a zero budget row *because* zero must be
//!   distinguishable. A6's `None` then means exactly "this epoch did not
//!   close with this shard in it".
//! - **One accrual row per epoch** (`ARW-Q3`, §3.5). The C++ wrote a row
//!   per block and range-summed at the close. Here the delta carries the
//!   open epoch's **post-image total** — what `archival_budget_accruing[E]`
//!   becomes — and the close's budget *is* that total, read from the same
//!   place the store will write it. Always carried, zero included.
//! - **The shard universe is the closed shard count** (`ARW-Q6`, §3.7),
//!   read off the chain through
//!   [`closed_shards_before`](crate::closed_shards_before); the C++ walked
//!   a segment table. A shard's close height, which the close's age term
//!   needs, is [`shard_close_height`] — the smallest height at which the
//!   cumulative archival fold reaches the shard's end, a binary search
//!   over that fold (`DRS_E4_ARCHIVAL_WRITER.md` §3.7). SI-13, enforced
//!   when the store connects each block, keeps the fold non-decreasing,
//!   and under it the landing height is the close. [`shard_close`] wraps
//!   it as `g(age)`'s operand against a [`ClosedUniverse`]: `ClosedAt(height)`
//!   below the count that read returned, `Open` at or beyond it. The count
//!   and the parent it was read through are one value, so a caller cannot
//!   name a different universe than the fold (`SHT-Q1` falsifier (i);
//!   `ARCHIVAL_SHARD_COUNT_CUTOVER.md` §F).
//! - **The stale eligibility copy is deliberate.** The C++ slash scan
//!   judged every shard of a record against the record *as the epoch's
//!   scan began* while applying each slash to the live row, so an offline
//!   N-shard record takes N slashes in one epoch and its open interval
//!   blocks the next epoch (`bond_connect::slash_open_interval_to_append`,
//!   P2B-9 Pin 5). That is a consensus behaviour, reproduced here on
//!   purpose: [`Transition::scan_epoch`] judges a snapshot and slashes the
//!   post-image.
//!
//! # Order
//!
//! Listed transactions in block order, inputs in transaction order, then
//! the accrual, then the slash scan (every epoch whose deadline `count`
//! passes, ascending; records in persona-key order), then the close. The
//! store writes the delta in the same order (§3.2 phase 2 and phase 9), so
//! the slash log's per-height sequence and every record's post-image are
//! functions of the view and the block, not of anything the store chose.

mod arm;
mod close;
mod delta;
mod inputs;
mod slash;

pub(crate) use arm::BondArm;
pub(crate) use close::{accrue, gather_epoch_snapshot, recorded_credits, EpochSnapshot};
pub use close::{closed_and_final, shard_close, shard_close_height, ClosedUniverse};
pub use delta::{
    Accrual, ArchivalDelta, EpochClose, RecordWrite, RecordWriteKind, ServeCreditKey, Slash,
};
pub(crate) use slash::apply_slash;

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use shekyl_archival_retention::SettlementSchedule;
use shekyl_types::archival::{BondRecord, Holdings, PassCount};
use shekyl_types::{BlockHeight, ChainCount, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use crate::block::Candidate;
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::{Corrupt, RecordInvariant, ViewRead};
use crate::rule_set::RuleSet;
use crate::rules::Rule;
use crate::verdict::{Locus, TxSlot, Verdict};
use crate::view::ChainView;

/// CEN-L7: the archival connect-writers, as the verdict's transition. What
/// the C++ hooks refused with a `throw` — a bond post, serve credit or
/// claim the folds cannot apply to the recorded state — this rule refuses
/// as a block, at the input's locus.
///
/// An unnamed bond-post kind is this row in `judge_bond_post` as well, at
/// the post's vin, so `tx_against` alone refuses it. The fold's arm stays
/// the belt for a transition caller that did not run that sequence.
pub(crate) struct L7;

impl Rule for L7 {
    const ROW: CenRow = CenRow::L7;
}

/// Derive the archival transition for `candidate` connecting at
/// `connecting` under `rule_set`, given the block's staker inflow
/// (`accrual`, the verdict's `PaidEmission::accrual`).
///
/// Every epoch boundary here — which epoch `connecting` opens, when a
/// challenge seals, which epoch's deadline `count` passes, whether this
/// block closes one — is `rule_set.settlement_schedule()`'s (`ARW-15`):
/// the validator never reads the process-latched schedule the daemon arms.
///
/// `Ok(Ok(delta))` records CEN-L7 in `coverage`. `Ok(Err(_))` is a refusal
/// at an input's locus. `Err(_)` is the view's fault or a [`Corrupt`]
/// state the folds exposed.
pub(crate) fn transition<'id, V: ChainView<'id>>(
    view: &V,
    connecting: BlockHeight,
    rule_set: &RuleSet,
    candidate: &Candidate,
    accrual: AtomicUnits,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<ArchivalDelta>, ViewRead<V::Fault>> {
    let mut transition = Transition::new(connecting, rule_set.settlement_schedule());
    for (n, tx) in candidate.transactions.iter().enumerate() {
        for (i, input) in tx.prefix.inputs.iter().enumerate() {
            let locus = Locus::Input {
                slot: TxSlot::Listed(n),
                input: i,
            };
            if let Err(refusal) = transition.apply_input(view, input, locus)? {
                return Ok(Err(refusal));
            }
        }
    }
    let accrued = transition.accrue(view, accrual)?;
    transition.scan_slashes(view)?;
    let close = transition.close(view, accrued)?;
    coverage.insert(L7::ROW);
    Ok(Ok(transition.into_delta(accrued, close)))
}

/// A compact holding with no shards — the Release's and the complete-tree
/// slash's post-holdings.
fn emptied() -> Holdings {
    Holdings::shard_set(Vec::new())
        .expect("an empty shard set has no duplicate and is under the cap")
}

/// A bond record's working copy: the post-image so far and whether the
/// block has changed it. `write: None` is a record read for its values
/// and not (yet) written.
struct Post {
    record: BondRecord,
    write: Option<RecordWriteKind>,
}

impl Post {
    /// Mark the record changed. An `Insert` stays an insert.
    fn touch(&mut self) {
        if self.write.is_none() {
            self.write = Some(RecordWriteKind::Update);
        }
    }
}

/// The transition in progress: the view plus what this block has done so
/// far, read through so each arm sees the arms before it.
struct Transition {
    connecting: BlockHeight,
    /// The rule set's epoch geometry — every `H_open` / `H_close` /
    /// deadline / close-due read below is this one's.
    schedule: SettlementSchedule,
    /// The epoch `connecting` sits in — the open epoch; the JoinMarket's
    /// join epoch and add epoch; the claim's `current_settled`.
    epoch: SettlementEpoch,
    posts: BTreeMap<PCanonicalId, Post>,
    serve_credits: Vec<ServeCreditKey>,
    slashes: Vec<Slash>,
    slash_watermark: Option<SettlementEpoch>,
}

impl Transition {
    fn new(connecting: BlockHeight, schedule: SettlementSchedule) -> Self {
        Self {
            connecting,
            schedule,
            epoch: SettlementEpoch::from_raw(schedule.epoch_at_height(connecting.to_raw())),
            posts: BTreeMap::new(),
            serve_credits: Vec::new(),
            slashes: Vec::new(),
            slash_watermark: None,
        }
    }

    /// The block count once this block connects — the C++ hooks' operand
    /// (module docs, *The count operand*), typed as the count it is
    /// ([`ChainCount::with_tip`] of the connecting block, `ARW-Q16` (a)):
    /// the schedule comparisons take it through `to_raw()` at their `u64`
    /// edge (Phase 2g's), and nothing here can hand it to a reader that
    /// wants the connecting height. `None` from the bridge is a connecting
    /// height of `u64::MAX`, which no chain this crate judges reaches.
    fn count(&self) -> ChainCount {
        ChainCount::with_tip(self.connecting).expect("a connecting height below u64::MAX")
    }

    /// `persona`'s working copy, read from the view on first touch;
    /// `None` for a persona with no bond.
    ///
    /// [`Self::merged`] has already inserted every recorded bond under the
    /// block's own post-images, so a touch after that finds the record in
    /// the map. A persona still absent is a persona with no bond.
    fn post<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        persona: PCanonicalId,
    ) -> Result<Option<&mut Post>, ViewRead<V::Fault>> {
        if let Entry::Vacant(slot) = self.posts.entry(persona) {
            if let Some(record) = view.bond_record(slot.key()).map_err(ViewRead::View)? {
                slot.insert(Post {
                    record,
                    write: None,
                });
            }
        }
        Ok(self.posts.get_mut(&persona))
    }

    /// Every bond record as it stands after the arms so far, in
    /// persona-key order (A11's order, overlaid with this block's
    /// post-images).
    ///
    /// The view fills personas this block has not touched. A post-image
    /// already in the map stays: the scan judges a snapshot and slashes
    /// the live row, and a later epoch's scan in the same block must see
    /// those slashes (`bond_connect::slash_open_interval_to_append`,
    /// P2B-9 Pin 5). The clone is that snapshot.
    fn merged<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
    ) -> Result<Vec<(PCanonicalId, BondRecord)>, ViewRead<V::Fault>> {
        for (persona, record) in view.bond_records().map_err(ViewRead::View)? {
            if let Entry::Vacant(slot) = self.posts.entry(persona) {
                slot.insert(Post {
                    record,
                    write: None,
                });
            }
        }
        Ok(self
            .posts
            .iter()
            .map(|(persona, post)| (*persona, post.record.clone()))
            .collect())
    }

    /// Whether `(persona, shard, epoch)` has a pass — recorded, or earned
    /// by this block (the C++ wrote the block's credits before the scan
    /// read them).
    fn passed<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        persona: PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<bool, ViewRead<V::Fault>> {
        if self
            .serve_credits
            .iter()
            .any(|k| k.persona == persona && k.shard == shard && k.epoch == epoch)
        {
            return Ok(true);
        }
        view.pass_count(&persona, shard, epoch)
            .map(PassCount::any)
            .map_err(ViewRead::View)
    }

    fn into_delta(self, accrual: Accrual, close: Option<EpochClose>) -> ArchivalDelta {
        let records = self
            .posts
            .into_iter()
            .filter_map(|(persona, post)| {
                post.write.map(|kind| RecordWrite {
                    persona,
                    record: post.record,
                    kind,
                })
            })
            .collect();
        ArchivalDelta::new(
            records,
            self.serve_credits,
            self.slashes,
            self.slash_watermark,
            accrual,
            close,
        )
    }
}

fn record_invariant<VF>(persona: PCanonicalId, which: RecordInvariant) -> ViewRead<VF> {
    ViewRead::Corrupt(Corrupt::BondRecordInvariant { persona, which })
}

#[cfg(test)]
#[path = "../archival_tests.rs"]
mod tests;
