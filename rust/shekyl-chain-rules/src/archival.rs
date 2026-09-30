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
//! The type enforces the ruling. Every field of [`ArchivalDelta`] is
//! private and its one constructor is crate-private, so **a delta the
//! validator did not produce cannot be spelled** — not refused at a
//! boundary, unrepresentable. The doctests on the type are the pin.
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
//!   needs, is [`shard_close_height`] — `SCC-Q3`'s formula, a binary
//!   search over the archival fold `cumulative_archival_len` (`SHT-Q2`),
//!   not a stored freeze.
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

use std::collections::BTreeMap;

use shekyl_archival_retention::{
    challenge_fire_height, challenge_seal_height, claimed_epochs_check_and_set,
    epoch_close_compute, failure_window_slashable, good_through, holds_shard_at, reinstate_connect,
    release_connect, slash_open_interval_to_append, BaselineObservation, BondPostKind as PostKind,
    CreditPair, EpochCloseBond, EpochCloseInputs, EpochCloseShard, ReinstateConnectError,
    ReleaseConnectError, SettlementSchedule, ARCHIVAL_BOND_FLOOR_ATOMIC, FAILURE_WINDOW_N,
    FAILURE_WINDOW_SERVE_BUDGET, MAX_BOND_BAD_INTERVALS,
};
use shekyl_types::archival::{
    BondRecord, FirstPayingHeight, HeldShard, Holdings, PassCount, RMarket, SigmaWorkMilli,
    SlashLogEntry, SlashedHolding,
};
use shekyl_types::{
    shard_start, ArchivalLength, BlockHeight, PCanonicalId, SettlementEpoch, ShardId,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::{
    BondPost, BondPostKind as WireKind, Holdings as WireHoldings, Input,
};

use crate::block::Candidate;
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::{Corrupt, RecordInvariant, ViewRead};
use crate::rule_set::RuleSet;
use crate::rules::body::ArchivalKey;
use crate::rules::miner::closed_shards_before;
use crate::rules::{recorded, Rule};
use crate::verdict::{refused, Locus, TxSlot, Verdict};
use crate::view::ChainView;

/// CEN-L7: the archival connect-writers, as the verdict's transition. What
/// the C++ hooks refused with a `throw` — a bond post, serve credit or
/// claim the folds cannot apply to the recorded state — this rule refuses
/// as a block, at the input's locus.
pub(crate) struct L7;

impl Rule for L7 {
    const ROW: CenRow = CenRow::L7;
}

/// Everything a block's connect does to the archival state, derived by the
/// verdict. The store writes it; it computes none of it (`ARW-Q1`).
///
/// `Clone` has one caller: the ingest connector's `Applied` reply, which
/// carries each connected block's delta beside its root, weights and
/// emission — the verdict's derivations, cloned off the `ChainValid`
/// before `connect` consumes it — so a scenario reads what the validator
/// derived for a block it mined through the production stack. Reopened if
/// a second caller emerges; a third would be the moment to ask whether the
/// verdict should hand the delta out by reference instead.
///
/// Cannot be constructed outside this crate. The fields are private:
///
/// ```compile_fail,E0451
/// let delta = shekyl_chain_rules::ArchivalDelta {
///     records: Vec::new(),
///     serve_credits: Vec::new(),
///     slashes: Vec::new(),
///     slash_watermark: None,
///     accrual: todo!(),
///     close: None,
/// };
/// ```
///
/// and there is no public constructor — the transition is the only site:
///
/// ```compile_fail,E0624
/// let delta = shekyl_chain_rules::ArchivalDelta::new(
///     Vec::new(),
///     Vec::new(),
///     Vec::new(),
///     None,
///     todo!(),
///     None,
/// );
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivalDelta {
    records: Vec<RecordWrite>,
    serve_credits: Vec<ServeCreditKey>,
    slashes: Vec<Slash>,
    slash_watermark: Option<SettlementEpoch>,
    accrual: Accrual,
    close: Option<EpochClose>,
}

impl ArchivalDelta {
    const fn new(
        records: Vec<RecordWrite>,
        serve_credits: Vec<ServeCreditKey>,
        slashes: Vec<Slash>,
        slash_watermark: Option<SettlementEpoch>,
        accrual: Accrual,
        close: Option<EpochClose>,
    ) -> Self {
        Self {
            records,
            serve_credits,
            slashes,
            slash_watermark,
            accrual,
            close,
        }
    }

    /// Every bond record this block changes, in persona-key order, as its
    /// **post-image** — the inserts (JoinMarket) and the updates (Release,
    /// Reinstate, claim, slash). A record no arm touched is not here.
    #[must_use]
    pub fn records(&self) -> &[RecordWrite] {
        &self.records
    }

    /// The serve-credit keys this block's transactions earn, in block
    /// order (§3.2 phase 2: each becomes a `Present` under its key).
    #[must_use]
    pub fn serve_credits(&self) -> &[ServeCreditKey] {
        &self.serve_credits
    }

    /// The slashes this block applies, in application order — the order
    /// the slash log records them in.
    #[must_use]
    pub fn slashes(&self) -> &[Slash] {
        &self.slashes
    }

    /// The last settlement epoch whose slash deadline this block passes,
    /// when it passes any — the new `archival_last_slash_epoch` (A9).
    /// `None` when the watermark does not move.
    #[must_use]
    pub const fn slash_watermark(&self) -> Option<SettlementEpoch> {
        self.slash_watermark
    }

    /// The open epoch's accruing budget **after** this block — the row
    /// `archival_budget_accruing[E]` becomes (§3.5). Always present.
    #[must_use]
    pub const fn accrual(&self) -> Accrual {
        self.accrual
    }

    /// The epoch close this block performs, when `count` is a settlement
    /// boundary (§3.2 phase 9); `None` otherwise.
    #[must_use]
    pub const fn close(&self) -> Option<&EpochClose> {
        self.close.as_ref()
    }
}

/// One bond record's post-image and whether the store inserts or replaces
/// it. Insert-once for the JoinMarket (SI-19); upsert with the pre-image
/// journaled for the rest (§3.2 phase 2). `Clone` for [`ArchivalDelta`]'s
/// one cloning caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordWrite {
    persona: PCanonicalId,
    record: BondRecord,
    kind: RecordWriteKind,
}

impl RecordWrite {
    /// The record's persona — the `archival_bond` key.
    #[must_use]
    pub const fn persona(&self) -> &PCanonicalId {
        &self.persona
    }

    /// The record as the store must hold it after this block.
    #[must_use]
    pub const fn record(&self) -> &BondRecord {
        &self.record
    }

    /// Insert or replace.
    #[must_use]
    pub const fn kind(&self) -> RecordWriteKind {
        self.kind
    }
}

/// Whether a [`RecordWrite`] is a new record or a replaced one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordWriteKind {
    /// A JoinMarket: no record existed for the persona. The store's write
    /// is insert-once (SI-19) — a record already there is the writer's
    /// error (CEN-L14).
    Insert,
    /// Release, Reinstate, claim or slash: the record existed and this is
    /// its post-image. The store journals the pre-image.
    Update,
}

/// A serve-credit key this block earns: `(persona, shard, epoch)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServeCreditKey {
    /// The serving persona.
    pub persona: PCanonicalId,
    /// The shard served.
    pub shard: ShardId,
    /// The settlement epoch credited.
    pub epoch: SettlementEpoch,
}

/// One slash: the log entry and what it burned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slash {
    /// The slash-log row — persona, shard, epoch, and the holding the
    /// shard was slashed out of (the pop's revert operand).
    pub entry: SlashLogEntry,
    /// What leaves the persona's `bonded_total` and enters `total_burned`
    /// (the store's SI-8 fold; one bond floor per slash).
    pub burned: AtomicUnits,
}

/// The open epoch's accruing budget after this block: the post-image of
/// `archival_budget_accruing[E]` (§3.5, SI-23).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accrual {
    /// The open epoch — the one `connecting` sits in.
    pub epoch: SettlementEpoch,
    /// The running total, this block's inflow included. Zero is a value.
    pub total: AtomicUnits,
}

/// An epoch's close: the frozen facts the fold produced over the epoch's
/// snapshot, each insert-once (SI-21). `Clone` for [`ArchivalDelta`]'s one
/// cloning caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochClose {
    epoch: SettlementEpoch,
    r_market: Vec<(ShardId, RMarket)>,
    sigma_work: SigmaWorkMilli,
    budget: AtomicUnits,
}

impl EpochClose {
    /// The epoch closing.
    #[must_use]
    pub const fn epoch(&self) -> SettlementEpoch {
        self.epoch
    }

    /// Every shard in the close's snapshot with its co-holder count —
    /// every closed shard, zeros included (`ARW-Q4`), then any shard a
    /// credit named beyond the closed count, in shard order within each.
    #[must_use]
    pub fn r_market(&self) -> &[(ShardId, RMarket)] {
        &self.r_market
    }

    /// `Σwork(E)` in milli-units — CEN-J25's stored denominator.
    #[must_use]
    pub const fn sigma_work(&self) -> SigmaWorkMilli {
        self.sigma_work
    }

    /// `budget(E)`: the accrual's total at the close (§3.5).
    #[must_use]
    pub const fn budget(&self) -> AtomicUnits {
        self.budget
    }
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

/// The height at which closed shard `shard` closed: the block whose
/// archival fold first reached the shard's end, the smallest `h ≤ parent`
/// with `cumulative_archival_len(h) ≥ (shard + 1) · W`
/// (`ARCHIVAL_SHARD_COUNT_CUTOVER.md` `SCC-Q3`, on `SHT-Q2`'s partition).
/// The close's age operand (`EpochCloseShard::freeze_height`), derived
/// from the recorded fold by binary search instead of read from a segment
/// table — the same crossing the store's prune places when it retires the
/// shard.
///
/// Public for the one reason [`closed_shards_before`] is: the producer
/// composing a close reads the operand here, never from a second copy of
/// the definition.
///
/// # Errors
///
/// The view's fault; [`Corrupt::ShardCloseUnplaced`] when the height the
/// search lands on does not carry the shard's end. The search assumes a
/// monotone fold — SI-13 is the store's belt at write, not this one's —
/// and a shard the parent has closed ([`closed_shards_before`]); under
/// those two, the landing height is the close. When either fails (the
/// shard is still open through `parent`, or the fold fell back below the
/// end), the one check a binary search can make is that its landing point
/// reaches the end, and it refuses rather than return a height it cannot
/// verify, exactly as the prune's twin does.
pub fn shard_close_height<'id, V: ChainView<'id>>(
    view: &V,
    shard: ShardId,
    parent: BlockHeight,
) -> Result<BlockHeight, ViewRead<V::Fault>> {
    let unplaced = |at: u64| {
        ViewRead::Corrupt(Corrupt::ShardCloseUnplaced {
            shard,
            at: BlockHeight::from_raw(at),
        })
    };
    // The shard's end, `(shard + 1) · W`. A closed shard's end is at most
    // the parent's fold, so one that does not fit was never closed.
    let target = shard
        .to_raw()
        .checked_add(1)
        .and_then(|next| shard_start(ShardId::from_raw(next)))
        .ok_or_else(|| unplaced(parent.to_raw()))?;
    let fold_through = |h: u64| -> Result<ArchivalLength, ViewRead<V::Fault>> {
        Ok(recorded(view, BlockHeight::from_raw(h))?.cumulative_archival_len)
    };
    let (mut lo, mut hi) = (0u64, parent.to_raw());
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if fold_through(mid)? >= target {
            hi = mid;
        } else {
            lo = mid.saturating_add(1);
        }
    }
    // Every height the search stepped past fell short of the end, so the
    // landing point is the first that can reach it; whether it does is the
    // one thing left to verify.
    if fold_through(lo)? < target {
        return Err(unplaced(lo));
    }
    Ok(BlockHeight::from_raw(lo))
}

/// The open epoch's accruing budget after adding this block's inflow
/// (§3.5). CEN-L8's overflow clause: a total that does not fit is a fold
/// that ran ahead of the chain, [`Corrupt::AccrualOverflow`].
///
/// # Errors
///
/// [`Corrupt::AccrualOverflow`] on overflow.
pub(crate) fn accrue(
    accrued: AtomicUnits,
    inflow: AtomicUnits,
    epoch: SettlementEpoch,
) -> Result<AtomicUnits, Corrupt> {
    accrued
        .checked_add(inflow)
        .ok_or(Corrupt::AccrualOverflow { epoch })
}

/// Apply one slash to `record` (`db_lmdb.cpp` `apply_archival_slash_one`,
/// the record half): a complete-tree record becomes an empty compact one;
/// a compact record loses `shard`; an open bad interval is appended unless
/// one is open already (P2B-9 Pin 5 coalescing); one bond floor leaves
/// `bonded_total`. Returns the log entry and the burn.
///
/// The record-shaped `FATAL`s of the C++ are [`Corrupt`] here (CEN-L9): a
/// compact record that does not hold the shard it is slashed on, an
/// interval log at its cap when a slash must append, a `bonded_total`
/// below the floor a held shard implies.
///
/// # Errors
///
/// [`Corrupt::BondRecordInvariant`] with the invariant named.
pub(crate) fn apply_slash(
    persona: PCanonicalId,
    record: &mut BondRecord,
    shard: ShardId,
    epoch: SettlementEpoch,
) -> Result<Slash, Corrupt> {
    let invariant = |which| Corrupt::BondRecordInvariant { persona, which };
    let holding = match &record.holdings {
        Holdings::CompleteTree => {
            record.holdings = emptied();
            SlashedHolding::CompleteTree
        }
        Holdings::ShardSet(held) => {
            let Some(add_epoch) = held.iter().find(|h| h.shard == shard).map(|h| h.add_epoch)
            else {
                return Err(invariant(RecordInvariant::ShardNotHeld));
            };
            let remaining = held
                .iter()
                .filter(|h| h.shard != shard)
                .copied()
                .collect::<Vec<HeldShard>>();
            record.holdings = Holdings::shard_set(remaining)
                .expect("a subset of a valid held set is a valid held set");
            SlashedHolding::Shard { add_epoch }
        }
    };
    // Decided on the pre-append log: append `[E, ∞)` only when no interval
    // is open, so N same-epoch slashes append one interval, not N.
    if let Some(open) = slash_open_interval_to_append(&record.bad_intervals, epoch.to_raw()) {
        if record.bad_intervals.len() >= MAX_BOND_BAD_INTERVALS {
            return Err(invariant(RecordInvariant::IntervalLogFull));
        }
        record.bad_intervals.push(open);
    }
    let burned = AtomicUnits::from_raw(ARCHIVAL_BOND_FLOOR_ATOMIC);
    record.bonded_total = record
        .bonded_total
        .checked_sub(burned)
        .ok_or_else(|| invariant(RecordInvariant::BondedUnderflow))?;
    Ok(Slash {
        entry: SlashLogEntry {
            persona,
            shard,
            epoch,
            holding,
        },
        burned,
    })
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
    /// Whether every recorded bond is in `posts` (after the first
    /// [`Self::merged`]), so a persona absent from the map is absent
    /// from the chain.
    all_loaded: bool,
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
            all_loaded: false,
            serve_credits: Vec::new(),
            slashes: Vec::new(),
            slash_watermark: None,
        }
    }

    /// The block count once this block connects — the C++ hooks' operand
    /// (module docs, *The count operand*).
    fn count(&self) -> u64 {
        self.connecting.to_raw().saturating_add(1)
    }

    /// `persona`'s working copy, read from the view on first touch;
    /// `None` for a persona with no bond.
    fn post<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        persona: PCanonicalId,
    ) -> Result<Option<&mut Post>, ViewRead<V::Fault>> {
        if !self.all_loaded && !self.posts.contains_key(&persona) {
            if let Some(record) = view.bond_record(&persona).map_err(ViewRead::View)? {
                self.posts.insert(
                    persona,
                    Post {
                        record,
                        write: None,
                    },
                );
            }
        }
        Ok(self.posts.get_mut(&persona))
    }

    /// Every bond record as it stands after the arms so far, in
    /// persona-key order (A11's order, overlaid with this block's
    /// post-images). Loads the whole table into `posts` once.
    fn merged<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
    ) -> Result<Vec<(PCanonicalId, BondRecord)>, ViewRead<V::Fault>> {
        if !self.all_loaded {
            for (persona, record) in view.bond_records().map_err(ViewRead::View)? {
                self.posts.entry(persona).or_insert(Post {
                    record,
                    write: None,
                });
            }
            self.all_loaded = true;
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

    // ---- phase 2: the transactions' arms ---------------------------------

    fn apply_input<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        input: &Input,
        locus: Locus,
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
        match input {
            Input::Gen(_) | Input::ToKey { .. } => Ok(Ok(())),
            Input::ServeCredit { .. } => {
                // A vin the crate's one parse cannot read writes nothing;
                // the block that carries it does not connect (CEN-J1 will
                // refuse it earlier; this is the backstop).
                let Some(ArchivalKey::ServeCredit { p, shard, epoch }) = ArchivalKey::of(input)
                else {
                    return refused(L7::ROW, locus);
                };
                let persona = PCanonicalId::from_bytes(p);
                // The persona must have a record (CEN-J4's rule; SI-15 is
                // the store's belt beneath it).
                if self.post(view, persona)?.is_none() {
                    return refused(L7::ROW, locus);
                }
                self.serve_credits.push(ServeCreditKey {
                    persona,
                    shard: ShardId::from_raw(shard),
                    epoch: SettlementEpoch::from_raw(epoch),
                });
                Ok(Ok(()))
            }
            Input::BondPost(post) => match &post.kind {
                WireKind::JoinMarket {
                    bond_spend_pk,
                    endpoint,
                } => self.join(view, post, bond_spend_pk, *endpoint, locus),
                WireKind::Other(kind) => match PostKind::from_u8(*kind) {
                    Ok(PostKind::Release) => self.release(view, post, locus),
                    Ok(PostKind::Reinstate) => self.reinstate(view, post, locus),
                    // `Other(0)` cannot come off the wire (the decoder
                    // reads 0 as `JoinMarket`); an unknown kind is a post
                    // no fold applies.
                    Ok(PostKind::JoinMarket) | Err(_) => refused(L7::ROW, locus),
                },
            },
            Input::ArchivalRewardEmission { .. } => {
                let Some(ArchivalKey::Claims { p, epochs }) = ArchivalKey::of(input) else {
                    return refused(L7::ROW, locus);
                };
                self.claim(view, PCanonicalId::from_bytes(p), &epochs, locus)
            }
        }
    }

    /// JoinMarket (`db_lmdb.cpp` `apply_archival_bond_post`, the join arm):
    /// a new record joining at the open epoch, every held shard added at
    /// that epoch, no claims, no first-paying height.
    fn join<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        post: &BondPost,
        bond_spend_pk: &[u8],
        endpoint: [u8; 32],
        locus: Locus,
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
        let persona = post.p_canonical_id;
        // A persona joins once (SI-19's insert-once, judged here first).
        if self.post(view, persona)?.is_some() {
            return refused(L7::ROW, locus);
        }
        let holdings = match &post.holdings {
            WireHoldings::CompleteTree => Holdings::CompleteTree,
            WireHoldings::ShardSetCompact(ids) => {
                if ids.is_empty() {
                    return refused(L7::ROW, locus);
                }
                let held = ids
                    .iter()
                    .map(|&id| HeldShard {
                        shard: ShardId::from_raw(id),
                        add_epoch: self.epoch,
                    })
                    .collect::<Vec<_>>();
                match Holdings::shard_set(held) {
                    Ok(holdings) => holdings,
                    Err(_) => return refused(L7::ROW, locus),
                }
            }
        };
        let record = BondRecord {
            hybrid_pubkey: post.hybrid_public_key.clone(),
            bond_spend_pk: bond_spend_pk.to_vec(),
            endpoint,
            join_settlement_epoch: self.epoch,
            bonded_total: AtomicUnits::from_raw(post.bonded_total_atomic),
            holdings,
            bad_intervals: Vec::new(),
            claimed_settlement_epochs: Vec::new(),
            first_paying_emission_height: None,
        };
        self.posts.insert(
            persona,
            Post {
                record,
                write: Some(RecordWriteKind::Insert),
            },
        );
        Ok(Ok(()))
    }

    /// Release (`apply_archival_unbond`): the fold decides; the record
    /// becomes bonded-zero with no holdings and a clean interval close.
    fn release<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        post: &BondPost,
        locus: Locus,
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
        let persona = post.p_canonical_id;
        let epoch = self.epoch.to_raw();
        let Some(current) = self.post(view, persona)? else {
            return refused(L7::ROW, locus);
        };
        let record = &mut current.record;
        let held = match &record.holdings {
            Holdings::CompleteTree => 0,
            Holdings::ShardSet(held) => held.len(),
        };
        let connect = match release_connect(
            record.bonded_total.to_raw(),
            record.holdings.kind(),
            held,
            record.bad_intervals.len(),
            post.bond_debit,
            epoch,
        ) {
            Ok(connect) => connect,
            // The post is wrong for the record: the block is refused.
            Err(ReleaseConnectError::DebitZero | ReleaseConnectError::DebitNotRecordTotal) => {
                return refused(L7::ROW, locus);
            }
            // The record is wrong: no block can be judged against it.
            Err(ReleaseConnectError::RecordFloorInvariantBroken) => {
                return Err(record_invariant(persona, RecordInvariant::FloorBroken));
            }
            Err(ReleaseConnectError::IntervalLogFull) => {
                return Err(record_invariant(persona, RecordInvariant::IntervalLogFull));
            }
        };
        record.bonded_total = AtomicUnits::from_raw(connect.post_bonded_total);
        record.holdings = emptied();
        record.bad_intervals.push(connect.interval_close);
        current.touch();
        Ok(Ok(()))
    }

    /// Reinstate (`apply_archival_reinstate`): the fold names the open
    /// interval to close in place and the epoch that closes it.
    fn reinstate<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        post: &BondPost,
        locus: Locus,
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
        let persona = post.p_canonical_id;
        let epoch = self.epoch.to_raw();
        let post_ids: &[u64] = match &post.holdings {
            WireHoldings::ShardSetCompact(ids) => ids,
            // A complete-tree post carries no shard list; the fold reads
            // an empty one and refuses it (`EmptyPost`), as the C++ did.
            WireHoldings::CompleteTree => &[],
        };
        let Some(current) = self.post(view, persona)? else {
            return refused(L7::ROW, locus);
        };
        let record = &mut current.record;
        let record_ids = match &record.holdings {
            Holdings::CompleteTree => Vec::new(),
            Holdings::ShardSet(held) => held.iter().map(|h| h.shard.to_raw()).collect::<Vec<_>>(),
        };
        let connect = match reinstate_connect(
            record.bonded_total.to_raw(),
            &record_ids,
            &record.bad_intervals,
            post_ids,
            epoch,
        ) {
            Ok(connect) => connect,
            Err(
                ReinstateConnectError::HoldingsChanged
                | ReinstateConnectError::EmptyPost
                | ReinstateConnectError::PostOversize
                | ReinstateConnectError::NoOpenInterval,
            ) => return refused(L7::ROW, locus),
            Err(ReinstateConnectError::RecordFloorInvariantBroken) => {
                return Err(record_invariant(persona, RecordInvariant::FloorBroken));
            }
            Err(ReinstateConnectError::MultipleOpenIntervals) => {
                return Err(record_invariant(
                    persona,
                    RecordInvariant::MultipleOpenIntervals,
                ));
            }
            Err(ReinstateConnectError::IntervalOrdering) => {
                return Err(record_invariant(persona, RecordInvariant::IntervalOrdering));
            }
            Err(ReinstateConnectError::CounterRange) => {
                return Err(record_invariant(persona, RecordInvariant::CounterRange));
            }
        };
        let Some(interval) = record.bad_intervals.get_mut(connect.closed_interval_index) else {
            return Err(record_invariant(persona, RecordInvariant::CounterRange));
        };
        interval.end_exclusive = connect.interval_end_exclusive;
        current.touch();
        Ok(Ok(()))
    }

    /// An emission claim (`apply_archival_emission_claim`): every named
    /// epoch is checked-and-set against the record's claim window, with
    /// the open epoch as `current_settled`; the first paying height is
    /// set once.
    fn claim<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        persona: PCanonicalId,
        epochs: &[u64],
        locus: Locus,
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
        if epochs.is_empty() {
            return refused(L7::ROW, locus);
        }
        let current_settled = self.epoch.to_raw();
        let connecting = self.connecting;
        let Some(current) = self.post(view, persona)? else {
            return refused(L7::ROW, locus);
        };
        let record = &mut current.record;
        let mut set = record
            .claimed_settlement_epochs
            .iter()
            .map(|e| e.to_raw())
            .collect::<Vec<_>>();
        for &epoch in epochs {
            match claimed_epochs_check_and_set(&mut set, epoch, current_settled) {
                Ok(true) => {}
                // Already claimed (a dedup breach past CEN-J25) or not
                // claimable (unsettled or expired): never a soft skip.
                Ok(false) | Err(_) => return refused(L7::ROW, locus),
            }
        }
        record.claimed_settlement_epochs = set.into_iter().map(SettlementEpoch::from_raw).collect();
        // Set-once. `new` is `None` at height 0, where no epoch has closed
        // and no claim can be — the C++'s 0-is-unset sentinel, by type.
        if record.first_paying_emission_height.is_none() {
            record.first_paying_emission_height = FirstPayingHeight::new(connecting);
        }
        current.touch();
        Ok(Ok(()))
    }

    // ---- phase 9: the block's own writes ---------------------------------

    /// The accrual post-image (§3.5): what the open epoch has accrued so
    /// far plus this block's inflow.
    fn accrue<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        inflow: AtomicUnits,
    ) -> Result<Accrual, ViewRead<V::Fault>> {
        let accrued = view
            .budget_accruing(self.epoch)
            .map_err(ViewRead::View)?
            .unwrap_or(AtomicUnits::ZERO);
        let total = accrue(accrued, inflow, self.epoch).map_err(ViewRead::Corrupt)?;
        Ok(Accrual {
            epoch: self.epoch,
            total,
        })
    }

    /// The slash scheduler (`process_archival_slash_at_height`): every
    /// epoch above the watermark whose deadline `count` passes, ascending.
    fn scan_slashes<'id, V: ChainView<'id>>(&mut self, view: &V) -> Result<(), ViewRead<V::Fault>> {
        let count = self.count();
        let mut next = view
            .last_settled_slash_epoch()
            .map_err(ViewRead::View)?
            .map_or(0, |last| last.to_raw().saturating_add(1));
        while count > self.schedule.slash_deadline_height(next) {
            let epoch = SettlementEpoch::from_raw(next);
            self.scan_epoch(view, epoch)?;
            self.slash_watermark = Some(epoch);
            let Some(after) = next.checked_add(1) else {
                break;
            };
            next = after;
        }
        Ok(())
    }

    /// One epoch's scan (`process_archival_slash_for_epoch`): every record
    /// in persona-key order, judged against a snapshot taken as the scan
    /// begins (module docs, *The stale eligibility copy*). A complete-tree
    /// record is challenged on every closed shard and slashed on the first
    /// failure only; a compact record on each shard it holds.
    fn scan_epoch<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        epoch: SettlementEpoch,
    ) -> Result<(), ViewRead<V::Fault>> {
        let universe = closed_shards_before(view, self.connecting)?.get();
        let snapshot = self.merged(view)?;
        for (persona, record) in &snapshot {
            match &record.holdings {
                Holdings::CompleteTree => {
                    for k in 0..universe {
                        let shard = ShardId::from_raw(k);
                        if self.challenge_failed(view, *persona, record, shard, epoch)? {
                            self.slash(*persona, shard, epoch)?;
                            break;
                        }
                    }
                }
                Holdings::ShardSet(held) => {
                    for h in held.as_slice() {
                        if self.challenge_failed(view, *persona, record, h.shard, epoch)? {
                            self.slash(*persona, h.shard, epoch)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// `archival_challenge_failed_at_height`: no pass, not already
    /// slashed, baseline observed, and the failure window says slash.
    fn challenge_failed<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        persona: PCanonicalId,
        record: &BondRecord,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<bool, ViewRead<V::Fault>> {
        if self.passed(view, persona, shard, epoch)? {
            return Ok(false);
        }
        let applied = view
            .slash_applied(&persona, shard, epoch)
            .map_err(ViewRead::View)?
            || self.slashes.iter().any(|s| {
                s.entry.persona == persona && s.entry.shard == shard && s.entry.epoch == epoch
            });
        if applied {
            return Ok(false);
        }
        if !self.baseline_observed(view, persona, record, shard, epoch)? {
            return Ok(false);
        }
        self.window_slashable(view, persona, record, shard, epoch)
    }

    /// `archival_baseline_observed_at_epoch`: the persona was good through
    /// `epoch`, the deadline has passed, the seal block is recorded, and
    /// the persona held the shard as of the fire height.
    fn baseline_observed<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        persona: PCanonicalId,
        record: &BondRecord,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<bool, ViewRead<V::Fault>> {
        let e = epoch.to_raw();
        if !good_through(
            record.join_settlement_epoch.to_raw(),
            e,
            &record.bad_intervals,
        ) {
            return Ok(false);
        }
        if self.count() <= self.schedule.slash_deadline_height(e) {
            return Ok(false);
        }
        let h_open = self.schedule.open_height(e);
        let h_close = self.schedule.last_block(e);
        let h_seal = challenge_seal_height(h_open);
        // The seal is a recorded block's hash, so it must sit below the
        // connecting height. Under the pinned constants a passed deadline
        // puts it there always; the guard is the observability boundary
        // stated, not a reachable arm.
        if h_seal >= self.connecting.to_raw() {
            return Ok(false);
        }
        let seal = recorded(view, BlockHeight::from_raw(h_seal))?.hash;
        let h_fire = challenge_fire_height(
            h_open,
            h_close,
            seal.as_bytes(),
            persona.as_bytes(),
            shard.to_raw(),
            e,
        );
        let fire = BlockHeight::from_raw(h_fire);
        // A2 plus this block's own entries for the persona — the fire
        // height is below `connecting`, so they qualify as "after".
        let mut slashed_after = view
            .slash_log_after(&persona, fire)
            .map_err(ViewRead::View)?;
        slashed_after.extend(
            self.slashes
                .iter()
                .map(|s| s.entry)
                .filter(|entry| entry.persona == persona),
        );
        Ok(holds_shard_at(record, shard, fire, &slashed_after))
    }

    /// `archival_failure_window_slashable`: the decision epoch is a miss;
    /// walk back through the pair's continuous challengeable run, at most
    /// `FAILURE_WINDOW_N` observations, stopping once passes exceed the
    /// serve budget.
    fn window_slashable<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        persona: PCanonicalId,
        record: &BondRecord,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<bool, ViewRead<V::Fault>> {
        let window = usize::try_from(FAILURE_WINDOW_N).expect("a u32 fits a usize");
        let mut observations = vec![BaselineObservation::missed(epoch.to_raw())];
        let mut passes_seen = 0u32;
        let mut e = epoch.to_raw();
        while observations.len() < window && e > 0 {
            e -= 1;
            let earlier = SettlementEpoch::from_raw(e);
            if !self.baseline_observed(view, persona, record, shard, earlier)? {
                break;
            }
            let passed = self.passed(view, persona, shard, earlier)?;
            observations.push(if passed {
                BaselineObservation::served(e)
            } else {
                BaselineObservation::missed(e)
            });
            if passed {
                passes_seen += 1;
                if passes_seen > FAILURE_WINDOW_SERVE_BUDGET {
                    break;
                }
            }
        }
        // The sequence always holds the decision epoch and never more than
        // the window: the fold's two refusals are unreachable from here.
        Ok(failure_window_slashable(&observations)
            .expect("the gathered window holds the decision epoch and at most FAILURE_WINDOW_N observations"))
    }

    /// Apply one slash to the persona's post-image and record it.
    fn slash<VF>(
        &mut self,
        persona: PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<(), ViewRead<VF>> {
        let post = self
            .posts
            .get_mut(&persona)
            .expect("the scan slashes a record it read into the snapshot; nothing removes one");
        let slash =
            apply_slash(persona, &mut post.record, shard, epoch).map_err(ViewRead::Corrupt)?;
        post.touch();
        self.slashes.push(slash);
        Ok(())
    }

    /// The epoch close (`process_archival_epoch_close_at_height`), when
    /// `count` is a settlement boundary.
    fn close<'id, V: ChainView<'id>>(
        &mut self,
        view: &V,
        accrual: Accrual,
    ) -> Result<Option<EpochClose>, ViewRead<V::Fault>> {
        let count = self.count();
        let Some(closing) = self.schedule.close_due_at_height(count) else {
            return Ok(None);
        };
        let epoch = SettlementEpoch::from_raw(closing);
        // `count = (E + 1) · SEB` puts `connecting` in `E`, so the open
        // epoch's accrual is the closing epoch's budget.
        debug_assert_eq!(accrual.epoch, epoch, "the close's epoch is the open epoch");

        // The snapshot's shards: every closed shard (ARW-Q4), with the
        // close height its age is measured from.
        let universe = closed_shards_before(view, self.connecting)?.get();
        let mut shards = Vec::new();
        for k in 0..universe {
            // `universe > 0` needs a fold of at least `W`, so a parent
            // exists; `saturating_sub` only spells that.
            let parent = BlockHeight::from_raw(self.connecting.to_raw().saturating_sub(1));
            shards.push(EpochCloseShard {
                shard_id: k,
                has_segment: true,
                freeze_height: shard_close_height(view, ShardId::from_raw(k), parent)?.to_raw(),
            });
        }

        // The snapshot's bonds: every record with a credit at `epoch`, in
        // persona-key order, after this block's slashes; a credit on a
        // shard beyond the closed count names a shard without a segment
        // (the C++'s `has_segment = false`: it counts, it has no age).
        let snapshot = self.merged(view)?;
        let mut bonds = Vec::new();
        let mut pairs = Vec::new();
        for (persona, record) in &snapshot {
            let credited = self.credited_shards(view, *persona, epoch)?;
            if credited.is_empty() {
                continue;
            }
            let bond_idx = bonds.len();
            bonds.push(EpochCloseBond {
                join_settlement_epoch: record.join_settlement_epoch.to_raw(),
                is_foundation_complete_tree: record.is_complete_tree(),
                bad_intervals: &record.bad_intervals,
            });
            for shard in credited {
                let shard_idx = match shards.iter().position(|s| s.shard_id == shard) {
                    Some(idx) => idx,
                    None => {
                        shards.push(EpochCloseShard {
                            shard_id: shard,
                            has_segment: false,
                            freeze_height: 0,
                        });
                        shards.len() - 1
                    }
                };
                pairs.push(CreditPair {
                    bond_idx,
                    shard_idx,
                });
            }
        }

        let inputs = EpochCloseInputs::under_schedule(
            self.schedule,
            closing,
            count,
            &bonds,
            &shards,
            &pairs,
        );
        let result = epoch_close_compute(&inputs)
            .expect("every credit pair indexes the bonds and shards it was built from");
        let r_market = shards
            .iter()
            .zip(result.r_market_by_shard)
            .map(|(shard, r)| (ShardId::from_raw(shard.shard_id), RMarket::from_raw(r)))
            .collect();
        Ok(Some(EpochClose {
            epoch,
            r_market,
            sigma_work: SigmaWorkMilli::from_raw(result.sigma_work_milli),
            budget: accrual.total,
        }))
    }

    /// The shards `persona` has a credit on at `epoch`, ascending and
    /// distinct: recorded (A4 narrows the candidates, A5 confirms) and
    /// this block's.
    fn credited_shards<'id, V: ChainView<'id>>(
        &self,
        view: &V,
        persona: PCanonicalId,
        epoch: SettlementEpoch,
    ) -> Result<Vec<u64>, ViewRead<V::Fault>> {
        let mut out = Vec::new();
        for served in view.served_shards(&persona).map_err(ViewRead::View)? {
            if served.last_served >= epoch
                && view
                    .pass_count(&persona, served.shard, epoch)
                    .map_err(ViewRead::View)?
                    .any()
            {
                out.push(served.shard.to_raw());
            }
        }
        out.extend(
            self.serve_credits
                .iter()
                .filter(|k| k.persona == persona && k.epoch == epoch)
                .map(|k| k.shard.to_raw()),
        );
        out.sort_unstable();
        out.dedup();
        Ok(out)
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
#[path = "archival_tests.rs"]
mod tests;
