// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The delta a block's archival transition hands the store (`ARW-Q1`).
//!
//! The fields are visible inside `archival` — the transition and its
//! siblings build the delta — and private past that module. The doctest on
//! [`ArchivalDelta`] is the pin. The store writes what it is given.

use shekyl_types::archival::{
    BlockDraws, BondRecord, CompleteTreeSet, DrawableDigest, RMarket, SettlementRow,
    SigmaWorkMilli, SlashLogEntry,
};
use shekyl_types::{PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

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
///     releases: Vec::new(),
///     serve_credits: Vec::new(),
///     settlements: Vec::new(),
///     gathers: Vec::new(),
///     slashes: Vec::new(),
///     slash_watermark: None,
///     accrual: todo!(),
///     close: None,
///     drawable_digest: None,
///     draws: todo!(),
/// };
/// ```
///
/// and there is no constructor at all: the transition builds the value
/// field by field, inside this module's parent, and is the only site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivalDelta {
    pub(super) records: Vec<RecordWrite>,
    pub(super) releases: Vec<ReleasePreImage>,
    pub(super) serve_credits: Vec<ServeCreditKey>,
    pub(super) settlements: Vec<Settlement>,
    pub(super) gathers: Vec<EpochGather>,
    pub(super) slashes: Vec<Slash>,
    pub(super) slash_watermark: Option<SettlementEpoch>,
    pub(super) accrual: Accrual,
    pub(super) close: Option<EpochClose>,
    pub(super) drawable_digest: Option<DrawableDigestWrite>,
    /// The draw count of the connecting block. Present at every height,
    /// including a schedule with no response window, which records zeros.
    pub(super) draws: BlockDraws,
}

impl ArchivalDelta {
    /// Every bond record this block changes, in persona-key order, as its
    /// **post-image** — the inserts (JoinMarket) and the updates (Release,
    /// Reinstate, claim, slash). A record no arm touched is not here.
    #[must_use]
    pub fn records(&self) -> &[RecordWrite] {
        &self.records
    }

    /// Every Release this block connects, in block order, each with the
    /// record as it stood before the Release changed it: what the store
    /// journals under `(height, persona)` (`archival_release_journal`,
    /// `SO-D12` increment 2). The post-image is in [`Self::records`].
    #[must_use]
    pub fn releases(&self) -> &[ReleasePreImage] {
        &self.releases
    }

    /// The serve-credit keys this block's transactions earn, in block
    /// order (§3.2 phase 2: each becomes a `Present` under its key).
    #[must_use]
    pub fn serve_credits(&self) -> &[ServeCreditKey] {
        &self.serve_credits
    }

    /// The settlement rows this block's slash pass derives, by epoch, then
    /// persona, then shard: one per pair with a counted draw in each epoch
    /// whose deadline this block passes
    /// (`ARCHIVAL_SETTLEMENT_WRITER.md` §14). The slashes below were
    /// decided on these rows and on rows already recorded; the store
    /// writes them first (`SO-D7`).
    #[must_use]
    pub fn settlements(&self) -> &[Settlement] {
        &self.settlements
    }

    /// The emission gather of every epoch this block's slash pass settled,
    /// in epoch order: each epoch's co-holder counts and `Σwork`, folded
    /// over the pairs its settlement rows say were Served
    /// (`ARCHIVAL_SETTLEMENT_WRITER.md` §15, `SO-D11`). One per settled
    /// epoch, whether or not any pair was Served — a zero is written, not
    /// skipped (`ARW-Q4`), so the epoch's `Σwork` row exists and a claim
    /// can cite it.
    #[must_use]
    pub fn gathers(&self) -> &[EpochGather] {
        &self.gathers
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

    /// The digest of the drawable set of the epoch this block opens, when
    /// it is an `h_open(E)` — genesis for epoch 0, and the first block of
    /// every later epoch; `None` at every other height. Taken over the
    /// state after this block, its slash pass included
    /// (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §4.1, §9.5 check 2).
    #[must_use]
    pub const fn drawable_digest(&self) -> Option<&DrawableDigestWrite> {
        self.drawable_digest.as_ref()
    }

    /// The draw count of the connecting block (`SO-D12` increment 3).
    /// Written at every height. `issued_short` is zero until admission.
    #[must_use]
    pub const fn draws(&self) -> BlockDraws {
        self.draws
    }
}

/// One Release's pre-image: the persona's record exactly as it stood before
/// the Release arm changed it. `Clone` for [`ArchivalDelta`]'s one cloning
/// caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleasePreImage {
    pub(super) persona: PCanonicalId,
    pub(super) record: BondRecord,
}

impl ReleasePreImage {
    /// The releasing persona.
    #[must_use]
    pub const fn persona(&self) -> &PCanonicalId {
        &self.persona
    }

    /// The record before the Release.
    #[must_use]
    pub const fn record(&self) -> &BondRecord {
        &self.record
    }
}

/// The digest of one epoch's drawable set, written once, at its open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrawableDigestWrite {
    pub(super) epoch: SettlementEpoch,
    pub(super) digest: DrawableDigest,
}

impl DrawableDigestWrite {
    /// The epoch the block opens.
    #[must_use]
    pub const fn epoch(&self) -> SettlementEpoch {
        self.epoch
    }

    /// `DrawableEpoch::digest` of its drawable set.
    #[must_use]
    pub const fn digest(&self) -> DrawableDigest {
        self.digest
    }
}

/// One bond record's post-image and whether the store inserts or replaces
/// it. Insert-once for the JoinMarket (SI-19); upsert with the pre-image
/// journaled for the rest (§3.2 phase 2). `Clone` for [`ArchivalDelta`]'s
/// one cloning caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordWrite {
    pub(super) persona: PCanonicalId,
    pub(super) record: BondRecord,
    pub(super) kind: RecordWriteKind,
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
    /// its post-image. The store replaces a present row and journals that
    /// pre-image; an absent persona is SI-20 before any journal entry.
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

/// One pair's settlement for one epoch: the `archival_settlement` key and
/// its row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settlement {
    /// The persona settled.
    pub persona: PCanonicalId,
    /// The shard settled.
    pub shard: ShardId,
    /// The epoch settled.
    pub epoch: SettlementEpoch,
    /// What it settled.
    pub row: SettlementRow,
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

/// An epoch's close: the budget it freezes, insert-once (SI-21).
///
/// The close used to carry the epoch's co-holder counts and `Σwork` as
/// well. Those are folded over settlement rows, which the slash pass
/// writes an epoch later, so they ride [`EpochGather`] (`SO-D11`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochClose {
    pub(super) epoch: SettlementEpoch,
    pub(super) budget: AtomicUnits,
}

impl EpochClose {
    /// The epoch closing.
    #[must_use]
    pub const fn epoch(&self) -> SettlementEpoch {
        self.epoch
    }

    /// `budget(E)`: the accrual's total at the close (§3.5).
    #[must_use]
    pub const fn budget(&self) -> AtomicUnits {
        self.budget
    }
}

/// One settled epoch's emission gather: the facts the slash pass folds
/// over the epoch's Served pairs, each insert-once and written whole
/// (SI-21). `Clone` for [`ArchivalDelta`]'s one cloning caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochGather {
    pub(super) epoch: SettlementEpoch,
    pub(super) r_market: Vec<(ShardId, RMarket)>,
    pub(super) sigma_work: SigmaWorkMilli,
    pub(super) complete_trees: CompleteTreeSet,
}

impl EpochGather {
    /// The epoch gathered.
    #[must_use]
    pub const fn epoch(&self) -> SettlementEpoch {
        self.epoch
    }

    /// Every shard in the gather's snapshot with its co-holder count —
    /// every shard closed and final as of the pass, zeros included
    /// (`ARW-Q4`), then any shard a Served row named beyond those, in
    /// shard order within each.
    #[must_use]
    pub fn r_market(&self) -> &[(ShardId, RMarket)] {
        &self.r_market
    }

    /// `Σwork(E)` in milli-units — CEN-J25's stored denominator.
    #[must_use]
    pub const fn sigma_work(&self) -> SigmaWorkMilli {
        self.sigma_work
    }

    /// The bonds the gather credited at `E` that it excluded from the
    /// market as complete trees — the flag frozen at the pass, which a
    /// claim's re-gather reads in place of the record's (`SO-D12h`). The
    /// empty set is written like any other.
    #[must_use]
    pub const fn complete_trees(&self) -> &CompleteTreeSet {
        &self.complete_trees
    }
}
