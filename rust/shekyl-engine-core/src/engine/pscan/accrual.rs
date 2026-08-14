// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SP-5 (PR-B) — [`PScanAccrual`]: the task's in-memory scan accrual, the
//! **accumulate** side of the Design-B crash-recovery decision, and
//! [`PFundingInflow`], the **finalized** per-epoch funding signal it guards.
//!
//! Mirrors the persisted [`PScanState`] exactly — a frontier [`BlockHeight`] plus
//! the per-[`SettlementEpoch`] accumulated confirmed funding — so the task seals
//! [`to_state`](PScanAccrual::to_state) atomically after each ingest.
//!
//! ## Accumulate, and why it is idempotent — via *atomic coupling*
//!
//! Each [`ScanStepResult`] carries public per-epoch *amount deltas* (the secret
//! outputs never crossed the actor boundary, so the task cannot refold over a
//! complete set the way SP-4's recompute did). [`ingest`](PScanAccrual::ingest)
//! adds those deltas to the running per-epoch totals and advances the frontier.
//!
//! Idempotency rests on **atomic coupling**, not a fold: the task seals
//! `(frontier, accruals)` in **one** atomic write ([`PScanState`]), so the two
//! advance together-or-not-at-all. Divergence is therefore *unrepresentable*. On a
//! crash, either the step's write landed (frontier *and* accrual both past the
//! range → resume re-scans nothing of it) or it did not (both *before* it → resume
//! re-adds the range for the first time). A re-scan can only ever re-add a range
//! whose accrual-add *also* did not persist — so accumulation never double-counts.
//!
//! This is **stronger** than the two-step "persist outputs, then seal the cursor"
//! write-discipline SP-2 originally specified: there is no ordering between two
//! writes to get wrong, because there is one write. The same one-atomic-file
//! design that contains the secrets (PR-A) is what makes accumulate safe.
//!
//! Finality is the cursor's invariant: the task scans only behind the reorg
//! horizon, so every accrued range is finality-confirmed. The frontier epoch's
//! accrual is nonetheless **partial** until the cursor passes it — see
//! [`finalized_inflow`](PScanAccrual::finalized_inflow) for the type-level guard.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_archival_retention::consensus_state::{epoch_close_height, settlement_epoch_at_height};
use shekyl_engine_state::pscan_cursor::PScanCursor;
use shekyl_engine_state::pscan_state::{
    BondPostRecord, PFundingOutputRecord, PScanState, RetiredPersonaRecord,
};
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch};
use shekyl_units::AtomicUnits;

use super::exhaustiveness::{VerifiedBatch, VerifiedRange};
use super::reconcile::PReconcileSet;
use super::scan_step::{BondPostMatch, FundingOutputMatch, ScanStepResult};

/// Per-epoch `P` funding inflow — the **finalized** confirmed amount that funded
/// `P` in one settlement epoch, the signal the cover's `C_min` (earnings ramp)
/// reads (SP-7).
///
/// ## The finalization guard (the type's job, post-recompute)
///
/// SP-4 made the inflow idempotent by *recompute over a complete output set*.
/// PR-A's firewall architecture made that impossible in the task — the secret
/// outputs never cross the actor boundary, only public deltas do — so the inflow
/// is *accumulated* (see [`PScanAccrual`]). Accumulation has one trap recompute
/// did not: the epoch the cursor is currently in has only a **partial** accrual,
/// and a partial read mis-sizes `C_min` — a DQ7-class firewall-parameter
/// corruption, not a benign rounding error.
///
/// `PFundingInflow` is the guard. Its constructor is **private to this module**
/// and reached **only** through [`PScanAccrual::finalized_inflow`], which refuses
/// an unfinalized epoch. So a `PFundingInflow` is *proof* its epoch is
/// finalized-and-confirmed — **confirmed** upstream by the dual extractor,
/// **finalized** by the cursor-check — and "read a partial in-progress epoch" is
/// structurally unrepresentable rather than a consumer obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // transient — the lib consumer is SP-7 `C_min` sizing.
pub(crate) struct PFundingInflow {
    settlement_epoch: SettlementEpoch,
    atomic: AtomicUnits,
}

#[allow(dead_code)] // transient — SP-7 `C_min` is the lib consumer.
impl PFundingInflow {
    /// The settlement epoch this inflow accrued in.
    pub(crate) fn epoch(&self) -> SettlementEpoch {
        self.settlement_epoch
    }

    /// The confirmed inflow amount `C_min` sizing consumes.
    pub(crate) fn atomic(&self) -> AtomicUnits {
        self.atomic
    }
}

/// Why ingesting a scan-step result into the accrual failed. Both arms fail
/// **closed** — a mis-attributed or wrapped funding total mis-sizes `C_min`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum AccrualError {
    /// The step's range did not begin exactly at the frontier — a gap or overlap
    /// that would skip or double-count blocks. The task feeds contiguous ranges;
    /// refuse rather than mis-attribute.
    #[error("non-contiguous scan step: frontier at {frontier:?}, step starts at {step_start:?}")]
    NonContiguous {
        frontier: BlockHeight,
        step_start: BlockHeight,
    },
    /// An epoch's accumulated inflow summed past `u64::MAX` (an attacker-stuffed
    /// or impossible amount set). Fail closed rather than wrap a money total.
    #[error("epoch {epoch:?} accrual overflowed u64")]
    InflowOverflow { epoch: SettlementEpoch },
    /// The verified-covered frontier did not meet the verified batch's range — the
    /// exhaustiveness-verified frontier and the scan frontier diverged (a sweep bug,
    /// not expected). Fail closed: refuse rather than record a `covered` with a gap,
    /// which would let the GC conclude absence over an unverified hole.
    #[error("verified-frontier gap: covered ends at {covered_high:?}, batch covers [{batch_low:?}, {batch_high:?})")]
    FrontierGap {
        covered_high: BlockHeight,
        batch_low: BlockHeight,
        batch_high: BlockHeight,
    },
}

/// The done-side slot ledger (SP-R0 arm #2): personas durably retired by the
/// token-corroborated retire-time prune, in retire order, plus a membership
/// index for O(log n) idempotency.
///
/// The `Vec` is the audit trail and the "stop deriving slot N" source (the open
/// path reads it), so it must persist; the `BTreeSet` is a *derived* index
/// (rebuilt from the records on load, never separately serialized) that turns
/// the per-retire idempotency check from an O(n) linear scan over an
/// append-only vector into an O(log n) lookup. Wrapping the two together makes
/// them **structurally unable to desync**: [`push`](Self::push) is the only
/// mutator and updates both, so a record is in the vector iff its id is in the
/// set.
///
/// Redacting `Debug` (the `bond_post_matches` idiom): the retired-persona set is
/// `P` persona-history and must not reach a clear log / `{:?}` path.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct RetiredLedger {
    /// The append-only done-side records (retire order) — the persisted half.
    records: Vec<RetiredPersonaRecord>,
    /// Derived membership index (`p_canonical_id`) for O(log n) idempotency;
    /// rebuilt from `records` on load, never serialized on its own.
    ids: BTreeSet<PCanonicalId>,
}

impl std::fmt::Debug for RetiredLedger {
    /// Redacted — the retired set is persona-history (see the type docs).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RetiredLedger(<redacted persona-history>)")
    }
}

impl RetiredLedger {
    /// Rebuild the ledger from its persisted records, deriving the membership
    /// index (the one place `ids` is populated other than [`push`](Self::push)).
    fn from_records(records: Vec<RetiredPersonaRecord>) -> Self {
        let ids = records.iter().map(|r| r.p_canonical_id).collect();
        Self { records, ids }
    }

    /// True if `id` is already durably retired (the O(log n) idempotency check).
    fn contains(&self, id: &PCanonicalId) -> bool {
        self.ids.contains(id)
    }

    /// Append a retired record, keeping the index in lockstep. The caller has
    /// already confirmed the id is not present ([`contains`](Self::contains)).
    fn push(&mut self, record: RetiredPersonaRecord) {
        self.ids.insert(record.p_canonical_id);
        self.records.push(record);
    }

    /// The persisted records (retire order) — the `to_state` / accessor source.
    fn records(&self) -> &[RetiredPersonaRecord] {
        &self.records
    }
}

/// The task's in-memory scan accrual: the frontier plus the per-epoch accumulated
/// confirmed funding. The mutable working copy of [`PScanState`].
///
/// `Debug` is hand-written (below) to redact `bond_post_matches` — the in-memory twin of
/// `PScanState`'s persona-history, under the same no-clear-`Debug` discipline (including
/// its count), symmetric to the redacted [`BondPostMatch`]/`BondPostRecord` records.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PScanAccrual {
    /// The scan frontier: every block below this height has been scanned and its
    /// confirmed funding folded into `accruals`.
    synced_height: BlockHeight,
    /// The recomputed hash of the last verified block (`block[synced_height − 1]`),
    /// or `[0; 32]` at genesis — the anchor the next batch must chain to (SP-6
    /// exhaustiveness). Advances together with `synced_height` (the verified
    /// `(height, hash)` frontier); mirrors [`PScanCursor::frontier_hash`].
    frontier_hash: [u8; 32],
    /// The cumulative **verified-covered** range `[0, synced_height)` — the range half
    /// of the SP-6 reconcile evidence. It is a [`VerifiedRange`] *token*, deliberately
    /// **not** derived from `synced_height`: it grows only through
    /// [`VerifiedRange::extend`], which requires a [`VerifiedBatch`], so the frontier
    /// cannot widen without verification (the structural guard against a future
    /// fast-forward minting `covered` over an unverified range → forged-absence GC).
    /// `ingest` advances it; `from_state` restores it from the sealed frontier.
    covered: VerifiedRange,
    /// Per settlement-epoch accumulated confirmed funding.
    accruals: BTreeMap<SettlementEpoch, AtomicUnits>,
    /// Confirmed-but-retire-pending personas ([`PCanonicalId`] → confirmed
    /// `Unbond` epoch). The durable record that survives restart and re-triggers
    /// the DQ8 retire — kept until SP-6 durably removes the persona (see
    /// [`PScanState::pending_unbonds`]).
    pending_unbonds: BTreeMap<PCanonicalId, SettlementEpoch>,
    /// Matched bond-posts accumulated across the scan — the **matches half** of the
    /// SP-6 reconcile evidence (`p_canonical_id` ∈ `P`'s personas), durable via
    /// [`PScanState::bond_post_matches`]. The most privacy-sensitive field here — a row
    /// of `P`'s persona-activity history — so [`BondPostMatch`] carries a redacting
    /// `Debug` (no clear log/`{:?}` path), unlike the public amount-deltas.
    bond_post_matches: Vec<BondPostMatch>,
    /// Per-output funding-discovery records (WI-2 D-A1) accumulated across the
    /// scan — the funding-selection substrate for production bond assembly,
    /// durable via [`PScanState::funding_outputs`]. Public output identity only
    /// (no derived secrets), but a row of `P`'s funding history — redacted
    /// `Debug` like the matches. SP-R0 arm #1 prunes confirmed-spent records
    /// out of it at ingest; their durable removal is their absence from the
    /// next seal.
    funding_outputs: Vec<FundingOutputMatch>,
    /// SP-R0 arm #1 fire counter: total spent funding records pruned by
    /// [`ingest`](Self::ingest) this run. **Not persisted** (the durable record
    /// is the pruned records' absence from the seal); this is the DQ-F
    /// logic-discharge observer — the CI fire lane asserts it non-zero after
    /// driving a real spend through the production scan path.
    spent_pruned_total: u64,
    /// The done-side slot ledger mirror (SP-R0 arm #2): personas durably
    /// retired by the token-corroborated retire-time prune. Append-only records
    /// plus a derived membership index ([`RetiredLedger`]) for O(log n) retire
    /// idempotency. Its unbounded growth is inherent, not a leak: the records
    /// are the durable "stop deriving slot N" source the open path reads, so a
    /// retired slot must stay listed for the life of the wallet or it would be
    /// re-derived back into the scan union.
    retired: RetiredLedger,
    /// SP-R0 arm #2 fire counter: personas durably retired this run (the
    /// DQ-F observer; not persisted — the durable record is the
    /// retired-record row plus the pruned rows' absence from the seal).
    retired_pruned_total: u64,
    /// Per-persona **watch floors** — id → the first scanned height the
    /// persona was watched at (the frontier when it entered the scan union).
    /// The provenance half of the reconcile evidence: `bond_post_matches` is
    /// complete only over the personas watched while `covered` advanced, so
    /// an absence claim for a persona is sound only over `[floor, high)`.
    /// Written once per persona at its first ingested step, never updated;
    /// durable via [`PScanState::watch_floors`].
    watch_floors: BTreeMap<PCanonicalId, BlockHeight>,
}

impl std::fmt::Debug for PScanAccrual {
    /// Redacts `bond_post_matches` to a constant placeholder (not even its length) — the
    /// persona-history must not leak its count through a `{:?}` / log path. Other fields
    /// render normally (`frontier_hash` / `covered` are public chain state).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PScanAccrual")
            .field("synced_height", &self.synced_height)
            .field("frontier_hash", &self.frontier_hash)
            .field("covered", &self.covered)
            .field("accruals", &self.accruals)
            .field("pending_unbonds", &self.pending_unbonds)
            .field("bond_post_matches", &"<redacted persona-history>")
            .field("funding_outputs", &"<redacted funding-history>")
            .field("spent_pruned_total", &self.spent_pruned_total)
            .field("retired", &self.retired)
            .field("retired_pruned_total", &self.retired_pruned_total)
            .field("watch_floors", &"<redacted persona-history>")
            .finish()
    }
}

impl PScanAccrual {
    /// A fresh accrual at genesis — pre-scan, no funding, no pending unbonds, an empty
    /// covered range, no matches.
    pub(crate) fn genesis() -> Self {
        Self {
            synced_height: BlockHeight::ZERO,
            frontier_hash: [0u8; 32],
            covered: VerifiedRange::genesis_empty(),
            accruals: BTreeMap::new(),
            pending_unbonds: BTreeMap::new(),
            bond_post_matches: Vec::new(),
            funding_outputs: Vec::new(),
            spent_pruned_total: 0,
            retired: RetiredLedger::default(),
            retired_pruned_total: 0,
            watch_floors: BTreeMap::new(),
        }
    }

    /// Resume from a loaded [`PScanState`] (crash recovery): the sealed frontier,
    /// the already-accumulated accruals, the pending unbonds (which re-trigger the
    /// retire), and the accumulated bond-post matches (the reconcile evidence). The
    /// task re-scans from [`next_height`](Self::next_height).
    ///
    /// `covered` is restored to `[0, synced_height)` from the sealed frontier — the one
    /// seal-trust boundary (see [`VerifiedRange::reconstruct_from_sealed_frontier`]):
    /// the *live* advance is verification-gated, so a sealed `synced_height` could only
    /// have been reached through verification, and restoring its range trusts our own
    /// prior seal exactly as loading `synced_height` does.
    pub(crate) fn from_state(state: &PScanState) -> Self {
        Self {
            synced_height: state.synced_height(),
            frontier_hash: state.cursor().frontier_hash(),
            covered: VerifiedRange::reconstruct_from_sealed_frontier(state.synced_height()),
            accruals: state.accruals().clone(),
            pending_unbonds: state.pending_unbonds().clone(),
            bond_post_matches: state
                .bond_post_matches()
                .iter()
                .map(|r| BondPostMatch {
                    height: r.height,
                    p_canonical_id: r.p_canonical_id,
                    post_kind: r.post_kind,
                })
                .collect(),
            funding_outputs: state
                .funding_outputs()
                .iter()
                .map(FundingOutputMatch::from)
                .collect(),
            spent_pruned_total: 0,
            retired: RetiredLedger::from_records(state.retired_records().to_vec()),
            retired_pruned_total: 0,
            watch_floors: state.watch_floors().clone(),
        }
    }

    /// The next height to scan — the frontier itself (ranges are half-open, so the
    /// frontier is the first unscanned height). The task scans `[next_height, …)`.
    pub(crate) fn next_height(&self) -> BlockHeight {
        self.synced_height
    }

    /// The verified-frontier anchor: the recomputed hash of the last verified block
    /// (`[0; 32]` at genesis). The sweep passes this to `verify_exhaustive` as the
    /// hash the next batch's first block must chain to.
    pub(crate) fn frontier_hash(&self) -> [u8; 32] {
        self.frontier_hash
    }

    /// Ingest one scan-step result against its [`VerifiedBatch`]: accumulate the
    /// confirmed per-epoch funding deltas and the matched bond-posts, and advance the
    /// frontier — height, `frontier_hash`, **and** the verified-`covered` range — to the
    /// step's end. `synced_height`, `frontier_hash`, and `covered` advance **together**.
    ///
    /// Takes the `verified` batch **by reference, not a bare frontier hash**, on
    /// purpose: it is the only thing that extends `covered`, and a `VerifiedBatch` exists
    /// only because [`verify_exhaustive`](super::exhaustiveness::verify_exhaustive)
    /// produced it. So the verified frontier cannot advance without verification — the
    /// structural guard that keeps `covered`'s "everything below here was verified"
    /// honest, rather than a number anyone could move.
    ///
    /// The step's range **must begin at the frontier** — a gap would skip blocks, an
    /// overlap would double-count. That contiguity, plus the monotone frontier and the
    /// atomic seal, is what makes accumulation idempotent (see the module docs on atomic
    /// coupling). Fails closed on a verified-frontier ↔ scan-frontier divergence
    /// (`FrontierGap`) rather than recording a `covered` with an unverified hole.
    pub(crate) fn ingest(
        &mut self,
        result: &ScanStepResult,
        verified: &VerifiedBatch,
    ) -> Result<(), AccrualError> {
        if result.range.start() != self.synced_height {
            return Err(AccrualError::NonContiguous {
                frontier: self.synced_height,
                step_start: result.range.start(),
            });
        }
        // Stage every delta against the live totals BEFORE mutating `self`, so a
        // later-delta overflow cannot leave earlier deltas partially applied. `ingest`
        // is **all-or-nothing**: a failed ingest is a no-op, so when `run_pscan_task`
        // retries a non-exhaustiveness error and re-ingests the same range, there is no
        // partially-applied prefix to double-count. This is the in-memory twin of the
        // seal's atomic coupling — the accrual advances together-or-not-at-all, exactly
        // as the persisted `(frontier, accruals)` pair does. `staged` holds only the
        // epochs this batch touches (one or two), not the whole map.
        let mut staged: BTreeMap<SettlementEpoch, AtomicUnits> = BTreeMap::new();
        for delta in &result.funding {
            let base = staged
                .get(&delta.epoch)
                .copied()
                .or_else(|| self.accruals.get(&delta.epoch).copied())
                .unwrap_or(AtomicUnits::ZERO);
            let updated = base
                .checked_add(delta.amount)
                .ok_or(AccrualError::InflowOverflow { epoch: delta.epoch })?;
            staged.insert(delta.epoch, updated);
        }
        // Advance the verified-covered frontier through the VERIFIED batch — the only
        // grow path. Fail closed if it does not contiguously meet the scanned range
        // (`extend` checks the low; the `filter` checks the high == scan end), so a
        // scan/verify divergence can never record a `covered` with an unverified hole.
        let new_covered = self
            .covered
            .extend(verified)
            .filter(|c| c.high() == result.range.end())
            .ok_or(AccrualError::FrontierGap {
                covered_high: self.covered.high(),
                batch_low: verified.range().low(),
                batch_high: verified.range().high(),
            })?;
        // Every delta validated and the frontier extended — commit atomically. The
        // matches append rides the same all-or-nothing commit as the accruals and the
        // frontier advance, so a retried sweep re-ingests from a clean state.
        self.accruals.extend(staged);
        self.bond_post_matches
            .extend(result.bond_post_matches.iter().cloned());
        self.funding_outputs
            .extend(result.funding_outputs.iter().cloned());
        // SP-R0 arm #1 prune-at-ingest (DQ-B): drop held records whose spend
        // arm (c) observed in this (finality-deep) step. After the extend, so
        // a discover-then-spend within one step nets to no record. The
        // removal's durable form is absence from the next seal — the same
        // one-atomic-write coupling that makes accumulation idempotent makes
        // the prune crash-self-healing: a prune lost to a pre-seal crash is
        // re-detected when the unsealed range re-scans. Infallible, so it
        // rides the all-or-nothing commit section.
        if !result.spent_funding.is_empty() {
            let spent: std::collections::BTreeSet<shekyl_types::GlobalOutputIndex> =
                result.spent_funding.iter().map(|s| s.gindex).collect();
            let before = self.funding_outputs.len();
            self.funding_outputs.retain(|m| !spent.contains(&m.gindex));
            self.spent_pruned_total += (before - self.funding_outputs.len()) as u64;
        }
        // Watch provenance: a persona entering the scan union is floored at
        // this step's start — the first height its absence evidence is valid
        // from. Insert-once (the floor never moves); rides the all-or-nothing
        // commit section (infallible).
        for persona in &result.watched_personas {
            self.watch_floors
                .entry(*persona)
                .or_insert_with(|| result.range.start());
        }
        self.synced_height = result.range.end();
        self.frontier_hash = verified.frontier_hash();
        self.covered = new_covered;
        Ok(())
    }

    /// The **finalized** funding inflow for `epoch`, or `None` if it is not yet
    /// fully scanned behind the frontier.
    ///
    /// This is the only constructor of [`PFundingInflow`]: the accrual for the
    /// epoch the cursor is currently in is a **partial** sum, so it refuses unless
    /// the epoch's close height `(epoch+1)·SETTLEMENT_EPOCH_BLOCKS` is at or behind
    /// the frontier. A finalized epoch with no funding of ours yields
    /// `Some(`[`AtomicUnits::ZERO`]`)` — a real, complete zero, distinct from the
    /// `None` of an unfinalized epoch.
    #[allow(dead_code)] // transient — the lib consumer is SP-7 `C_min` sizing.
    pub(crate) fn finalized_inflow(&self, epoch: SettlementEpoch) -> Option<PFundingInflow> {
        // The first height past `epoch` (its close); finalized iff the frontier
        // has reached it. Checked — an absurdly-distant epoch can't be finalized.
        // Single-sourced close-boundary formula (shared with the consensus crate) rather
        // than a hand-inlined `(epoch+1)·SEB`, so this genesis-frozen mapping can't drift.
        // `None` on overflow (an absurdly-distant epoch can't be finalized) — fail closed.
        let epoch_end = epoch_close_height(epoch.to_raw())?;
        if epoch_end > self.synced_height.to_raw() {
            return None; // frontier still inside (or before) this epoch → partial
        }
        let atomic = self
            .accruals
            .get(&epoch)
            .copied()
            .unwrap_or(AtomicUnits::ZERO);
        Some(PFundingInflow {
            settlement_epoch: epoch,
            atomic,
        })
    }

    /// Record a confirmed `Unbond` for a persona (2d-1 DQ8) — `p_canonical_id` →
    /// the settlement epoch it was confirmed in. Idempotent: re-seeing the same
    /// Unbond keeps the recorded epoch (a persona unbonds once; the block is never
    /// re-scanned). Kept until SP-6 durably removes the persona — never dropped on
    /// retire, since this is the sole durable "known-unbonded" record.
    pub(crate) fn record_unbond(
        &mut self,
        p_canonical_id: PCanonicalId,
        unbond_epoch: SettlementEpoch,
    ) {
        self.pending_unbonds
            .entry(p_canonical_id)
            .or_insert(unbond_epoch);
    }

    /// The confirmed-but-retire-pending personas — the task iterates these and
    /// builds a `RetirementWitness` per entry (the witness's claim-window check is
    /// the eligibility gate; entries that aren't yet expired yield no witness).
    pub(crate) fn pending_unbonds(&self) -> &BTreeMap<PCanonicalId, SettlementEpoch> {
        &self.pending_unbonds
    }

    /// The latest **finalized settled** settlement epoch — the epoch *before* the
    /// frontier epoch (the frontier epoch is in-progress, not settled), or `None`
    /// before the first epoch closes. This is the finalized epoch the retire
    /// predicate must use (never the in-progress cursor epoch, which would fire
    /// early), the same finalization discipline as [`finalized_inflow`].
    pub(crate) fn settled_epoch(&self) -> Option<SettlementEpoch> {
        settlement_epoch_at_height(self.synced_height.to_raw())
            .checked_sub(1)
            .map(SettlementEpoch::from_raw)
    }

    /// Snapshot to the persisted [`PScanState`] for sealing — cursor + accruals +
    /// pending unbonds + bond-post matches as one atomic unit (the write half of the
    /// SP-2 discipline). The matches convert to their state-shaped twin
    /// [`BondPostRecord`] at this seam (rule 18); `covered` is not serialized — it is
    /// `[0, synced_height)` and `from_state` reconstructs it from the sealed frontier.
    pub(crate) fn to_state(&self) -> PScanState {
        PScanState::new(
            PScanCursor::at(self.synced_height, self.frontier_hash),
            self.accruals.clone(),
            self.pending_unbonds.clone(),
            self.bond_post_matches
                .iter()
                .map(|m| BondPostRecord {
                    height: m.height,
                    p_canonical_id: m.p_canonical_id,
                    post_kind: m.post_kind,
                })
                .collect(),
            self.funding_outputs
                .iter()
                .map(PFundingOutputRecord::from)
                .collect(),
            self.retired.records().to_vec(),
            self.watch_floors.clone(),
        )
    }

    /// The discovered `P`-owned funding outputs behind the verified frontier —
    /// the funding-selection substrate for production bond assembly (WI-2 D-A2).
    /// Public output identity only; spend secrets are re-derived at assemble
    /// time inside the actor.
    #[allow(dead_code)] // transient — the consumer is WI-2's funding selection.
    pub(crate) fn funding_outputs(&self) -> &[FundingOutputMatch] {
        &self.funding_outputs
    }

    /// SP-R0 arm #1 fire counter — total spent funding records pruned by
    /// [`ingest`](Self::ingest) this run (see the field docs; the DQ-F
    /// logic-discharge lane asserts this non-zero).
    // Consumers (`arm1_fire`, the accrual tests) exist only under
    // `test-helpers` / `cfg(test)`; a plain dependency build sees no caller.
    #[allow(dead_code)]
    pub(crate) fn spent_pruned_total(&self) -> u64 {
        self.spent_pruned_total
    }

    /// SP-R0 **arm #2** — the atomic retire-time prune (the 2D2 §15 pin:
    /// *"in the same atomic step"*). Drops the persona's `bond_post_matches`
    /// rows and `pending_unbonds` entry and appends the
    /// [`RetiredPersonaRecord`] — one in-memory mutation, persisted by the next
    /// seal's one atomic write (the same coupling that makes accumulation
    /// idempotent makes the prune crash-safe: either the whole retire lands or
    /// the durable `pending_unbonds` trigger survives and the retire re-fires).
    ///
    /// This is the bound on the unbounded growth of `bond_post_matches` —
    /// `P`'s persona-activity history, the most privacy-sensitive structure
    /// in the state. The caller (the scan task) has already: (a) confirmed
    /// the retire via the actor wipe (`RetireOutcome::Retired`), and (b)
    /// corroborated the claim-window expiry against the DQ-D canonicity
    /// token — this function is the *removal*, not the trigger (the SP-R0
    /// framing pin).
    ///
    /// **Funded-gate invariant.** The actor refuses to wipe a slot that still
    /// holds unspent funding (returns `RetireOutcome::SkippedFunded` instead of
    /// `Retired`), so a slot reaching this call is already drained and the
    /// `funding_outputs` retain below drops *zero* rows. That is the load-bearing
    /// property: the actor wipe is irreversible and the open path stops deriving
    /// a retired slot, so wiping a *funded* slot would strand spendable `P`
    /// funds. The retain is kept as defense-in-depth (a future path that bypassed
    /// the gate must not leave a phantom, unspendable funding row behind a wiped,
    /// never-re-derived slot), guarded by a `debug_assert` that the invariant held.
    pub(crate) fn retire_persona(
        &mut self,
        id: PCanonicalId,
        slot: shekyl_types::PSlot,
        unbond_epoch: SettlementEpoch,
        retired_epoch: SettlementEpoch,
    ) -> bool {
        if self.retired.contains(&id) {
            return false; // idempotent: already durably retired (O(log n) index).
        }
        debug_assert!(
            !self.funding_outputs.iter().any(|f| f.p_slot == slot),
            "funded-gate: a retiring slot must hold no unspent funding output",
        );
        self.bond_post_matches.retain(|m| m.p_canonical_id != id);
        self.funding_outputs.retain(|f| f.p_slot != slot);
        self.pending_unbonds.remove(&id);
        self.retired.push(RetiredPersonaRecord {
            p_slot: slot,
            p_canonical_id: id,
            unbond_epoch,
            retired_epoch,
        });
        self.retired_pruned_total += 1;
        true
    }

    /// Test-only pending-unbond seeder (the production writer is
    /// `record_unbonds` in the scan task, fed by real `Unbond` matches).
    #[cfg(test)]
    pub(crate) fn record_pending_unbond_for_test(
        &mut self,
        id: PCanonicalId,
        epoch: SettlementEpoch,
    ) {
        self.pending_unbonds.insert(id, epoch);
    }

    /// The accumulated bond-post matches (the reconcile-evidence rows) —
    /// exposed for the arm-#2 prune assertions.
    #[cfg(test)]
    pub(crate) fn bond_post_matches(&self) -> &[BondPostMatch] {
        &self.bond_post_matches
    }

    /// SP-R0 arm #2 fire counter (see the field docs).
    // rule-21: the non-test consumer is the arm-#2 production-discharge lane
    // (PR-4b-gated regtest); until it lands the counter is asserted by the
    // task-level tests.
    #[allow(dead_code)]
    pub(crate) fn retired_pruned_total(&self) -> u64 {
        self.retired_pruned_total
    }

    /// The done-side slot ledger (retired personas, in retire order).
    // rule-21: same consumer as the fire counter above.
    #[allow(dead_code)]
    pub(crate) fn retired_records(&self) -> &[RetiredPersonaRecord] {
        self.retired.records()
    }

    /// Personas with a reorg-deep **JoinMarket** bond-post match — the WI-3
    /// dispatch driver's confirmation set (`ARCHIVAL_BOND_WI3_DISPATCH.md`
    /// §3.5). Every match here came out of our own verified, exhaustive scan
    /// below the finality horizon — never a daemon claim — which is what makes
    /// it safe to retire a pending post (and release its funding reservation)
    /// against.
    pub(crate) fn confirmed_join_market_personas(
        &self,
    ) -> std::collections::BTreeSet<PCanonicalId> {
        // `m.post_kind` is the wire byte the extractor recorded (`post_kind_byte`
        // in `scan_step`), so compare against the wire crate's own JoinMarket
        // constant — the *same* definition that produced the byte. Comparing to an
        // unrelated `archival_retention::BondPostKind::JoinMarket as u8` would only
        // coincidentally agree (both map to 0 today) and could silently diverge if
        // either enum were reordered.
        self.bond_post_matches
            .iter()
            .filter(|m| m.post_kind == shekyl_wire::transaction::BOND_POST_KIND_JOINMARKET)
            .map(|m| m.p_canonical_id)
            .collect()
    }

    /// The SP-6 reconcile evidence: the matched bond-posts bound to the verified
    /// `covered` range they were gathered over, **plus the per-persona watch
    /// floors** that scope the completeness claim. Constructible only here, from
    /// the accrual's own verification-gated `covered` — so 2d-2 SP-R0 receives a
    /// match set it cannot reason about absence beyond (`absence ≠ unscanned`,
    /// and per-persona: absence ≠ scanned-unwatched). The matches are complete
    /// over `covered` *for each persona only from its floor onward*, because the
    /// scan is exhaustive across `covered` but watched only the union it held at
    /// each step.
    #[allow(dead_code)] // transient — the consumer is 2d-2 SP-R0's reconcile GC.
    pub(crate) fn reconcile_set(&self) -> PReconcileSet {
        PReconcileSet::from_verified_scan(
            self.covered,
            self.bond_post_matches.clone(),
            self.watch_floors.clone(),
        )
    }
}

#[cfg(test)]
#[path = "accrual_tests.rs"]
mod tests;
