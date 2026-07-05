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

use std::collections::BTreeMap;

use shekyl_archival_retention::consensus_state::{epoch_close_height, settlement_epoch_at_height};
use shekyl_engine_state::pscan_cursor::PScanCursor;
use shekyl_engine_state::pscan_state::{BondPostRecord, PFundingOutputRecord, PScanState};
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
    /// `Debug` like the matches.
    funding_outputs: Vec<FundingOutputMatch>,
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

    /// The SP-6 reconcile evidence: the matched bond-posts bound to the verified
    /// `covered` range they were gathered over. Constructible only here, from the
    /// accrual's own verification-gated `covered` — so 2d-2 SP-R0 receives a match set
    /// it cannot reason about absence beyond (`absence ≠ unscanned`). The matches are
    /// complete over `covered` because the scan is exhaustive across it.
    #[allow(dead_code)] // transient — the consumer is 2d-2 SP-R0's reconcile GC.
    pub(crate) fn reconcile_set(&self) -> PReconcileSet {
        PReconcileSet::from_verified_scan(self.covered, self.bond_post_matches.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS;

    use crate::engine::pscan::reconcile::ReconcileVerdict;
    use crate::engine::pscan::scan_step::{BlockRange, EpochInflowDelta, ScanStepResult};

    /// A funding-only scan-step result over `[start, end)` carrying `deltas`.
    fn step(start: u64, end: u64, deltas: &[(u64, u64)]) -> ScanStepResult {
        ScanStepResult {
            range: BlockRange::new(BlockHeight::from_raw(start), BlockHeight::from_raw(end))
                .expect("range"),
            funding: deltas
                .iter()
                .map(|&(e, a)| EpochInflowDelta {
                    epoch: SettlementEpoch::from_raw(e),
                    amount: AtomicUnits::from_raw(a),
                })
                .collect(),
            bond_post_matches: Vec::new(),
            funding_outputs: Vec::new(),
        }
    }

    fn epoch(e: u64) -> SettlementEpoch {
        SettlementEpoch::from_raw(e)
    }

    const SEB: u64 = SETTLEMENT_EPOCH_BLOCKS;

    fn match_post(height: u64, id: u8, kind: u8) -> BondPostMatch {
        BondPostMatch {
            height: BlockHeight::from_raw(height),
            p_canonical_id: PCanonicalId::from_bytes([id; 32]),
            post_kind: kind,
        }
    }

    /// A scan step over `[start, end)` carrying `matches` (no funding).
    fn match_step(start: u64, end: u64, matches: Vec<BondPostMatch>) -> ScanStepResult {
        ScanStepResult {
            range: BlockRange::new(BlockHeight::from_raw(start), BlockHeight::from_raw(end))
                .expect("range"),
            funding: Vec::new(),
            bond_post_matches: matches,
            funding_outputs: Vec::new(),
        }
    }

    #[test]
    fn accumulates_matches_and_builds_a_reconcile_set_over_the_verified_covered() {
        let mut acc = PScanAccrual::genesis();
        acc.ingest(
            &match_step(0, 5, vec![match_post(2, 0xAA, 0)]),
            &VerifiedBatch::for_test(0, 5, [0x01; 32]),
        )
        .expect("batch 1");
        acc.ingest(
            &match_step(5, 9, vec![match_post(6, 0xBB, 2)]),
            &VerifiedBatch::for_test(5, 9, [0x02; 32]),
        )
        .expect("batch 2");

        let set = acc.reconcile_set();
        // `covered` is the cumulative [0, 9) the verified batches advanced it to.
        assert_eq!(set.covered().low(), BlockHeight::from_raw(0));
        assert_eq!(set.covered().high(), BlockHeight::from_raw(9));
        assert_eq!(set.matches().len(), 2);
        assert_eq!(
            set.reconcile(
                PCanonicalId::from_bytes([0xAA; 32]),
                BlockHeight::from_raw(2)
            ),
            ReconcileVerdict::Present {
                height: BlockHeight::from_raw(2),
                post_kind: 0,
            }
        );
        // A persona never matched, queried in-range → provably absent.
        assert_eq!(
            set.reconcile(
                PCanonicalId::from_bytes([0xEE; 32]),
                BlockHeight::from_raw(3)
            ),
            ReconcileVerdict::AbsentWithinCovered
        );
    }

    #[test]
    fn ingest_refuses_a_verified_batch_that_does_not_meet_the_frontier() {
        // The structural guard: `covered` only grows behind a `VerifiedBatch` that
        // *contiguously meets* the frontier. A verified range that skips it is refused
        // (FrontierGap) rather than recording a `covered` with an unverified hole — so a
        // future fast-forward can't widen the verified frontier without verification.
        let mut acc = PScanAccrual::genesis();
        acc.ingest(&step(0, 5, &[]), &VerifiedBatch::for_test(0, 5, [0u8; 32]))
            .expect("batch 1");
        let err = acc
            .ingest(&step(5, 9, &[]), &VerifiedBatch::for_test(6, 9, [0u8; 32]))
            .expect_err("a verified range that skips the frontier must be refused");
        assert!(
            matches!(err, AccrualError::FrontierGap { .. }),
            "got {err:?}"
        );
        assert_eq!(
            acc.next_height(),
            BlockHeight::from_raw(5),
            "the frontier did not advance over the refused batch"
        );
        assert_eq!(
            acc.reconcile_set().covered().high(),
            BlockHeight::from_raw(5),
            "covered did not widen over the refused batch"
        );
    }

    #[test]
    fn matches_and_covered_round_trip_through_to_state_from_state() {
        let mut acc = PScanAccrual::genesis();
        acc.ingest(
            &match_step(0, 7, vec![match_post(3, 0xAA, 0), match_post(5, 0xBB, 2)]),
            &VerifiedBatch::for_test(0, 7, [0x42; 32]),
        )
        .expect("ingest");
        let back = PScanAccrual::from_state(&acc.to_state());
        assert_eq!(
            back, acc,
            "matches + covered survive the seal round-trip (covered reconstructed from the sealed frontier)"
        );
        assert_eq!(
            back.reconcile_set().covered().high(),
            BlockHeight::from_raw(7)
        );
        assert_eq!(back.reconcile_set().matches().len(), 2);
    }

    #[test]
    fn bond_post_match_debug_is_redacted() {
        let rendered = format!("{:?}", match_post(123_456, 0xAB, 2));
        assert!(
            rendered.contains("redacted"),
            "Debug must redact persona history: {rendered}"
        );
        assert!(
            !rendered.contains("123456") && !rendered.contains("171"),
            "neither the height nor the id byte may appear: {rendered}"
        );
    }

    #[test]
    fn ingest_accumulates_across_steps_and_advances_the_frontier() {
        // Two steps within epoch 0, then a step finishing it.
        let mut acc = PScanAccrual::genesis();
        acc.ingest(
            &step(0, 4_000, &[(0, 100)]),
            &VerifiedBatch::for_test(0, 4_000, [0u8; 32]),
        )
        .expect("step1");
        acc.ingest(
            &step(4_000, SEB, &[(0, 50)]),
            &VerifiedBatch::for_test(4_000, SEB, [0u8; 32]),
        )
        .expect("step2");
        assert_eq!(acc.next_height(), BlockHeight::from_raw(SEB));
        // Epoch 0 is now finalized (close == SEB <= frontier) → 100 + 50.
        let inflow = acc.finalized_inflow(epoch(0)).expect("epoch 0 finalized");
        assert_eq!(inflow.epoch(), epoch(0));
        assert_eq!(inflow.atomic(), AtomicUnits::from_raw(150));
    }

    #[test]
    fn finalized_inflow_refuses_an_in_progress_epoch() {
        // Frontier mid epoch 0 ⇒ epoch 0's accrual is partial ⇒ no PFundingInflow.
        let mut acc = PScanAccrual::genesis();
        acc.ingest(
            &step(0, 4_000, &[(0, 100)]),
            &VerifiedBatch::for_test(0, 4_000, [0u8; 32]),
        )
        .expect("partial");
        assert!(
            acc.finalized_inflow(epoch(0)).is_none(),
            "an in-progress epoch must not yield a (partial) PFundingInflow"
        );
    }

    #[test]
    fn finalized_empty_epoch_is_a_real_zero_distinct_from_unfinalized() {
        // Scan past epoch 0 with nothing of ours in it.
        let mut acc = PScanAccrual::genesis();
        acc.ingest(
            &step(0, SEB, &[(1, 5)]),
            &VerifiedBatch::for_test(0, SEB, [0u8; 32]),
        )
        .expect("ingest");
        // Epoch 0 finalized with no funding → Some(ZERO); epoch 1 in progress → None.
        assert_eq!(
            acc.finalized_inflow(epoch(0))
                .expect("epoch 0 finalized")
                .atomic(),
            AtomicUnits::ZERO
        );
        assert!(
            acc.finalized_inflow(epoch(1)).is_none(),
            "epoch 1 in progress"
        );
    }

    #[test]
    fn resume_from_a_sealed_state_continues_without_double_count() {
        // Scan a partial epoch 0, seal, "crash" (snapshot → reload), then finish it.
        let mut acc = PScanAccrual::genesis();
        acc.ingest(
            &step(0, 6_000, &[(0, 50)]),
            &VerifiedBatch::for_test(0, 6_000, [0u8; 32]),
        )
        .expect("step1");
        let sealed = acc.to_state();

        let mut resumed = PScanAccrual::from_state(&sealed);
        assert_eq!(resumed.next_height(), BlockHeight::from_raw(6_000));
        // Still partial after reload — the guard holds across a crash.
        assert!(resumed.finalized_inflow(epoch(0)).is_none());

        // Continue from the frontier to the epoch boundary — same epoch accrues.
        resumed
            .ingest(
                &step(6_000, SEB, &[(0, 25)]),
                &VerifiedBatch::for_test(6_000, SEB, [0u8; 32]),
            )
            .expect("step2");
        assert_eq!(
            resumed
                .finalized_inflow(epoch(0))
                .expect("finalized")
                .atomic(),
            AtomicUnits::from_raw(75),
            "resume must continue the accrual, not double-count or drop it"
        );
    }

    #[test]
    fn rejects_a_non_contiguous_step() {
        let mut acc = PScanAccrual::genesis(); // frontier = 0
        let err = acc
            .ingest(
                &step(5, 6, &[(0, 1)]),
                &VerifiedBatch::for_test(5, 6, [0u8; 32]),
            )
            .expect_err("a gap must fail closed");
        assert_eq!(
            err,
            AccrualError::NonContiguous {
                frontier: BlockHeight::from_raw(0),
                step_start: BlockHeight::from_raw(5),
            }
        );
    }

    #[test]
    fn accrual_overflow_fails_closed() {
        let mut acc = PScanAccrual::genesis();
        acc.ingest(
            &step(0, 1, &[(0, u64::MAX)]),
            &VerifiedBatch::for_test(0, 1, [0u8; 32]),
        )
        .expect("near-max");
        let err = acc
            .ingest(
                &step(1, 2, &[(0, 1)]),
                &VerifiedBatch::for_test(1, 2, [0u8; 32]),
            )
            .expect_err("overflow must fail closed");
        assert_eq!(err, AccrualError::InflowOverflow { epoch: epoch(0) });
    }

    #[test]
    fn ingest_overflow_is_a_no_op_so_a_retry_cannot_double_count() {
        // Epoch 0 seeded near the ceiling; the frontier sits at height 1.
        let mut acc = PScanAccrual::genesis();
        acc.ingest(
            &step(0, 1, &[(0, u64::MAX)]),
            &VerifiedBatch::for_test(0, 1, [0x11; 32]),
        )
        .expect("seed epoch 0 near max");

        // A batch whose deltas would partially apply under a naive loop: a benign
        // epoch-1 delta lands first, then an epoch-0 delta overflows. With atomic
        // ingest the whole batch is rejected and `self` is untouched.
        let err = acc
            .ingest(
                &step(1, 2, &[(1, 5), (0, 1)]),
                &VerifiedBatch::for_test(1, 2, [0x22; 32]),
            )
            .expect_err("the overflowing delta must reject the batch");
        assert_eq!(err, AccrualError::InflowOverflow { epoch: epoch(0) });

        // No partial mutation: the benign epoch-1 delta did NOT survive, the frontier
        // did not advance, and the anchor was not changed — so the sweep's retry of
        // [1, 2) re-ingests from a clean state instead of double-counting.
        let sealed = acc.to_state();
        assert_eq!(
            sealed.accrual_for(epoch(1)),
            AtomicUnits::ZERO,
            "the benign delta from the failed batch must not have been applied"
        );
        assert_eq!(
            sealed.accrual_for(epoch(0)),
            AtomicUnits::from_raw(u64::MAX),
            "epoch 0 is unchanged by the rejected batch"
        );
        assert_eq!(
            acc.next_height(),
            BlockHeight::from_raw(1),
            "the frontier did not advance over the rejected batch"
        );
        assert_eq!(
            acc.frontier_hash(),
            [0x11; 32],
            "the verified-frontier anchor was not changed by the rejected batch"
        );
    }

    #[test]
    fn to_state_then_from_state_round_trips() {
        let mut acc = PScanAccrual::genesis();
        // A non-zero frontier hash so the round-trip exercises the verified-frontier
        // anchor, not just the height.
        acc.ingest(
            &step(0, 10, &[(0, 7), (2, 9)]),
            &VerifiedBatch::for_test(0, 10, [0x42; 32]),
        )
        .expect("ingest");
        acc.record_unbond(PCanonicalId::from_bytes([0x11; 32]), epoch(0));
        assert_eq!(acc.frontier_hash(), [0x42; 32]);
        let back = PScanAccrual::from_state(&acc.to_state());
        assert_eq!(
            back, acc,
            "the in-memory accrual (incl. frontier hash + pending unbonds) mirrors the persisted state"
        );
        assert_eq!(
            back.frontier_hash(),
            [0x42; 32],
            "the verified-frontier anchor round-trips through the seal"
        );
    }

    /// WI-2 D-A1: per-output funding records accumulate through `ingest` and
    /// survive the `to_state` → `from_state` seal round-trip unchanged (the
    /// funding-selection substrate is durable).
    #[test]
    fn funding_outputs_accumulate_and_round_trip_through_the_seal() {
        let record = FundingOutputMatch {
            p_slot: 3,
            tx_hash: [0xAA; 32],
            index_in_transaction: 1,
            gindex: 42,
            output_key: [0xBB; 32],
            commitment: [0xCC; 32],
            ciphertext_x25519: [0xDD; 32],
            ciphertext_ml_kem: vec![0xEE; 4],
            amount: AtomicUnits::from_raw(500),
            height: BlockHeight::from_raw(5),
            epoch: epoch(0),
        };
        let mut acc = PScanAccrual::genesis();
        let mut step = step(0, 10, &[(0, 500)]);
        step.funding_outputs = vec![record.clone()];
        acc.ingest(&step, &VerifiedBatch::for_test(0, 10, [0x42; 32]))
            .expect("ingest");
        assert_eq!(acc.funding_outputs(), &[record.clone()]);

        let back = PScanAccrual::from_state(&acc.to_state());
        assert_eq!(
            back.funding_outputs(),
            &[record],
            "the funding-selection substrate survives the seal round-trip"
        );
        assert_eq!(back, acc);
    }

    #[test]
    fn settled_epoch_excludes_the_in_progress_frontier_epoch() {
        let mut acc = PScanAccrual::genesis();
        assert_eq!(acc.settled_epoch(), None, "no epoch closed yet");
        // Edge case (the retire-boundary off-by-one): frontier EXACTLY on the epoch-2
        // boundary (`2·SEB`) — epoch 1 fully scanned, epoch 2 not yet started. The
        // just-completed epoch is settled; the empty in-progress epoch is not. Guards
        // against a cursor-shape change silently shifting the boundary by one.
        acc.ingest(
            &step(0, 2 * SEB, &[]),
            &VerifiedBatch::for_test(0, 2 * SEB, [0u8; 32]),
        )
        .expect("to edge");
        assert_eq!(
            acc.settled_epoch(),
            Some(epoch(1)),
            "on the epoch boundary, the just-completed epoch settles, not the in-progress one"
        );
        // Frontier mid epoch 2 (2·SEB + 1): still epochs 0,1 settled; epoch 2 in progress.
        acc.ingest(
            &step(2 * SEB, 2 * SEB + 1, &[]),
            &VerifiedBatch::for_test(2 * SEB, 2 * SEB + 1, [0u8; 32]),
        )
        .expect("past edge");
        assert_eq!(
            acc.settled_epoch(),
            Some(epoch(1)),
            "the latest settled epoch is the one before the in-progress frontier epoch"
        );
    }

    #[test]
    fn record_unbond_is_idempotent_and_durable() {
        let id = PCanonicalId::from_bytes([0xAB; 32]);
        let mut acc = PScanAccrual::genesis();
        acc.record_unbond(id, epoch(5));
        // Re-seeing the same persona keeps the first recorded epoch.
        acc.record_unbond(id, epoch(9));
        assert_eq!(acc.pending_unbonds().get(&id), Some(&epoch(5)));

        // It survives a seal + reload (the durable retire-trigger).
        let back = PScanAccrual::from_state(&acc.to_state());
        assert_eq!(back.pending_unbonds().get(&id), Some(&epoch(5)));
    }
}
