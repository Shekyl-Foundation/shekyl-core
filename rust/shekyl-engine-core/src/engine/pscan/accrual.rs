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

use shekyl_archival_retention::consensus_state::settlement_epoch_at_height;
use shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS;
use shekyl_engine_state::pscan_cursor::PScanCursor;
use shekyl_engine_state::pscan_state::PScanState;
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch};
use shekyl_units::AtomicUnits;

use super::scan_step::ScanStepResult;

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
#[allow(dead_code)] // transient — surfaced through the SP-5 task's error once it lands.
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
}

/// The task's in-memory scan accrual: the frontier plus the per-epoch accumulated
/// confirmed funding. The mutable working copy of [`PScanState`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // transient — the SP-5 scan task (later commit) is the lib consumer.
pub(crate) struct PScanAccrual {
    /// The scan frontier: every block below this height has been scanned and its
    /// confirmed funding folded into `accruals`.
    synced_height: BlockHeight,
    /// The recomputed hash of the last verified block (`block[synced_height − 1]`),
    /// or `[0; 32]` at genesis — the anchor the next batch must chain to (SP-6
    /// exhaustiveness). Advances together with `synced_height` (the verified
    /// `(height, hash)` frontier); mirrors [`PScanCursor::frontier_hash`].
    frontier_hash: [u8; 32],
    /// Per settlement-epoch accumulated confirmed funding.
    accruals: BTreeMap<SettlementEpoch, AtomicUnits>,
    /// Confirmed-but-retire-pending personas ([`PCanonicalId`] → confirmed
    /// `Unbond` epoch). The durable record that survives restart and re-triggers
    /// the DQ8 retire — kept until SP-6 durably removes the persona (see
    /// [`PScanState::pending_unbonds`]).
    pending_unbonds: BTreeMap<PCanonicalId, SettlementEpoch>,
}

#[allow(dead_code)] // transient — the SP-5 scan task (later commit) is the lib consumer.
impl PScanAccrual {
    /// A fresh accrual at genesis — pre-scan, no funding, no pending unbonds.
    pub(crate) fn genesis() -> Self {
        Self {
            synced_height: BlockHeight::ZERO,
            frontier_hash: [0u8; 32],
            accruals: BTreeMap::new(),
            pending_unbonds: BTreeMap::new(),
        }
    }

    /// Resume from a loaded [`PScanState`] (crash recovery): the sealed frontier,
    /// the already-accumulated accruals, and the pending unbonds (which re-trigger
    /// the retire). The task re-scans from [`next_height`](Self::next_height).
    pub(crate) fn from_state(state: &PScanState) -> Self {
        Self {
            synced_height: state.synced_height(),
            frontier_hash: state.cursor().frontier_hash(),
            accruals: state.accruals().clone(),
            pending_unbonds: state.pending_unbonds().clone(),
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

    /// Ingest one scan-step result: accumulate its confirmed per-epoch deltas and
    /// advance the frontier to the step's end, recording `frontier_hash` (the
    /// recomputed hash of the step's last block) as the new verified-frontier
    /// anchor — `synced_height` and `frontier_hash` advance **together**.
    ///
    /// The step's range **must begin at the frontier** — a gap would skip blocks,
    /// an overlap would double-count. That contiguity, plus the monotone frontier
    /// and the atomic seal, is what makes accumulation idempotent (see the module
    /// docs on atomic coupling). The caller has already exhaustiveness-verified the
    /// step (`verify_exhaustive`) and supplies the resulting frontier hash.
    pub(crate) fn ingest(
        &mut self,
        result: &ScanStepResult,
        frontier_hash: [u8; 32],
    ) -> Result<(), AccrualError> {
        if result.range.start() != self.synced_height {
            return Err(AccrualError::NonContiguous {
                frontier: self.synced_height,
                step_start: result.range.start(),
            });
        }
        for delta in &result.funding {
            let acc = self
                .accruals
                .entry(delta.epoch)
                .or_insert(AtomicUnits::ZERO);
            *acc = acc
                .checked_add(delta.amount)
                .ok_or(AccrualError::InflowOverflow { epoch: delta.epoch })?;
        }
        self.synced_height = result.range.end();
        self.frontier_hash = frontier_hash;
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
    pub(crate) fn finalized_inflow(&self, epoch: SettlementEpoch) -> Option<PFundingInflow> {
        // The first height past `epoch` (its close); finalized iff the frontier
        // has reached it. Checked — an absurdly-distant epoch can't be finalized.
        let epoch_end = epoch
            .to_raw()
            .checked_add(1)
            .and_then(|next| next.checked_mul(SETTLEMENT_EPOCH_BLOCKS))?;
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
    /// pending unbonds as one atomic unit (the write half of the SP-2 discipline).
    pub(crate) fn to_state(&self) -> PScanState {
        PScanState::new(
            PScanCursor::at(self.synced_height, self.frontier_hash),
            self.accruals.clone(),
            self.pending_unbonds.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        }
    }

    fn epoch(e: u64) -> SettlementEpoch {
        SettlementEpoch::from_raw(e)
    }

    const SEB: u64 = SETTLEMENT_EPOCH_BLOCKS;

    #[test]
    fn ingest_accumulates_across_steps_and_advances_the_frontier() {
        // Two steps within epoch 0, then a step finishing it.
        let mut acc = PScanAccrual::genesis();
        acc.ingest(&step(0, 4_000, &[(0, 100)]), [0u8; 32])
            .expect("step1");
        acc.ingest(&step(4_000, SEB, &[(0, 50)]), [0u8; 32])
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
        acc.ingest(&step(0, 4_000, &[(0, 100)]), [0u8; 32])
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
        acc.ingest(&step(0, SEB, &[(1, 5)]), [0u8; 32])
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
        acc.ingest(&step(0, 6_000, &[(0, 50)]), [0u8; 32])
            .expect("step1");
        let sealed = acc.to_state();

        let mut resumed = PScanAccrual::from_state(&sealed);
        assert_eq!(resumed.next_height(), BlockHeight::from_raw(6_000));
        // Still partial after reload — the guard holds across a crash.
        assert!(resumed.finalized_inflow(epoch(0)).is_none());

        // Continue from the frontier to the epoch boundary — same epoch accrues.
        resumed
            .ingest(&step(6_000, SEB, &[(0, 25)]), [0u8; 32])
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
            .ingest(&step(5, 6, &[(0, 1)]), [0u8; 32])
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
        acc.ingest(&step(0, 1, &[(0, u64::MAX)]), [0u8; 32])
            .expect("near-max");
        let err = acc
            .ingest(&step(1, 2, &[(0, 1)]), [0u8; 32])
            .expect_err("overflow must fail closed");
        assert_eq!(err, AccrualError::InflowOverflow { epoch: epoch(0) });
    }

    #[test]
    fn to_state_then_from_state_round_trips() {
        let mut acc = PScanAccrual::genesis();
        // A non-zero frontier hash so the round-trip exercises the verified-frontier
        // anchor, not just the height.
        acc.ingest(&step(0, 10, &[(0, 7), (2, 9)]), [0x42; 32])
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

    #[test]
    fn settled_epoch_excludes_the_in_progress_frontier_epoch() {
        let mut acc = PScanAccrual::genesis();
        assert_eq!(acc.settled_epoch(), None, "no epoch closed yet");
        // Frontier mid epoch 2 (2·SEB + 1): epochs 0,1 settled; epoch 2 in progress.
        acc.ingest(&step(0, 2 * SEB + 1, &[]), [0u8; 32])
            .expect("ingest");
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
