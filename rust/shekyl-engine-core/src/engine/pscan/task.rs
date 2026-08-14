// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SP-5 (PR-B) — the driving `P`-scan task: the loop that assembles the layer.
//!
//! Owns the cursor (via [`PScanAccrual`]), an injected cadence
//! ([`ScanSchedule`]), a [`BlockSource`], and a [`PScanStore`]; messages the
//! `view_sk`-vault [`StakeEngineHandle`] for the offloaded scan-step. Per cadence
//! tick it runs one **catch-up sweep**: fetch each bounded range behind the
//! finality horizon, dual-extract, accumulate, record/act on `Unbond`s, and seal
//! `(cursor, accruals, pending_unbonds)` atomically after each step (the SP-2
//! write-discipline). `view_sk` never crosses the actor boundary; only public
//! results do.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use shekyl_archival_retention::consensus_state::settlement_epoch_at_height;
use shekyl_archival_retention::{BondPostKind, ARCHIVAL_REORG_DEPTH_BLOCKS};
use shekyl_engine_state::pscan_state::PScanState;
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch};
use tokio_util::sync::CancellationToken;

use super::accrual::{AccrualError, PScanAccrual};
use super::block_source::{BlockSource, BlockSourceError};
use super::cadence::ScanSchedule;
use super::dispatch::{DispatchError, DispatchTick};
use super::exhaustiveness::{verify_exhaustive, ExhaustivenessError};
use super::scan_step::{BlockRange, BondPostMatch, FundingOutputMatch, MAX_SCAN_STEP_BLOCKS};
use crate::engine::stake_engine::{
    FundedSlots, RetireOutcome, RetirementWitness, StakeEngineError, StakeEngineHandle,
};

/// The wire post-kind byte of an `Unbond` bond-post — the terminal post that makes
/// a persona retire-eligible (DQ8). Single-sourced from the consensus
/// [`BondPostKind`] enum, which *is* the on-chain byte assignment; `shekyl-wire`
/// transports that byte unchanged (`Other(b)`), so the comparison in
/// [`record_unbonds`] is the consensus definition, not a parallel constant.
///
/// **Genesis-dormant.** `shekyl-wire` is JoinMarket-only at genesis
/// (`shekyl_wire::transaction::BondPostKind`), so no `Unbond` post is wire-valid
/// yet — this retire path is forward-looking and cannot fire until `Unbond` posts
/// are added to the wire post-genesis. The byte equivalence (wire `Other(2)` ==
/// `BondPostKind::Unbond as u8`) is pinned by a `scan_step` test so the two crates'
/// assignments cannot drift before the wire format freezes.
const UNBOND_POST_KIND: u8 = BondPostKind::Unbond as u8;

/// Default per-step batch size — the bounded `ScanStep` the actor offloads (DQ6).
/// Well under [`MAX_SCAN_STEP_BLOCKS`]; sized to interleave rotation/sign between
/// batches. Tuning, not architecture (2d-2 may revisit against worst-case blocks).
const DEFAULT_PSCAN_BATCH_BLOCKS: u64 = 128;

/// Tuning knobs for the scan loop. The production path takes the consensus
/// finality depth; tests inject a small horizon so they need not build a
/// reorg-depth-deep chain.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PScanConfig {
    /// Blocks below `tip` the scan stays behind — the finality horizon. Production
    /// is `ARCHIVAL_REORG_DEPTH_BLOCKS` (the consensus const); a smaller value is a
    /// weaker finality guarantee and must only be used in tests.
    pub reorg_depth: u64,
    /// Blocks per bounded scan-step. Must be `1..=MAX_SCAN_STEP_BLOCKS`.
    pub batch_blocks: u64,
}

impl PScanConfig {
    /// The production config: the consensus finality depth + the default batch.
    pub(crate) fn production() -> Self {
        Self {
            reorg_depth: ARCHIVAL_REORG_DEPTH_BLOCKS,
            batch_blocks: DEFAULT_PSCAN_BATCH_BLOCKS,
        }
    }

    /// The bounded batch, clamped into `1..=MAX_SCAN_STEP_BLOCKS` (a 0 or oversized
    /// batch would stall or never progress).
    fn batch(&self) -> u64 {
        self.batch_blocks.clamp(1, MAX_SCAN_STEP_BLOCKS)
    }
}

/// Single-flight slot for the per-wallet `P`-scan task — mirrors
/// [`RefreshSlot`](crate::engine::refresh::RefreshSlot). At most one scan task runs
/// per wallet, so two `start_pscan` calls cannot race read-modify-seal on the same
/// `.wallet.pscan` (the atomic-coupling idempotency in [`PScanAccrual`] defends a
/// crash — one writer — not two concurrent writers). Cloneable; the slot is
/// reference-counted — the engine holds one handle, the running task's
/// [`PScanSlotGuard`] holds another for its lifetime.
#[derive(Clone, Debug)]
pub(crate) struct PScanSlot {
    flag: Arc<AtomicBool>,
}

impl PScanSlot {
    /// A fresh slot in the released state. Built once at `Engine::assemble`.
    pub(crate) fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Claim the slot, or `None` if a scan task already holds it. Single CAS
    /// (`Acquire` on success, pairs with the guard's `Release` on drop).
    pub(crate) fn try_claim(&self) -> Option<PScanSlotGuard> {
        match self
            .flag
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        {
            Ok(_) => Some(PScanSlotGuard {
                flag: self.flag.clone(),
            }),
            Err(_) => None,
        }
    }

    /// Whether a scan task currently holds the slot (for the engine's `Debug`).
    pub(crate) fn is_claimed(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }
}

/// RAII guard for [`PScanSlot`]. Held by the running task; `Drop` releases the slot
/// whether the task returned, was cancelled, or panicked. Not `Clone` — the claim
/// is unique, which is the point of single-flight.
#[derive(Debug)]
pub(crate) struct PScanSlotGuard {
    flag: Arc<AtomicBool>,
}

impl Drop for PScanSlotGuard {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

/// The durable sink for `P`'s scan state — the `.wallet.pscan` seal, behind a
/// trait so the loop is testable with an in-memory store and the engine layer
/// supplies the [`WalletFile`](shekyl_engine_file::WalletFile)-backed impl.
///
/// **Async** because the production impl reaches the live `WalletFile` — held by
/// value inside the `Engine` (no `Arc`, not `Clone`) — through the
/// `Arc<RwLock<Engine>>` under a brief read lock (the seal stays single-sourced in
/// `WalletFile::save_pscan_state`, per seam choice (b)). RPITIT `+ Send` mirrors
/// `PersistenceEngine` so the futures cross the `tokio::spawn` boundary.
pub(crate) trait PScanStore: Send + Sync + 'static {
    /// The store's failure type (rendered into [`PScanTaskError::Store`]).
    type Error: std::error::Error + Send + Sync + 'static;

    /// Load the sealed state, or `None` for a wallet that has never scanned as `P`
    /// (the loop then starts at [`PScanAccrual::genesis`]).
    fn load(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<PScanState>, Self::Error>> + Send;

    /// Seal the state to the `P`-isolated file (cursor + accruals + pending
    /// unbonds, one atomic write).
    fn save(
        &self,
        state: &PScanState,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;
}

/// Why the scan loop failed. Transient I/O is fatal to a single sweep; the loop
/// logs and retries on the next cadence tick.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PScanTaskError {
    /// The per-`P` block source failed (transport / parse / daemon).
    #[error("block source failed: {0}")]
    BlockSource(#[from] BlockSourceError),
    /// The scan-step actor (or the retire) failed.
    #[error("stake engine failed: {0}")]
    StakeEngine(#[from] StakeEngineError),
    /// Folding a step into the accrual failed (non-contiguous / overflow).
    #[error("accrual failed: {0}")]
    Accrual(#[from] AccrualError),
    /// Sealing the P-scan state failed. Boxed (not stringified) so the store's
    /// typed error stays walkable as a `source()` chain for tracing.
    #[error("persisting the P-scan state failed: {0}")]
    Store(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// A block below the finality horizon was absent — a withholding/short source.
    /// The 2d-1 `DaemonBlockSource` cannot *prove* absence, so this is a fetch
    /// failure, not a proven gap (SP-7's root-anchored job).
    #[error("block {height} missing below the finality horizon")]
    MissingBlock { height: u64 },
    /// The end-of-sweep dispatch tick failed to seal the pending-post block
    /// (WI-3 §4 row 2: the error is logged, no send happened, and the tick
    /// retries on the next sweep — every scan batch this sweep already
    /// sealed, so nothing is lost).
    #[error("bond-post dispatch tick failed: {0}")]
    Dispatch(#[from] DispatchError),
    /// Chain-exhaustiveness verification failed: a fetched batch did not chain to the
    /// stored verified frontier, or a body did not match its committed hash.
    ///
    /// **This is unlike every other arm: it is fatal to the *task*, not just the
    /// sweep.** The scan stays below `ARCHIVAL_REORG_DEPTH_BLOCKS`, so **given an
    /// honest tip** the verified frontier sits beneath the reorg horizon and an
    /// ordinary reorg cannot reach it — a mismatch is then a **beyond-finality
    /// anomaly**. That finality-depth is *conditional*: the horizon is `tip −
    /// reorg_depth` where `tip` is the source's **claimed** height (tip-honesty is a
    /// posture / 2d-2 property, not one this layer establishes alone). Under an
    /// over-claiming source the horizon is too high, the frontier can sit *within*
    /// reorg range, and this mismatch may instead be an **ordinary reorg** — still
    /// correctly caught as a halt, because 2d-1 cannot distinguish the two and a loud
    /// halt is the safe response to both. Either way [`run_pscan_task`] **halts
    /// loudly** instead of retrying: it does not rewind the cursor and does not
    /// re-derive the anchor (either would be the resume-splice the verified
    /// `(height, hash)` frontier exists to forbid — the cursor's `frontier_hash` is the
    /// only anchor a forging source cannot change). Resolution is a posture / 2d-2
    /// concern, not a re-fetch.
    #[error("chain-exhaustiveness verification failed: {0}")]
    Exhaustiveness(#[from] ExhaustivenessError),
}

/// Run one **catch-up sweep**: scan every bounded range from the accrual frontier
/// up to the finality horizon (`tip − reorg_depth`), accumulating funding,
/// recording `Unbond`s, retiring eligible terminal personas, and sealing after
/// each step. Idempotent across crashes by atomic coupling (see [`PScanAccrual`]).
// Eight parameters: three collaborators (source/stake/store), three pieces of
// per-task mutable state (accrual/retired/dispatch), config, cancel. Bundling
// them into a struct would only relocate the same list; the internal call has
// exactly one production caller ([`run_pscan_task`]) plus tests.
#[allow(clippy::too_many_arguments)]
async fn pscan_sweep<B, S, D>(
    block_source: &B,
    stake: &StakeEngineHandle,
    store: &S,
    accrual: &mut PScanAccrual,
    retired_this_session: &mut BTreeSet<PCanonicalId>,
    dispatch: &mut D,
    config: &PScanConfig,
    cancel: &CancellationToken,
) -> Result<(), PScanTaskError>
where
    B: BlockSource + Sync,
    S: PScanStore,
    D: DispatchTick,
{
    let tip = block_source.tip_height().await?;
    // Finality horizon: scan only blocks behind `tip − reorg_depth`, so every
    // accrued range and every witnessed Unbond is reorg-deep.
    let horizon = tip.to_raw().saturating_sub(config.reorg_depth);
    let batch = config.batch();

    // Observability: when the horizon is at or below the frontier the loop below never runs
    // and the sweep returns `Ok(())`. The COMMON cause is benign — the frontier has caught
    // up to the finality horizon, so there are simply no new reorg-deep blocks to scan this
    // tick (normal steady-state). The same condition also covers a young chain
    // (`tip < reorg_depth`) or a source claiming a stale/truncated tip — but those are only
    // distinguishable when *persistent* (the SP-7 tip-honesty residual, deferred to 2d-2).
    // Emit a neutral trace so a persistently-idle scan is visible without painting normal
    // catch-up as tip dishonesty; it is not an error (the safe action is to keep waiting —
    // never re-fund/GC on a stale tip), so it stays at `trace`.
    let frontier = accrual.next_height().to_raw();
    if horizon <= frontier {
        tracing::trace!(
            tip = tip.to_raw(),
            horizon,
            frontier,
            "P-scan sweep: frontier reached the finality horizon — no new final blocks this tick \
             (normal when caught up; only a persistently non-advancing horizon indicates a young \
             chain or a stale/withheld tip)"
        );
    }

    // SP-R0 arm #1: the held-funding list rides every `ScanStep` (the actor's
    // watch-cache refresh needs the authoritative list). Snapshot it once as a
    // shared slice and re-snapshot only when an ingest changed it — the
    // steady-state step then sends an `Arc` bump instead of deep-cloning every
    // record's ~1 KB ML-KEM ciphertext per batch of a long catch-up.
    let mut held_funding: Arc<[FundingOutputMatch]> = accrual.funding_outputs().into();
    while accrual.next_height().to_raw() < horizon {
        // Cancellation is checked per batch, not just between sweeps: a cold-start
        // catch-up is many batches, and shutdown must not wait for the whole sweep.
        // Each batch already sealed, so bailing mid-catch-up loses no progress.
        if cancel.is_cancelled() {
            return Ok(());
        }
        let start = accrual.next_height().to_raw();
        let end = start.saturating_add(batch).min(horizon);
        // `start < horizon` (loop guard) and `batch >= 1`, so `start < end <= horizon`:
        // the range is non-empty and within the batch bound — `new` cannot fail here.
        let range = BlockRange::new(BlockHeight::from_raw(start), BlockHeight::from_raw(end))
            .expect("start < end by loop invariant");

        // `end - start` is the bounded batch (≤ MAX_SCAN_STEP_BLOCKS), so it fits
        // `usize`; preallocate to avoid repeated reallocation as blocks are fetched.
        let mut blocks = Vec::with_capacity(usize::try_from(end - start).unwrap_or(0));
        for height in start..end {
            let block = block_source
                .block_at(BlockHeight::from_raw(height))
                .await?
                .ok_or(PScanTaskError::MissingBlock { height })?;
            // Tripwire only: the scan trusts the *anchored* position (`height`), never
            // the coinbase's self-claimed height, so a height-lying block is not
            // exploitable here — but in tests a source serving misaligned blocks should
            // fail fast, and this documents that the two are expected to agree.
            debug_assert_eq!(
                block.block.number(),
                Some(height),
                "coinbase self-claimed height must match the anchored fetch position"
            );
            blocks.push(block);
        }

        // SP-6 exhaustiveness gate (seam choice (b)): before extracting anything,
        // prove this batch chains to *our own sealed* verified frontier and that
        // every body matches its committed hash. The anchor is the stored
        // `frontier_hash`, never a freshly re-derived one — re-deriving it would let
        // a source splice a different chain at the resume boundary (and under
        // no-wallet-PoW a fabricated fork is free, so the stored hash is the only
        // thing a forging source cannot change). A failure halts the task loudly
        // (the `?` lifts it via `#[from]` into `PScanTaskError::Exhaustiveness`); the
        // cursor never advances past it. The verified batch hands back the recomputed
        // frontier hash, so the new anchor is the value continuity chained through —
        // not a separate re-hash of the last block that must merely agree.
        //
        // This gate is deliberately run in the *task*, before the blocks enter the
        // actor — keeping the public exhaustiveness check out of the `view_sk` context
        // and making it decide whether the secret scan runs at all. The cost is one
        // extra pass over the batch (hash here, decode in the actor), the right trade
        // for the firewall boundary. It hashes inline rather than via `spawn_blocking`
        // like `scan_step`; bounded by `MAX_SCAN_STEP_BLOCKS` that is fine, and it is
        // the natural second offload candidate if batch sizes ever grow materially.
        let verified = verify_exhaustive(
            BlockHeight::from_raw(start),
            accrual.frontier_hash(),
            &blocks,
        )?;

        // Offloaded dual extraction behind the actor; only public results
        // return. The held-funding list (as of the frontier) rides along so
        // the actor can refresh its key-image watch cache (SP-R0 arm #1,
        // DQ-A) before the step runs.
        let result = stake
            .scan_step(range, blocks, Arc::clone(&held_funding))
            .await?;
        // Ingest against the *verified batch* (not a bare hash): it is what advances the
        // accrual's verified-`covered` range, so the frontier can only move behind a
        // `VerifiedBatch` (the structural reconcile-evidence guard).
        accrual.ingest(&result, &verified)?;
        // Re-snapshot the shared held list only when this ingest changed it
        // (a discovery extended it, a prune shrank it) — `ingest` is the only
        // mutator of `funding_outputs`, so an unchanged step reuses the
        // snapshot.
        if !result.funding_outputs.is_empty() || !result.spent_funding.is_empty() {
            held_funding = accrual.funding_outputs().into();
        }
        record_unbonds(accrual, &result.bond_post_matches);

        // Seal (cursor + accruals + pending unbonds + bond-post matches) atomically —
        // the write half of the SP-2 discipline, after every step so a crash re-scans
        // at most one batch. `to_state()` clones the maps + the match vec, but that
        // clone is not the cost here: it is dwarfed by the postcard serialize + AEAD
        // seal + `atomic_write_file` fsync. Note the growth profiles differ — `accruals`
        // is bounded (~1 entry per 10k-block settlement epoch, hundreds over the chain),
        // but `bond_post_matches` grows per matched bond-post, so for a long-lived active
        // operator it can reach thousands of tiny rows, not hundreds. Still small in
        // absolute terms; the lever if per-batch persistence ever profiles hot is seal
        // *cadence* (trade the at-most-one-batch crash re-scan), not a borrowed-codec
        // micro-opt. Keeping the persisted `PScanState` (engine-state) distinct from the
        // working `PScanAccrual` (engine-core) is worth the clone.
        store
            .save(&accrual.to_state())
            .await
            .map_err(|e| PScanTaskError::Store(Box::new(e)))?;

        // Retire AFTER the seal, not before — **seal-then-act**. `retire_bonded_persona`
        // irreversibly wipes the persona's bond_spend key in the actor; its durable
        // *trigger* is the `pending_unbonds` entry just sealed above. Sealing first means a
        // crash between seal and wipe leaves the trigger durable (the retire re-fires from
        // it on restart, the persona re-derives from seed), whereas wiping first could lose
        // the trigger if the seal never landed. The wipe is idempotent (re-firing re-wipes),
        // so applying it after the seal is safe; the ordering makes the irreversible side
        // effect strictly follow the durability of what justifies it.
        // SP-R0 arm #2: the retire pass may durably prune (the atomic
        // retire-time removal of a *drained* slot's bond-post rows + pending
        // trigger + retired-record append). Re-seal promptly so the prune's
        // durable form lands now rather than a sweep later; a crash in between is
        // safe either way (the pending trigger re-fires). This second seal fires
        // ONLY on a pruning step (rare — a persona reaching claim-window expiry),
        // so the two-seals-per-step cost is not the common case: every step pays
        // the one cursor-durability seal above; only a pruning step pays this
        // extra prune-durability seal. Both are load-bearing under seal-then-act
        // (the first makes the wipe recoverable, the second makes the prune
        // durable); collapsing them would re-introduce the crash windows each
        // guards. The lever if this ever profiles hot is seal *cadence*, as noted
        // above — not merging these two.
        if dispatch_retires(stake, accrual, retired_this_session, cancel, tip, *config).await? {
            // Re-snapshot the held-funding list the actor watches. The funded-gate
            // keeps retire from ever pruning `funding_outputs` (it fires only for a
            // drained slot), so this is defensive — but it guarantees the actor's
            // key-image watch cache can never be handed a wiped persona's outputs
            // even if a future path pruned funding at retire.
            held_funding = accrual.funding_outputs().into();
            store
                .save(&accrual.to_state())
                .await
                .map_err(|e| PScanTaskError::Store(Box::new(e)))?;
        }
    }

    // WI-3 end-of-sweep dispatch tick (§3.1): rides *this sweep's own* tip read
    // — no second network fetch, no separate timer task — and hands the driver
    // the accrual's reorg-deep JoinMarket confirmations (§3.5: our own verified
    // scan, never a daemon claim). Runs after the catch-up loop so a due-check
    // against a fresh tip never races the same sweep's confirmation retire.
    dispatch
        .on_tick(tip, &accrual.confirmed_join_market_personas(), cancel)
        .await?;
    Ok(())
}

/// Record every confirmed `Unbond` in a step's bond-post matches into the
/// accrual's durable pending set (the sole durable "known-unbonded" record).
fn record_unbonds(accrual: &mut PScanAccrual, matches: &[BondPostMatch]) {
    for m in matches {
        if m.post_kind == UNBOND_POST_KIND {
            // Record the **containing** epoch (floor division). Load-bearing for the
            // stuck-funds guard: `dispatch_retires` feeds this as `e_last` to
            // `RetirementWitness::from_confirmed_unbond`, whose claim-window check rounds
            // **conservatively** (toward a later expiry). Recording the *settling* epoch
            // instead would silently shorten the window → premature retire → stuck funds.
            // Keep it the containing epoch — see the conservative `e_last` contract at the
            // witness builder.
            let unbond_epoch =
                SettlementEpoch::from_raw(settlement_epoch_at_height(m.height.to_raw()));
            accrual.record_unbond(m.p_canonical_id, unbond_epoch);
        }
    }
}

/// Retire every pending persona whose claim window has closed against the
/// **finalized** settled epoch. The witness's [`epoch_is_claim_expired`] check is
/// the eligibility gate. The pending entry's fate then splits with the DQ-D
/// token (SP-R0 arm #2): under a **corroborated** durable prune,
/// `retire_persona` **removes** it in the same mutation that writes the
/// retired-record — the trigger has served its purpose; when the prune is
/// **deferred** (token uncorroborated, or the wipe skipped), the entry is
/// **kept** as the durable retire-trigger — suppressed for the rest of this
/// session via `retired_this_session`, re-firing on the re-derived persona
/// after a restart (Finding 1).
///
/// [`epoch_is_claim_expired`]: shekyl_archival_retention::epoch_is_claim_expired
async fn dispatch_retires(
    stake: &StakeEngineHandle,
    accrual: &mut PScanAccrual,
    retired_this_session: &mut BTreeSet<PCanonicalId>,
    cancel: &CancellationToken,
    claimed_tip: BlockHeight,
    config: PScanConfig,
) -> Result<bool, PScanTaskError> {
    let Some(settled) = accrual.settled_epoch() else {
        return Ok(false); // no epoch settled yet → nothing can have expired
    };
    // SP-R0 arm #2, DQ-D: the canonicity token for the IRREVERSIBLE durable
    // prune — the sweep-corroborated tip clamp, min(claimed_tip,
    // verified_frontier + reorg_depth), held in reserve since WI-3 R2-1 and
    // consumed here as **corroboration** (records-driven: the trigger is the
    // wallet's own pending record; the token only corroborates that the
    // claim-window expiry is not an artifact of a forged-high verified view
    // — a source lying LOW merely defers the prune, fail-safe). The actor
    // key-wipe keeps its existing frontier basis (idempotent + re-derivable);
    // only the durable removal takes the token gate.
    let token_height = claimed_tip.to_raw().min(
        accrual
            .next_height()
            .to_raw()
            .saturating_add(config.reorg_depth),
    );
    let token_settled = settlement_epoch_at_height(token_height)
        .checked_sub(1)
        .map(SettlementEpoch::from_raw);
    let mut pruned_any = false;
    // The funded-gate operand: the set of slots that still hold unspent funding.
    // Never wipe one of these — the actor wipe is irreversible and the open path
    // stops deriving a retired slot, so wiping a funded slot would strand
    // spendable `P` funds (the funding-output analog of the claim-window
    // stuck-funds guard the witness already enforces). Snapshotted once: nothing
    // in this loop mutates `funding_outputs` (retire_persona only drops a
    // *drained* slot's rows, of which there are none), so it stays consistent
    // across the candidates.
    // Built once per retire pass; each candidate's message clones the
    // pointer, not the set (the sweep can carry thousands of candidates).
    let funded_slots = std::sync::Arc::new(FundedSlots::from_slots(
        accrual.funding_outputs().iter().map(|f| f.p_slot),
    ));
    // Snapshot the candidates so the await loop holds no borrow of `accrual`.
    let candidates: Vec<(PCanonicalId, SettlementEpoch)> = accrual
        .pending_unbonds()
        .iter()
        .filter(|&(id, _)| !retired_this_session.contains(id))
        .map(|(&id, &unbond)| (id, unbond))
        .collect();

    for (id, unbond_epoch) in candidates {
        // Shutdown responsiveness: the candidate set can be large (the module notes
        // thousands of rows for a long-lived operator) and each retire is an actor
        // round-trip, so a cancel must not wait for the whole list to drain. A half-done
        // pass is safe — pending entries are durable and re-fire next sweep.
        if cancel.is_cancelled() {
            return Ok(pruned_any);
        }
        // `e_last = unbond_epoch` (conservative); the witness exists only if it has
        // fallen out of the claim window.
        let Some(witness) = RetirementWitness::from_confirmed_unbond(id, unbond_epoch, settled)
        else {
            continue; // not yet expired — re-checked on a later sweep
        };
        // DQ-D corroboration for the DURABLE side, shared by both wiped arms.
        let corroborated = token_settled.is_some_and(|ts| {
            RetirementWitness::from_confirmed_unbond(id, unbond_epoch, ts).is_some()
        });
        match stake
            .retire_bonded_persona(witness, std::sync::Arc::clone(&funded_slots))
            .await?
        {
            // Wiped: the actor side is done (the slot was drained, per the
            // funded-gate). The durable side (arm #2) runs only under the token
            // corroboration. Without it the wipe still fired but the durable
            // prune is deferred — `retired_this_session` suppresses re-attempt
            // for the rest of THIS session, and the surviving `pending_unbonds`
            // trigger re-fires the retire after a **restart** (the persona is not
            // in `retired_records`, so it re-derives at the next open, the actor
            // holds it again, and the now-corroborated sweep prunes). Not "a later
            // sweep" — the session dedup below blocks that.
            RetireOutcome::Retired { slot } => {
                retired_this_session.insert(id);
                if corroborated && accrual.retire_persona(id, slot, unbond_epoch, settled) {
                    pruned_any = true;
                }
            }
            // Already gone from the union this session. No durable prune
            // here: if a prior session's wipe ran but its prune seal never
            // landed, the un-pruned `bonded_slots` hint re-derives the
            // persona at the next open, the actor holds it again, and the
            // retire re-fires through the `Retired { slot }` arm above — the
            // durable prune always eventually flows through the arm that
            // knows the slot.
            RetireOutcome::NotHeld => {
                retired_this_session.insert(id);
            }
            // Deferred, not retired — leave the pending trigger and, deliberately,
            // do NOT add to `retired_this_session`: we want to re-check on a later
            // sweep once the blocking condition clears. Two blocking conditions,
            // both meaning "not safe to wipe yet":
            //   - `SkippedActive`: the slot is the active persona; retry once
            //     rotation moves `active` away (a terminal persona should not be
            //     active, but we never wipe it mid-use).
            //   - `SkippedFunded`: the slot still holds unspent funding (the
            //     funded-gate); wiping it would strand the funds. Retry once the
            //     funding is drained (arm #1 prunes the last funding output on its
            //     spend and the slot leaves `funded_slots`).
            RetireOutcome::SkippedActive { .. } | RetireOutcome::SkippedFunded { .. } => {}
        }
    }
    Ok(pruned_any)
}

/// The long-running `P`-scan task: resume from `initial` (the state `start_pscan`
/// loaded, or `None` for genesis), then loop — wait for the injected cadence, run
/// one catch-up sweep, repeat — until cancelled. A sweep failure is **logged and
/// retried** on the next tick (a transient transport blip must not kill the
/// firewalled scan) — with **one exception**: a [`PScanTaskError::Exhaustiveness`]
/// failure (the served chain diverged from the sealed verified frontier below the
/// finality horizon) **halts the task loudly** instead of retrying, because a
/// beyond-finality anomaly cannot clear by re-fetching and a silent retry would risk
/// absorbing a resume-splice.
///
/// `_slot_guard` is the single-flight claim ([`PScanSlot`]); it is held for the
/// task's whole life and releases the slot on exit (cancel or panic), so the next
/// `start_pscan` can claim. The initial load is done by `start_pscan` (not here),
/// so a corrupt/version-mismatched seal surfaces as a `start_pscan` error rather
/// than a silent task death.
// `too_many_arguments`: each is a distinct spawn input (source, vault, store,
// cadence, config, resume-state, cancel, single-flight guard); grouping them into a
// struct would only move the same fields behind one more name. Mirrors the
// many-parameter `run_refresh_task` spawn entry-point.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_pscan_task<B, S, Sched, D>(
    block_source: B,
    stake: StakeEngineHandle,
    store: S,
    mut schedule: Sched,
    config: PScanConfig,
    initial: Option<PScanState>,
    mut dispatch: D,
    cancel: CancellationToken,
    _slot_guard: PScanSlotGuard,
) where
    B: BlockSource + Sync,
    S: PScanStore,
    Sched: ScanSchedule,
    D: DispatchTick,
{
    let mut accrual = match initial {
        Some(state) => PScanAccrual::from_state(&state),
        None => PScanAccrual::genesis(),
    };
    let mut retired_this_session: BTreeSet<PCanonicalId> = BTreeSet::new();

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            () = schedule.next_tick() => {}
        }
        if let Err(e) = pscan_sweep(
            &block_source,
            &stake,
            &store,
            &mut accrual,
            &mut retired_this_session,
            &mut dispatch,
            &config,
            &cancel,
        )
        .await
        {
            match &e {
                // The served chain diverged from our *own sealed* verified frontier.
                // Given an honest tip this is a beyond-finality anomaly (the frontier is
                // below `ARCHIVAL_REORG_DEPTH_BLOCKS` of the *real* tip, so an ordinary
                // reorg can't reach it); under an over-claiming source it may instead be
                // an ordinary reorg the too-high horizon let the frontier advance into
                // — tip-honesty is posture/2d-2 (see `PScanTaskError::Exhaustiveness`).
                // The response is the same for both, which is why halting is right:
                // retrying just re-fetches the same forked material and re-fails;
                // rewinding the cursor or re-deriving the anchor would silently absorb
                // the splice the verified frontier exists to refuse. So halt loudly and
                // let the guard release the slot — not 2d-1's to resolve.
                PScanTaskError::Exhaustiveness(_) => {
                    tracing::error!(
                        error = %e,
                        "P-scan: chain-exhaustiveness verification failed below the \
                         finality horizon — halting (no rewind, no re-fetch); resolution \
                         is a posture / 2d-2 concern"
                    );
                    return;
                }
                // Transient transport / parse / actor / seal blip: log and retry next
                // tick. A blip must not kill the firewalled scan.
                _ => tracing::warn!(error = %e, "P-scan sweep failed; retrying next tick"),
            }
        }
    }
}

#[cfg(test)]
#[path = "task_tests.rs"]
mod tests;
