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
use super::exhaustiveness::{verify_exhaustive, ExhaustivenessError};
use super::scan_step::{BlockRange, BondPostMatch, MAX_SCAN_STEP_BLOCKS};
use crate::engine::stake_engine::{
    RetireOutcome, RetirementWitness, StakeEngineError, StakeEngineHandle,
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
#[allow(dead_code)] // transient — `Engine::start_pscan` (later commit) is the lib consumer.
pub(crate) struct PScanConfig {
    /// Blocks below `tip` the scan stays behind — the finality horizon. Production
    /// is `ARCHIVAL_REORG_DEPTH_BLOCKS` (the consensus const); a smaller value is a
    /// weaker finality guarantee and must only be used in tests.
    pub reorg_depth: u64,
    /// Blocks per bounded scan-step. Must be `1..=MAX_SCAN_STEP_BLOCKS`.
    pub batch_blocks: u64,
}

#[allow(dead_code)] // transient — `Engine::start_pscan` (later commit) is the lib consumer.
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
#[allow(dead_code)] // transient — `Engine::start_pscan` (later commit) claims it.
pub(crate) struct PScanSlot {
    flag: Arc<AtomicBool>,
}

#[allow(dead_code)] // transient — `Engine::start_pscan` is the claim site.
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
#[allow(dead_code)] // transient — held by `run_pscan_task` once the Engine spawns it.
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
#[allow(dead_code)] // transient — `Engine::start_pscan` (later commit) supplies the impl.
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
#[allow(dead_code)] // transient — surfaced/logged by `run_pscan_task` / the Engine wiring.
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
#[allow(dead_code)] // transient — `run_pscan_task` is the lib consumer.
async fn pscan_sweep<B, S>(
    block_source: &B,
    stake: &StakeEngineHandle,
    store: &S,
    accrual: &mut PScanAccrual,
    retired_this_session: &mut BTreeSet<PCanonicalId>,
    config: &PScanConfig,
    cancel: &CancellationToken,
) -> Result<(), PScanTaskError>
where
    B: BlockSource + Sync,
    S: PScanStore,
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

        // Offloaded dual extraction behind the actor; only public results return.
        let result = stake.scan_step(range, blocks).await?;
        // Ingest against the *verified batch* (not a bare hash): it is what advances the
        // accrual's verified-`covered` range, so the frontier can only move behind a
        // `VerifiedBatch` (the structural reconcile-evidence guard).
        accrual.ingest(&result, &verified)?;
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
        dispatch_retires(stake, accrual, retired_this_session, cancel).await?;
    }
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
/// the eligibility gate; entries are **kept** in the accrual (the durable
/// retire-trigger) and only suppressed for the rest of this session via
/// `retired_this_session`, so the retire re-fires once on the re-derived persona
/// after a restart (Finding 1).
///
/// [`epoch_is_claim_expired`]: shekyl_archival_retention::epoch_is_claim_expired
async fn dispatch_retires(
    stake: &StakeEngineHandle,
    accrual: &PScanAccrual,
    retired_this_session: &mut BTreeSet<PCanonicalId>,
    cancel: &CancellationToken,
) -> Result<(), PScanTaskError> {
    let Some(settled) = accrual.settled_epoch() else {
        return Ok(()); // no epoch settled yet → nothing can have expired
    };
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
            return Ok(());
        }
        // `e_last = unbond_epoch` (conservative); the witness exists only if it has
        // fallen out of the claim window.
        let Some(witness) = RetirementWitness::from_confirmed_unbond(id, unbond_epoch, settled)
        else {
            continue; // not yet expired — re-checked on a later sweep
        };
        match stake.retire_bonded_persona(witness).await? {
            // Wiped, or already gone: don't re-message this session. The durable
            // pending entry stays, so it re-fires after a restart.
            RetireOutcome::Retired { .. } | RetireOutcome::NotHeld => {
                retired_this_session.insert(id);
            }
            // Terminal-but-active: never wipe the active slot mid-use; retry on a
            // later sweep once rotation moves `active` away.
            RetireOutcome::SkippedActive { .. } => {}
        }
    }
    Ok(())
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
#[allow(dead_code)]
// transient — `Engine::start_pscan` (later commit) spawns it.
// `too_many_arguments`: each is a distinct spawn input (source, vault, store,
// cadence, config, resume-state, cancel, single-flight guard); grouping them into a
// struct would only move the same fields behind one more name. Mirrors the
// many-parameter `run_refresh_task` spawn entry-point.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_pscan_task<B, S, Sched>(
    block_source: B,
    stake: StakeEngineHandle,
    store: S,
    mut schedule: Sched,
    config: PScanConfig,
    initial: Option<PScanState>,
    cancel: CancellationToken,
    _slot_guard: PScanSlotGuard,
) where
    B: BlockSource + Sync,
    S: PScanStore,
    Sched: ScanSchedule,
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
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use shekyl_archival_retention::MAX_CLAIM_AGE_W;
    use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
    use shekyl_crypto_pq::archival_p::{derive_archival_p_keys, ArchivalPKeys};
    use shekyl_crypto_pq::kem::HybridKemPublicKey;
    use shekyl_engine_state::pscan_cursor::PScanCursor;
    use shekyl_scanner::bench_fixtures::scannable_block_for_recipient;
    use shekyl_scanner::ScannableBlock;
    use shekyl_units::AtomicUnits;

    use crate::engine::pscan::scan_step::BondPostMatch;
    use crate::engine::stake_engine::{PSlot, StakeEngineHandle};
    use crate::engine::test_support::{make_synthetic_block, TestDaemon, DEFAULT_TEST_SEED};

    const SEED: [u8; MASTER_SEED_BYTES] = [0x33u8; MASTER_SEED_BYTES];

    fn persona(slot: u32) -> ArchivalPKeys {
        derive_archival_p_keys(&SEED, DerivationNetwork::Mainnet, SeedFormat::Bip39, slot)
            .expect("derive persona")
    }

    fn canonical_id(p: &ArchivalPKeys) -> PCanonicalId {
        use shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey;
        p_canonical_id_from_hybrid_pubkey(&p.hybrid_bond_id().to_canonical_bytes().expect("id"))
    }

    /// A block addressed to `recipient` (one funding output).
    fn funding_block(recipient: &ArchivalPKeys) -> ScannableBlock {
        let kem = HybridKemPublicKey {
            x25519: recipient.x25519_pk,
            ml_kem: recipient.ml_kem_ek.to_vec(),
        };
        scannable_block_for_recipient(1, &kem, recipient.spend_pk.as_canonical_bytes())
    }

    /// A chain of `len` blocks: `recipient_at[i]` (if present) is addressed to the
    /// persona; the rest are foreign dummies. Length sets the source's tip.
    ///
    /// The blocks are made **exhaustiveness-verifiable** (the sweep now runs
    /// `verify_exhaustive` before extracting): each non-miner body is committed to its
    /// real hash (the bench fixture writes a `[0xAA; 32]` placeholder, which the
    /// per-body check would reject), and each block is chained to the recomputed hash
    /// of its predecessor (anchored at the genesis `[0; 32]`). Linking is
    /// deterministic, so an identical prefix in two `chain(..)` calls produces an
    /// identical frontier hash — which is what lets the resume test carry an anchor
    /// across a rebuilt chain.
    fn chain(len: usize, recipient_blocks: &[(usize, ScannableBlock)]) -> Vec<ScannableBlock> {
        let mut c: Vec<ScannableBlock> = (0..len)
            .map(|h| make_synthetic_block(h as u64, [0u8; 32]))
            .collect();
        for (i, b) in recipient_blocks {
            c[*i] = b.clone();
        }
        let mut prev = [0u8; 32];
        for (h, sb) in c.iter_mut().enumerate() {
            // The coinbase claims its own height. The bench fixture hard-codes `Gen(0)`,
            // so set it to the position — both to keep the F5 fetch-loop tripwire honest
            // (a real coinbase claims its height) and because it is folded into the hash
            // recomputed below. The synthetic dummies already carry `Gen(h)`.
            if let Some(input) = sb.block.miner_transaction.prefix.inputs.first_mut() {
                *input = shekyl_wire::Input::Gen(h as u64);
            }
            sb.block.transaction_hashes = sb
                .transactions
                .iter()
                .map(shekyl_wire::Transaction::hash)
                .collect();
            sb.block.header.previous = prev;
            prev = sb.block.hash();
        }
        c
    }

    fn source(
        chain: Vec<ScannableBlock>,
    ) -> crate::engine::pscan::block_source::DaemonBlockSource<TestDaemon> {
        crate::engine::pscan::block_source::DaemonBlockSource::new(TestDaemon::with_seed_and_chain(
            DEFAULT_TEST_SEED,
            chain,
        ))
    }

    /// In-memory [`PScanStore`] for the loop tests.
    #[derive(Default)]
    struct MemStore(Mutex<Option<PScanState>>);

    #[derive(Debug, thiserror::Error)]
    #[error("mem store error")]
    struct MemErr;

    impl PScanStore for MemStore {
        type Error = MemErr;
        fn load(
            &self,
        ) -> impl std::future::Future<Output = Result<Option<PScanState>, MemErr>> + Send {
            // Sync work up front; the returned future is ready (no `self` borrow
            // crosses the await point, so it is trivially `Send`).
            let loaded = self.0.lock().unwrap().clone();
            async move { Ok(loaded) }
        }
        fn save(
            &self,
            state: &PScanState,
        ) -> impl std::future::Future<Output = Result<(), MemErr>> + Send {
            *self.0.lock().unwrap() = Some(state.clone());
            async move { Ok(()) }
        }
    }

    /// Spawn a StakeEngine over `bonded` persona slots.
    fn spawn_stake(bonded: &[u32]) -> StakeEngineHandle {
        let bundles: BTreeMap<PSlot, ArchivalPKeys> =
            bonded.iter().map(|&s| (PSlot(s), persona(s))).collect();
        let bonded: BTreeSet<PSlot> = bonded.iter().map(|&s| PSlot(s)).collect();
        StakeEngineHandle::spawn(bundles, bonded, None)
    }

    /// A tiny test horizon so a sweep needs only a few real blocks.
    fn cfg(reorg_depth: u64, batch_blocks: u64) -> PScanConfig {
        PScanConfig {
            reorg_depth,
            batch_blocks,
        }
    }

    #[tokio::test]
    async fn sweep_accumulates_funding_and_advances_the_cursor() {
        let p = persona(0);
        // tip = 6, horizon = 6 - 4 = 2 → scan [0, 2). Funding output in block 1.
        let c = chain(6, &[(1, funding_block(&p))]);
        let src = source(c);
        let stake = spawn_stake(&[0]);
        let store = MemStore::default();
        let mut accrual = PScanAccrual::genesis();
        let mut retired = BTreeSet::new();

        pscan_sweep(
            &src,
            &stake,
            &store,
            &mut accrual,
            &mut retired,
            &cfg(4, 1),
            &CancellationToken::new(),
        )
        .await
        .expect("sweep");

        assert_eq!(
            accrual.next_height(),
            BlockHeight::from_raw(2),
            "cursor at the horizon"
        );
        // Epoch 0 is in progress (< SETTLEMENT_EPOCH_BLOCKS), so finalized_inflow is
        // None, but the partial accrual is sealed.
        let sealed = store.load().await.expect("load").expect("sealed");
        assert_eq!(sealed.synced_height(), BlockHeight::from_raw(2));
        assert!(
            sealed.accrual_for(SettlementEpoch::from_raw(0)) > AtomicUnits::ZERO,
            "the persona's funding accumulated and sealed"
        );
    }

    #[tokio::test]
    async fn resume_from_the_store_does_not_double_count() {
        let p = persona(0);
        // First sweep: tip = 5, horizon = 1 → scan [0, 1). Funding in block 0.
        let store = MemStore::default();
        let stake = spawn_stake(&[0]);
        {
            let src = source(chain(5, &[(0, funding_block(&p))]));
            let mut accrual = PScanAccrual::genesis();
            let mut retired = BTreeSet::new();
            pscan_sweep(
                &src,
                &stake,
                &store,
                &mut accrual,
                &mut retired,
                &cfg(4, 4),
                &CancellationToken::new(),
            )
            .await
            .expect("sweep 1");
        }
        let after_first = store
            .load()
            .await
            .unwrap()
            .unwrap()
            .accrual_for(SettlementEpoch::from_raw(0));

        // "Crash + restart": reload the accrual from the store, grow the chain.
        let mut accrual = PScanAccrual::from_state(&store.load().await.unwrap().unwrap());
        assert_eq!(accrual.next_height(), BlockHeight::from_raw(1));
        let src = source(chain(6, &[(0, funding_block(&p)), (1, funding_block(&p))]));
        let mut retired = BTreeSet::new();
        // tip = 6, horizon = 2 → scan [1, 2) only (block 0 already counted).
        pscan_sweep(
            &src,
            &stake,
            &store,
            &mut accrual,
            &mut retired,
            &cfg(4, 4),
            &CancellationToken::new(),
        )
        .await
        .expect("sweep 2");

        let after_second = accrual.to_state().accrual_for(SettlementEpoch::from_raw(0));
        assert_eq!(
            accrual.next_height(),
            BlockHeight::from_raw(2),
            "sweep 2 advanced the cursor 1→2 (it scanned [1,2), not [0,2))"
        );
        assert_eq!(
            after_second.to_raw(),
            after_first.to_raw() * 2,
            "blocks 0 and 1 each counted exactly once — block 0 not re-added on resume"
        );
    }

    #[tokio::test]
    async fn sweep_halts_and_surfaces_on_a_boundary_mismatch_without_rewinding() {
        // The resume-splice (b) exists to forbid: the source serves a chain that does
        // NOT attach to our *own sealed* verified frontier. The cursor resumes at a
        // sealed `(height, hash)` frontier, but the served block's `previous` is a
        // different chain's hash. Given an honest tip this is a beyond-finality anomaly
        // (the frontier is below `ARCHIVAL_REORG_DEPTH_BLOCKS` of the real tip); under
        // an over-claiming source it could be an ordinary reorg the too-high horizon
        // admitted — either way the sweep must RAISE it, never silently rewind or
        // re-derive the anchor, because a silent recovery here re-introduces the (a)
        // vulnerability through the error path. (No fork-point machinery, unlike the
        // principal refresh: 2d-1 can't distinguish the two and halting is safe for both.)
        let p = persona(0);
        // tip=6, horizon=2 → scan [1, 2). Served block[1] chains to block[0], a hash
        // our (deliberately wrong) seeded anchor will not match.
        let src = source(chain(6, &[(1, funding_block(&p))]));
        let stake = spawn_stake(&[0]);
        let store = MemStore::default();

        let wrong_anchor = [0xEE; 32];
        let seeded = PScanState::new(
            PScanCursor::at(BlockHeight::from_raw(1), wrong_anchor),
            BTreeMap::new(),
            BTreeMap::new(),
            Vec::new(),
        );
        store.save(&seeded).await.expect("seed");
        let mut accrual = PScanAccrual::from_state(&seeded);
        let mut retired = BTreeSet::new();

        let err = pscan_sweep(
            &src,
            &stake,
            &store,
            &mut accrual,
            &mut retired,
            &cfg(4, 4),
            &CancellationToken::new(),
        )
        .await
        .expect_err("a boundary mismatch must surface, not be absorbed");

        // 1. RAISED as an exhaustiveness failure (the loud halt), not a transient that
        //    `run_pscan_task` would retry.
        assert!(
            matches!(err, PScanTaskError::Exhaustiveness(_)),
            "expected an exhaustiveness halt, got {err:?}"
        );
        // 2. The cursor did NOT advance past the mismatch.
        assert_eq!(
            accrual.next_height(),
            BlockHeight::from_raw(1),
            "the cursor must not advance over an unverified batch"
        );
        // 3. The anchor was NOT rewound and NOT re-derived from the served chain — a
        //    silent re-fetch of a new anchor IS the resume-splice (b) forbids.
        assert_eq!(
            accrual.frontier_hash(),
            wrong_anchor,
            "the sealed anchor is untouched: no silent rewind, no re-derived anchor"
        );
        // 4. Nothing was sealed past the mismatch (the store still holds the pre-sweep
        //    frontier — the halt left no partial advance behind).
        let sealed = store.load().await.expect("load").expect("state");
        assert_eq!(
            sealed.synced_height(),
            BlockHeight::from_raw(1),
            "no advance was sealed across the halt"
        );
    }

    #[test]
    fn record_unbonds_records_only_unbond_posts() {
        let p = persona(0);
        // Drive record_unbonds with the extractor's output shape (the bond-post
        // matches a `ScanStepResult` carries), which is what the sweep feeds it.
        let mut accrual = PScanAccrual::genesis();
        let matches = vec![BondPostMatch {
            height: BlockHeight::from_raw(123),
            p_canonical_id: canonical_id(&p),
            post_kind: UNBOND_POST_KIND,
        }];
        record_unbonds(&mut accrual, &matches);
        assert_eq!(
            accrual.pending_unbonds().get(&canonical_id(&p)),
            Some(&SettlementEpoch::from_raw(0)),
            "an Unbond post at height 123 (epoch 0) is recorded durably"
        );

        // A non-Unbond post is ignored.
        let mut accrual2 = PScanAccrual::genesis();
        record_unbonds(
            &mut accrual2,
            &[BondPostMatch {
                height: BlockHeight::from_raw(1),
                p_canonical_id: canonical_id(&p),
                post_kind: 0, // JoinMarket
            }],
        );
        assert!(accrual2.pending_unbonds().is_empty());
    }

    #[tokio::test]
    async fn dispatch_retires_an_expired_persona_and_dedups_within_session() {
        // A persona whose Unbond at epoch 0 has fallen out of the claim window:
        // settled = W + 1 ⇒ eligible. Build the accrual directly (a real scan to
        // settled = W+1 would be ~270k blocks).
        let p = persona(0);
        let cursor_height =
            (MAX_CLAIM_AGE_W + 2) * shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS;
        let mut pending = BTreeMap::new();
        pending.insert(canonical_id(&p), SettlementEpoch::from_raw(0));
        let state = PScanState::new(
            // Built for `dispatch_retires` (no sweep), so the frontier hash is inert.
            PScanCursor::at(BlockHeight::from_raw(cursor_height), [0u8; 32]),
            BTreeMap::new(),
            pending,
            Vec::new(),
        );
        let accrual = PScanAccrual::from_state(&state);
        assert_eq!(
            accrual.settled_epoch(),
            Some(SettlementEpoch::from_raw(MAX_CLAIM_AGE_W + 1))
        );

        let stake = spawn_stake(&[0]);
        let mut retired = BTreeSet::new();
        dispatch_retires(&stake, &accrual, &mut retired, &CancellationToken::new())
            .await
            .expect("dispatch");
        assert!(
            retired.contains(&canonical_id(&p)),
            "the expired persona was retired"
        );

        // Dedup within the session: a second dispatch sends nothing new (the entry
        // stays in the accrual — the durable retire-trigger — but is suppressed).
        let before = retired.clone();
        dispatch_retires(&stake, &accrual, &mut retired, &CancellationToken::new())
            .await
            .expect("dispatch 2");
        assert_eq!(retired, before, "no re-dispatch within the session");
        assert!(
            accrual.pending_unbonds().contains_key(&canonical_id(&p)),
            "the durable pending entry is KEPT (re-fires after a restart, not dropped)"
        );
    }

    #[tokio::test]
    async fn dispatch_does_not_retire_before_the_window_closes() {
        // settled = W exactly: U=0 is still the oldest claimable epoch → no retire.
        let p = persona(0);
        let cursor_height =
            (MAX_CLAIM_AGE_W + 1) * shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS;
        let mut pending = BTreeMap::new();
        pending.insert(canonical_id(&p), SettlementEpoch::from_raw(0));
        let accrual = PScanAccrual::from_state(&PScanState::new(
            // Built for `dispatch_retires` (no sweep), so the frontier hash is inert.
            PScanCursor::at(BlockHeight::from_raw(cursor_height), [0u8; 32]),
            BTreeMap::new(),
            pending,
            Vec::new(),
        ));
        assert_eq!(
            accrual.settled_epoch(),
            Some(SettlementEpoch::from_raw(MAX_CLAIM_AGE_W))
        );

        let stake = spawn_stake(&[0]);
        let mut retired = BTreeSet::new();
        dispatch_retires(&stake, &accrual, &mut retired, &CancellationToken::new())
            .await
            .expect("dispatch");
        assert!(
            retired.is_empty(),
            "U is still claimable at settled = U + W; retiring here would be stuck funds"
        );
    }
}
