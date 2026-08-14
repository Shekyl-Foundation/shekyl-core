// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Engine-side merge of [`crate::scan::ScanResult`] into the
//! persisted ledger plus the runtime indexes.
//!
//! [`Engine::apply_scan_result`] is the only audited code path that
//! mutates `WalletLedger`'s scanner-derived slice and the runtime
//! `LedgerIndexes` during refresh. As of Stage 1 PR 2, it takes
//! `&self` and the interior [`super::LocalLedger`] `RwLock` provides
//! the audited single-flight enforcement: each merge call acquires
//! the LocalLedger write guard for the duration of the merge, then
//! drops it before returning. The JSON-RPC binary wraps `Engine<S>`
//! in `Arc<RwLock<…>>` for cross-thread access; the outer borrow is
//! shared (`read`) for the merge call because mutation is now
//! interior to `LocalLedger`.
//!
//! # Three-stage merge
//!
//! 1. **Snapshot invariants.** Reject with
//!    [`RefreshError::ConcurrentMutation`] if the scan result was
//!    produced against a wallet snapshot that no longer matches the
//!    current `Engine<S>` state. Two checks fire:
//!
//!    - `processed_height_range.start == self.synced_height() + 1`
//!    - `parent_hash == self.ledger.ledger.block_hash_at(start - 1)`
//!      (or `None` matching `start == 1` for genesis)
//!
//!    The two checks together cover both racing-mutation and
//!    silent-reorg gaps; see
//!    `docs/V3_WALLET_DECISION_LOG.md`
//!    (`Engine::apply_scan_result invariants`, 2026-04-26) for the
//!    full rationale.
//!
//! 2. **Producer-contract invariants.** Reject with
//!    [`RefreshError::MalformedScanResult`] if the result's internal
//!    shape disagrees with itself: `block_hashes` carries an
//!    out-of-range height, a duplicate height, or a height count that
//!    does not match the range length; or `new_transfers` /
//!    `spent_key_images` carry a height outside
//!    `processed_height_range`. These are scanner-bug signals, not
//!    races; the [`super::Engine::refresh`] retry loop does not retry
//!    on them. The post-loop assertion that the per-height transfer
//!    and key-image maps are empty is the audit witness for "every
//!    in-range entry was consumed exactly once."
//!
//!    See `docs/V3_WALLET_DECISION_LOG.md`
//!    (`MalformedScanResult: producer-bug signal vs. ConcurrentMutation`,
//!    2026-04-26) for the rationale.
//!
//! 3. **Apply.** With both invariant gates satisfied, the merge runs
//!    in a fixed order so reorg-rewind always precedes per-height
//!    additive events:
//!
//!    a. If `reorg_rewind` is `Some`, drop wallet state at and
//!    above its `fork_height` (single `LedgerIndexes::handle_reorg`
//!    call).
//!    b. Per height in `processed_height_range`, in ascending
//!    order: ingest the block (advances `synced_height` and
//!    records the block hash, even when no events fired), process
//!    detected outputs for that height, mark spent key images for
//!    that height.
//!
//! # Internal helper for tests
//!
//! [`apply_scan_result_to_state`] is the same merge body, exposed
//! `pub(crate)` so tests can drive it against a free
//! `(LedgerBlock, LedgerIndexes)` pair without standing up a full
//! `Engine<S>` (whose lifecycle methods land in a later commit).
//! `Engine::apply_scan_result` is a one-line wrapper that acquires
//! the [`super::LocalLedger`] write guard and calls the helper
//! against the guarded `(LedgerBlock, LedgerIndexes)` pair.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use shekyl_crypto_pq::{handle::derive_output_handle, kem::HybridCiphertext};
use shekyl_curve_tree::{BlockHeight, ClientError};
use shekyl_engine_state::{LedgerBlock, LedgerIndexes};
use shekyl_scanner::{LedgerIndexesExt, RecoveredWalletOutput, Timelocked};

use crate::{
    attribution::{
        apply_receive_attributions, collect_label_residue,
        rewind_matched_payment_requests_after_reorg,
    },
    engine::{
        curve_tree_actor::{CurveTreeHandle, CurveTreeHandleError},
        curve_tree_decode,
        error::IoError,
        local_ledger::LocalLedger,
        traits::{DaemonEngine, LedgerEngine},
        Engine, EngineSignerKind, RefreshError,
    },
    scan::{OwnedTxLeaves, ScanResult},
};

// `D: DaemonEngine` private-bound: see the rationale on the
// `pub struct Engine` definition in `engine/mod.rs`. The
// `L = LocalLedger` specialization remains because
// [`Engine::apply_scan_result`] drives the merge body via
// `self.ledger.write()` — a `LocalLedger` inherent method — to
// acquire the synchronous write guard, and then runs the M3b
// engine post-pass ([`populate_engine_handle_fields`]) under that
// same guard using the engine's `view_secret`. As of PR 2 commit 5,
// [`Engine::synced_height`] reads through the
// [`LedgerEngine::synced_height`] trait method (no longer a direct
// inherent call), and `apply_scan_result` flipped from `&mut self`
// to `&self` (the interior `LocalLedger` `RwLock` provides the
// audited mutation point). The `LedgerEngine` trait is read-only
// (no mutator method) as of the FOLLOWUPS P1 async-post-pass fix:
// the merge-plus-post-pass cannot be a trait method because the
// post-pass needs key material the implementor does not hold, and
// must share one write guard with the merge. Full generalization of
// this block to `impl<S, D, L: LedgerEngine>` is therefore deferred
// to the Stage 4 actor that owns key material and can run the
// post-pass internally.
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        E: super::traits::EconomicsEngine,
        R: super::traits::RefreshEngine,
        P: super::traits::PendingTxEngine,
    > Engine<S, D, LocalLedger, E, R, P>
{
    /// Current scanned-chain height: the highest block height the
    /// wallet's persisted ledger has fully ingested. `0` for a
    /// freshly-created wallet that has never refreshed.
    ///
    /// Delegates to [`LedgerEngine::synced_height`] on the
    /// implementor field; the implementor manages its own guard
    /// acquisition and projection.
    pub fn synced_height(&self) -> u64 {
        self.ledger.synced_height()
    }

    /// Apply a scanner-produced [`ScanResult`] to the wallet's
    /// persisted ledger and runtime indexes.
    ///
    /// This is the single audited mutation point for the
    /// scanner-derived slice of [`WalletLedger`](shekyl_engine_state::WalletLedger)
    /// and for [`LedgerIndexes`]. The full merge contract is
    /// described in this module's docstring.
    ///
    /// # Errors
    ///
    /// Returns [`RefreshError::ConcurrentMutation`] when either
    /// the start-height or the parent-hash invariant fails. The
    /// caller should retry refresh — the failure indicates that
    /// the wallet's recorded state moved between the snapshot the
    /// scanner saw and the merge.
    ///
    /// Returns [`RefreshError::MalformedScanResult`] when the result's
    /// internal shape disagrees with itself (out-of-range or
    /// duplicate heights, missing per-height block hash, residual
    /// per-height entries after the apply loop). This is a
    /// scanner-bug signal; the caller should **not** retry the
    /// refresh, because re-running the scan against the same daemon
    /// will produce the same contract violation. [`super::Engine::refresh`]'s
    /// retry loop honours this distinction.
    ///
    /// # Atomicity
    ///
    /// The merge is all-or-nothing only against the invariant
    /// gates: if both gates pass, the merge proceeds and applies
    /// every event. Per-event errors do not currently exist —
    /// every `LedgerIndexes` mutator the merge calls is infallible
    /// once both invariants have been verified.
    ///
    /// # M3b engine post-pass
    ///
    /// Per `docs/design/STAGE_1_PR_3_M3B_PREFLIGHT.md` §3 (disposition
    /// (δ), permanent sync/async split), the body is two stages
    /// inside one critical section:
    ///
    /// 1. **Sync bookkeeping merge** — the existing
    ///    [`apply_scan_result_to_state`] body, unchanged. Maintains
    ///    the in-crate tests / `LocalLedger::apply_scan_result`
    ///    callers that exercise the bookkeeping pipeline without
    ///    engine context.
    /// 2. **Engine handle population** — [`populate_engine_handle_fields`]
    ///    walks the freshly-merged transfers and fills
    ///    `td.source_ciphertext` / `td.output_handle` from the
    ///    `RecoveredWalletOutput` residue (collected before the
    ///    merge consumes the [`ScanResult`]). This is the audit's
    ///    "engine post-pass" — the orchestrator-side equivalent of
    ///    the migration plan's "scanner emits `OutputClaim` to
    ///    `KeyEngine::try_claim_output`" framing.
    ///
    /// The two stages are atomic against external readers because
    /// they share the same [`super::LocalLedger`] write guard — a
    /// concurrent reader either sees the pre-merge ledger or the
    /// post-population ledger, never an intermediate state with
    /// freshly-merged transfers whose `output_handle` field is
    /// transiently `None`.
    pub fn apply_scan_result(&self, mut result: ScanResult) -> Result<(), RefreshError> {
        // §3 reroute (M3b): pre-collect the public on-chain residue
        // from the scan result *before* `apply_scan_result_to_state`
        // consumes it. The post-pass below uses this map to bind
        // each freshly-merged `TransferDetails` to its source
        // ciphertext and to populate the deterministic
        // `OutputHandle`. The map is `Hash`-keyed because lookup
        // ordering is not required.
        let detection_residue = collect_detection_residue(&result);
        let label_residue = collect_label_residue(&result.new_transfers);
        let reorg_fork_height = result.reorg_rewind.as_ref().map(|r| r.fork_height);

        // Bond-watch sightings ride the same result but mutate the STAKING
        // block, which `apply_scan_result_to_state` (LedgerBlock-scoped)
        // cannot reach — validated here (cache membership needs the staking
        // block) under the write guard *before* the ledger apply, so a
        // malformed slot cannot advance the tip.
        let mut guard = self.ledger.write();
        let state = &mut *guard;
        super::bond_watch::validate_bond_sightings(&result, &state.ledger.staking)?;
        let bond_sightings = std::mem::take(&mut result.bond_sightings);
        // Capture the inserted-index list under the same write guard
        // so it remains valid for the post-pass. No external mutation
        // can shrink `ledger.transfers` between the merge body's
        // return and the post-pass's read — both run with `state` as
        // a borrow of the guarded inner.
        let inserted =
            apply_scan_result_to_state(&mut state.ledger.ledger, &mut state.indexes, result)?;
        if reorg_fork_height.is_some() {
            rewind_matched_payment_requests_after_reorg(
                &mut state.ledger.bookkeeping.payment_requests,
                &state.ledger.ledger,
                state.ledger.ledger.height(),
            );
        }

        // Engine post-pass: idempotent population of the
        // engine-derived fields on the freshly-merged transfers.
        // Sync at M3b (handle derivation is a pure cryptographic
        // primitive); becomes async at M3c+ when re-routed through
        // `KeyEngine::try_claim_output`. Walks only the inserted
        // indices in O(k) per
        // PERF_MERGE_INSERTION_INDICES_PREFLIGHT.md §1.
        populate_engine_handle_fields(
            &mut state.ledger.ledger,
            self.merge_view_secret.as_canonical_bytes(),
            &detection_residue,
            &inserted,
        );
        apply_receive_attributions(
            &mut state.ledger.bookkeeping.payment_requests,
            &mut state.ledger.ledger,
            &label_residue,
            &inserted,
        );
        // Bond watch (SA-R-6): reorg hygiene, then adopt + raise, under the
        // same write guard — the whole `WalletLedger` serializes atomically
        // at every save site, so no save can persist a synced tip past a
        // sighted block without its adoption.
        //
        // A rewind first invalidates every stored sighting at/above the fork:
        // those rows name orphaned blocks, and a stale height would poison
        // arm #3's height-gated verdict (a re-mined post sits elsewhere) and
        // wedge the first-stake AlreadyStaked guard on a bond the canonical
        // chain no longer carries. The re-scan's own sightings — adopted
        // next — re-insert every surviving post at its canonical height.
        if let Some(fork) = reorg_fork_height {
            let dropped = state
                .ledger
                .staking
                .discard_sightings_at_or_above(shekyl_types::BlockHeight::from_raw(fork));
            if !dropped.is_empty() {
                tracing::info!(
                    dropped = dropped.len(),
                    fork_height = fork,
                    "bond watch: reorg orphaned sighting rows discarded at merge"
                );
            }
        }
        let newly_adopted =
            super::bond_watch::adopt_bond_sightings(&mut state.ledger.staking, &bond_sightings);
        // Session record for the status surface: an adopted persona cannot
        // become operational this session (Model D — no seed, no actor
        // respawn), so the wallet reports staking recovery as pending until
        // the next open re-derives and spawns over the updated record.
        state.slots_adopted_this_session.extend(newly_adopted);
        // WI-RPC-3 retention reconciler (`docs/api/wallet_rpc.yaml`
        // OUTBOUND PREREQUISITE pins 2–3 + PR-SJ-1 P3-1: after the merge
        // and the post-passes, retire retention orphans the chain now
        // references and run the send-journal reorg / confirm /
        // evidence-bound-release edges. Same write guard so I-2 and the
        // journal's lifecycle states hold atomically with the scan merge
        // (see `WalletLedger::reconcile_after_scan_merge`).
        state.ledger.reconcile_after_scan_merge(reorg_fork_height);
        Ok(())
    }

    /// Feed the curve tree the heights carried by `result` **before** the
    /// ledger merge commits them — the ack-before-commit half of CT-5 §3.2
    /// (R1-Q2) under the fork-three genesis-anchored feed (§3.2.1). The tree
    /// is updated and acknowledged here so [`Self::apply_scan_result`] can
    /// advance the ledger knowing the tree already covers the range; the
    /// ledger tip never outruns the tree (O2).
    ///
    /// # Cursor-driven (D2)
    ///
    /// Every iteration reads the tree's own
    /// [`super::curve_tree_actor::CurveTreeHandle::ingested_tip_height`] and
    /// ingests `tip + 1` (`BlockHeight(0)` when the tree is fresh). The
    /// driver holds **no** local fetch frontier, which makes counter/cursor
    /// drift unrepresentable: it is idempotent under the refresh retry loop
    /// (a merge that failed [`RefreshError::ConcurrentMutation`] left the tree
    /// ahead of the ledger; the re-produced result is skipped up to the tip)
    /// and resumes correctly after a reorg rollback.
    ///
    /// # Two leaf sources, one consecutive feed (§3.2.1 R3-Q1)
    ///
    /// - Heights below the producer's floored range — the genesis/birthday
    ///   backfill, `[tip + 1, range.start)` — are daemon-fetched and decoded
    ///   here (tree-only fetch; the owned-output scanner never descends here).
    /// - Heights in `[range.start, range.end)` reuse the producer's
    ///   already-materialized `result.block_leaves` (fetch-once).
    ///
    /// # Reorg
    ///
    /// When `result.reorg_rewind` is present its `fork_height` is the first
    /// *divergent* height (`find_fork_point` returns `h + 1`); the tree is
    /// rolled back to keep `fork_height - 1` (the last common height) so the
    /// cursor-driven loop re-ingests the new fork's blocks. The rollback fires
    /// only when the tree actually holds an orphaned suffix
    /// (`tip >= fork_height`); a tree still backfilling below the fork has
    /// nothing to drop (R3-Q6).
    ///
    /// # Errors
    ///
    /// - Daemon transport failure during the backfill fetch
    ///   (`fetch_scannable_block`) → [`RefreshError::Io`]
    ///   (`IoError::Daemon`).
    /// - A `block_leaves` height missing from the producer range →
    ///   [`RefreshError::MalformedScanResult`] (a producer-contract defect,
    ///   same class as the in-range checks in [`apply_scan_result_to_state`]).
    /// - Backfill block decode, or the actor ingest/rollback handshake →
    ///   [`RefreshError::CurveTreeIngest`].
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn ingest_scan_result_into_curve_tree(
        &self,
        result: &mut ScanResult,
    ) -> Result<(), RefreshError> {
        let producer_leaves = index_block_leaves(std::mem::take(&mut result.block_leaves))?;
        curve_tree_ingest_scan_result(&self.curve_tree, &self.daemon, result, &producer_leaves)
            .await
    }

    /// Ingest a scan result into the curve tree, healing a single fail-stop /
    /// poison with a resume-over-held-store respawn-and-retry (R1-Q4, §3.3 happy path).
    ///
    /// It drains `result.block_leaves` once into an `Arc`-shared, height-keyed
    /// map and delegates to `curve_tree_ingest_scan_result_with_respawn`. On
    /// a respawn-eligible failure ([`RefreshError::CurveTreeIngest`] with
    /// `recoverable_by_respawn`) that helper reopens the actor via
    /// [`CurveTreeHandle::respawn`](super::curve_tree_actor::CurveTreeHandle::respawn)
    /// and re-runs the cursor-driven ingest **once** against the *same* drained
    /// leaves (the `Arc` map is retained across the retry, R1-Q4). The retry is
    /// correct because the resumed client rebuilds from the persisted store
    /// cursor (D2): the loop skips already-ingested heights and continues from
    /// the tree's own tip, so a re-run never double-ingests. Re-invoking
    /// [`ingest_scan_result_into_curve_tree`](Self::ingest_scan_result_into_curve_tree)
    /// itself would *not* heal — it would `take` the now-empty `block_leaves`;
    /// the drained map is the retry's source of truth.
    ///
    /// **One retry only.** The bounded retry budget that distinguishes a
    /// transient persistence hiccup from a deterministically-corrupt store —
    /// which would otherwise livelock reopen → poison → reopen (O3-sub) — is
    /// CT-5d, coupled to the existing refresh retry/cancel budget (O6). Here a
    /// respawn whose retry also fails surfaces terminally, and a non-recoverable
    /// failure passes straight through without a respawn.
    ///
    /// This is the curve-tree ingest entry point the refresh path calls; the
    /// inner [`ingest_scan_result_into_curve_tree`](Self::ingest_scan_result_into_curve_tree)
    /// stays `pub(crate)` for the tests that drive the bare ingest/rollback
    /// pre-pass.
    pub(crate) async fn ingest_scan_result_with_respawn(
        &self,
        result: &mut ScanResult,
    ) -> Result<(), RefreshError> {
        let producer_leaves = index_block_leaves(std::mem::take(&mut result.block_leaves))?;
        curve_tree_ingest_scan_result_with_respawn(
            &self.curve_tree,
            &self.daemon,
            result,
            &producer_leaves,
        )
        .await
    }
}

/// Collapse a [`CurveTreeHandleError`] into a
/// [`RefreshError::CurveTreeIngest`], classifying whether a drop-and-reopen
/// respawn (R1-Q4) can heal it:
///
/// - A fail-stopped actor ([`CurveTreeHandleError::Unavailable`]) and a
///   poisoned client ([`ClientError::Poisoned`] — whose own documented
///   recovery is "drop this object and resume over the same store") are
///   `recoverable_by_respawn = true`: [`Engine::ingest_scan_result_with_respawn`]
///   respawns the actor and retries the cursor-driven ingest once, which
///   resumes from the held store's persisted tip (D2).
/// - Every other client error (e.g.
///   [`ClientError::NonConsecutiveBlockHeight`], a producer-contract or
///   store-state fault) is `false`: a reopen resumes the same cursor and
///   reproduces it, so it surfaces terminally rather than livelocking a retry.
fn map_curve_tree_handle_error(err: &CurveTreeHandleError) -> RefreshError {
    match err {
        CurveTreeHandleError::Unavailable => RefreshError::CurveTreeIngest {
            context: "curve-tree actor unavailable",
            recoverable_by_respawn: true,
        },
        CurveTreeHandleError::Client(ClientError::Poisoned) => RefreshError::CurveTreeIngest {
            context: "curve-tree client poisoned",
            recoverable_by_respawn: true,
        },
        // §3.3 (CT-5b, O5): the reconstructed root diverged from the consensus
        // header-committed root. Terminal — a respawn re-derives the same root
        // from the same store, so it reproduces the mismatch rather than
        // healing it. Distinct context so an auditor reads the lying-daemon DoS
        // apart from a generic client rejection.
        CurveTreeHandleError::Client(ClientError::RootMismatch { .. }) => {
            RefreshError::CurveTreeIngest {
                context: "curve-tree root mismatch vs header",
                recoverable_by_respawn: false,
            }
        }
        CurveTreeHandleError::Client(_) => RefreshError::CurveTreeIngest {
            context: "curve-tree client rejected ingest",
            recoverable_by_respawn: false,
        },
    }
}

/// Ingest a scan result into the curve tree from cloned deps — lets the async
/// refresh task drop the engine `RwLock` read guard before the long-running
/// backfill fetches and per-height actor round-trips.
pub(super) async fn curve_tree_ingest_scan_result_with_respawn<D: super::traits::DaemonEngine>(
    curve_tree: &CurveTreeHandle,
    daemon: &D,
    result: &ScanResult,
    producer_leaves: &BTreeMap<u64, Arc<Vec<OwnedTxLeaves>>>,
) -> Result<(), RefreshError> {
    match curve_tree_ingest_scan_result(curve_tree, daemon, result, producer_leaves).await {
        Ok(()) => Ok(()),
        Err(RefreshError::CurveTreeIngest {
            recoverable_by_respawn: true,
            ..
        }) => {
            // Engine-side respawn (clause 2): runs after the failed `ask`
            // returned, never inside a handler under the engine guard.
            curve_tree
                .respawn()
                .await
                .map_err(|_| RefreshError::CurveTreeIngest {
                    context: "curve-tree respawn resume failed",
                    recoverable_by_respawn: false,
                })?;
            curve_tree_ingest_scan_result(curve_tree, daemon, result, producer_leaves).await
        }
        Err(other) => Err(other),
    }
}

/// Index the producer's per-block leaf sets by height, rejecting a repeated
/// height as a producer-contract violation.
///
/// `block_leaves` is a transit-only field on an untrusted [`ScanResult`] (O5).
/// A plain `BTreeMap`-via-`collect()` would silently overwrite a duplicate
/// height and feed the curve tree an unintended leaf set — the same hazard the
/// `block_hashes` duplicate-height check closes in [`apply_scan_result_to_state`].
pub(super) fn index_block_leaves(
    block_leaves: Vec<(u64, Vec<OwnedTxLeaves>)>,
) -> Result<BTreeMap<u64, Arc<Vec<OwnedTxLeaves>>>, RefreshError> {
    let mut map = BTreeMap::new();
    for (height, leaves) in block_leaves {
        if map.insert(height, Arc::new(leaves)).is_some() {
            return Err(RefreshError::MalformedScanResult {
                reason: "block_leaves contains duplicate height",
            });
        }
    }
    Ok(map)
}

/// Reject a reorg `fork_height` of 0 as a producer-contract violation.
///
/// `fork_height` is the *first divergent* height; genesis (height 0) is the
/// universal common ancestor and can never be orphaned, so the honest producer
/// never emits 0 (`find_fork_point` bottoms out at `Ok(1)`). A 0 reaching here
/// is a malformed/hostile [`ScanResult`] (O5): left unchecked it silently
/// rewinds the *entire* tree (`keep = fork_height - 1` underflowing to genesis)
/// or wipes the whole ledger ([`LedgerIndexes::handle_reorg`] drops state
/// at-and-above 0). Surface it loudly instead of absorbing it.
fn validate_reorg_fork_height(fork_height: u64) -> Result<(), RefreshError> {
    if fork_height == 0 {
        return Err(RefreshError::MalformedScanResult {
            reason: "reorg fork_height of 0 would orphan genesis",
        });
    }
    Ok(())
}

async fn curve_tree_ingest_scan_result<D: super::traits::DaemonEngine>(
    curve_tree: &CurveTreeHandle,
    daemon: &D,
    result: &ScanResult,
    producer_leaves: &BTreeMap<u64, Arc<Vec<OwnedTxLeaves>>>,
) -> Result<(), RefreshError> {
    // Range well-formedness (O5/O2). This pre-pass runs *before* the ledger
    // merge's own `end >= start` check (`apply_scan_result_to_state`), so guard
    // the same property here: an inverted range would otherwise drive
    // unintended daemon backfill and advance the tree on a malformed result
    // before the merge ever rejects it. Same reason string as the ledger
    // surface so the error taxonomy reads identically to an auditor.
    let range_start = result.processed_height_range.start;
    let range_end = result.processed_height_range.end;
    if range_end < range_start {
        return Err(RefreshError::MalformedScanResult {
            reason: "processed_height_range end precedes start",
        });
    }

    // §3.3 (CT-5b): index the producer's per-height consensus header roots for
    // the verify-after-ingest in the loop below. A duplicate height is a
    // producer-contract violation (same discipline as `block_leaves` and
    // `block_hashes`). Backfill heights below `range_start` are not in this map
    // (the producer only emits roots for its scanned range); their header root
    // comes from the daemon-fetched block instead.
    let mut producer_roots: BTreeMap<u64, [u8; 32]> = BTreeMap::new();
    for (height, root) in &result.block_curve_tree_roots {
        if producer_roots.insert(*height, *root).is_some() {
            return Err(RefreshError::MalformedScanResult {
                reason: "block_curve_tree_roots contains duplicate height",
            });
        }
    }

    // Reorg: drop the orphaned suffix so the cursor-driven loop re-ingests
    // the new fork. `fork_height` is the first divergent height (validated
    // ≥ 1 below), so the last common height to keep is `fork_height - 1`.
    // Only roll back when the tree holds blocks at or above the fork — a tree
    // still climbing below it has nothing to drop (R3-Q6).
    if let Some(rewind) = result.reorg_rewind.as_ref() {
        validate_reorg_fork_height(rewind.fork_height)?;
        let keep = BlockHeight(rewind.fork_height - 1);
        if let Some(tip) = curve_tree
            .ingested_tip_height()
            .await
            .map_err(|e| map_curve_tree_handle_error(&e))?
        {
            if tip.0 > keep.0 {
                curve_tree
                    .rollback_to_fork(keep)
                    .await
                    .map_err(|e| map_curve_tree_handle_error(&e))?;
            }
        }
    }

    loop {
        let tip = curve_tree
            .ingested_tip_height()
            .await
            .map_err(|e| map_curve_tree_handle_error(&e))?;
        // `checked_add` defends the cursor advance: the `next >= range_end`
        // break bounds `next` at `range_end`, so this never trips in practice,
        // but block heights are consensus-adjacent — never silently wrap.
        let next = match tip {
            None => 0,
            Some(t) => t.0.checked_add(1).ok_or(RefreshError::CurveTreeIngest {
                context: "ingested tip height overflow",
                recoverable_by_respawn: false,
            })?,
        };
        if next >= range_end {
            break;
        }

        // Acquire the block's leaves and the header root the §3.3 verify must
        // match. Both branches yield the pair so the verify below is uniform.
        let (leaves, expected_root) = if next < range_start {
            // Genesis/birthday backfill: tree-only daemon fetch + decode.
            let number = usize::try_from(next).map_err(|_| RefreshError::CurveTreeIngest {
                context: "backfill height exceeds usize",
                recoverable_by_respawn: false,
            })?;
            let block = daemon.fetch_scannable_block(number).await.map_err(|e| {
                RefreshError::Io(IoError::Daemon {
                    detail: e.to_string(),
                })
            })?;
            let leaves =
                Arc::new(curve_tree_decode::decode_block_leaves(&block).map_err(|_| {
                    RefreshError::CurveTreeIngest {
                        context: "backfill block decode failed",
                        recoverable_by_respawn: false,
                    }
                })?);
            // Backfill heights are below the producer's scanned range, so their
            // header root is not in `producer_roots`; take it from the
            // daemon-fetched block. The §3.3 verify still gates it: a daemon
            // serving leaves that don't reconstruct to its own header root
            // fails loudly below.
            (leaves, block.block.header.curve_tree_root)
        } else {
            // Producer range: reuse the materialized leaves (no re-fetch).
            // `Arc::clone` is a refcount bump, not a deep copy, and crucially
            // RETAINS the map entry: if this height's `ingest` `ask` fails
            // with a respawn-recoverable error, `*_with_respawn` re-runs this
            // loop after the respawn and must find the same leaves again
            // (R1-Q4). Heights already persisted are skipped by the cursor, so
            // a retained entry is never re-ingested — it just drops with the
            // map at end of the (batch-bounded) producer range.
            let leaves = producer_leaves
                .get(&next)
                .ok_or(RefreshError::MalformedScanResult {
                    reason: "block_leaves missing a height in processed_height_range",
                })?
                .clone();
            let expected_root =
                *producer_roots
                    .get(&next)
                    .ok_or(RefreshError::MalformedScanResult {
                        reason: "block_curve_tree_roots missing a height in processed_height_range",
                    })?;
            (leaves, expected_root)
        };

        curve_tree
            .ingest(BlockHeight(next), leaves)
            .await
            .map_err(|e| map_curve_tree_handle_error(&e))?;

        // §3.3 ingest-time integrity verify (CT-5b, O5 lying-daemon defense).
        // The root the tree reconstructs for `next` must byte-equal the
        // consensus header-committed root. A mismatch is the inconsistent liar
        // (bad leaves, honest header): fail loudly and terminally — a respawn
        // re-derives the same root, so it is not recoverable — never advancing
        // the ledger past tree state we cannot reproduce (O2/ack-before-commit;
        // the merge runs only after this pre-pass returns `Ok`). The consistent
        // liar (bad leaves + matching bad header) passes here and is caught at
        // consensus submit — still DoS, never a witness leak.
        curve_tree
            .verify_root(BlockHeight(next), expected_root)
            .await
            .map_err(|e| map_curve_tree_handle_error(&e))?;
    }
    Ok(())
}

/// Merge body shared between [`Engine::apply_scan_result`] and the
/// in-crate tests that operate on a free
/// `(LedgerBlock, LedgerIndexes)` pair.
///
/// `pub(crate)`: callers outside `shekyl-engine-core` go through
/// [`Engine::apply_scan_result`].
///
/// On success, returns the flat list of `ledger.transfers` indices
/// into which freshly-scanned transfers were appended across every
/// height in `result.processed_height_range`. The list is the
/// concatenation of the per-height [`LedgerIndexes::ingest_block`]
/// ranges; its length is the total accepted-transfer count after
/// burning-bug duplicates are dropped, and its entries are
/// monotonically increasing. The engine post-pass at
/// [`populate_engine_handle_fields`] uses this list to walk only the
/// freshly-merged transfers (O(k)) rather than the entire ledger
/// (O(n)) — closing the FOLLOWUPS V3.0 entry on
/// `populate_engine_handle_fields` cost.
///
/// The empty-range fast path returns `Ok(Vec::new())`.
///
/// **This function is `LedgerBlock`-scoped by design** — it cannot reach the
/// staking block, so it does not (and must not) process `bond_sightings`.
/// [`Engine::apply_scan_result`] validates and takes them under the same
/// write guard before calling here; a result arriving with sightings still
/// attached is a caller that skipped that seam, refused loudly below rather
/// than silently dropping chain evidence.
pub(crate) fn apply_scan_result_to_state(
    ledger: &mut LedgerBlock,
    indexes: &mut LedgerIndexes,
    result: ScanResult,
) -> Result<Vec<usize>, RefreshError> {
    let synced = ledger.height();

    // Bond sightings mutate the STAKING block, which this LedgerBlock-scoped
    // body cannot reach — the caller (`Engine::apply_scan_result`) validates
    // and takes them first. A populated field here means a direct caller
    // bypassed that seam; refusing turns what would be a silent drop of
    // chain evidence (an unadopted real bond) into a loud contract error.
    if !result.bond_sightings.is_empty() {
        return Err(RefreshError::MalformedScanResult {
            reason: "bond_sightings must be taken by the engine seam before the ledger apply",
        });
    }

    // Fork-height well-formedness. A `fork_height` of 0 would have
    // `handle_reorg` drop ledger/index state at-and-above genesis (a full
    // wipe); reject it before it is used as `expected_start` or fed to the
    // reorg below (O5 untrusted-`ScanResult` defense).
    if let Some(rewind) = result.reorg_rewind.as_ref() {
        validate_reorg_fork_height(rewind.fork_height)?;
    }

    // Start-height invariant. When `reorg_rewind` is present the
    // result is replayed from the fork height, so the expected start
    // is `fork_height` rather than `synced + 1`. Without rewind the
    // result must continue exactly where the wallet left off.
    let expected_start = match result.reorg_rewind {
        Some(rewind) => rewind.fork_height,
        None => synced.saturating_add(1),
    };
    if result.processed_height_range.start != expected_start {
        return Err(RefreshError::ConcurrentMutation {
            wallet: synced,
            result: result.processed_height_range.start,
        });
    }

    // Parent-hash invariant. Heights `< fork_height` survive a
    // reorg rewind unchanged, so this check applies in both branches:
    // the wallet's recorded `block_hash_at(start - 1)` must match the
    // result's claim. (For `start == 1`, both sides must be `None`.)
    let start = result.processed_height_range.start;
    if start > 1 {
        let stored = ledger.block_hash_at(start - 1).copied();
        match (stored, result.parent_hash) {
            (Some(stored_hash), Some(claimed_hash)) if stored_hash == claimed_hash => {}
            // Stored / claimed disagree, or one side is `None` and the
            // other is `Some`. Both cases are concurrent-mutation: the
            // chain at `start - 1` shifted under the scanner, or the
            // scanner produced a result against a wallet snapshot the
            // current wallet no longer matches.
            _ => {
                return Err(RefreshError::ConcurrentMutation {
                    wallet: synced,
                    result: start,
                });
            }
        }
    } else if result.parent_hash.is_some() {
        // start == 1 means the scanner ran from genesis; the wallet
        // has nothing recorded at height 0, so a `Some` parent_hash
        // here is itself a snapshot-disagreement signal.
        return Err(RefreshError::ConcurrentMutation {
            wallet: synced,
            result: start,
        });
    }

    let ScanResult {
        processed_height_range,
        parent_hash: _,
        block_hashes,
        new_transfers,
        spent_key_images,
        reorg_rewind,
        // CT-5 §3.2 transit fields. `block_leaves` is consumed by the
        // curve-tree ingest pre-pass (`ingest_scan_result_into_curve_tree`,
        // CT-5a commit 4) that runs *before* this merge; it is ignored here
        // because `apply_scan_result_to_state` only advances ledger/index
        // state. `block_curve_tree_roots` is the write-but-not-read transit
        // field (E6b): the producer populates it; the §3.3 ingest-time verify
        // that consumes it lands in CT-5b, so nothing reads it yet.
        block_leaves: _,
        block_curve_tree_roots: _,
        // Taken by the outer `apply_scan_result` before this call (they
        // mutate the staking block, out of this fn's LedgerBlock scope);
        // enforced empty by the refusal at the top of this function.
        bond_sightings: _,
    } = result;

    if let Some(rewind) = reorg_rewind {
        indexes.handle_reorg(ledger, rewind.fork_height);
    }

    if processed_height_range.start == processed_height_range.end {
        // Empty range — every per-height vector must also be empty;
        // a non-empty vector against a zero-length range is a
        // producer-contract violation, not a no-op.
        if !block_hashes.is_empty() {
            return Err(RefreshError::MalformedScanResult {
                reason: "block_hashes non-empty for empty processed_height_range",
            });
        }
        if !new_transfers.is_empty() {
            return Err(RefreshError::MalformedScanResult {
                reason: "new_transfers non-empty for empty processed_height_range",
            });
        }
        if !spent_key_images.is_empty() {
            return Err(RefreshError::MalformedScanResult {
                reason: "spent_key_images non-empty for empty processed_height_range",
            });
        }
        return Ok(Vec::new());
    }

    // Pre-size the inserted-index list against the upper-bound
    // `new_transfers.len()`. Burning-bug duplicates dropped at
    // `LedgerIndexes::ingest_block` narrow the actual count; the
    // pre-sized capacity keeps the allocation hot-path-friendly even
    // when no duplicates fire.
    let mut inserted = Vec::with_capacity(new_transfers.len());

    // --- Producer-contract gate ----------------------------------------
    //
    // The remaining checks ensure the result's internal shape is
    // self-consistent. Failures are
    // `RefreshError::MalformedScanResult` (producer bug, not race),
    // distinct from the snapshot-disagreement gate above.

    // `block_hashes` length must match the range length, every entry
    // must lie inside the range, and no height may repeat. Together
    // with len-equality these three rules pigeonhole into "exactly one
    // entry per height in range," which is what the per-height apply
    // loop relies on.
    // `start == end` returned early above, but an inverted range
    // (`start > end`) is a producer-contract violation, not a panic — a
    // hostile daemon must not be able to crash the merge with `start > end`
    // (X7). Treat it as `MalformedScanResult`, like the shape checks below.
    let range_len_u64 = processed_height_range
        .end
        .checked_sub(processed_height_range.start)
        .ok_or(RefreshError::MalformedScanResult {
            reason: "processed_height_range end precedes start",
        })?;
    let expected_len =
        usize::try_from(range_len_u64).map_err(|_| RefreshError::MalformedScanResult {
            reason: "processed_height_range length exceeds usize",
        })?;
    if block_hashes.len() != expected_len {
        return Err(RefreshError::MalformedScanResult {
            reason: "block_hashes length does not match processed_height_range length",
        });
    }

    let mut hash_at: BTreeMap<u64, [u8; 32]> = BTreeMap::new();
    for (h, hash) in block_hashes {
        if !processed_height_range.contains(&h) {
            return Err(RefreshError::MalformedScanResult {
                reason: "block_hashes entry outside processed_height_range",
            });
        }
        if hash_at.insert(h, hash).is_some() {
            return Err(RefreshError::MalformedScanResult {
                reason: "block_hashes contains duplicate height",
            });
        }
    }

    let mut transfers_by_height: BTreeMap<u64, Vec<RecoveredWalletOutput>> = BTreeMap::new();
    for dt in new_transfers {
        if !processed_height_range.contains(&dt.block_height) {
            return Err(RefreshError::MalformedScanResult {
                reason: "new_transfers entry outside processed_height_range",
            });
        }
        transfers_by_height
            .entry(dt.block_height)
            .or_default()
            .push(dt.output);
    }

    // Each observation pairs the key image with its containing txid so
    // `detect_spends` can record the spend-quadruple leg (F-9:
    // `TransferDetails::spending_tx_hash`).
    let mut key_images_by_height: BTreeMap<
        u64,
        Vec<(shekyl_crypto_pq::key_image::KeyImage, shekyl_types::TxHash)>,
    > = BTreeMap::new();
    for ki in spent_key_images {
        if !processed_height_range.contains(&ki.block_height) {
            return Err(RefreshError::MalformedScanResult {
                reason: "spent_key_images entry outside processed_height_range",
            });
        }
        key_images_by_height
            .entry(ki.block_height)
            .or_default()
            .push((ki.key_image, ki.containing_tx_hash));
    }

    // --- Apply phase ---------------------------------------------------

    for h in processed_height_range.start..processed_height_range.end {
        let Some(block_hash) = hash_at.remove(&h) else {
            // Defensive: pre-validation (length match + in-range +
            // no-duplicates) makes this branch unreachable. We keep it
            // and surface as `MalformedScanResult` so audit can read a
            // typed contract failure rather than a panic if the
            // pre-validation logic ever drifts.
            return Err(RefreshError::MalformedScanResult {
                reason: "block_hashes missing entry for processed height",
            });
        };

        let outputs = transfers_by_height.remove(&h).unwrap_or_default();
        let timelocked = Timelocked::from_vec(outputs);
        let inserted_range = indexes.process_scanned_outputs(ledger, h, block_hash, timelocked);
        // Per-height ranges are contiguous suffixes of
        // `ledger.transfers`, monotonically advancing across the loop
        // (each iteration appends, never reorders). Flattening to a
        // Vec gives the post-pass an O(k) iteration domain.
        inserted.extend(inserted_range);

        if let Some(kis) = key_images_by_height.remove(&h) {
            let _spent = indexes.detect_spends(ledger, h, &kis);
        }
    }

    // Post-loop residue check: pre-validation rejects out-of-range
    // entries, and the loop consumes every in-range one, so all three
    // maps must be empty here. The audit witness for "every entry was
    // consumed exactly once."
    if !hash_at.is_empty() {
        return Err(RefreshError::MalformedScanResult {
            reason: "block_hashes had residual entries after per-height apply loop",
        });
    }
    if !transfers_by_height.is_empty() {
        return Err(RefreshError::MalformedScanResult {
            reason: "new_transfers had residual entries after per-height apply loop",
        });
    }
    if !key_images_by_height.is_empty() {
        return Err(RefreshError::MalformedScanResult {
            reason: "spent_key_images had residual entries after per-height apply loop",
        });
    }

    Ok(inserted)
}

/// Pre-collected public on-chain residue from a [`ScanResult`]'s
/// detected transfers, keyed by `(tx_hash, internal_output_index)`.
///
/// This is the side-channel the engine post-pass
/// ([`populate_engine_handle_fields`]) consumes after
/// [`apply_scan_result_to_state`] has destructured the
/// [`ScanResult`]. The key matches the corresponding fields on
/// [`shekyl_engine_state::TransferDetails`] post-merge.
type DetectionResidue = HashMap<([u8; 32], u64), HybridCiphertext>;

/// Build a [`DetectionResidue`] map from a [`ScanResult`]'s detected
/// transfers before they are consumed by
/// [`apply_scan_result_to_state`].
///
/// The on-chain hybrid ciphertext is preserved on each
/// [`shekyl_scanner::RecoveredWalletOutput`] per the M3b scanner
/// residue plumbing; this helper just lifts it into a lookup table
/// keyed by `(tx_hash, internal_output_index)`. Both fields are
/// public on-chain values.
fn collect_detection_residue(result: &ScanResult) -> DetectionResidue {
    let mut map = HashMap::with_capacity(result.new_transfers.len());
    for dt in &result.new_transfers {
        let wo = dt.output.wallet_output();
        map.insert(
            (wo.transaction(), wo.index_in_transaction()),
            dt.output.source_ciphertext().clone(),
        );
    }
    map
}

/// Engine post-pass for the M3b scanner reroute (per
/// `docs/design/STAGE_1_PR_3_M3B_PREFLIGHT.md` §3).
///
/// Populates `td.source_ciphertext` and `td.output_handle` on each
/// freshly-merged `TransferDetails` whose
/// `(tx_hash, internal_output_index)` matches an entry in `residue`.
///
/// **Idempotent.** Transfers whose fields are already populated
/// (e.g., a prior merge that observed the same outputs, or the M3d
/// fallback path before legacy fields are dropped) are left
/// untouched.
///
/// # Synchronous body, async-ready surface
///
/// At M3b the post-pass derives the [`shekyl_crypto_pq::handle::OutputHandle`]
/// directly via the public cryptographic primitive
/// [`derive_output_handle`] — a stateless pure function that requires
/// only `(view_secret, tx_hash, output_index)`. No
/// [`super::traits::KeyEngine`] instance is needed; no `.await` chain
/// is introduced. The orchestrator-side handle population property
/// M3b ships (every output the scanner ingests has a deterministic
/// handle on its `TransferDetails`) is delivered by the cryptographic
/// primitive directly.
///
/// M3c+ wires `LocalKeys` onto `Engine` and re-routes this helper
/// through [`super::traits::KeyEngine::try_claim_output`] — at that
/// point the helper signature becomes `async fn` and
/// [`Engine::apply_scan_result`] takes the corresponding `.await`.
/// The two-step trajectory is intentional: M3b's architectural
/// property (the orchestrator persists handles) does not require the
/// audit's "engine sole authority on handles" framing to activate,
/// which lands at M3d. See `STAGE_1_PR_3_MIGRATION_PLAN.md` §3.4.
///
/// # Permanent sync/async split
///
/// Per `STAGE_1_PR_3_M3B_PREFLIGHT.md` §3 disposition (δ), the
/// engine post-pass is layered atop the existing sync
/// [`apply_scan_result_to_state`] body rather than absorbed into it.
/// Both halves have legitimate consumers: the sync substrate serves
/// the bookkeeping pipeline (in-crate tests,
/// [`LocalLedger::apply_scan_result`](super::local_ledger::LocalLedger)
/// where engine integration is not in scope); the engine post-pass
/// layers handle population on top. The split is **load-bearing and
/// intentional**, not a transitional shape pending convergence — a
/// future maintainer reading "why two helpers?" finds the
/// load-bearing answer here rather than re-litigating it as
/// transitional drift.
///
/// **Visibility.** `pub(crate)` (rather than module-private) so the
/// §5.3 B9 merge-path bench fixture (`key_dispatch_bench`, gated behind
/// `bench-internals`) can drive this exact post-pass over a synthetic
/// batch — the bench measures the real 6-i projection, not a
/// re-implementation. Production callers still reach it only through
/// [`Engine::apply_scan_result`].
pub(crate) fn populate_engine_handle_fields(
    ledger: &mut LedgerBlock,
    view_secret: &[u8; 32],
    residue: &DetectionResidue,
    inserted: &[usize],
) {
    if residue.is_empty() || inserted.is_empty() {
        return;
    }
    // O(k) iteration domain: `inserted` is the flat index list
    // `apply_scan_result_to_state` returned for this merge. Indices
    // are post-burning-bug-drop and post-reorg-rewind by construction
    // (they were captured during the apply loop, after
    // `LedgerIndexes::handle_reorg` ran), and they remain valid for
    // the post-pass because the same write guard owns
    // `ledger.transfers` between `apply_scan_result_to_state`'s
    // return and this call.
    //
    // Caller-supplied invariant: every index in `inserted` is in
    // bounds for `ledger.transfers`. The `apply_scan_result_to_state`
    // construction site enforces this; the `debug_assert!` below
    // pins the contract for any future caller that constructs
    // `inserted` independently. Out-of-bounds indices fail loud at
    // the indexing site below rather than silently skipping — a
    // silent skip would leave engine-derived fields un-populated
    // for transfers the caller intended to process, an
    // audit-invisible corruption.
    //
    // Closes FOLLOWUPS V3.0 entry "populate_engine_handle_fields
    // O(n) → O(k) per scan" — see PERF_MERGE_INSERTION_INDICES_PREFLIGHT.md
    // §1 for the historical O(n × B) refresh shape this fixes.
    debug_assert!(
        inserted.iter().all(|&i| i < ledger.transfers.len()),
        "populate_engine_handle_fields: every inserted index must be in bounds for ledger.transfers",
    );
    for &i in inserted {
        let td = &mut ledger.transfers[i];
        // `residue` is keyed by the scanner's raw `[u8; 32]` txid; convert.
        let key = (td.tx_hash.to_bytes(), td.internal_output_index);
        let Some(ciphertext) = residue.get(&key) else {
            continue;
        };
        // Per-field idempotency: respect already-populated values
        // independently. Skipping only when *both* are `Some` would
        // overwrite a partial population, contradicting the "leaves
        // populated fields untouched" contract above. The two fields
        // are derived from disjoint inputs (`source_ciphertext` from
        // residue; `output_handle` from cSHAKE256 over the view
        // secret + tx_hash + index), so partial-population is
        // possible if a future caller writes one without the other.
        if td.source_ciphertext.is_none() {
            td.source_ciphertext = Some(ciphertext.clone());
        }
        if td.output_handle.is_none() {
            td.output_handle = Some(derive_output_handle(
                view_secret,
                td.tx_hash.as_bytes(),
                td.internal_output_index,
            ));
        }
    }
}

#[cfg(test)]
#[path = "merge_tests.rs"]
mod tests;
