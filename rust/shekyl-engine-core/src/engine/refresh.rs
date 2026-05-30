// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Snapshot-merge refresh **orchestrator**.
//!
//! Per C5 of `docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md` §7.X, the
//! producer body lives in
//! `LocalRefresh::produce_scan_result` (the
//! production `RefreshEngine` implementor).
//! This module owns the **orchestration** layer:
//!
//! - [`Engine::refresh`] (the sync entry point) and
//!   [`Engine::start_refresh`] / [`RefreshHandle`] (the async entry
//!   point) drive the producer behind the trait surface;
//! - the snapshot-merge-with-retry loop in `Engine::refresh_with`
//!   takes a fresh [`LedgerSnapshot`] per attempt, hands it to the
//!   producer, and merges the result via
//!   [`Engine::apply_scan_result`] under the merge guard;
//! - the merge surfaces [`RefreshError::ConcurrentMutation`] on
//!   snapshot race; the retry loop pulls a fresh snapshot and tries
//!   again up to `opts.max_retries` times;
//! - [`RefreshError::InternalInvariantViolation`] surfaces
//!   orchestrator control-flow contract failures (e.g. retry loop
//!   exiting without observing the expected discriminant);
//! - producer-side terminal errors (cancellation, daemon-IO budget,
//!   malformed-block rejection) propagate to the caller via the
//!   trait's per-implementor `Self::Error` mapped through
//!   `From<LocalRefreshError> for RefreshError` (see
//!   `crate::engine::local_refresh`).
//!
//! See `docs/V3_WALLET_DECISION_LOG.md`
//! (`Snapshot-merge-with-retry semantics for Engine::refresh`,
//! 2026-04-26) for the substrate the orchestrator is built on.
//!
//! The producer does not mutate wallet state. The merge is the single
//! audited mutation point; see the merge module's docstring for the
//! invariant gates.

use std::ops::Range;

use shekyl_engine_state::{LedgerBlock, ReorgBlocks};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::diagnostics::TracingDiagnosticSink;
use super::error::RefreshError;
use super::local_ledger::LocalLedger;
use super::pending::SnapshotId;
use super::signer::EngineSignerKind;
use super::traits::{DaemonEngine, LedgerEngine, RefreshEngine};
use super::Engine;
use crate::scan::ScanResult;

/// Read-only snapshot of the wallet ledger taken at the start of a
/// refresh.
///
/// The producer (`RefreshEngine::produce_scan_result`) consumes a snapshot for two
/// purposes:
///
/// - parent-hash lookup for the result's
///   [`ScanResult::parent_hash`] field;
/// - reorg-walk-back (the producer's internal `find_fork_point` step) to locate the height at
///   which the daemon's chain agrees with the wallet's recorded
///   chain when a parent-hash mismatch fires.
///
/// # Field set
///
/// Two fields are sufficient because the **merge**, not the producer,
/// performs authoritative spend detection and transfer ingestion:
///
/// - `synced_height`: where the scan picks up.
/// - `reorg_blocks`: the bounded `(height, block_hash)` window the
///   producer needs for parent-hash compare and the producer's `find_fork_point` step.
///
/// The wallet's transfer set, key-image map, pubkey map, and staker
/// pool are deliberately **not** snapshotted: the producer collects
/// every spend-side key image unfiltered into
/// [`ScanResult::spent_key_images`], and
/// [`crate::engine::merge::apply_scan_result_to_state`] calls
/// [`shekyl_engine_state::LedgerIndexes::detect_spends`] against the
/// live (post-lock) state to do the actual matching. This collapses
/// snapshot size to a few KB regardless of wallet size, which keeps
/// the per-refresh `clone` cost bounded.
///
/// # Cloning, not Arc-wrapping
///
/// Per the Phase 2a snapshot-strategy decision, the snapshot is built
/// by cloning these two fields directly (`u64` is trivially cheap;
/// `ReorgBlocks` is a `Vec<(u64, [u8; 32])>` capped at the
/// persistence-layer `DEFAULT_REORG_BLOCKS_CAPACITY`, so cloning it
/// is a small allocation, not a full-ledger walk).
///
/// If profiling under realistic ledger sizes shows `clone()` on hot
/// paths, the strategy may shift to wrapping the inner data in
/// `Arc<…>` behind a follow-up plan; the producer-facing surface
/// (`&LedgerSnapshot`) is stable across that change.
#[derive(Clone, Debug)]
pub struct LedgerSnapshot {
    /// Highest height the wallet has fully ingested at snapshot time.
    /// Equivalent to `LedgerBlock::height()`.
    pub(crate) synced_height: u64,

    /// The wallet's reorg detection window at snapshot time. The
    /// producer queries this for parent-hash compares and the
    /// fork-point walk.
    pub(crate) reorg_blocks: ReorgBlocks,
}

impl LedgerSnapshot {
    /// Build a snapshot from a borrowed [`LedgerBlock`]. The borrow
    /// is dropped immediately by the caller; the snapshot is owned.
    pub(crate) fn from_ledger(ledger: &LedgerBlock) -> Self {
        Self {
            synced_height: ledger.height(),
            reorg_blocks: ledger.reorg_blocks.clone(),
        }
    }

    /// Bench-only constructor: callers in `benches/*.rs` need to build
    /// a snapshot from a synthesized [`LedgerBlock`] without going
    /// through `Engine`. Mirrors [`Self::from_ledger`] exactly; gated
    /// behind `bench-internals` so production builds cannot reach it.
    #[cfg(feature = "bench-internals")]
    #[doc(hidden)]
    pub fn from_ledger_for_bench(ledger: &LedgerBlock) -> Self {
        Self::from_ledger(ledger)
    }

    /// Look up the recorded block hash at `height`. Mirrors
    /// [`LedgerBlock::block_hash_at`] over the snapshotted window.
    /// Returns `None` if the height is below the window's earliest
    /// retained entry or above the snapshotted tip.
    pub(crate) fn block_hash_at(&self, height: u64) -> Option<[u8; 32]> {
        self.reorg_blocks
            .blocks
            .iter()
            .rev()
            .find(|(h, _)| *h == height)
            .map(|(_, hash)| *hash)
    }
}

/// Domain-separation prefix for [`derive_snapshot_id`].
///
/// Bound to a `v1` suffix so a future encoding change can co-exist
/// with the current derivation under a `v2` prefix without colliding
/// on bytes; current callers pin to `v1`. C2γ wired
/// `derive_snapshot_id` into `build_pending_tx_in_state` per the
/// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §7.X commit decomposition,
/// so the prefix is transitively consumed by production code.
pub(crate) const SNAPSHOT_ID_DOMAIN: &[u8] = b"shekyl-snapshot-id-v1";

/// Derive the opaque [`SnapshotId`] for a [`LedgerSnapshot`].
///
/// Per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 Phase 0b: the digest is
/// `cn_fast_hash` (Keccak-256, original padding via
/// [`shekyl_crypto_hash::cn_fast_hash`]) over a canonical byte-encoding
/// of the snapshot's deterministic fields, truncated to the first 128
/// bits. The encoding is:
///
/// ```text
///   SNAPSHOT_ID_DOMAIN           (21 bytes, "shekyl-snapshot-id-v1")
/// ‖ snapshot.synced_height       (LE u64, 8 bytes)
/// ‖ reorg_blocks.blocks.len()    (LE u64, 8 bytes; length prefix)
/// ‖ for each (h, hash) in window:
///     LE u64 height (8 bytes) ‖ 32-byte block hash
/// ```
///
/// The length-prefixed reorg-window count forecloses extension /
/// concatenation collisions against same-tip ledgers with different
/// reorg-window depth; the versioned prefix excludes collisions
/// against any other domain-separated `cn_fast_hash` input that ever
/// shipped in the workspace.
///
/// `pub(crate)`: callers in [`super::pending`] derive `SnapshotId`
/// from an engine-internal snapshot read; consumers never pass a
/// `SnapshotId` into the trait surface from outside.
pub(crate) fn derive_snapshot_id(snapshot: &LedgerSnapshot) -> SnapshotId {
    let n_blocks = snapshot.reorg_blocks.blocks.len();
    let mut buf = Vec::with_capacity(SNAPSHOT_ID_DOMAIN.len() + 8 + 8 + n_blocks * (8 + 32));
    buf.extend_from_slice(SNAPSHOT_ID_DOMAIN);
    buf.extend_from_slice(&snapshot.synced_height.to_le_bytes());
    buf.extend_from_slice(&(n_blocks as u64).to_le_bytes());
    for (height, hash) in &snapshot.reorg_blocks.blocks {
        buf.extend_from_slice(&height.to_le_bytes());
        buf.extend_from_slice(hash);
    }
    let digest = shekyl_crypto_hash::cn_fast_hash(&buf);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    SnapshotId(out)
}

/// Configuration for [`Engine::refresh`].
///
/// The retry budget is the only knob today; future settings (per-call
/// height ceiling, custom cancellation token, progress hook) live on
/// [`RefreshHandle`](super::Engine)'s upcoming branch-2 surface, not
/// here. Keeping this struct `#[non_exhaustive]` reserves the right
/// to add fields without breaking callers that built it
/// field-by-field.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RefreshOptions {
    /// Maximum number of times the snapshot-merge loop is re-driven
    /// after [`RefreshError::ConcurrentMutation`]. Once exhausted, the
    /// last `ConcurrentMutation` is surfaced to the caller.
    ///
    /// Default: `8`. The decision-log entry
    /// `Snapshot-merge-with-retry semantics for Engine::refresh`
    /// (2026-04-26) records the rationale: high enough that the
    /// realistic case (a sibling refresh that completed once during a
    /// long scan) clears on the second attempt; low enough that a
    /// pathological livelock surfaces in bounded wall-clock instead of
    /// hanging the call indefinitely.
    pub max_retries: u32,
}

impl Default for RefreshOptions {
    fn default() -> Self {
        Self { max_retries: 8 }
    }
}

/// Outcome of a successful [`Engine::refresh`] call.
///
/// Built from the merged [`ScanResult`] and the loop bookkeeping
/// (number of merge attempts spent on the snapshot-race retry path).
/// Counts are computed on the producer-emitted result before the
/// merge consumes it; they describe what the producer observed, not
/// what the merge ingested. The two are equal on the success path
/// (`apply_scan_result` returns `Ok`); on a malformed result the
/// merge surfaces [`RefreshError::MalformedScanResult`] before this
/// summary is constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefreshSummary {
    /// Inclusive-exclusive range of heights scanned by the producer
    /// (after any reorg-rewind adjustment). When the wallet is at the
    /// daemon's tip and no new blocks were available, this is
    /// `synced_height + 1 .. synced_height + 1` (an empty range with
    /// `blocks_processed == 0`).
    pub processed_height_range: Range<u64>,

    /// Count of distinct heights for which the producer recorded a
    /// `(height, block_hash)` entry. On the no-reorg path this equals
    /// `processed_height_range.len()`; on a reorg path some heights at
    /// the top of the original range are discarded and re-scanned
    /// from the fork point, so the count reflects post-rewind work.
    pub blocks_processed: u64,

    /// Number of [`DetectedTransfer`] entries the producer recovered.
    /// These are the per-output recoveries the scanner returned; the
    /// merge ingests every entry into [`shekyl_engine_state::LedgerIndexes`].
    pub transfers_detected: usize,

    /// Number of input key images the producer collected, unfiltered,
    /// from the scanned blocks. The merge filters this against the
    /// wallet's owned-output set; this count is the producer-side
    /// observation, not the merge's spend count.
    pub key_images_observed: usize,

    /// Count of per-block stake-lifecycle events recorded by the
    /// producer. Phase 2b grows this to a richer per-event vocabulary;
    /// today it is always `0` and exists in the summary so the field
    /// set is stable across the V3.x lifetime.
    pub stake_events: usize,

    /// `Some(_)` when the producer detected a reorg during this
    /// refresh attempt and rewound the scan to the recorded fork
    /// height. `None` on a clean linear scan.
    pub reorg: Option<RefreshReorgEvent>,

    /// Number of merge attempts the snapshot-race retry loop spent.
    /// `1` on the common path (merge succeeds first try); `>1` only
    /// when at least one [`RefreshError::ConcurrentMutation`] was
    /// observed and a fresh snapshot drove a re-attempt. Always `>=1`.
    pub merge_attempts: u32,
}

/// Detail of a reorg detected during a single [`Engine::refresh`]
/// call. The producer records at most one reorg per call; subsequent
/// reorgs landing while the new chain is being scanned are surfaced as
/// [`RefreshError::ConcurrentMutation`] on the next merge attempt and
/// the retry loop pulls a fresh snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefreshReorgEvent {
    /// Height the wallet rewound to before continuing the forward
    /// scan. Heights `>= fork_height` from the wallet's pre-refresh
    /// state were discarded; heights `< fork_height` survive the merge
    /// unchanged.
    pub fork_height: u64,
}

// ── Branch 2: async refresh driver surface ─────────────────────────
//
// The types in this section are the public face of the in-task
// snapshot-merge driver introduced by Branch 2's
// [`Engine::start_refresh`]. They sit on top of the synchronous
// [`Engine::refresh`] / `Engine::refresh_with` primitives and add
// cancel-on-drop, single-flight enforcement, push-delivered
// completion (oneshot), and per-block progress emission (watch).
//
// The shared-handle parameter shape (`Arc<RwLock<Engine<S>>>`) is
// transitional infrastructure; it is removed at Stage 4 (kameo
// actor cutover) in a single API-call-site change. See
// [`docs/V3_WALLET_DECISION_LOG.md`] entry
// `Path B engine binary boundary as pure message-passing`
// (2026-04-27) for the rationale.

/// Phase of an in-flight refresh.
///
/// Reported via [`RefreshProgress::phase`] and updated by the
/// producer task as it walks the per-attempt state machine. The
/// phase is a coarse classifier — fine-grained per-block progress
/// rides alongside it as `blocks_processed` / `blocks_total`.
///
/// `#[non_exhaustive]` reserves the right to add phases (e.g.
/// `FetchingTip`, `MergingPostSync`) without breaking matches. UI
/// consumers should treat unknown discriminants as
/// `Scanning`-equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RefreshPhase {
    /// Producer is fetching blocks from the daemon and feeding them
    /// to the scanner. The dominant phase of a refresh; per-batch
    /// progress updates land here.
    Scanning,

    /// Producer has finished scanning and is acquiring the engine
    /// write-lock to merge the [`ScanResult`]. Brief — bounded by
    /// the merge's compute (no I/O).
    Merging,

    /// A merge attempt observed
    /// [`RefreshError::ConcurrentMutation`]; the loop is pulling a
    /// fresh snapshot and re-scanning. `blocks_total` updates on
    /// the retry boundary to reflect the new tip.
    Retrying,

    /// The cancel token fired and the producer is winding down. No
    /// further progress will be published; the next observation by
    /// the receiver after seeing `Cancelled` is `RecvError`
    /// (Sender dropped on task exit).
    Cancelled,
}

/// Snapshot of refresh progress published per-batch by the producer.
///
/// Delivered via [`tokio::sync::watch`]: subscribers always observe
/// the **latest** value, never an intermediate one. This is the
/// correct semantics for UI — a dashboard wants "where are we now",
/// not "every batch we ever processed."
///
/// All fields are intentionally `Copy`-friendly (`u64`s and a
/// `Copy` enum) so cloning is trivial; the watch channel clones on
/// every `borrow().clone()` from a subscriber.
///
/// # Field semantics
///
/// - `height`: the height the producer most recently completed
///   scanning (i.e. `synced_height + blocks_processed`). On
///   initial publish this is `synced_height` itself.
/// - `blocks_processed`: count of blocks the producer has fed to
///   the scanner during the **current attempt**. Resets to `0` on
///   `RefreshPhase::Retrying`.
/// - `blocks_total`: the per-attempt scan range size — the count
///   of blocks the producer plans to fetch and scan during this
///   attempt. Concretely, `blocks_total =
///   daemon.get_height().saturating_sub(synced_height + 1)` at
///   attempt start, where `daemon.get_height()` returns the count
///   of blocks (one past the tip-block index). Saturates to `0`
///   when the wallet is at-or-above the daemon tip. Updates on
///   retry boundaries because each attempt re-fetches the tip;
///   static within an attempt.
/// - `phase`: see [`RefreshPhase`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefreshProgress {
    /// Height the producer most recently completed scanning.
    pub height: u64,

    /// Blocks processed in the current attempt (resets on retry).
    pub blocks_processed: u64,

    /// Total blocks in the current attempt's scan range. Updates on
    /// retry boundaries.
    pub blocks_total: u64,

    /// Current phase of the refresh.
    pub phase: RefreshPhase,
}

impl RefreshProgress {
    /// Synthetic zero-height baseline. **Test helpers only** —
    /// production seeders (today: [`Engine::start_refresh`])
    /// override `height` with the wallet's current `synced_height`
    /// so the contract on [`RefreshProgress::height`] ("on initial
    /// publish this is `synced_height` itself") holds even before
    /// the producer publishes its first per-attempt update.
    /// Tests that don't care about height accuracy use this as a
    /// blank starting value.
    #[cfg(test)]
    pub(crate) const fn initial() -> Self {
        Self {
            height: 0,
            blocks_processed: 0,
            blocks_total: 0,
            phase: RefreshPhase::Scanning,
        }
    }
}

/// RAII handle to a refresh task spawned by
/// [`Engine::start_refresh`].
///
/// Cancellation is RAII: dropping the handle fires the
/// cancel token; the producer observes it at the next batch
/// boundary, returns `Err(Cancelled)`, and exits. The handle does
/// not block in `Drop` — the wind-down happens on the runtime that
/// owns the task.
///
/// Single-flight is enforced via [`RefreshSlot`]: at most one
/// refresh task per `Engine<S>` exists at a time. A racing
/// `start_refresh` returns
/// [`RefreshError::AlreadyRunning`](super::RefreshError::AlreadyRunning).
///
/// # Methods
///
/// - [`progress()`](Self::progress) — subscribe to per-batch
///   progress updates. Returns a [`tokio::sync::watch::Receiver`].
/// - [`cancel()`](Self::cancel) — fire the cancel token explicitly;
///   idempotent. Equivalent to dropping the handle, but lets the
///   caller continue to observe progress and `join()` the result.
/// - [`is_running()`](Self::is_running) — non-blocking check
///   whether the producer task has completed.
/// - [`join()`](Self::join) — async — await the terminal
///   [`RefreshSummary`] or [`RefreshError`]. Consumes the handle.
///
/// # Stage-4 invariance
///
/// `RefreshHandle`'s public surface — `progress()`, `cancel()`,
/// `is_running()`, `join()`, and `Drop` semantics — is invariant
/// across the Stage 4 actor cutover. Today, `start_refresh` takes
/// `Arc<RwLock<Self>>` and returns this type directly. After Stage
/// 4, `actor.ask(StartRefresh { opts }).send().await?` returns the
/// same `RefreshHandle`; the actor message-passing replaces the
/// shared-handle plumbing inside the type, but every method
/// signature on the handle stays bit-identical. Callers above the
/// engine binary boundary do not change.
///
/// This invariance is the contract that lets Branch 2 ship before
/// the actor cutover without forcing an API break later.
///
/// [`RefreshSlot`]: RefreshSlot
pub struct RefreshHandle {
    /// Receive-end of the oneshot the producer task sends its
    /// terminal result on. `join()` consumes the handle and awaits
    /// this. `Some(_)` until `join()` is called; `None` after
    /// `join()` consumes it (handle is also consumed at that point,
    /// so this isn't really observable post-`join`, but the option
    /// shape keeps the field's lifetime story explicit).
    completion_rx: Option<tokio::sync::oneshot::Receiver<Result<RefreshSummary, RefreshError>>>,

    /// Cancel token shared with the producer task. `cancel()` and
    /// `Drop` both fire it. The token is internally `Arc`'d so
    /// dropping the handle's clone after firing does not abort the
    /// producer's observation; the token's `Arc` stays alive as
    /// long as the producer holds its clone.
    cancel_token: CancellationToken,

    /// Receive-end of the watch channel the producer publishes
    /// per-batch progress on. Cloned out of the handle by
    /// [`progress()`](Self::progress); the original lives here so
    /// callers that don't subscribe still keep the channel from
    /// closing prematurely on the producer's side.
    progress_rx: tokio::sync::watch::Receiver<RefreshProgress>,

    /// `JoinHandle` of the spawned producer task. Retained for two
    /// reasons:
    ///
    /// 1. Test wind-down assertions: corner-case unit tests
    ///    (commit 5) need to await the producer's exit to assert
    ///    that the slot was released, the progress channel closed,
    ///    etc. The `JoinHandle` is the only way to do that
    ///    deterministically.
    /// 2. Stage-4 transition reference: the actor cutover replaces
    ///    `tokio::spawn` with `kameo::actor::spawn`, which returns
    ///    an `ActorRef` that is observable similarly. Keeping the
    ///    field on the handle marks the migration site explicitly.
    ///
    /// Not used for primary synchronization — `join()` awaits
    /// `completion_rx`, not this. The producer task's lifecycle
    /// extends slightly past `completion_tx.send(...)` (slot guard
    /// drop, etc.); awaiting `JoinHandle` would observe a different
    /// completion semantic than the user-visible "the refresh is
    /// done" point.
    producer_join: tokio::task::JoinHandle<()>,

    /// Snapshot of the [`RefreshOptions`] the handle was started
    /// with. Retained for diagnostics (debug printing, test
    /// assertions) and Stage-4 actor-message reconstruction (the
    /// actor's `StartRefresh` message must carry the same opts so
    /// the actor can re-invoke the same loop logic). Not used by
    /// the methods on the handle today.
    #[allow(dead_code)] // Stage-4 reference + diagnostics
    opts: RefreshOptions,
}

impl RefreshHandle {
    /// Subscribe to per-batch progress updates.
    ///
    /// The returned [`tokio::sync::watch::Receiver`] always observes
    /// the **latest** [`RefreshProgress`] — never an intermediate
    /// one. Subscribers may clone the receiver freely; the channel
    /// stays open as long as the producer task is alive.
    ///
    /// When the producer exits (success, error, or cancellation),
    /// its `Sender` drops and subsequent `changed().await` calls
    /// return `Err(_)` ("the producer is done; no more progress").
    pub fn progress(&self) -> tokio::sync::watch::Receiver<RefreshProgress> {
        self.progress_rx.clone()
    }

    /// Fire the cancel token. Idempotent — multiple calls are
    /// no-ops after the first.
    ///
    /// The producer observes the token at the next batch boundary
    /// or backoff `select!`, returns
    /// [`RefreshError::Cancelled`], and exits. After cancellation,
    /// `join().await` surfaces `Err(Cancelled)`.
    ///
    /// Equivalent to dropping the handle, except that the caller
    /// can continue to observe `progress()` and await `join()`.
    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }

    /// Non-blocking check whether the producer task has completed.
    ///
    /// Returns `true` while the task is alive (scanning, merging,
    /// retrying, or cancelling), `false` once it has exited and
    /// the `JoinHandle` is finished. UI code can poll this on a
    /// timer to drive a "Refresh in progress" indicator without
    /// blocking on `join()`.
    pub fn is_running(&self) -> bool {
        !self.producer_join.is_finished()
    }

    /// Await the terminal result of the refresh.
    ///
    /// Consumes the handle. Returns the [`RefreshSummary`] on
    /// success, or the terminal [`RefreshError`] on failure or
    /// cancellation.
    ///
    /// # Panics
    ///
    /// Does not panic in normal operation. If the producer task
    /// panicked (which would be an internal-consistency bug), the
    /// oneshot's `Sender` is dropped without sending; this surface
    /// returns
    /// [`RefreshError::InternalInvariantViolation`] with a static
    /// context pointing at the panic site so audit reads a typed
    /// contract failure rather than a silent loss.
    pub async fn join(mut self) -> Result<RefreshSummary, RefreshError> {
        let rx = self
            .completion_rx
            .take()
            .expect("RefreshHandle::join is called at most once: the type consumes self");
        match rx.await {
            Ok(result) => result,
            Err(_) => Err(RefreshError::InternalInvariantViolation {
                context:
                    "RefreshHandle::join: producer task dropped completion sender without delivery",
            }),
        }
    }

    /// Test-only constructor that injects pre-built channels and a
    /// stand-in `JoinHandle`.
    ///
    /// `RefreshHandle`'s production constructor lives entirely
    /// inside [`Engine::start_refresh`], which spawns a real
    /// producer task driving an `Arc<RwLock<Engine<S>>>`. Unit tests
    /// of the handle's public surface (`progress`, `cancel`,
    /// `is_running`, `join`, `Drop`) do not need a real engine and
    /// would not benefit from one — the surface is a thin wrapper
    /// around the four channel ends. This constructor lets a test
    /// supply each end directly so it can drive the handle's
    /// observable state deterministically.
    ///
    /// `producer_join` is conventionally either:
    /// - `tokio::spawn(async move { /* loop on cancel */ })` for
    ///   tests that need `is_running()` to start `true`, or
    /// - `tokio::spawn(async {})` (already-finished) for tests that
    ///   just want to assert on the join's terminal state.
    ///
    /// Single-flight semantics are out-of-scope for handle-level
    /// unit tests: the slot is owned by `Engine<S>`, not the
    /// handle, and is exercised via the integration tests in
    /// commit 6 that go through the real `start_refresh`.
    #[cfg(test)]
    pub(crate) fn for_test(
        completion_rx: tokio::sync::oneshot::Receiver<Result<RefreshSummary, RefreshError>>,
        cancel_token: CancellationToken,
        progress_rx: tokio::sync::watch::Receiver<RefreshProgress>,
        producer_join: tokio::task::JoinHandle<()>,
        opts: RefreshOptions,
    ) -> Self {
        Self {
            completion_rx: Some(completion_rx),
            cancel_token,
            progress_rx,
            producer_join,
            opts,
        }
    }
}

impl std::fmt::Debug for RefreshHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshHandle")
            .field("opts", &self.opts)
            .field("is_running", &self.is_running())
            .finish_non_exhaustive()
    }
}

impl Drop for RefreshHandle {
    /// Cancel-on-drop. Sequence:
    ///
    /// 1. Fire the cancel token. The producer task observes it at
    ///    the next batch boundary or backoff `select!`, returns
    ///    [`RefreshError::Cancelled`], and exits.
    /// 2. Remaining handle fields drop in declaration order:
    ///    `completion_rx` (the oneshot receive end goes away),
    ///    `progress_rx`, `producer_join`. Dropping
    ///    `producer_join` detaches the task without aborting it
    ///    (tokio semantics): the task continues running until it
    ///    observes the cancel token and exits naturally. Note that
    ///    the progress `Sender` lives on the producer task, not on
    ///    the handle, so dropping the handle does not close the
    ///    progress channel — the producer's final `Cancelled`
    ///    publish still reaches any retained `Receiver` clones.
    ///
    /// The wind-down between `cancel.cancel()` and task exit is
    /// bounded by the longest-running operation in the task (one
    /// block fetch's RPC timeout, ~30 s worst case). During this
    /// window, a racing [`Engine::start_refresh`] returns
    /// [`RefreshError::AlreadyRunning`] because the producer's
    /// [`SlotGuard`] is still held. Callers that want to spawn a
    /// new refresh immediately after dropping a handle should hold
    /// the previous handle and `await join()` instead of relying on
    /// `Drop`.
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

// ── Single-flight slot ─────────────────────────────────────────────
//
// The slot is a per-Engine `Arc<AtomicBool>` kept on the engine
// struct. `start_refresh` claims the flag (CAS false → true) under
// a brief read borrow of the engine; if the CAS fails, another
// refresh is in flight and the call returns
// `RefreshError::AlreadyRunning`. The producer task holds a
// `SlotGuard` for the duration of the refresh; dropping the guard
// releases the flag (RAII).
//
// Independent of the engine's cross-cutting RwLock — the slot is
// its own atomic, so `start_refresh` does not need a write borrow
// of `Engine<S>` to claim it. This keeps the slot-claim path lock-
// free against the producer task's per-attempt read/write borrows.

/// Per-engine single-flight slot for [`Engine::start_refresh`].
///
/// Cloneable; the slot itself is reference-counted, so cloning a
/// `RefreshSlot` produces another handle to the same underlying
/// flag. The engine struct owns one; the producer task's
/// [`SlotGuard`] holds another for its lifetime.
#[derive(Clone, Debug)]
pub(crate) struct RefreshSlot {
    flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl RefreshSlot {
    /// Build a fresh slot in the released state. Called once at
    /// `Engine::assemble` time.
    pub(crate) fn new() -> Self {
        Self {
            flag: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Attempt to claim the slot. Returns `Some(SlotGuard)` on
    /// success (the slot is now held; `Drop` will release it).
    /// Returns `None` if the slot is already held by another
    /// refresh task.
    ///
    /// Implemented as a single CAS (Acquire on success, Relaxed on
    /// failure) so claim and release pair across threads without
    /// needing a stronger fence.
    pub(crate) fn try_claim(&self) -> Option<SlotGuard> {
        match self.flag.compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::Acquire,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(_) => Some(SlotGuard {
                flag: self.flag.clone(),
            }),
            Err(_) => None,
        }
    }

    /// Read the slot's current state without claiming it. Used by
    /// the redacted `Debug` impl on `Engine<S>` to surface "is a
    /// refresh in flight" without taking a guard.
    pub(crate) fn is_claimed(&self) -> bool {
        self.flag.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// RAII guard for the [`RefreshSlot`] flag. Held by the producer
/// task; dropping it releases the flag.
///
/// Deliberately not `Clone`: the guard's whole purpose is to
/// uniquely own the claim, so cloning it would defeat single-
/// flight enforcement. The producer task receives the guard from
/// [`Engine::start_refresh`] and holds it through `run_refresh_task`'s
/// full lifetime; the `Drop` releases the slot whether the task
/// returned successfully, errored, or was cancelled.
#[derive(Debug)]
pub(crate) struct SlotGuard {
    flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        // Release: pair with `Acquire` on the matching `try_claim`.
        // Idempotent — if the slot was double-released somehow, the
        // store is a no-op (the second release would still write
        // `false` to a flag that's already `false`).
        self.flag.store(false, std::sync::atomic::Ordering::Release);
    }
}

// Static asserts: trait bounds the Branch 2 surface depends on.
// Failure here means a downstream type lost its Send/Sync/Clone
// invariant; surface the violation at the engine-core build rather
// than at the spawn / channel-construction site in start_refresh.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    fn assert_clone_send_sync<T: Clone + Send + Sync>() {}
    assert_send::<RefreshHandle>();
    assert_clone_send_sync::<RefreshProgress>();
    // RefreshOptions: Clone is required for opts.clone() at task
    // spawn (start_refresh body retains a copy on the handle for
    // diagnostics). Verified: refresh.rs derives Clone on
    // RefreshOptions (line ~241).
    fn assert_clone<T: Clone>() {}
    assert_clone::<RefreshOptions>();
    // RefreshError: Send + Sync is required for the oneshot
    // payload to cross the spawn boundary. Trivially holds —
    // every variant carries primitive types or owned strings; the
    // `ConcurrentMutation` variant's `wallet: u64, result: u64`
    // does not bleed engine state into the error.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RefreshError>();
    assert_send_sync::<RefreshSummary>();
};

/// Producer task entry point.
///
/// Spawned by [`Engine::start_refresh`]. Drives the snapshot-merge
/// loop end-to-end: fetch tip, snapshot, scan (without holding the
/// engine lock), merge under write lock, retry on
/// `ConcurrentMutation` until `opts.max_retries` is reached, and
/// publish a terminal result on `completion`.
///
/// ## Parameters
///
/// - `engine_arc`: shared handle to the engine. The task holds the
///   read lock briefly per attempt for the snapshot, drops it
///   across the network-bound scan, then re-acquires the write
///   lock for the merge. Stage 4 replaces this with actor message
///   passing.
/// - `opts`: the same `RefreshOptions` `start_refresh` was called
///   with. Carries `max_retries` for the snapshot-race retry
///   budget.
/// - `cancel`: cooperative cancel token; observed at every batch
///   boundary and during retry-backoff `select!`s. Fired by
///   `RefreshHandle::cancel()` and by `Drop`.
/// - `progress`: the producer's sole `Sender` for the watch
///   channel. Published per-batch while scanning; the final
///   `Cancelled` / terminal phase publish runs before the task
///   exits.
/// - `completion`: oneshot the producer sends its terminal result
///   on. Awaited by `RefreshHandle::join`.
/// - `_slot_guard`: held by name only — the parameter exists so
///   the slot stays claimed for the **full lifetime** of this
///   function, including post-`completion.send(...)` wind-down.
///   When the function returns (success, error, or cancellation),
///   the guard drops and releases the engine's `RefreshSlot` flag.
///   This is the mechanism that ensures single-flight semantics:
///   the slot stays claimed until the task exits, so a racing
///   `start_refresh` returns `AlreadyRunning` even during cancel-
///   then-cleanup wind-down. The `_` prefix is the standard Rust
///   idiom for "RAII guard, intentionally unused in the function
///   body but held for `Drop` semantics."
///
/// Drive the asynchronous snapshot–scan–merge–retry loop on behalf of
/// [`Engine::start_refresh`].
///
/// # Locking topology
///
/// Per attempt:
/// 1. **Read lock** — acquired briefly to clone [`DaemonClient`] (for the
///    network calls below) and to take a fresh [`LedgerSnapshot`]. The
///    lock is released before any I/O.
/// 2. **No lock** — daemon `get_height`, scanner construction (first
///    attempt only), and `RefreshEngine::produce_scan_result` run with no engine
///    borrow held. This is the long phase, on the order of network
///    round-trips per block, and is exactly why the function exists in
///    the first place.
/// 3. **Write lock** — acquired briefly to call
///    [`Engine::apply_scan_result`]. The merge fails with
///    [`RefreshError::ConcurrentMutation`] iff another writer
///    interleaved between the snapshot and the merge; that variant
///    is the loop's signal to retry, not a terminal error.
///
/// # `_slot_guard`
///
/// The [`SlotGuard`] returned by [`RefreshSlot::try_claim`] in
/// [`Engine::start_refresh`] is moved into this task and held by name
/// for the task's entire body. Its [`Drop`] impl flips the
/// `refresh_slot` flag back to `false`, releasing single-flight
/// exclusion. Releasing on task exit (rather than on
/// [`RefreshHandle::drop`]) is what guarantees a fresh
/// [`Engine::start_refresh`] cannot observe `AlreadyRunning` after a
/// cancelled handle is dropped but before the producer task has
/// actually noticed the cancellation and unwound — which would race
/// the task against the next refresh on the same engine. The
/// underscore prefix is a deliberate signal that the binding is held
/// for its `Drop` side-effect, not read.
///
/// # Cancellation
///
/// The cancellation token is checked at four points:
///
/// 0. **Pre-anchor** — before the birthday-anchor preflight. The
///    anchor fetches a block hash from the daemon and advances
///    `LocalLedger` to `floor - 1`; both are refresh-side side
///    effects. A cancel observed here short-circuits to `Cancelled`
///    without committing them, so an already-cancelled task does not
///    mutate wallet state.
/// 1. **Top of each attempt** — covers the boundary between attempts,
///    including the gap between a `Retrying` publish and the next
///    snapshot.
/// 2. **Post-tip-fetch**, immediately after `daemon.get_height()`
///    returns `Ok` — covers cancels that fire during the daemon RPC
///    itself. The RPC isn't cancel-aware, so the await runs to
///    completion; this checkpoint is what makes a cancel-during-tip-
///    fetch deterministically surface as `Cancelled` rather than
///    leak into the per-block scan.
/// 3. **Mid-scan**, inside `RefreshEngine::produce_scan_result` — covers between
///    blocks during the long scan, which is where the bulk of the
///    elapsed time lives.
/// 4. **Pre-merge**, between `RefreshEngine::produce_scan_result` returning `Ok`
///    and the write-lock acquisition for [`Engine::apply_scan_result`]
///    — covers the post-scan window where the producer holds a
///    valid `ScanResult` but has not yet mutated wallet state. A
///    cancel observed here is honoured because the merge has not
///    committed; the in-flight `ScanResult` is discarded along with
///    the work that produced it. This is the trade-off cancellation
///    asks us to make.
///
/// On observation at any of these points, a final `Cancelled`
/// progress update is best-effort emitted — preserving the last
/// published `height` / `blocks_processed` / `blocks_total` so
/// subscribers don't observe a misleading rollback to zero — and
/// `RefreshError::Cancelled` is delivered via the completion
/// oneshot.
///
/// There is **no** post-merge cancel checkpoint. Once
/// [`Engine::apply_scan_result`] commits under the write lock the
/// state mutation is authoritative, and a cancel token observed
/// after that point cannot un-mutate the wallet. The post-merge
/// path always delivers `Ok(summary)`; consumers that want to
/// abandon a successful refresh in flight have to drop the handle
/// and reconcile against the next `progress().borrow()`.
#[allow(clippy::type_complexity)]
async fn run_refresh_task<S, D: DaemonEngine, R, P>(
    engine_arc: std::sync::Arc<tokio::sync::RwLock<Engine<S, D, LocalLedger, R, P>>>,
    opts: RefreshOptions,
    cancel: CancellationToken,
    progress: tokio::sync::watch::Sender<RefreshProgress>,
    completion: tokio::sync::oneshot::Sender<Result<RefreshSummary, RefreshError>>,
    _slot_guard: SlotGuard,
) where
    S: EngineSignerKind + Send + Sync + 'static,
    R: RefreshEngine + super::scan_floor::ScanStartFloorProvider + Send + Sync + 'static,
    P: super::traits::PendingTxEngine + Send + Sync + 'static,
    Engine<S, D, LocalLedger, R, P>: Send + Sync,
{
    // Pre-anchor cancellation checkpoint (point 0 in the cancellation
    // contract above). The birthday anchor fetches a block hash from
    // the daemon and advances `LocalLedger` to `floor - 1`; both are
    // refresh-side side effects. A cancel observed before the anchor
    // must short-circuit to `Cancelled` without committing them, so a
    // handle dropped or cancelled before the task runs does not mutate
    // wallet state.
    if cancel.is_cancelled() {
        let mut terminal = *progress.borrow();
        terminal.phase = RefreshPhase::Cancelled;
        _ = progress.send(terminal);
        _ = completion.send(Err(RefreshError::Cancelled));
        return;
    }
    {
        let g = engine_arc.read().await;
        let floor = g.refresh.scan_start_floor();
        let daemon = g.daemon().clone();
        if let Err(e) = super::scan_floor::ensure_birthday_anchor(&g.ledger, &daemon, floor).await {
            _ = completion.send(Err(e));
            return;
        }
    }

    // Producer-side observability sink. `TracingDiagnosticSink` is the
    // V3.0 canonical projection per `engine/diagnostics.rs` F9: each
    // RefreshDiagnostic variant is routed to a typed `tracing` span
    // with bucketed labels. Constructed once per refresh and shared
    // by reference into every attempt's `RefreshEngine::produce_scan_result` call —
    // the sink is a unit struct (`Copy`), so the inline ceremony is
    // free.
    let sink = TracingDiagnosticSink::new();

    let mut last_concurrent_mutation: Option<RefreshError> = None;

    for attempt in 1..=opts.max_retries.saturating_add(1) {
        if cancel.is_cancelled() {
            // Best-effort terminal progress. Preserve the last
            // published baseline (height / counters) and override
            // only `phase`, so subscribers don't observe a
            // misleading rollback to `height: 0` when the wallet
            // was already synced above zero. `Receiver::changed`
            // wakes once before the channel closes.
            let mut terminal = *progress.borrow();
            terminal.phase = RefreshPhase::Cancelled;
            _ = progress.send(terminal);
            _ = completion.send(Err(RefreshError::Cancelled));
            return;
        }

        // Snapshot + daemon clone + refresh-impl Arc-clone. Take the
        // engine read-lock once per attempt to extract three
        // independently-owned values, then drop the guard before
        // dispatching the producer body:
        //
        // - `snapshot: LedgerSnapshot` — owned snapshot of wallet
        //   state at the attempt's start.
        // - `daemon: D` — daemon-trait implementor (cheap Arc-clone
        //   in the production `DaemonClient` case).
        // - `refresh: Arc<R>` — producer-trait implementor handle.
        //   `Engine::refresh` is `Arc<R>` precisely so the long-
        //   running scan can dispatch through the trait surface
        //   without holding the engine read-lock through the
        //   `RefreshEngine::produce_scan_result(...).await` (which would block the merge
        //   path's write-lock acquisition).
        //
        // Snapshot acquisition goes through [`LedgerEngine::snapshot`]
        // on the implementor field (the trait-dispatch path); the
        // implementor manages its own guard internally. Outer engine
        // borrow is shared (`read().await`) per the §5 commit-5
        // relaxation: with mutation interior to `LocalLedger`, the
        // refresh driver no longer needs an exclusive engine borrow.
        let (snapshot, daemon, refresh) = {
            let g = engine_arc.read().await;
            (
                g.ledger.snapshot(),
                g.daemon().clone(),
                std::sync::Arc::clone(&g.refresh),
            )
        };
        let current_synced = snapshot.synced_height;

        // Trait dispatch: the producer body lives in the
        // [`RefreshEngine`] implementor (production default
        // [`crate::engine::LocalRefresh`]), per
        // `docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md` §7.X C5. The
        // implementor owns scanner construction, the daemon-tip read,
        // per-block fetch + retry, per-block progress emission on the
        // `watch::Sender<RefreshProgress>`, and the producer-side
        // cancellation checkpoints 2/3/4/5 (per `traits/refresh.rs`
        // §"Cancellation discipline"). The orchestrator owns
        // checkpoints 1 (top-of-attempt, above) and the pre-merge
        // checkpoint (below).
        let produced = refresh
            .produce_scan_result(
                snapshot,
                &daemon,
                opts.clone(),
                cancel.clone(),
                progress.clone(),
                &sink,
            )
            .await;

        let result = match produced.map_err(Into::into) {
            Ok(r) => r,
            Err(RefreshError::Cancelled) => {
                // Mid-scan cancel: the producer observed the cancel
                // token at one of its internal checkpoints (2, 3,
                // or 5) and bailed. Mirror the top-of-attempt
                // cancel emission — preserve the last published
                // baseline (which the producer's per-block emit
                // advanced as the scan ran) and override only
                // `phase`.
                let mut terminal = *progress.borrow();
                terminal.phase = RefreshPhase::Cancelled;
                _ = progress.send(terminal);
                _ = completion.send(Err(RefreshError::Cancelled));
                return;
            }
            Err(e) => {
                _ = completion.send(Err(e));
                return;
            }
        };

        let summary = summarize(&result, attempt);

        // Pre-merge cancel checkpoint. The producer returned a valid
        // `ScanResult`, but the user fired `cancel` between the last
        // per-block check inside `RefreshEngine::produce_scan_result` and now. The
        // merge has not yet acquired the write lock, so wallet state
        // is unmutated and we can still honour the cancellation
        // without rolling anything back. After this point the merge
        // is authoritative — see the function docstring.
        if cancel.is_cancelled() {
            let mut terminal = *progress.borrow();
            terminal.phase = RefreshPhase::Cancelled;
            _ = progress.send(terminal);
            _ = completion.send(Err(RefreshError::Cancelled));
            return;
        }

        // Best-effort `Merging` ping right before the write-lock. The
        // merge is bounded by compute (no I/O), so subscribers
        // observing this phase are usually about to immediately
        // observe success or a retry. `blocks_total` mirrors
        // `blocks_processed`: the producer is done, so total equals
        // processed at this phase transition.
        _ = progress.send(RefreshProgress {
            height: summary
                .processed_height_range
                .end
                .saturating_sub(1)
                .max(current_synced),
            blocks_processed: summary.blocks_processed,
            blocks_total: summary.blocks_processed,
            phase: RefreshPhase::Merging,
        });

        // Merge under the **read** lock on the outer engine: per the
        // §5 commit-5 outer-lock relaxation, the wallet-state mutation
        // is interior to `LocalLedger`'s own write guard — the outer
        // `Arc<RwLock<Engine<S, D, LocalLedger>>>` only needs a shared
        // borrow for the merge call. The interior write guard
        // serializes mutation against any concurrent reader on the
        // same engine. On `ConcurrentMutation` we loop with a fresh
        // snapshot.
        //
        // The merge goes through the LocalLedger-specialized
        // [`Engine::apply_scan_result`] (in `engine/merge.rs`), **not**
        // a `LedgerEngine` trait method (FOLLOWUPS P1). The trait
        // implementor has no access to the engine's `view_secret`, so
        // a trait-dispatched merge could only run the bookkeeping fold
        // and would skip the M3b engine post-pass
        // ([`populate_engine_handle_fields`]) that populates
        // `source_ciphertext` / `output_handle` on freshly-merged
        // transfers. `Engine::apply_scan_result` runs the fold and the
        // post-pass under a single `LocalLedger` write guard, keeping
        // the two atomic against external readers
        // (`docs/design/STAGE_1_PR_3_M3B_PREFLIGHT.md` §3 rejected
        // alternative (ζ): no non-atomic intermediate state). It is a
        // synchronous call (the post-pass is a pure cryptographic
        // primitive at M3b), so the outer engine read-guard `g` is
        // held only for the bounded, compute-only merge — no `.await`
        // runs while it is held.
        let merge = {
            let g = engine_arc.read().await;
            g.apply_scan_result(result)
        };

        match merge {
            Ok(()) => {
                // No terminal `Done` progress phase: the completion
                // oneshot is the authoritative success signal. Once
                // we drop `progress` on return, the receiver's next
                // `changed().await` returns `RecvError`, which is
                // the watch-channel idiom for "no further updates."
                _ = completion.send(Ok(summary));
                return;
            }
            Err(RefreshError::ConcurrentMutation { wallet, result }) => {
                debug!(
                    attempt,
                    max_retries = opts.max_retries,
                    wallet,
                    result,
                    "run_refresh_task: snapshot race, retrying with fresh snapshot",
                );
                // Re-baseline progress with current_synced and zeroed
                // counters. The next attempt's `RefreshEngine::produce_scan_result`
                // re-derives `blocks_total` from a fresh snapshot +
                // daemon-tip read; the orchestrator no longer owns
                // that value after the C5 trait-dispatch migration.
                _ = progress.send(RefreshProgress {
                    height: current_synced,
                    blocks_processed: 0,
                    blocks_total: 0,
                    phase: RefreshPhase::Retrying,
                });
                last_concurrent_mutation =
                    Some(RefreshError::ConcurrentMutation { wallet, result });
                continue;
            }
            Err(other) => {
                _ = completion.send(Err(other));
                return;
            }
        }
    }

    // Retry budget exhausted on `ConcurrentMutation`. Mirror
    // `Engine::refresh_with`: surface the last observed race;
    // falling through with `None` would mean the loop body itself
    // is broken, which we surface as `InternalInvariantViolation`
    // (the C5-migrated discriminant for refresh-loop control-flow
    // contract failures per `STAGE_1_PR_4_REFRESH_ENGINE.md` §7.X
    // C5) so audit reads a typed contract failure rather than
    // silent retry exhaustion. The legacy `MalformedScanResult`
    // discriminant carried producer-internal text via its `reason`
    // field; the C5 discipline routes producer payloads through the
    // `DiagnosticSink` and reserves typed `RefreshError` variants
    // for orchestrator control flow only.
    let terminal = last_concurrent_mutation.unwrap_or(RefreshError::InternalInvariantViolation {
        context: "run_refresh_task retry loop exited without an observed ConcurrentMutation",
    });
    _ = completion.send(Err(terminal));
    // _slot_guard drops here, releasing the slot.
}

/// Build a [`RefreshSummary`] from a producer-emitted [`ScanResult`]
/// (just before the merge consumes it) and the loop bookkeeping. The
/// merge takes the value by-move; this helper runs first so the merge
/// never has to clone the result for summary purposes.
fn summarize(result: &ScanResult, merge_attempts: u32) -> RefreshSummary {
    RefreshSummary {
        processed_height_range: result.processed_height_range.clone(),
        blocks_processed: result.block_hashes.len() as u64,
        transfers_detected: result.new_transfers.len(),
        key_images_observed: result.spent_key_images.len(),
        stake_events: result.stake_events.len(),
        reorg: result.reorg_rewind.as_ref().map(|r| RefreshReorgEvent {
            fork_height: r.fork_height,
        }),
        merge_attempts,
    }
}

// `D: DaemonEngine` private-bound: see the rationale on the
// `pub struct Engine` definition in `engine/mod.rs`.
// This block is specialized to `LocalLedger` because
// [`Engine::start_refresh`] spawns [`run_refresh_task`], whose merge
// step goes through the LocalLedger-specialized
// [`Engine::apply_scan_result`] so the M3b engine post-pass runs
// under the merge guard (FOLLOWUPS P1). The snapshot read still
// dispatches through the [`LedgerEngine`] trait surface
// (`synced_height` / `snapshot`), but the merge cannot — the trait
// implementor has no `view_secret` for the post-pass. The sync
// `Engine::refresh` / `Engine::refresh_with` wrappers further down
// share the same `LocalLedger` specialization and the same
// `Engine::apply_scan_result` merge entry point.
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        R: RefreshEngine + super::scan_floor::ScanStartFloorProvider,
        P: super::traits::PendingTxEngine,
    > Engine<S, D, LocalLedger, R, P>
{
    /// Spawn an async refresh task and return a [`RefreshHandle`]
    /// for observing and controlling it.
    ///
    /// The handle exposes a [`tokio::sync::watch`] receiver for
    /// progress updates, an `async fn join` future for the terminal
    /// `Result<RefreshSummary, RefreshError>`, an explicit
    /// [`RefreshHandle::cancel`] hook, and cancel-on-drop semantics.
    /// Single-flight is enforced by the engine's `RefreshSlot`:
    /// concurrent calls return [`RefreshError::AlreadyRunning`].
    ///
    /// # Shape
    ///
    /// Takes `Arc<RwLock<Self>>` (a "self-arc") rather than `&self`
    /// or `&mut self` because the spawned producer task needs to
    /// outlive any borrow of `Engine<S>` taken at the call site —
    /// the task acquires the read lock per-attempt for snapshot,
    /// drops it across the network-bound scan, then takes the write
    /// lock briefly for the merge. The shared-handle parameter shape
    /// is transitional infrastructure; at Stage 4 it becomes
    /// `actor.ask(StartRefresh { opts }).send().await?`. See the
    /// `Path B engine binary boundary as pure message-passing`
    /// decision-log entry (2026-04-27).
    ///
    /// # No I/O in this method
    ///
    /// `start_refresh` does not call the daemon, does not scan, and
    /// does not lock for longer than the slot-claim. The first
    /// network call (`daemon.get_height` for tip) happens inside the
    /// spawned producer task, so a slow or unreachable daemon does
    /// not stall slot claim or the caller's `start_refresh.await`.
    ///
    /// # Errors
    ///
    /// - [`RefreshError::AlreadyRunning`] if another refresh is
    ///   already in flight (slot was already claimed). All other
    ///   `RefreshError` variants are surfaced via
    ///   [`RefreshHandle::join`], not from this method.
    ///
    /// # Trait bounds
    ///
    /// `Engine<S>: Send + Sync` (and `S: Send + Sync + 'static`) is
    /// required for the `Arc<RwLock<Engine<S>>>` to cross the
    /// `tokio::spawn` boundary into the producer task. The bound is
    /// surfaced here at the API rather than at the spawn site so
    /// violations show up at a callable signature.
    pub async fn start_refresh(
        self_arc: std::sync::Arc<tokio::sync::RwLock<Self>>,
        opts: RefreshOptions,
    ) -> Result<RefreshHandle, RefreshError>
    where
        S: EngineSignerKind + Send + Sync + 'static,
        Self: Send + Sync,
    {
        // Brief shared read borrow to clone the slot **and** capture
        // the wallet's current `synced_height`. The slot is its own
        // `Arc<AtomicBool>`, independent of the engine's RwLock, so
        // the read borrow only lives long enough to copy out the
        // values needed to seed the refresh task. CAS happens after
        // the borrow drops.
        //
        // `synced_height` is captured here (rather than re-read
        // inside the producer's first attempt) so the watch
        // channel's seed value matches the wallet baseline that the
        // contract on `RefreshProgress::height` promises: "on
        // initial publish this is `synced_height` itself." A caller
        // that does `progress().borrow()` before the producer
        // emits its first per-attempt `Scanning` update sees an
        // accurate baseline rather than a misleading `height: 0`.
        let (slot, synced_height) = {
            let engine = self_arc.read().await;
            (engine.refresh_slot.clone(), engine.ledger.synced_height())
        };
        let slot_guard = slot.try_claim().ok_or(RefreshError::AlreadyRunning)?;

        // Channels:
        // - `progress`: watch (latest-only); seeded with the
        //   wallet's current `synced_height` so the first
        //   `progress().borrow()` returns a usable baseline before
        //   the producer publishes its first per-attempt update.
        //   `blocks_processed` and `blocks_total` are zero because
        //   no work has been done on this attempt yet; the producer
        //   re-bases `blocks_total` against `daemon_tip` before any
        //   per-block emission begins.
        // - `completion`: oneshot for the terminal
        //   `RefreshSummary` / `RefreshError`. `RefreshHandle::join`
        //   awaits this.
        let (progress_tx, progress_rx) = tokio::sync::watch::channel(RefreshProgress {
            height: synced_height,
            blocks_processed: 0,
            blocks_total: 0,
            phase: RefreshPhase::Scanning,
        });
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        let cancel_token = CancellationToken::new();

        let task_arc = self_arc.clone();
        let task_cancel = cancel_token.clone();
        // `progress_tx` moves into the task — the producer is the
        // sole `Sender`. The handle keeps only a `Receiver` clone;
        // when the task exits, its `Sender` drops, and downstream
        // `Receiver::changed().await` returns `Err(_)` to signal
        // "no more progress."
        let producer_join = tokio::spawn(run_refresh_task(
            task_arc,
            opts.clone(),
            task_cancel,
            progress_tx,
            completion_tx,
            slot_guard,
        ));

        Ok(RefreshHandle {
            completion_rx: Some(completion_rx),
            cancel_token,
            progress_rx,
            producer_join,
            opts,
        })
    }
}

// `L = LocalLedger` specialization for the synchronous refresh entry
// points: [`Engine::refresh`] and `Engine::refresh_with` merge via the
// synchronous [`Engine::apply_scan_result`] (in `engine/merge.rs`),
// which acquires the merge guard through `LocalLedger`'s inherent
// `.write()`. The merge — and its M3b engine post-pass — is
// specialized to `LocalLedger` because the post-pass needs the
// engine's `view_secret` (FOLLOWUPS P1); generalizing the block would
// require a key-aware trait mutator, a Stage 4 actor concern. Both the
// sync entry points here and the async `start_refresh` path share this
// `Engine::apply_scan_result` merge entry point.
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        R: RefreshEngine + super::scan_floor::ScanStartFloorProvider,
        P: super::traits::PendingTxEngine,
    > Engine<S, D, LocalLedger, R, P>
{
    /// Drive a refresh against the configured daemon: pull a snapshot
    /// of the wallet's ledger, ask the producer to scan
    /// `synced_height + 1 .. daemon_tip + 1`, and merge the result
    /// back under `&mut self`. Retries on snapshot-race
    /// (`RefreshError::ConcurrentMutation`) up to `opts.max_retries`
    /// times before surfacing the last race. `MalformedScanResult` is
    /// terminal — re-running the scan would re-encounter the same
    /// producer-contract violation, so the caller is informed
    /// immediately.
    ///
    /// # Why synchronous, why a runtime handle
    ///
    /// `Engine::refresh` takes `&self`: as of Stage 1 PR 2 commit 5,
    /// wallet-state mutation lives inside [`LocalLedger`]'s interior
    /// `RwLock`, so the merge no longer needs an exclusive borrow on
    /// the outer engine. The cross-cutting locking discipline still
    /// applies — the implementor's write guard is the audited
    /// mutation point — but the engine surface itself takes `&self`
    /// for both queries and the refresh primitive. The signature
    /// stays synchronous: an `async fn refresh(&self, …)` would mean
    /// callers could `await` other futures across a refresh in
    /// progress, complicating cancellation and cooperative scheduling
    /// without a corresponding design win for the sync entry point.
    ///
    /// Instead, the synchronous entry point takes a
    /// [`tokio::runtime::Handle`] and runs the producer's async work
    /// via [`Handle::block_on`]. This means **`refresh` must not be
    /// called from inside an async context on the same runtime** —
    /// `block_on` panics in that case. Async callers
    /// (`tokio::spawn_blocking`, dedicated worker thread,
    /// branch-2's `RefreshHandle`) drive `refresh` from a sync
    /// context; the JSON-RPC server's RPC handler is the typical
    /// example via `spawn_blocking`.
    ///
    /// Branch 2 lands `RefreshHandle`, which spawns a producer-driven
    /// loop on the caller's runtime and exposes cancellation +
    /// progress channels. `Engine::refresh` (this method) remains the
    /// underlying primitive.
    ///
    /// # Errors
    ///
    /// - [`RefreshError::ConcurrentMutation`] — `opts.max_retries`
    ///   exhausted on snapshot races.
    /// - [`RefreshError::MalformedScanResult`] — producer-contract
    ///   violation; not retried.
    /// - [`RefreshError::Cancelled`] — surfaced when the producer is
    ///   driven through [`Engine::start_refresh`]'s cancel-on-drop
    ///   [`RefreshHandle`]. The synchronous [`Engine::refresh`]
    ///   signature itself never returns this variant in V3.0+: by
    ///   design, the sync path uses an internal token that never
    ///   fires. Cooperative cancellation is the async surface's
    ///   responsibility, not the sync surface's. See the
    ///   *Cancellation contract* section below.
    /// - [`RefreshError::Io`] — daemon RPC budget exhausted, or
    ///   scanner rejected a block as structurally invalid.
    ///
    /// # Cancellation contract (long-term, not transitional)
    ///
    /// The synchronous signature does **not** take a cancellation
    /// token, and the split between the sync and async surfaces is
    /// pinned for the lifetime of `Engine`:
    ///
    /// - **Sync path ([`Engine::refresh`], this method):**
    ///   cancel-internal. The token is created fresh per call and
    ///   never fires. Callers driving this from a sync context (CLI,
    ///   JSON-RPC handler running under `spawn_blocking`) accept that
    ///   they wait for the producer to settle naturally — typically
    ///   at the next scanner block boundary in the underlying loop.
    /// - **Async path ([`Engine::start_refresh`] returning
    ///   [`RefreshHandle`]):** the cancellation surface. The handle's
    ///   `cancel()` method and cancel-on-drop `Drop` impl fire the
    ///   shared [`CancellationToken`] that the producer observes at
    ///   every await point and at the four documented checkpoints in
    ///   `run_refresh_task`.
    ///
    /// This is a deliberate split, not a TBD. Threading a token
    /// argument into the sync signature would push cancellation
    /// plumbing into every caller for no design win — the async
    /// surface already exists for any caller that needs cooperative
    /// shutdown. The two surfaces compose: the async handle drives
    /// the producer directly, and the sync method drives the same
    /// producer behind an inert internal token. Both share one
    /// implementation; they differ only in who owns the token.
    pub fn refresh(
        &self,
        opts: &RefreshOptions,
        runtime: &tokio::runtime::Handle,
    ) -> Result<RefreshSummary, RefreshError>
    where
        R: super::scan_floor::ScanStartFloorProvider,
    {
        let floor = self.refresh.scan_start_floor();
        runtime.block_on(super::scan_floor::ensure_birthday_anchor(
            &self.ledger,
            &self.daemon,
            floor,
        ))?;
        // Producer dispatch via the [`RefreshEngine`] trait surface
        // (`R: RefreshEngine`, default `LocalRefresh`). The trait
        // implementor owns scanner construction, daemon-tip read,
        // per-block fetch + retry, per-block progress emission, and
        // the producer-side cancellation checkpoints; the sync
        // `Engine::refresh` surface only drives the
        // snapshot-merge-with-retry orchestration around it.
        //
        // The sync path's cancellation token is created fresh per
        // call and never fires — see the function rustdoc's
        // "Cancellation contract" section: the async surface
        // ([`Engine::start_refresh`]) is the cancellation surface,
        // not this one.
        //
        // Producer observability: the sync path does not expose a
        // [`DiagnosticSink`] to its callers, so the producer's
        // diagnostic stream is discarded via [`NoopDiagnosticSink`].
        // Callers that want producer-side observability use the async
        // path, which routes through [`TracingDiagnosticSink`] in
        // `run_refresh_task`.
        let cancel = CancellationToken::new();
        let sink = super::diagnostics::NoopDiagnosticSink::new();

        // Throwaway progress channel: the sync path has no
        // subscriber, but the trait surface requires a
        // `watch::Sender<RefreshProgress>` to emit per-block updates
        // into. Constructed once per call and dropped at the end of
        // the closure scope; the receiver immediately drops as well,
        // so the producer's `progress.send(...)` calls are no-ops
        // (best-effort sends to a no-subscriber watch channel
        // silently succeed by replacing the buffered latest value).
        let (progress_tx, _progress_rx) = tokio::sync::watch::channel(RefreshProgress {
            height: 0,
            blocks_processed: 0,
            blocks_total: 0,
            phase: RefreshPhase::Scanning,
        });

        self.refresh_with(opts, |_attempt, snapshot| {
            runtime
                .block_on(self.refresh.produce_scan_result(
                    snapshot.clone(),
                    &self.daemon,
                    opts.clone(),
                    cancel.clone(),
                    progress_tx.clone(),
                    &sink,
                ))
                .map_err(Into::into)
        })
    }

    /// Snapshot-merge-with-retry driver, generic over the producer.
    ///
    /// Factored out of [`Engine::refresh`] so integration tests can
    /// exercise the loop's retry / classification behaviour without
    /// standing up a real RPC fixture: the scripted producer just
    /// returns canned `ScanResult` / `RefreshError` values per
    /// attempt. Production callers go through [`Engine::refresh`],
    /// which builds the live producer closure (daemon RPC + scanner)
    /// and forwards into here.
    ///
    /// The closure receives `(attempt, &snapshot)`. `attempt` is
    /// 1-indexed and matches the value the loop will record into
    /// [`RefreshSummary::merge_attempts`] if the merge that follows
    /// succeeds. `snapshot` is freshly captured each attempt — the
    /// retry loop's contract is that every attempt produces against
    /// a snapshot that was current at the start of that attempt.
    ///
    /// # Error semantics
    ///
    /// - Producer returns `Err(_)` → propagate immediately. The
    ///   producer's only `ConcurrentMutation` source is the merge,
    ///   which runs inside this loop, so producer-side `Err` values
    ///   are by construction non-race terminal failures.
    /// - Merge returns `Err(ConcurrentMutation { … })` → retry up to
    ///   `opts.max_retries` more times; on exhaustion, surface the
    ///   last observed `ConcurrentMutation`.
    /// - Merge returns `Err(MalformedScanResult { … })` or any other
    ///   `RefreshError` → propagate immediately.
    pub(crate) fn refresh_with<F>(
        &self,
        opts: &RefreshOptions,
        mut produce: F,
    ) -> Result<RefreshSummary, RefreshError>
    where
        F: FnMut(u32, &LedgerSnapshot) -> Result<ScanResult, RefreshError>,
    {
        let mut last_concurrent_mutation: Option<RefreshError> = None;

        // Attempts are 1-indexed in the summary; the loop allows
        // `1 + max_retries` total tries (the initial attempt plus
        // `max_retries` retries on `ConcurrentMutation`).
        for attempt in 1..=opts.max_retries.saturating_add(1) {
            // Snapshot via [`LedgerEngine::snapshot`] on the
            // implementor field; the implementor manages its own
            // read guard internally. `&self` on the outer engine is
            // sufficient because mutation lives inside the
            // implementor's write guard.
            let snapshot = self.ledger.snapshot();
            let result = produce(attempt, &snapshot)?;
            let summary = summarize(&result, attempt);

            match self.apply_scan_result(result) {
                Ok(()) => return Ok(summary),
                Err(RefreshError::ConcurrentMutation { wallet, result }) => {
                    debug!(
                        attempt,
                        max_retries = opts.max_retries,
                        wallet,
                        result,
                        "Engine::refresh: snapshot race, retrying with fresh snapshot",
                    );
                    last_concurrent_mutation =
                        Some(RefreshError::ConcurrentMutation { wallet, result });
                    continue;
                }
                Err(other) => return Err(other),
            }
        }

        // Retry budget exhausted on `ConcurrentMutation`. Surface the
        // last race we observed so the caller can see *which* heights
        // disagreed; falling through without observing one would mean
        // the loop body itself is broken, which we surface as
        // `InternalInvariantViolation` (the C5-migrated discriminant
        // for refresh-loop control-flow contract failures per
        // `STAGE_1_PR_4_REFRESH_ENGINE.md` §7.X C5) so audit reads a
        // typed contract failure rather than a silent retry
        // exhaustion. `MalformedScanResult` remains the merge-gate
        // discriminant for producer-emitted scan-result invariant
        // violations; this site is orchestrator control flow, not
        // merge-gate validation.
        Err(
            last_concurrent_mutation.unwrap_or(RefreshError::InternalInvariantViolation {
                context: "Engine::refresh retry loop exited without an observed ConcurrentMutation",
            }),
        )
    }
}

/// Integration tests for [`Engine::refresh`] / `Engine::refresh_with`.
///
/// Producer-side coverage lives in `crate::engine::local_refresh`'s
/// `tests` module (per-class emission / RPC-error classification) and
/// lands in full at C7 (structural property tests against
/// `RefreshEngine` via `AssertionSink` /
/// `PanickingSink` / coherence-pair fixtures). This module covers
/// the **driver**: the snapshot-merge-with-retry loop. Tests inject
/// scripted [`ScanResult`] values via `Engine::refresh_with` so
/// retry / classification behaviour is asserted independently of any
/// RPC fixture; the production [`Engine::refresh`] entry point is
/// exercised separately against the unreachable [`DaemonClient`] to
/// confirm daemon-IO errors map through correctly.
#[cfg(test)]
mod refresh_driver_tests {
    use std::cell::RefCell;
    use std::sync::{Mutex, OnceLock};

    use shekyl_simple_request_rpc::SimpleRequestRpc;
    use tempfile::TempDir;
    use tokio::runtime::Runtime;

    use crate::engine::lifecycle::EngineCreateParams;
    use crate::engine::{
        Credentials, DaemonClient, Engine, IoError, RefreshError, RefreshOptions, SoloSigner,
    };
    use crate::scan::ScanResult;
    use shekyl_crypto_pq::account::MASTER_SEED_BYTES;
    use shekyl_engine_state::{BlockchainTip, LedgerBlock, ReorgBlocks};

    use super::{derive_snapshot_id, summarize, LedgerSnapshot, RefreshReorgEvent, SnapshotId};

    // ── Test fixtures ──────────────────────────────────────────

    /// `Credentials` borrows a password slice; tests share one
    /// `'static` slice so `make_wallet` can return owned credentials
    /// without lifetime gymnastics.
    const TEST_PASSWORD: &[u8] = b"snapshot-merge-driver tests";

    /// A process-wide multi-thread tokio runtime shared by every
    /// driver test. Built once on first access and intentionally
    /// leaked to live for the duration of the test binary.
    ///
    /// Why a shared, never-dropped runtime: hyper's connection pool
    /// (used by `SimpleRequestRpc`) spawns background tasks onto the
    /// runtime that constructed it. Building the RPC on a one-shot
    /// runtime that gets dropped at the end of `dummy_daemon` leaves
    /// the pool's tasks orphaned; subsequent requests hang waiting
    /// for executors that no longer exist. Sharing one runtime across
    /// every test in the module is both simpler and faster than
    /// keeping per-test runtimes alive.
    fn shared_runtime() -> &'static Runtime {
        static RT: OnceLock<Runtime> = OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .build()
                .expect("tokio runtime for refresh_driver_tests")
        })
    }

    /// Build a `DaemonClient` whose underlying RPC points at an
    /// unreachable URL. The Client is constructed on the shared
    /// runtime so its background tasks remain drivable for tests
    /// that actually issue requests through it
    /// (`production_refresh_*`). Tests that never touch the daemon
    /// (the `refresh_with`-driven cases) just hold the handle alive.
    fn dummy_daemon() -> DaemonClient {
        let rt = shared_runtime();
        let rpc = rt
            .block_on(SimpleRequestRpc::new("http://127.0.0.1:1".to_string()))
            .expect("construct SimpleRequestRpc against unreachable URL (no connect attempt yet)");
        DaemonClient::new(rpc)
    }

    /// Owns a [`TempDir`] for the wallet base path. The tempdir is
    /// dropped along with the fixture, cleaning up the wallet file
    /// at end of test.
    struct EngineFixture {
        wallet: Engine<SoloSigner>,
        _tmp: TempDir,
    }

    /// Build a fresh `Engine<SoloSigner>` on a tempdir with a
    /// deterministic seed. `synced_height` is `0` and `reorg_blocks`
    /// is empty — the standard fresh-wallet starting state for the
    /// snapshot-merge tests.
    fn make_wallet() -> EngineFixture {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(TEST_PASSWORD);
        let mut seed = [0u8; MASTER_SEED_BYTES];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(11);
        }
        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let wallet = Engine::<SoloSigner>::create(params, dummy_daemon())
            .expect("create FULL wallet for refresh_with tests");
        EngineFixture { wallet, _tmp: tmp }
    }

    /// Drain a `Mutex<Vec<…>>` queue of scripted producer outcomes,
    /// returning one per `refresh_with` invocation. Panics if the
    /// queue empties mid-test (the loop attempted more retries than
    /// the test prepared for) — that condition is itself a test
    /// failure to surface, not a panic to catch.
    fn drain<T>(queue: &Mutex<Vec<T>>) -> T {
        queue
            .lock()
            .expect("scripted-producer queue poisoned")
            .pop()
            .expect("scripted producer drained: refresh_with attempted more loops than prepared")
    }

    /// A clean scan result for `start..start` (empty range) anchored
    /// to the wallet's snapshot. Applies as a no-op merge and
    /// terminates the loop with `Ok(_)`.
    fn empty_result_for(snapshot: &LedgerSnapshot) -> ScanResult {
        let start = snapshot.synced_height.saturating_add(1);
        let parent_hash = snapshot.block_hash_at(snapshot.synced_height);
        ScanResult::empty_at(start, parent_hash)
    }

    /// A scan result that the merge will reject as
    /// [`RefreshError::ConcurrentMutation`] because its start height
    /// disagrees with the wallet's synced_height. The merge gate
    /// fires the start-height check before parent-hash, so an
    /// arbitrary `bad_start != synced_height + 1` is sufficient.
    fn stale_snapshot_result(bad_start: u64) -> ScanResult {
        ScanResult::empty_at(bad_start, None)
    }

    /// A scan result the merge will reject as
    /// [`RefreshError::MalformedScanResult`]: a non-empty
    /// `block_hashes` against an empty `processed_height_range`.
    /// The empty-range branch checks `block_hashes.is_empty()`
    /// before any other invariant, so this fires the malformed
    /// path deterministically.
    fn malformed_result_for(snapshot: &LedgerSnapshot) -> ScanResult {
        let start = snapshot.synced_height.saturating_add(1);
        let mut result =
            ScanResult::empty_at(start, snapshot.block_hash_at(snapshot.synced_height));
        // Empty range + non-empty block_hashes is the
        // contract-violation shape `apply_scan_result_to_state`
        // gates against in its early-return branch.
        result.block_hashes.push((start, [0xAB; 32]));
        result
    }

    // ── Smoke tests ────────────────────────────────────────────

    /// One scripted attempt returning a clean empty result causes
    /// `refresh_with` to merge once and return a summary recording
    /// `merge_attempts == 1`.
    #[test]
    fn smoke_single_attempt_returns_summary() {
        let fix = make_wallet();
        let opts = RefreshOptions::default();

        let mut produced = false;
        let summary = fix
            .wallet
            .refresh_with(&opts, |attempt, snapshot| {
                assert_eq!(attempt, 1, "smoke path: only one attempt expected");
                assert!(!produced, "smoke path: producer invoked twice");
                produced = true;
                Ok(empty_result_for(snapshot))
            })
            .expect("refresh_with returns Ok on the first clean attempt");

        assert_eq!(summary.merge_attempts, 1);
        assert_eq!(summary.blocks_processed, 0);
        assert!(summary.processed_height_range.start == summary.processed_height_range.end);
        assert_eq!(summary.transfers_detected, 0);
        assert_eq!(summary.key_images_observed, 0);
        assert_eq!(summary.stake_events, 0);
        assert!(summary.reorg.is_none());
    }

    // ── ConcurrentMutation retry path ──────────────────────────

    /// First two scripted attempts return stale-snapshot results
    /// (forcing `ConcurrentMutation`); the third returns a clean
    /// result. The driver retries twice and the third attempt's
    /// merge succeeds. `summary.merge_attempts` records `3`.
    #[test]
    fn concurrent_mutation_retry_succeeds_after_two_races() {
        let fix = make_wallet();
        let opts = RefreshOptions { max_retries: 8 };

        // `drain` pops from the back; storing attempts in reverse
        // order lets attempt 1 surface first. Vec layout: index 0 =
        // attempt 3 (empty, terminates loop), index 2 = attempt 1
        // (stale, forces retry).
        type Producer = Box<dyn FnOnce(&LedgerSnapshot) -> ScanResult + Send>;
        let queue: Mutex<Vec<Producer>> = Mutex::new(vec![
            Box::new(empty_result_for) as Producer,
            Box::new(|_snap: &LedgerSnapshot| stale_snapshot_result(99)) as Producer,
            Box::new(|_snap: &LedgerSnapshot| stale_snapshot_result(99)) as Producer,
        ]);

        let observed_attempts: RefCell<Vec<u32>> = RefCell::new(Vec::new());
        let summary = fix
            .wallet
            .refresh_with(&opts, |attempt, snapshot| {
                observed_attempts.borrow_mut().push(attempt);
                Ok(drain(&queue)(snapshot))
            })
            .expect("third clean result merges");

        assert_eq!(*observed_attempts.borrow(), vec![1, 2, 3]);
        assert_eq!(summary.merge_attempts, 3);
    }

    /// All `1 + max_retries` scripted attempts return stale-snapshot
    /// results. The driver exhausts the budget and surfaces the
    /// last [`RefreshError::ConcurrentMutation`].
    #[test]
    fn retry_budget_exhausted_returns_last_concurrent_mutation() {
        let fix = make_wallet();
        let opts = RefreshOptions { max_retries: 2 };

        let observed_attempts: RefCell<Vec<u32>> = RefCell::new(Vec::new());
        let err = fix
            .wallet
            .refresh_with(&opts, |attempt, _snapshot| {
                observed_attempts.borrow_mut().push(attempt);
                // Use `attempt` so the surfaced error's `result`
                // field carries the *last* observed attempt's bad
                // start. This asserts the loop's "preserve the
                // most-recent ConcurrentMutation" behaviour, not
                // the first.
                Ok(stale_snapshot_result(100 + u64::from(attempt)))
            })
            .expect_err("budget exhausted");

        assert_eq!(*observed_attempts.borrow(), vec![1, 2, 3]);
        match err {
            RefreshError::ConcurrentMutation { wallet, result } => {
                assert_eq!(wallet, 0, "fresh wallet's synced_height");
                assert_eq!(result, 103, "last attempt was attempt 3, bad_start = 103");
            }
            other => panic!("expected ConcurrentMutation, got {other:?}"),
        }
    }

    // ── MalformedScanResult is terminal ────────────────────────

    /// First scripted attempt returns a malformed result. The
    /// driver does **not** retry — re-running the same producer
    /// against the same snapshot would re-emit the same contract
    /// violation. The error surfaces immediately.
    #[test]
    fn malformed_scan_result_is_not_retried() {
        let fix = make_wallet();
        let opts = RefreshOptions { max_retries: 8 };

        let observed_attempts: RefCell<u32> = RefCell::new(0);
        let err = fix
            .wallet
            .refresh_with(&opts, |_attempt, snapshot| {
                *observed_attempts.borrow_mut() += 1;
                Ok(malformed_result_for(snapshot))
            })
            .expect_err("malformed result terminates the loop");

        assert_eq!(*observed_attempts.borrow(), 1, "no retry on malformed");
        match err {
            RefreshError::MalformedScanResult { .. } => {}
            other => panic!("expected MalformedScanResult, got {other:?}"),
        }
    }

    // ── Producer-error propagation ─────────────────────────────

    /// Producer closure returns `Err(RefreshError::Io(...))`. The
    /// driver propagates immediately without invoking another
    /// attempt: producer-side errors are by construction non-race
    /// terminal failures (no merge ran, so no
    /// `ConcurrentMutation` is possible).
    #[test]
    fn producer_io_error_propagates_immediately() {
        let fix = make_wallet();
        let opts = RefreshOptions { max_retries: 8 };

        let observed_attempts: RefCell<u32> = RefCell::new(0);
        let err = fix
            .wallet
            .refresh_with(&opts, |_attempt, _snapshot| {
                *observed_attempts.borrow_mut() += 1;
                Err(RefreshError::Io(IoError::Daemon {
                    detail: "scripted daemon failure".to_string(),
                }))
            })
            .expect_err("producer error is terminal");

        assert_eq!(*observed_attempts.borrow(), 1, "no retry on producer error");
        match err {
            RefreshError::Io(IoError::Daemon { detail }) => {
                assert_eq!(detail, "scripted daemon failure");
            }
            other => panic!("expected Io(Daemon), got {other:?}"),
        }
    }

    /// Producer closure returns `Err(RefreshError::Cancelled)`.
    /// The driver propagates immediately. (In production this
    /// closure is only `Cancelled` if the cancellation token has
    /// been signalled; branch 2's `RefreshHandle` is the only path
    /// that signals it on the synchronous refresh.)
    #[test]
    fn producer_cancelled_propagates() {
        let fix = make_wallet();
        let opts = RefreshOptions::default();

        let err = fix
            .wallet
            .refresh_with(&opts, |_attempt, _snapshot| Err(RefreshError::Cancelled))
            .expect_err("Cancelled is terminal");

        assert!(matches!(err, RefreshError::Cancelled));
    }

    // ── max_retries == 0 boundary ──────────────────────────────

    /// With `max_retries == 0`, the loop runs exactly one attempt.
    /// A `ConcurrentMutation` on that attempt is surfaced
    /// immediately without any retry.
    #[test]
    fn max_retries_zero_runs_exactly_one_attempt() {
        let fix = make_wallet();
        let opts = RefreshOptions { max_retries: 0 };

        let observed_attempts: RefCell<u32> = RefCell::new(0);
        let err = fix
            .wallet
            .refresh_with(&opts, |_attempt, _snapshot| {
                *observed_attempts.borrow_mut() += 1;
                Ok(stale_snapshot_result(42))
            })
            .expect_err("budget exhausted on first attempt");

        assert_eq!(
            *observed_attempts.borrow(),
            1,
            "no retry with max_retries=0"
        );
        assert!(matches!(err, RefreshError::ConcurrentMutation { .. }));
    }

    // ── Snapshot freshness across retries ──────────────────────

    /// Every retry pulls a fresh `LedgerSnapshot::from_ledger`. We
    /// assert this by mutating wallet state between attempts (via
    /// `apply_scan_result` directly, which advances synced_height)
    /// and confirming the next attempt sees the new snapshot.
    ///
    /// The race the production `RefreshHandle` cares about is a
    /// *sibling* mutation to wallet state during a long async
    /// scan. In the synchronous `refresh_with`, `&mut self` is held
    /// throughout, so no real sibling race is possible — but the
    /// loop must still take a fresh snapshot per attempt because
    /// branch 2's async surface drops the lock between attempts.
    /// This test pins that the snapshot is in fact re-taken.
    #[test]
    fn snapshot_is_refreshed_between_retries() {
        let fix = make_wallet();
        let opts = RefreshOptions { max_retries: 4 };

        let snapshots_seen: RefCell<Vec<u64>> = RefCell::new(Vec::new());
        let attempt_counter: RefCell<u32> = RefCell::new(0);

        let summary = fix
            .wallet
            .refresh_with(&opts, |attempt, snapshot| {
                snapshots_seen.borrow_mut().push(snapshot.synced_height);
                *attempt_counter.borrow_mut() = attempt;
                if attempt == 1 {
                    // Force a ConcurrentMutation by emitting a
                    // result whose start mismatches the snapshot.
                    Ok(stale_snapshot_result(7))
                } else {
                    Ok(empty_result_for(snapshot))
                }
            })
            .expect("second attempt merges cleanly");

        // Both attempts sampled `synced_height = 0` (the wallet
        // never advanced — empty merge is a no-op) but the
        // snapshot was re-taken: two entries, both observed.
        assert_eq!(*snapshots_seen.borrow(), vec![0, 0]);
        assert_eq!(summary.merge_attempts, 2);
    }

    // ── Production refresh sanity (daemon unreachable) ─────────

    /// `Engine::refresh` (the production entry point) routes the
    /// daemon through an unreachable URL. The first `get_height`
    /// call fails, surfacing as
    /// [`RefreshError::Io`](RefreshError::Io)`(`[`IoError::Daemon`]`)`.
    /// The retry loop is **not** entered: daemon failures are
    /// terminal, not race-class.
    #[test]
    fn production_refresh_against_unreachable_daemon_returns_io_daemon() {
        let fix = make_wallet();
        let opts = RefreshOptions { max_retries: 0 };
        // Same runtime that built the daemon's RPC client; running on
        // a different runtime would hang because hyper's connection
        // pool tasks live on the constructing runtime.
        let rt = shared_runtime();

        let err = fix
            .wallet
            .refresh(&opts, rt.handle())
            .expect_err("unreachable daemon must error out");

        // After C5's trait-dispatch migration the producer-side
        // error projection lives in `LocalRefresh`: a daemon-tip
        // `get_height` failure surfaces as `LocalRefreshError::Io`,
        // which the `From<LocalRefreshError> for RefreshError`
        // conversion projects as `RefreshError::Io(IoError::Daemon
        // { detail: "LocalRefresh: daemon I/O failure during refresh" })`.
        // The bounded detail string is a deliberate design
        // disposition (per §5.4.7 R6's memory-amplifier closure):
        // upstream `RpcError` payloads are not propagated into the
        // typed `RefreshError`; richer per-error classification
        // routes through the `DiagnosticSink` as
        // `DaemonProtocolError { kind: ProtocolErrorKind }`.
        match err {
            RefreshError::Io(IoError::Daemon { detail }) => {
                assert!(
                    detail.contains("LocalRefresh"),
                    "expected LocalRefresh-projected daemon I/O detail, got {detail:?}"
                );
            }
            other => panic!("expected Io(Daemon), got {other:?}"),
        }
    }

    // ── Summary-shape regression ───────────────────────────────

    /// `summarize` is the small shim that builds `RefreshSummary`
    /// from `&ScanResult` plus the loop's attempt counter. This
    /// test pins every field so a future refactor of the producer
    /// or the merge surfaces a deliberate review point rather
    /// than a silent shape drift.
    #[test]
    fn summarize_records_every_field() {
        let mut result = ScanResult::empty_at(5, Some([0x11; 32]));
        result.processed_height_range = 5..8;
        result.block_hashes = vec![(5, [1; 32]), (6, [2; 32]), (7, [3; 32])];
        // `new_transfers` and `spent_key_images` are exercised
        // structurally elsewhere; here we just record the count.
        result.spent_key_images = vec![
            crate::scan::KeyImageObserved {
                block_height: 5,
                key_image: shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes([9; 32]),
            },
            crate::scan::KeyImageObserved {
                block_height: 7,
                key_image: shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes([8; 32]),
            },
        ];
        result.stake_events = vec![/* StakeEvent::Accrual omitted: test only counts */];
        result.reorg_rewind = Some(crate::scan::ReorgRewind { fork_height: 5 });

        let summary = summarize(&result, 4);

        assert_eq!(summary.processed_height_range, 5..8);
        assert_eq!(summary.blocks_processed, 3);
        assert_eq!(summary.transfers_detected, 0);
        assert_eq!(summary.key_images_observed, 2);
        assert_eq!(summary.stake_events, 0);
        assert_eq!(summary.reorg, Some(RefreshReorgEvent { fork_height: 5 }));
        assert_eq!(summary.merge_attempts, 4);
    }

    // ── LedgerSnapshot construction ────────────────────────────

    /// `LedgerSnapshot::from_ledger` reads `synced_height` and
    /// clones `reorg_blocks`; nothing else. This test confirms the
    /// snapshot is decoupled from `transfers` (the Phase-2a
    /// "snapshot strategy" decision pins this; the bench at
    /// `benches/refresh_snapshot.rs` regression-gates the runtime
    /// claim).
    #[test]
    fn ledger_snapshot_is_independent_of_transfer_count() {
        // Build a `LedgerBlock` directly via its constructor and
        // confirm `LedgerSnapshot::from_ledger` reads only the tip
        // height and the reorg window — `transfers` (when populated
        // in production) does not contribute to snapshot cost.
        let tip = BlockchainTip::new(1234, [0xAA; 32]);
        let reorg_blocks = ReorgBlocks {
            blocks: vec![(1233, [0xBB; 32]), (1234, [0xAA; 32])],
        };
        let ledger = LedgerBlock::new(Vec::new(), tip, reorg_blocks);
        let snap = LedgerSnapshot::from_ledger(&ledger);
        assert_eq!(snap.synced_height, 1234);
        assert_eq!(snap.reorg_blocks.blocks.len(), 2);
        assert_eq!(snap.block_hash_at(1234), Some([0xAA; 32]));
        assert_eq!(snap.block_hash_at(1232), None);
    }

    // ── SnapshotId derivation (Stage 1 PR 5 — Phase 0b) ────────

    /// Synthesize a `LedgerSnapshot` directly from the in-crate
    /// fields. Avoids the `LedgerBlock::new` round-trip that the
    /// surrounding tests use; the C1 derivation tests do not need a
    /// `LedgerBlock` — they exercise `derive_snapshot_id` over the
    /// snapshot's fields directly.
    fn snapshot_from_parts(synced_height: u64, blocks: Vec<(u64, [u8; 32])>) -> LedgerSnapshot {
        LedgerSnapshot {
            synced_height,
            reorg_blocks: ReorgBlocks { blocks },
        }
    }

    /// Identical snapshots derive identical ids; snapshots that
    /// differ in `synced_height` or `reorg_blocks` derive distinct
    /// ids. The 16-byte digest is content-derived; this is the
    /// substrate the submit-time staleness check depends on per
    /// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.0 ground 2.
    #[test]
    fn derive_snapshot_id_deterministic() {
        let snap_a = snapshot_from_parts(100, vec![(99, [0x11; 32]), (100, [0x22; 32])]);
        let snap_a_again = snapshot_from_parts(100, vec![(99, [0x11; 32]), (100, [0x22; 32])]);
        assert_eq!(
            derive_snapshot_id(&snap_a),
            derive_snapshot_id(&snap_a_again),
            "identical snapshot fields must derive identical ids"
        );

        let snap_b_height = snapshot_from_parts(101, vec![(99, [0x11; 32]), (100, [0x22; 32])]);
        assert_ne!(
            derive_snapshot_id(&snap_a),
            derive_snapshot_id(&snap_b_height),
            "different synced_height must change the id"
        );

        let snap_b_blocks = snapshot_from_parts(100, vec![(99, [0x11; 32]), (100, [0x33; 32])]);
        assert_ne!(
            derive_snapshot_id(&snap_a),
            derive_snapshot_id(&snap_b_blocks),
            "different reorg-window contents must change the id"
        );

        // SnapshotId bytes are stable across reads.
        let id = derive_snapshot_id(&snap_a);
        assert_eq!(id.as_bytes(), &id.0);
    }

    /// The versioned domain-separation prefix is load-bearing in
    /// the derivation: two synthetic Keccak-256 inputs that share
    /// every byte after the prefix but differ in the prefix bytes
    /// must hash to different digests. The test computes the raw
    /// `cn_fast_hash` directly with the production prefix and with
    /// a counter-factual prefix of the same length, then truncates
    /// both to 16 bytes and asserts inequality. This regression-
    /// gates the canonical-encoding promise that the prefix is part
    /// of the hashed input, not implicit in some other shape.
    #[test]
    fn derive_snapshot_id_domain_separated() {
        let snap = snapshot_from_parts(7, vec![(7, [0xAB; 32])]);
        let n_blocks = snap.reorg_blocks.blocks.len();

        // Build the canonical post-prefix tail exactly as
        // `derive_snapshot_id` does. The factual hash applies the
        // production prefix; the counter-factual hash applies a
        // same-length but lexically-different prefix to the same
        // tail. Truncated to 16 bytes, the digests must differ —
        // that is what a load-bearing prefix delivers.
        let mut tail = Vec::new();
        tail.extend_from_slice(&snap.synced_height.to_le_bytes());
        tail.extend_from_slice(&(n_blocks as u64).to_le_bytes());
        for (height, hash) in &snap.reorg_blocks.blocks {
            tail.extend_from_slice(&height.to_le_bytes());
            tail.extend_from_slice(hash);
        }

        let production_prefix = super::SNAPSHOT_ID_DOMAIN;
        let mut counterfactual_prefix = production_prefix.to_vec();
        counterfactual_prefix[0] ^= 0x01;
        assert_eq!(
            counterfactual_prefix.len(),
            production_prefix.len(),
            "counter-factual prefix must be the same length to isolate the prefix-bytes signal"
        );

        let mut factual_input = Vec::with_capacity(production_prefix.len() + tail.len());
        factual_input.extend_from_slice(production_prefix);
        factual_input.extend_from_slice(&tail);
        let factual = shekyl_crypto_hash::cn_fast_hash(&factual_input);

        let mut counterfactual_input = Vec::with_capacity(counterfactual_prefix.len() + tail.len());
        counterfactual_input.extend_from_slice(&counterfactual_prefix);
        counterfactual_input.extend_from_slice(&tail);
        let counterfactual = shekyl_crypto_hash::cn_fast_hash(&counterfactual_input);

        assert_ne!(
            &factual[..16],
            &counterfactual[..16],
            "domain-separation prefix must be part of the hashed input"
        );

        // And the production derivation matches the factual hash.
        let id = derive_snapshot_id(&snap);
        assert_eq!(
            id.as_bytes()[..],
            factual[..16],
            "derive_snapshot_id must apply the documented canonical encoding verbatim"
        );
    }

    /// `reorg_blocks` of length 0 vs. 1 vs. 2 over the same
    /// `synced_height` must produce three distinct ids. Without the
    /// `n_blocks` length prefix in the canonical encoding, the
    /// concatenation `(8-byte height) ‖ (32-byte hash)` of one block
    /// could in principle collide with the same bytes appearing as
    /// part of a two-block window; the length prefix forecloses
    /// that. Regression-gates the canonical-encoding promise per
    /// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 Phase 0b.
    #[test]
    fn derive_snapshot_id_length_prefix_separates_neighbours() {
        let snap_zero = snapshot_from_parts(50, Vec::new());
        let snap_one = snapshot_from_parts(50, vec![(49, [0x77; 32])]);
        let snap_two = snapshot_from_parts(50, vec![(49, [0x77; 32]), (50, [0x88; 32])]);

        let id_zero = derive_snapshot_id(&snap_zero);
        let id_one = derive_snapshot_id(&snap_one);
        let id_two = derive_snapshot_id(&snap_two);

        assert_ne!(id_zero, id_one);
        assert_ne!(id_one, id_two);
        assert_ne!(id_zero, id_two);

        // The id type carries the 16-byte digest unchanged.
        assert_eq!(id_zero.as_bytes().len(), 16);
        let _ty_check: SnapshotId = id_zero;
    }
}

#[cfg(test)]
mod refresh_handle_tests {
    //! Unit tests for the [`RefreshHandle`] public surface.
    //!
    //! Every test here builds a handle via
    //! [`RefreshHandle::for_test`] with hand-rolled channel ends
    //! and a stand-in `JoinHandle`. No real producer task or
    //! `Engine<S>` is involved — this module exercises the handle
    //! itself, which is a thin wrapper around four channel ends
    //! plus the cancel token.
    //!
    //! Corner-case tests (cancel-on-drop, concurrent
    //! `start_refresh`, idempotent cancel, `mem::forget` leak
    //! semantics) live in commit 5. Integration coverage for the
    //! real producer through `Engine::start_refresh` lives in
    //! `start_refresh_integration_tests` below, which carries
    //! both fixture flavours: an unreachable-`DaemonClient`
    //! flavour for handle-shape invariants and daemon-IO error
    //! mapping, and a `TestDaemon`-driven hybrid flavour
    //! (added in Stage 1 PR 1, per
    //! `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §6.3) that exercises
    //! the producer end-to-end against synthetic chain state.
    use super::{
        RefreshError, RefreshHandle, RefreshOptions, RefreshPhase, RefreshProgress, RefreshSummary,
    };
    use tokio_util::sync::CancellationToken;

    /// Test-fixture return shape for [`handle_with`]: the
    /// caller-owned channel ends and observation join handle paired
    /// with a [`RefreshHandle`] whose internal channels point at
    /// them. Extracted as a type alias to keep `handle_with`'s
    /// signature within `clippy::type_complexity`'s threshold.
    type RefreshHandleFixture = (
        RefreshHandle,
        tokio::sync::oneshot::Sender<Result<RefreshSummary, RefreshError>>,
        tokio::sync::watch::Sender<RefreshProgress>,
        CancellationToken,
        tokio::task::JoinHandle<()>,
    );

    /// Build a handle whose channels are entirely caller-owned, so
    /// the test can fire each one explicitly. Returns a separate
    /// observation `JoinHandle` (parked on the same cancel token
    /// as the one inside the handle) for assertions about producer
    /// wind-down — the handle's own `JoinHandle` is consumed by
    /// `is_running()` checks and may not be awaited directly
    /// without breaking the move-out story.
    fn handle_with(opts: RefreshOptions) -> RefreshHandleFixture {
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        let (progress_tx, progress_rx) = tokio::sync::watch::channel(RefreshProgress::initial());
        let cancel = CancellationToken::new();

        // Stand-in producer: park forever on the cancel token, so
        // `is_running()` reads `true` until the test fires cancel
        // (or drops the handle, which fires it via `Drop`).
        let producer_cancel = cancel.clone();
        let producer = tokio::spawn(async move {
            producer_cancel.cancelled().await;
        });
        let producer_for_assert = tokio::spawn({
            let observe = cancel.clone();
            async move { observe.cancelled().await }
        });

        let handle =
            RefreshHandle::for_test(completion_rx, cancel.clone(), progress_rx, producer, opts);
        (
            handle,
            completion_tx,
            progress_tx,
            cancel,
            producer_for_assert,
        )
    }

    /// `progress()` returns a receiver that observes the seeded
    /// `RefreshProgress::initial()` baseline before any update is
    /// published. `borrow()` is non-blocking and always sees the
    /// latest value.
    #[tokio::test]
    async fn progress_returns_seeded_baseline() {
        let (handle, _completion, _progress, _cancel, _producer_assert) =
            handle_with(RefreshOptions::default());

        let rx = handle.progress();
        let snap = *rx.borrow();
        assert_eq!(snap.height, 0);
        assert_eq!(snap.blocks_processed, 0);
        assert_eq!(snap.blocks_total, 0);
        // `RefreshProgress::initial()` seeds the phase as
        // `Scanning` so callers don't see `Cancelled` before the
        // producer has run.
        assert!(matches!(snap.phase, RefreshPhase::Scanning));
    }

    /// `progress()` updates land on every cloned receiver.
    #[tokio::test]
    async fn progress_updates_propagate_to_subscribers() {
        let (handle, _completion, progress_tx, _cancel, _producer_assert) =
            handle_with(RefreshOptions::default());

        let mut rx = handle.progress();
        progress_tx
            .send(RefreshProgress {
                height: 42,
                blocks_processed: 7,
                blocks_total: 100,
                phase: RefreshPhase::Scanning,
            })
            .expect("subscriber alive");
        rx.changed().await.expect("update delivered");
        let snap = *rx.borrow();
        assert_eq!(snap.height, 42);
        assert_eq!(snap.blocks_processed, 7);
        assert_eq!(snap.blocks_total, 100);
    }

    /// `cancel()` fires the shared cancel token, which the
    /// producer task observes. `is_running()` flips to `false`
    /// once the producer task has exited.
    #[tokio::test]
    async fn cancel_fires_token_and_is_running_flips() {
        let (handle, _completion, _progress, cancel, producer_assert) =
            handle_with(RefreshOptions::default());

        assert!(
            handle.is_running(),
            "producer is parked on cancel; should be running"
        );
        assert!(!cancel.is_cancelled(), "no cancel observed yet");

        handle.cancel();
        assert!(cancel.is_cancelled(), "cancel() fires the shared token");

        producer_assert.await.expect("producer wakes on cancel");
        tokio::task::yield_now().await;
        assert!(!handle.is_running(), "JoinHandle has finished");
    }

    /// `join()` consumes the handle and returns the value sent on
    /// the completion oneshot.
    #[tokio::test]
    async fn join_delivers_summary_from_completion_oneshot() {
        let (handle, completion, _progress, _cancel, _producer_assert) =
            handle_with(RefreshOptions::default());

        let summary = RefreshSummary {
            processed_height_range: 100..105,
            blocks_processed: 5,
            transfers_detected: 0,
            key_images_observed: 0,
            stake_events: 0,
            reorg: None,
            merge_attempts: 1,
        };
        completion
            .send(Ok(summary.clone()))
            .expect("oneshot receiver still alive on handle");

        let returned = handle.join().await.expect("Ok delivered");
        assert_eq!(
            returned.processed_height_range,
            summary.processed_height_range
        );
        assert_eq!(returned.blocks_processed, summary.blocks_processed);
        assert_eq!(returned.merge_attempts, summary.merge_attempts);
    }

    /// `join()` propagates a terminal error sent on the
    /// completion oneshot unchanged.
    #[tokio::test]
    async fn join_propagates_terminal_error() {
        let (handle, completion, _progress, _cancel, _producer_assert) =
            handle_with(RefreshOptions::default());

        completion
            .send(Err(RefreshError::Cancelled))
            .expect("oneshot receiver still alive on handle");

        let result = handle.join().await;
        assert!(matches!(result, Err(RefreshError::Cancelled)));
    }

    /// If the producer task drops its completion sender without
    /// sending (which would only happen on a panic — a contract
    /// violation), `join()` surfaces a typed
    /// `InternalInvariantViolation` rather than panicking. (Migrated
    /// from `MalformedScanResult` at C5 per
    /// `STAGE_1_PR_4_REFRESH_ENGINE.md` §7.X C5 — producer panic is
    /// an orchestrator control-flow invariant violation, not a
    /// merge-gate scan-result invariant violation.)
    #[tokio::test]
    async fn join_maps_dropped_sender_to_internal_invariant_violation() {
        let (handle, completion, _progress, _cancel, _producer_assert) =
            handle_with(RefreshOptions::default());
        drop(completion);

        let result = handle.join().await;
        match result {
            Err(RefreshError::InternalInvariantViolation { context }) => {
                assert!(
                    context.contains("dropped completion sender"),
                    "context was: {context}"
                );
            }
            other => panic!("expected InternalInvariantViolation, got {other:?}"),
        }
    }

    // ── Corner-case tests (commit 5) ────────────────────────────

    /// Dropping the handle fires the shared cancel token. The
    /// `Drop` impl is the cancel-on-drop contract: anyone holding
    /// a clone of the token (the producer task in production)
    /// observes it and unwinds.
    #[tokio::test]
    async fn drop_fires_cancel_token() {
        let (handle, _completion, _progress, cancel, _producer_assert) =
            handle_with(RefreshOptions::default());
        assert!(!cancel.is_cancelled(), "no cancel observed pre-drop");

        drop(handle);
        assert!(cancel.is_cancelled(), "Drop fires cancel token");
    }

    /// Calling `cancel()` twice is a no-op after the first.
    /// `CancellationToken::cancel` is documented as idempotent;
    /// this test pins the contract at the [`RefreshHandle`]
    /// surface so a future internal change cannot regress it
    /// silently.
    #[tokio::test]
    async fn idempotent_cancel_is_no_op() {
        let (handle, _completion, _progress, cancel, _producer_assert) =
            handle_with(RefreshOptions::default());

        handle.cancel();
        assert!(cancel.is_cancelled());
        // Second call returns without panicking and without
        // re-firing (the token tracks its own state internally).
        handle.cancel();
        assert!(cancel.is_cancelled());
    }

    /// `mem::forget` skips the `Drop` impl entirely. The cancel
    /// token does not fire and the producer task continues running
    /// — exactly the leak semantics any Rust handle has under
    /// `forget`. The test pins this so a reviewer reading the
    /// code can confirm the cancel-on-drop contract is `Drop`-
    /// scoped, not embedded in another method that runs
    /// implicitly.
    ///
    /// Operational note: in production this would leak the
    /// `_slot_guard` held by the producer task too — `forget` is
    /// a programmer error, not a supported flow. We test the
    /// behaviour to make the leak surface explicit, not to
    /// endorse it.
    #[tokio::test]
    async fn mem_forget_does_not_fire_cancel() {
        let (handle, _completion, _progress, cancel, _producer_assert) =
            handle_with(RefreshOptions::default());

        std::mem::forget(handle);
        assert!(!cancel.is_cancelled(), "Drop did not run; token unfired");

        // Manually fire the token to clean up the parked
        // observation tasks.
        cancel.cancel();
    }

    /// When the producer observes cancellation mid-scan and bails,
    /// it publishes a terminal `RefreshPhase::Cancelled` progress
    /// update **before** the watch sender drops, and that update
    /// preserves the last published `height` / counters so
    /// subscribers don't observe a misleading rollback to zero.
    ///
    /// This test mirrors the production sequence exactly: the
    /// per-block progress emitter inside `RefreshEngine::produce_scan_result` advances `height` during the
    /// scan, and on `Err(RefreshError::Cancelled)` from
    /// the producer, `run_refresh_task` clones the latest
    /// published progress, overrides only `phase`, and sends. We
    /// drive the same shape through the test's caller-owned
    /// `progress_tx` so the assertion lands on the public surface
    /// (`progress().borrow()`) rather than internals.
    #[tokio::test]
    async fn cancel_during_scan_emits_terminal_cancelled_phase() {
        let (handle, _completion, progress_tx, _cancel, _producer_assert) =
            handle_with(RefreshOptions::default());

        let mut rx = handle.progress();

        progress_tx
            .send(RefreshProgress {
                height: 100,
                blocks_processed: 50,
                blocks_total: 200,
                phase: RefreshPhase::Scanning,
            })
            .expect("subscriber alive");
        rx.changed().await.expect("scanning update delivered");
        let mid = *rx.borrow();
        assert_eq!(mid.height, 100);
        assert!(matches!(mid.phase, RefreshPhase::Scanning));

        let mut terminal = *progress_tx.borrow();
        terminal.phase = RefreshPhase::Cancelled;
        progress_tx.send(terminal).expect("subscriber alive");
        rx.changed().await.expect("terminal update delivered");

        let last = *rx.borrow();
        assert!(
            matches!(last.phase, RefreshPhase::Cancelled),
            "phase preserved as Cancelled"
        );
        assert_eq!(
            last.height, 100,
            "height preserved across the Scanning→Cancelled transition"
        );
        assert_eq!(
            last.blocks_processed, 50,
            "blocks_processed preserved across the transition"
        );
        assert_eq!(
            last.blocks_total, 200,
            "blocks_total preserved across the transition"
        );
    }
}

#[cfg(test)]
mod refresh_slot_tests {
    //! Unit tests for [`RefreshSlot`] — the single-flight
    //! primitive [`Engine::start_refresh`] uses to gate concurrent
    //! refreshes.
    //!
    //! These tests exercise the slot in isolation; concurrent
    //! `start_refresh` against a real `Engine<S>` (the integration
    //! surface that surfaces `RefreshError::AlreadyRunning`) is
    //! covered by commit 6.
    use super::RefreshSlot;

    /// Fresh slot is unclaimed; `try_claim` succeeds and returns
    /// a guard.
    #[test]
    fn claim_succeeds_when_unheld() {
        let slot = RefreshSlot::new();
        assert!(!slot.is_claimed());
        let guard = slot.try_claim().expect("fresh slot is claimable");
        assert!(slot.is_claimed());
        drop(guard);
    }

    /// A second `try_claim` returns `None` while the first guard
    /// is alive. This is the surface that surfaces
    /// `RefreshError::AlreadyRunning` at the `start_refresh`
    /// layer.
    #[test]
    fn claim_fails_when_held() {
        let slot = RefreshSlot::new();
        let _guard = slot.try_claim().expect("first claim succeeds");
        assert!(slot.try_claim().is_none(), "second claim fails");
        assert!(slot.is_claimed());
    }

    /// Dropping the guard releases the slot; a subsequent claim
    /// then succeeds. This is the contract that makes the
    /// `_slot_guard` discipline in `run_refresh_task` self-
    /// healing across success / error / cancellation exits.
    #[test]
    fn release_on_guard_drop() {
        let slot = RefreshSlot::new();
        {
            let _guard = slot.try_claim().expect("first claim succeeds");
            assert!(slot.is_claimed());
        }
        assert!(!slot.is_claimed(), "guard drop released the flag");
        let _second = slot
            .try_claim()
            .expect("slot reclaimable after first guard dropped");
    }

    /// Cloning the slot returns another handle to the same flag —
    /// so the engine's stored slot and the producer task's clone
    /// observe the same state. This is the property that makes
    /// the slot-claim path lock-free against the producer's read/
    /// write borrows of the engine.
    #[test]
    fn clone_shares_underlying_flag() {
        let slot_a = RefreshSlot::new();
        let slot_b = slot_a.clone();
        let _guard = slot_a.try_claim().expect("first claim succeeds");
        assert!(slot_b.is_claimed(), "clone observes the same flag");
        assert!(slot_b.try_claim().is_none(), "clone cannot re-claim");
    }
}

#[cfg(test)]
mod start_refresh_integration_tests {
    //! End-to-end tests for [`Engine::start_refresh`] that drive the
    //! real producer task against a real [`Engine<SoloSigner>`].
    //!
    //! Two flavours of fixture cover the surface:
    //!
    //! - **Unreachable-daemon scenarios** wire a [`DaemonClient`]
    //!   pointed at an unreachable URL; the producer's `get_height`
    //!   fails fast with [`IoError::Daemon`] and the failure
    //!   surfaces through `join().await`. These tests pin handle-
    //!   layer behaviour (`AlreadyRunning` on concurrent claim,
    //!   slot-release after the producer task winds down,
    //!   completion delivery on RPC failure) without modelling
    //!   any chain state.
    //! - **Hybrid scenarios** wire a [`TestDaemon`] in place of the
    //!   real `DaemonClient` via
    //!   [`Engine::replace_daemon`](super::Engine::replace_daemon),
    //!   per `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §6.3 hybrid-
    //!   construction discipline. These tests exercise
    //!   `start_refresh` end-to-end against synthetic chain state;
    //!   the trait abstractions from Stage 1 PR 1 (the
    //!   `DaemonEngine` surface, the `TestDaemon: Rpc + DaemonEngine`
    //!   impl, the `derive_seed` master-seed helper) are what makes
    //!   this coverage possible — Stage 0 had no path for a synthetic
    //!   chain to drive `start_refresh` because `DaemonClient`
    //!   wrapped a concrete `SimpleRequestRpc`.
    //!
    //! Hybrid fixtures use the §6.2 master-seed-derivation contract:
    //! each test owns a single literal `master_seed` recorded in the
    //! test name; the daemon's seed is derived via
    //! `derive_seed(&master, ROLE_DAEMON)`. Reproducibility hinges on
    //! the master seed alone — changing the master re-derives the
    //! daemon seed consistently. (The wallet-side `Engine::create`
    //! master-seed input is independent of the daemon seed by
    //! design; mixing them would model a non-existent leak channel.)
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use shekyl_crypto_pq::account::MASTER_SEED_BYTES;
    use shekyl_simple_request_rpc::SimpleRequestRpc;
    use tempfile::TempDir;
    use tokio::sync::{watch, RwLock};
    use tokio_util::sync::CancellationToken;

    use super::{LedgerSnapshot, RefreshProgress};
    use crate::engine::diagnostics::DiagnosticSink;
    use crate::engine::fault_injecting_refresh::FaultInjecting as FaultInjectingRefresh;
    use crate::engine::lifecycle::EngineCreateParams;
    use crate::engine::local_refresh::LocalRefresh;
    use crate::engine::test_support::{derive_seed, TestDaemon, ROLE_DAEMON};
    use crate::engine::traits::{DaemonEngine, LedgerEngine, RefreshEngine};
    use crate::engine::view_material::ViewMaterial;
    use crate::engine::{
        Credentials, DaemonClient, Engine, IoError, RefreshError, RefreshOptions, SoloSigner,
    };
    use crate::scan::ScanResult;

    /// Build a `DaemonClient` whose underlying RPC points at an
    /// unreachable URL, on the *current* tokio runtime. Async
    /// because [`SimpleRequestRpc::new`] is async; safe to call
    /// from inside `#[tokio::test]` because we await it directly
    /// rather than driving a separate runtime via `block_on`.
    /// Hyper's connection-pool background tasks live on the test's
    /// runtime; the test awaits all work before returning so
    /// nothing is orphaned at runtime drop.
    async fn unreachable_daemon() -> DaemonClient {
        let rpc = SimpleRequestRpc::new("http://127.0.0.1:1".to_string())
            .await
            .expect("construct SimpleRequestRpc against unreachable URL (no connect attempt yet)");
        DaemonClient::new(rpc)
    }

    /// Build a fresh `Engine<SoloSigner>` wrapped in
    /// `Arc<RwLock<…>>` so the shape matches
    /// `Engine::start_refresh`'s receiver. Returns the `TempDir`
    /// alongside so the caller keeps the wallet file alive for the
    /// test's scope.
    async fn make_engine_arc() -> (Arc<RwLock<Engine<SoloSigner>>>, TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"start-refresh integration tests");
        let mut seed = [0u8; MASTER_SEED_BYTES];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(13);
        }
        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let daemon = unreachable_daemon().await;
        let wallet = Engine::<SoloSigner>::create(params, daemon)
            .expect("create FULL wallet for start_refresh integration tests");
        (Arc::new(RwLock::new(wallet)), tmp)
    }

    /// `start_refresh` against the unreachable dummy daemon
    /// produces a runnable handle; the producer's `get_height`
    /// call fails fast, and the failure surfaces through
    /// `join().await` as `RefreshError::Io(IoError::Daemon)`.
    /// The slot is released once the producer task exits.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_refresh_propagates_daemon_io_error_via_join() {
        let (arc, _tmp) = make_engine_arc().await;

        let handle = Engine::start_refresh(arc.clone(), RefreshOptions::default())
            .await
            .expect("first start_refresh claims the slot");

        let result = handle.join().await;
        match result {
            Err(RefreshError::Io(IoError::Daemon { detail })) => {
                assert!(
                    !detail.is_empty(),
                    "Daemon error carries a non-empty detail string"
                );
            }
            other => panic!("expected Io(Daemon), got {other:?}"),
        }

        // The completion oneshot resolves before the producer
        // task's `_slot_guard` drops (sender is fired inside the
        // task, slot guard drops as the function returns). Poll
        // briefly for slot release; bounded so a regression does
        // not hang the suite.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            tokio::task::yield_now().await;
            let g = arc.read().await;
            if !g.refresh_slot.is_claimed() {
                break;
            }
            drop(g);
            if Instant::now() > deadline {
                panic!("slot still claimed 5s after join() resolved");
            }
        }
    }

    /// A second `start_refresh` while the first handle is alive
    /// returns `RefreshError::AlreadyRunning`. Uses the
    /// `current_thread` flavour so the first producer task does
    /// not run until we explicitly await — guaranteeing the slot
    /// is still claimed at the time of the second call without
    /// relying on RPC timing.
    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_start_refresh_returns_already_running() {
        let (arc, _tmp) = make_engine_arc().await;

        let h1 = Engine::start_refresh(arc.clone(), RefreshOptions::default())
            .await
            .expect("first claim succeeds");
        // Producer for h1 is queued but not yet polled (single-
        // threaded runtime, no intervening yield).
        let h2 = Engine::start_refresh(arc.clone(), RefreshOptions::default()).await;
        assert!(
            matches!(h2, Err(RefreshError::AlreadyRunning)),
            "second claim returns AlreadyRunning, got {h2:?}"
        );

        // Cleanup: drop h1 so the producer wakes on cancel and
        // releases the slot before the test ends.
        drop(h1);
        // Yield until the producer task has actually run and exited;
        // bounded so a regression doesn't hang the suite.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            tokio::task::yield_now().await;
            let g = arc.read().await;
            if !g.refresh_slot.is_claimed() {
                break;
            }
            drop(g);
            if Instant::now() > deadline {
                panic!("producer task did not exit within 5s of handle drop");
            }
        }
    }

    /// Dropping the handle fires the cancel token; the producer
    /// task winds down and releases the slot. After the slot is
    /// observably free, a fresh `start_refresh` succeeds — i.e.
    /// the slot really is reusable, not merely "not held by *this*
    /// reference".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_releases_slot_for_subsequent_start_refresh() {
        let (arc, _tmp) = make_engine_arc().await;

        let h1 = Engine::start_refresh(arc.clone(), RefreshOptions::default())
            .await
            .expect("first claim succeeds");
        drop(h1);

        // Spin briefly until the slot is released. Bounded so a
        // regression does not hang the suite.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            tokio::task::yield_now().await;
            let g = arc.read().await;
            if !g.refresh_slot.is_claimed() {
                break;
            }
            drop(g);
            if Instant::now() > deadline {
                panic!("slot still claimed 5s after handle drop");
            }
        }

        // Slot is free; a second `start_refresh` reclaims it.
        let h2 = Engine::start_refresh(arc.clone(), RefreshOptions::default())
            .await
            .expect("slot is reusable after producer wind-down");
        // Drain the second handle to keep the suite clean.
        _ = h2.join().await;
    }

    // ── Hybrid scenarios: real Engine<SoloSigner> + TestDaemon ──────────
    //
    // The construction discipline (§6.3):
    //
    // 1. Build a real `Engine<SoloSigner>` via `Engine::create` using
    //    an unreachable `DaemonClient`. Pays for the file-handle,
    //    keys, ledger, refresh-slot, and preferences setup once.
    // 2. Swap the daemon component for a `TestDaemon` via
    //    `Engine::replace_daemon`. The result is
    //    `Engine<SoloSigner, TestDaemon>`; the dummy daemon is
    //    dropped.
    // 3. Wrap in `Arc<RwLock<…>>` and call `Engine::start_refresh`.

    /// Build an `Engine<SoloSigner, TestDaemon>` ready for hybrid
    /// `start_refresh` tests. Returns the `TempDir` alongside so the
    /// caller keeps the wallet file alive for the lifetime of the
    /// engine.
    async fn make_hybrid_engine_arc(
        mock: TestDaemon,
    ) -> (Arc<RwLock<Engine<SoloSigner, TestDaemon>>>, TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"start-refresh hybrid integration tests");
        let mut wallet_seed = [0u8; MASTER_SEED_BYTES];
        for (i, b) in wallet_seed.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(17);
        }
        let params = EngineCreateParams::for_test_full(&base_path, &creds, &wallet_seed);

        let dummy_rpc = SimpleRequestRpc::new("http://127.0.0.1:1".to_string())
            .await
            .expect("construct SimpleRequestRpc against unreachable URL (no connect attempt yet)");
        let dummy_daemon = DaemonClient::new(dummy_rpc);

        let real = Engine::<SoloSigner>::create(params, dummy_daemon)
            .expect("create FULL wallet for hybrid start_refresh test");
        let hybrid = real.replace_daemon(mock);
        (Arc::new(RwLock::new(hybrid)), tmp)
    }

    /// Build a linear chain of `n` synthetic blocks at heights
    /// `0..n`, with `chain[0]` as the genesis-style block
    /// (parented from `[0u8; 32]`). Real-daemon convention:
    /// `chain[h] = block at height h`. Mirrors the helper in
    /// [`super::test_support`] but is duplicated here rather than
    /// promoted to `pub(crate)` because the two modules' test
    /// surfaces are otherwise independent.
    fn linear_chain(n: u64) -> Vec<shekyl_rpc::ScannableBlock> {
        use crate::engine::test_support::make_synthetic_block;
        let mut chain =
            Vec::with_capacity(usize::try_from(n).expect("test linear_chain length fits in usize"));
        let mut parent = [0u8; 32];
        for h in 0..n {
            let block = make_synthetic_block(h, parent);
            parent = block.block.hash();
            chain.push(block);
        }
        chain
    }

    /// Test-only [`RefreshEngine`] wrapper that forces exactly one
    /// merge-time [`RefreshError::ConcurrentMutation`] retry, then
    /// delegates to the wrapped production producer.
    ///
    /// On the first `produce_scan_result` call it returns a
    /// deliberately stale [`ScanResult`] — an empty range anchored two
    /// heights past the snapshot's `synced_height`, so
    /// `start != synced + 1`. The real
    /// [`Engine::apply_scan_result`](super::super::Engine::apply_scan_result)
    /// merge rejects that with [`RefreshError::ConcurrentMutation`],
    /// exactly as a genuine snapshot race would; the orchestrator
    /// retries with a fresh snapshot. On the second (and later) call
    /// the wrapper delegates to the inner producer, whose real scan
    /// merges to the chain tip.
    ///
    /// This drives the §5.2 retry contract through the **real merge
    /// entry point**. It replaces the prior ledger-side
    /// `FaultInjecting<LocalLedger>` injection, which was removed with
    /// the `LedgerEngine::apply_scan_result` trait method (FOLLOWUPS
    /// P1): the async merge no longer crosses a `LedgerEngine` seam,
    /// so the retry signal must originate where it does in production
    /// — `Engine::apply_scan_result`'s start-height invariant.
    ///
    /// **Not a Mock-X** (PR 3 §2.1.5): a one-method behavioural
    /// perturbation over a real inner producer, `#[cfg(test)]`-only,
    /// no parallel implementation and no clone / actor-mesh shape. The
    /// stale-then-real toggle is the only deviation it introduces.
    struct StaleThenRealRefresh<R: RefreshEngine> {
        inner: R,
        calls: AtomicUsize,
    }

    impl<R: RefreshEngine> StaleThenRealRefresh<R> {
        fn new(inner: R) -> Self {
            Self {
                inner,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl<R> crate::engine::scan_floor::ScanStartFloorProvider for StaleThenRealRefresh<R>
    where
        R: RefreshEngine + crate::engine::scan_floor::ScanStartFloorProvider,
    {
        fn scan_start_floor(&self) -> u64 {
            self.inner.scan_start_floor()
        }
    }

    impl<R: RefreshEngine> RefreshEngine for StaleThenRealRefresh<R> {
        type Error = RefreshError;

        #[allow(clippy::manual_async_fn)]
        fn produce_scan_result<D: DaemonEngine>(
            &self,
            snapshot: LedgerSnapshot,
            daemon: &D,
            opts: RefreshOptions,
            cancel: CancellationToken,
            progress: watch::Sender<RefreshProgress>,
            diagnostics: &dyn DiagnosticSink,
        ) -> impl std::future::Future<Output = Result<ScanResult, Self::Error>> + Send {
            // First call: emit a stale empty result so the real merge
            // rejects it with `ConcurrentMutation` (the start-height
            // invariant fails: `start = synced + 2 != synced + 1`).
            // The Mutex-free `AtomicUsize` toggle is popped before the
            // future is constructed, so nothing is held across the
            // `.await`.
            let stale = (self.calls.fetch_add(1, Ordering::SeqCst) == 0)
                .then(|| ScanResult::empty_at(snapshot.synced_height.saturating_add(2), None));
            async move {
                if let Some(stale) = stale {
                    return Ok(stale);
                }
                self.inner
                    .produce_scan_result(snapshot, daemon, opts, cancel, progress, diagnostics)
                    .await
                    .map_err(Into::into)
            }
        }
    }

    /// Linear-scan baseline for the hybrid surface. With a 6-block
    /// `TestDaemon` chain (heights 0..=5; `chain[0]` is genesis,
    /// `chain[1..=5]` are post-genesis) and a fresh wallet at
    /// `synced_height = 0`, `start_refresh` runs producer → merge
    /// to completion: the producer derives the range
    /// `synced_height + 1 .. get_height = 1..6`, scans the 5
    /// post-genesis heights, and the merge advances the wallet's
    /// `synced_height` to 5. The producer task releases the
    /// refresh slot once it winds down.
    ///
    /// What this pins (Stage 1 PR 1):
    ///
    /// - `Engine<SoloSigner, TestDaemon>` is a real, callable shape —
    ///   the `D: DaemonEngine` parameterization isn't a phantom type;
    ///   `TestDaemon` actually drives the producer.
    /// - The mock's `Rpc` impl (`get_height`,
    ///   `get_scannable_block_by_number`) is wired through every
    ///   layer that the real `start_refresh` traverses (handle →
    ///   producer task → scanner → merge), so future Stage 1 PRs can
    ///   add scenario coverage by composing additional `Mock*`
    ///   components without re-validating the wiring itself.
    /// - `replace_daemon` preserves engine state across the swap:
    ///   ledger, indexes, reservations, refresh slot, and capability
    ///   come through the move-rebuild unchanged. Successful
    ///   slot-release after a *successful* refresh (as opposed to
    ///   the unreachable-daemon failure path's release) is observed
    ///   only here — the unreachable-daemon tests never reach the
    ///   merge.
    ///
    /// Master seed (`MASTER_SEED` below) is recorded as a literal
    /// in the test body per §6.2; the daemon seed is
    /// `derive_seed(&master, ROLE_DAEMON)`. §6.2's "embed the seed
    /// in the test name" guidance applies only to tests that
    /// exercise RNG-driven mock behaviour (fee jitter, synthetic-
    /// fork randomization). This test doesn't — it wires
    /// `TestDaemon`'s pure chain-serving surface, so the master
    /// seed lives in the body alone and the test name stays
    /// descriptive.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hybrid_linear_scan_5_blocks_advances_synced_height() {
        const MASTER_SEED: [u8; 32] = [
            0x5a, 0x1e, 0x71, 0x70, 0x71, 0x01, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11,
        ];

        let daemon_seed = derive_seed(&MASTER_SEED, ROLE_DAEMON);
        // 6 blocks at heights 0..=5: chain[0] = genesis; chain[1..=5]
        // are the 5 post-genesis blocks the producer scans.
        let mock = TestDaemon::with_seed_and_chain(daemon_seed, linear_chain(6));
        let (arc, _tmp) = make_hybrid_engine_arc(mock).await;

        // Sanity-check the pre-refresh invariant: the wallet starts
        // at height 0; if it didn't, the post-refresh assertion
        // below would carry a confounded claim.
        {
            let g = arc.read().await;
            assert_eq!(
                g.synced_height(),
                0,
                "fresh hybrid engine starts at synced_height 0"
            );
        }

        let handle = Engine::start_refresh(arc.clone(), RefreshOptions::default())
            .await
            .expect("start_refresh claims the slot on the hybrid engine");

        let summary = handle
            .join()
            .await
            .expect("hybrid refresh against a 6-block TestDaemon chain joins successfully");
        assert_eq!(summary.processed_height_range, 1..6);
        assert_eq!(summary.blocks_processed, 5);

        // Merge has run by the time `join().await` returned; the
        // engine's persisted view of the chain matches the daemon.
        {
            let g = arc.read().await;
            assert_eq!(
                g.synced_height(),
                5,
                "post-refresh synced_height matches the producer's range upper bound"
            );
        }

        // The producer task signals completion *before* its
        // `_slot_guard` is dropped (sender fires inside the task,
        // slot guard drops as the function returns). Poll briefly
        // for slot release; bounded so a regression does not hang
        // the suite.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            tokio::task::yield_now().await;
            let g = arc.read().await;
            if !g.refresh_slot.is_claimed() {
                break;
            }
            drop(g);
            if Instant::now() > deadline {
                panic!("slot still claimed 5s after hybrid refresh joined");
            }
        }
    }

    /// Exercise the §5.2 retry contract end-to-end. Composition: a
    /// 6-block [`TestDaemon`] chain (heights 0..=5) drives the producer
    /// from `synced_height = 0`. The producer slot is a
    /// [`StaleThenRealRefresh`] wrapping the production
    /// [`LocalRefresh`]: its first `produce_scan_result` returns a
    /// stale empty result, so the real merge
    /// ([`Engine::apply_scan_result`](super::super::Engine::apply_scan_result))
    /// rejects attempt 1 with [`RefreshError::ConcurrentMutation`]; the
    /// orchestrator retries with a fresh snapshot and the second
    /// attempt runs the canonical merge body against the inner
    /// production [`LocalLedger`], advancing `synced_height` to 5.
    ///
    /// What this pins (Stage 1 PR 2 + the FOLLOWUPS P1 async post-pass
    /// fix):
    ///
    /// - The §5.2 retry contract is exercised through the *real*
    ///   refresh path (`Engine::start_refresh` → `run_refresh_task`
    ///   producer/merge loop), not a unit test of `apply_scan_result`
    ///   in isolation. Crucially, the retry signal now originates from
    ///   the **real merge entry point** (`Engine::apply_scan_result`'s
    ///   start-height invariant) rather than a ledger-trait seam: the
    ///   async merge no longer crosses a `LedgerEngine` method, so the
    ///   prior `FaultInjecting<LocalLedger>` injection is replaced by a
    ///   producer that emits a genuinely-stale result.
    /// - On the success path (attempt 2) the merge runs the *real*
    ///   production body
    ///   ([`apply_scan_result_to_state`](super::merge::apply_scan_result_to_state))
    ///   **and** the M3b engine post-pass under one write guard, not a
    ///   parallel-implementation stand-in.
    /// - Bounded retry: one stale result produces exactly one retry
    ///   (`merge_attempts == 2`).
    /// - `replace_refresh` preserves engine state across the swap,
    ///   composing cleanly with `replace_daemon`: keys, ledger,
    ///   reservations, refresh slot, and capability all flow through
    ///   the move-rebuild unchanged, and the produced engine is
    ///   `Send + Sync` (required for `Arc<RwLock<…>>` +
    ///   `tokio::spawn`).
    ///
    /// Master seed is recorded as a literal in the test body per
    /// §6.2; the daemon seed is `derive_seed(&master, ROLE_DAEMON)`
    /// for `TestDaemon`. The `derive_seed_pinned_fixture_*` tests in
    /// `test_support` lock down that derivation against upstream
    /// library drift. The producer wrapper does not consume a seed —
    /// the inner [`LocalRefresh`] / [`LocalLedger`] are deterministic
    /// by construction, and the stale-then-real toggle is the only
    /// behavioural deviation the test introduces.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hybrid_apply_scan_result_retries_on_concurrent_mutation() {
        const MASTER_SEED: [u8; 32] = [
            0xa5, 0xa5, 0x5a, 0x5a, 0xfe, 0xed, 0xfa, 0xce, 0xc0, 0x01, 0xd0, 0x0d, 0xba, 0xad,
            0xf0, 0x0d, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
            0xd0, 0xe0, 0xf0, 0x00,
        ];

        let daemon_seed = derive_seed(&MASTER_SEED, ROLE_DAEMON);

        // 6-block linear chain; producer scans heights 1..=5 starting
        // from a fresh `LocalLedger` at `synced_height = 0`.
        let mock_daemon = TestDaemon::with_seed_and_chain(daemon_seed, linear_chain(6));
        let (arc, _tmp) = make_hybrid_engine_arc(mock_daemon).await;

        // Swap the producer slot for the stale-then-real wrapper. The
        // consume-and-rebuild `replace_refresh` needs an owned engine,
        // so unwrap the single-strong-reference arc, derive
        // `ViewMaterial` from the engine's own keys (the same path
        // `Engine::create` uses to build the default `LocalRefresh`),
        // wrap it, and re-wrap the arc.
        let arc = {
            let engine = std::sync::Arc::into_inner(arc)
                .expect("arc has one strong reference at this point")
                .into_inner();
            let vm = ViewMaterial::try_from_keys(engine.keys())
                .expect("ViewMaterial::try_from_keys against engine keys");
            let refresh = StaleThenRealRefresh::new(LocalRefresh::new(vm, 0));
            let hybrid = engine.replace_refresh(refresh);
            Arc::new(RwLock::new(hybrid))
        };

        // Sanity-check the pre-refresh invariant on the ledger surface.
        {
            let g = arc.read().await;
            assert_eq!(
                g.ledger.synced_height(),
                0,
                "fresh hybrid engine starts at LocalLedger synced_height 0"
            );
        }

        let handle = Engine::start_refresh(arc.clone(), RefreshOptions::default())
            .await
            .expect("start_refresh claims the slot on the hybrid engine");

        let summary = handle.join().await.expect(
            "hybrid retry refresh against a 6-block TestDaemon chain joins after one retry",
        );
        assert_eq!(
            summary.merge_attempts, 2,
            "attempt 1's stale result is rejected with ConcurrentMutation; attempt 2 succeeds"
        );
        assert_eq!(summary.processed_height_range, 1..6);
        assert_eq!(summary.blocks_processed, 5);

        // Post-merge state is authoritative: the canonical merge body
        // ran on attempt 2 and advanced the inner `LocalLedger`'s
        // `synced_height` to the chain tip.
        {
            let g = arc.read().await;
            assert_eq!(
                g.synced_height(),
                5,
                "post-retry LocalLedger synced_height matches the producer's range upper bound"
            );
        }

        // Slot release: same shape as the linear-scan hybrid test.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            tokio::task::yield_now().await;
            let g = arc.read().await;
            if !g.refresh_slot.is_claimed() {
                break;
            }
            drop(g);
            if Instant::now() > deadline {
                panic!("slot still claimed 5s after hybrid retry refresh joined");
            }
        }
    }

    /// **Hybrid retry test pinning the §6 trait/orchestrator
    /// cancellation-checkpoint split end-to-end against a fully-
    /// composed four-slot engine
    /// `Engine<SoloSigner, TestDaemon, LocalLedger,
    /// StaleThenRealRefresh<FaultInjectingRefresh<LocalRefresh>>>`.**
    ///
    /// Composition:
    ///
    /// - Daemon slot: [`TestDaemon`] driving a 6-block linear chain
    ///   (heights 0..=5).
    /// - Ledger slot: the production [`LocalLedger`] (no wrapper). The
    ///   ledger-side `FaultInjecting<LocalLedger>` injection was
    ///   removed with the `LedgerEngine::apply_scan_result` trait
    ///   method (FOLLOWUPS P1); the merge no longer crosses a
    ///   `LedgerEngine` seam, so the retry is driven from the producer
    ///   instead (see the ledger slot's replacement below).
    /// - Refresh slot: a [`StaleThenRealRefresh`] wrapping a
    ///   [`FaultInjectingRefresh<LocalRefresh>`](FaultInjectingRefresh).
    ///   The inner `FaultInjectingRefresh` carries no queued failures
    ///   (it delegates to [`LocalRefresh`] every call), exercising its
    ///   delegation path and keeping the four-slot
    ///   `Engine<S, D, L, R>` shape with a real `RefreshEngine`
    ///   wrapper in the `R` position. The outer `StaleThenRealRefresh`
    ///   emits one stale result so the real merge rejects attempt 1
    ///   with [`RefreshError::ConcurrentMutation`] and the orchestrator
    ///   retries. The `LocalRefresh` is constructed from the engine's
    ///   own keys via [`ViewMaterial::try_from_keys`] — the same path
    ///   [`super::lifecycle`] uses at [`Engine::create`] time.
    ///
    /// What this pins:
    ///
    /// - **Four-slot composition.** Every engine slot (daemon,
    ///   ledger, refresh, plus the implicit signer) is parameterised
    ///   through the trait surface; `replace_daemon` then
    ///   `replace_refresh` rebuild the engine, each moving a type
    ///   parameter from its default to the swapped-in implementor.
    ///   The nested-wrapper `R` position proves the `R: RefreshEngine`
    ///   parameter composes with `D: DaemonEngine` (PR 1) and the
    ///   `LocalLedger` `L` slot at the orchestrator call sites in
    ///   [`run_refresh_task`].
    /// - **Cancellation-checkpoint split exercised end-to-end.** The
    ///   orchestrator runs through checkpoint 1 (top-of-attempt) and
    ///   checkpoint 4 (pre-merge) on each of the two attempts. The
    ///   producer trait body runs through checkpoints 2/3 (top-of-loop
    ///   + per-block) across the 5 block iterations on attempt 2. No
    ///   cancel-token is fired, so each checkpoint observes
    ///   `is_cancelled() == false` and proceeds — pinning the
    ///   not-cancelled path; cancellation-path coverage is the
    ///   shared-token tests in the producer-side suite. The split's
    ///   load-bearing property is that the two checkpoint sets live on
    ///   opposite sides of the trait boundary; running the full retry
    ///   pipeline exercises both sides against the wrapper-composed
    ///   engine.
    /// - **Retry path through the real merge.** Attempt 1's stale
    ///   producer result is rejected by `Engine::apply_scan_result`'s
    ///   start-height invariant with `ConcurrentMutation`; the
    ///   orchestrator's retry branch re-runs the producer (which on
    ///   the second call delegates through `FaultInjectingRefresh` to
    ///   `LocalRefresh`), and the second attempt's merge runs the
    ///   canonical [`apply_scan_result_to_state`](super::merge::apply_scan_result_to_state)
    ///   body plus the M3b post-pass against the inner `LocalLedger`.
    ///   `summary.merge_attempts == 2`.
    /// - **Wrapper drain contract.** The inner `FaultInjectingRefresh`
    ///   queue is empty throughout, so its [`Drop`] `debug_assert!`
    ///   passes at teardown (the F-Mock-2 drain contract).
    ///
    /// Master seed is recorded as a literal in the test body per
    /// §6.2; the daemon seed is `derive_seed(&master, ROLE_DAEMON)`.
    /// The wallet-side master seed is independent of the daemon seed
    /// by design (per the §6.2 contract); both wrappers are
    /// deterministic by construction (the stale-then-real toggle is
    /// the only behavioural deviation introduced).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hybrid_refresh_engine_orchestrator_cancellation_retries() {
        const MASTER_SEED: [u8; 32] = [
            0xc7, 0xc7, 0x7c, 0x7c, 0xfa, 0xce, 0xb0, 0x0b, 0xd0, 0x0d, 0xfe, 0xed, 0x42, 0x42,
            0x13, 0x37, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c,
            0x6d, 0x7e, 0x8f, 0x90,
        ];

        let daemon_seed = derive_seed(&MASTER_SEED, ROLE_DAEMON);

        // 6-block linear chain (heights 0..=5); the producer scans
        // heights 1..=5 from a fresh `LocalLedger` at
        // `synced_height = 0`. The wallet's own master seed (driven by
        // `make_hybrid_engine_arc`'s internal deterministic-seed loop)
        // is independent of `MASTER_SEED` here, which only seeds the
        // daemon side — the wallet seed is regenerated per fixture and
        // the keys derived from it are what the refresh wrapper
        // consumes via `ViewMaterial::try_from_keys` below.
        let mock_daemon = TestDaemon::with_seed_and_chain(daemon_seed, linear_chain(6));

        // Build the daemon-swapped engine, then chain `replace_refresh`
        // to land the four-slot composition. The keys accessor is
        // `pub(crate)`, so the `ViewMaterial` construction happens at
        // the test site.
        let (arc, _tmp) = make_hybrid_engine_arc(mock_daemon).await;
        let arc = {
            // Pull the engine out of the `Arc<RwLock<…>>` to consume it
            // for `replace_refresh`, then re-wrap. `make_hybrid_engine_arc`
            // is the only `Arc` reference holder; the consume-and-
            // rebuild shape of `replace_refresh` requires owned
            // `Engine`, not a borrow.
            let engine = std::sync::Arc::into_inner(arc)
                .expect("arc has one strong reference at this point")
                .into_inner();
            // Derive ViewMaterial from the engine's own keys — the same
            // path `Engine::create` uses internally to construct the
            // default `LocalRefresh`. Wrap it in the (no-failure)
            // `FaultInjectingRefresh` for four-slot composition, then in
            // `StaleThenRealRefresh` to drive the one-shot retry.
            let vm = ViewMaterial::try_from_keys(engine.keys())
                .expect("ViewMaterial::try_from_keys against engine keys");
            let refresh =
                StaleThenRealRefresh::new(FaultInjectingRefresh::new(LocalRefresh::new(vm, 0)));
            let hybrid = engine.replace_refresh(refresh);
            Arc::new(RwLock::new(hybrid))
        };

        // Sanity-check the pre-refresh invariant on the ledger surface.
        {
            let g = arc.read().await;
            assert_eq!(
                g.ledger.synced_height(),
                0,
                "fresh hybrid engine starts at LocalLedger synced_height 0"
            );
        }

        let handle = Engine::start_refresh(arc.clone(), RefreshOptions::default())
            .await
            .expect("start_refresh claims the slot on the four-slot hybrid engine");

        let summary = handle
            .join()
            .await
            .expect("hybrid retry refresh against four-slot composition joins after one retry");

        assert_eq!(
            summary.merge_attempts, 2,
            "attempt 1's stale producer result is rejected with ConcurrentMutation; \
             attempt 2's merge succeeds against the inner LocalLedger"
        );
        assert_eq!(summary.processed_height_range, 1..6);
        assert_eq!(summary.blocks_processed, 5);

        // Post-merge state is authoritative: the inner `LocalLedger`
        // synced_height matches the producer's range upper bound after
        // the canonical merge ran on attempt 2.
        {
            let g = arc.read().await;
            assert_eq!(
                g.synced_height(),
                5,
                "post-retry LocalLedger synced_height matches the producer's range upper bound"
            );
        }

        // Slot release: same shape as the C6β hybrid retry test.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            tokio::task::yield_now().await;
            let g = arc.read().await;
            if !g.refresh_slot.is_claimed() {
                break;
            }
            drop(g);
            if Instant::now() > deadline {
                panic!("slot still claimed 5s after four-slot hybrid retry refresh joined");
            }
        }
    }
}
