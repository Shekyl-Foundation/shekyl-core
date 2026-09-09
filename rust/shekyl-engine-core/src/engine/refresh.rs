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

// The single-flight primitive lives in its own module now that
// `start_refresh` and `start_rescan` both claim it; re-exported here so
// existing `refresh::RefreshSlot` paths (notably `Engine`'s field type in
// `engine/mod.rs`) keep resolving.
pub(crate) use super::refresh_slot::{RefreshSlot, SlotGuard};

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

/// cSHAKE256 customization for [`derive_snapshot_id`].
///
/// House form `b"shekyl/<name>-v1"` (mechanism 1). Versioned so an encoding
/// change mints `shekyl/snapshot-id-v2` rather than reinterpreting these bytes.
/// Registered in `docs/design/CRYPTO_DOMAIN_REGISTRY.tsv`. SA-3c mint rationale
/// (unpersisted internal digest; not a re-spelling of a live persisted domain):
/// `docs/V3_WALLET_DECISION_LOG.md` entry 2026-08-11.
pub(crate) const SNAPSHOT_ID_CUSTOMIZATION: &[u8] = b"shekyl/snapshot-id-v1";

/// Canonical cSHAKE **input** for [`derive_snapshot_id`] (domain is the
/// customization, not part of these bytes):
///
/// ```text
///   snapshot.synced_height       (LE u64, 8 bytes)
/// ‖ reorg_blocks.blocks.len()    (LE u64, 8 bytes; length prefix)
/// ‖ for each (h, hash) in window:
///     LE u64 height (8 bytes) ‖ 32-byte block hash
/// ```
///
/// The length prefix forecloses extension/concatenation collisions against
/// same-tip ledgers with different reorg-window depth.
fn snapshot_id_preimage(snapshot: &LedgerSnapshot) -> Vec<u8> {
    let n_blocks = snapshot.reorg_blocks.blocks.len();
    let mut buf = Vec::with_capacity(8 + 8 + n_blocks * (8 + 32));
    buf.extend_from_slice(&snapshot.synced_height.to_le_bytes());
    buf.extend_from_slice(&(n_blocks as u64).to_le_bytes());
    for (height, hash) in &snapshot.reorg_blocks.blocks {
        buf.extend_from_slice(&height.to_le_bytes());
        buf.extend_from_slice(hash);
    }
    buf
}

/// Derive the opaque [`SnapshotId`] for a [`LedgerSnapshot`].
///
/// `cSHAKE256` ([`shekyl_crypto_hash::cshake256_32`]) with
/// [`SNAPSHOT_ID_CUSTOMIZATION`] over [`snapshot_id_preimage`], truncated to
/// the first 128 bits. Structural domain separation (SP 800-185); the
/// customization excludes collisions against any other domain-separated digest
/// in the workspace.
///
/// `pub(crate)`: callers in [`super::pending`] derive `SnapshotId` from an
/// engine-internal snapshot read; consumers never pass a `SnapshotId` into the
/// trait surface from outside.
pub(crate) fn derive_snapshot_id(snapshot: &LedgerSnapshot) -> SnapshotId {
    let digest = shekyl_crypto_hash::cshake256_32(
        SNAPSHOT_ID_CUSTOMIZATION,
        &snapshot_id_preimage(snapshot),
    );
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
/// - `pending_incoming_count` / `pending_incoming_atomic_units`: the
///   per-attempt "you have incoming" summary (CT-5 §3.2.1 D3 display
///   surface) — the count and summed amount of [`DetectedTransfer`]
///   entries the producer recovered this attempt. Transient: it
///   reflects the in-flight attempt, resets to `0` on
///   `RefreshPhase::Retrying`, and is `0` on attempts that detect
///   nothing. It is the detection ("received") signal, decoupled from
///   spendability — a detected output can be displayed before its
///   curve-tree membership is provable.
/// - `rebuilding_membership`: `true` while the curve tree is behind the
///   ledger (the ledger has confirmed blocks the tree has not yet
///   ingested), i.e. the adopting / tree-wiped wallet whose backfill is
///   in progress. Spending may be temporarily gated
///   ([`SendError::SpendUnavailableRebuilding`](super::error::SendError::SpendUnavailableRebuilding))
///   while this holds. The forward-from-genesis common case never sets
///   it (tree and ledger advance in lockstep).
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

    /// Count of outputs detected ("received") this attempt. See the
    /// type docstring's pending-incoming field semantics.
    pub pending_incoming_count: u64,

    /// Summed amount (atomic units) of the outputs detected this
    /// attempt. See the type docstring's pending-incoming semantics.
    pub pending_incoming_atomic_units: u64,

    /// `true` while the curve tree lags the ledger (rebuild in
    /// progress); spending may be temporarily gated. See the type
    /// docstring.
    pub rebuilding_membership: bool,
}

impl RefreshProgress {
    /// Construct a phase-transition snapshot with the curve-tree
    /// display fields zeroed (no per-attempt detection, not rebuilding)
    /// — the common shape for the seed, retry, and cancel pings that do
    /// not carry a pending-incoming summary. The merge / success
    /// emissions that *do* carry the summary build the literal directly.
    pub(crate) const fn phase_only(
        height: u64,
        blocks_processed: u64,
        blocks_total: u64,
        phase: RefreshPhase,
    ) -> Self {
        Self {
            height,
            blocks_processed,
            blocks_total,
            phase,
            pending_incoming_count: 0,
            pending_incoming_atomic_units: 0,
            rebuilding_membership: false,
        }
    }

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
        Self::phase_only(0, 0, 0, RefreshPhase::Scanning)
    }
}

/// Whether the curve tree lags the ledger and is therefore rebuilding
/// membership data. `tree_cursor` is the tree's last-ingested height
/// ([`super::curve_tree_actor::CurveTreeHandle::ingested_tip_height`]),
/// `None` when the tree is fresh; `ledger_synced` is the ledger's
/// confirmed tip. The tree is behind iff its covered height (treating a
/// fresh tree as `0`) is strictly below the ledger tip — i.e. there are
/// confirmed blocks whose leaves the tree has not yet ingested. A fresh
/// wallet syncing from genesis (`ledger_synced == 0`) is not rebuilding;
/// only an adopting / tree-wiped wallet (ledger ahead of a lagging tree)
/// is.
fn membership_rebuilding(
    tree_cursor: Option<shekyl_curve_tree::BlockHeight>,
    ledger_synced: u64,
) -> bool {
    let covered = tree_cursor.map_or(0, |h| h.0);
    covered < ledger_synced
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
/// The cancellation token is checked at five points:
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
async fn run_refresh_task<S, D: DaemonEngine, E, R, P>(
    engine_arc: std::sync::Arc<tokio::sync::RwLock<Engine<S, D, LocalLedger, E, R, P>>>,
    opts: RefreshOptions,
    cancel: CancellationToken,
    progress: tokio::sync::watch::Sender<RefreshProgress>,
    completion: tokio::sync::oneshot::Sender<Result<RefreshSummary, RefreshError>>,
    _slot_guard: SlotGuard,
) where
    S: EngineSignerKind + Send + Sync + 'static,
    E: super::traits::EconomicsEngine,
    R: RefreshEngine + super::scan_floor::ScanStartFloorProvider + Send + Sync + 'static,
    P: super::traits::PendingTxEngine + Send + Sync + 'static,
    Engine<S, D, LocalLedger, E, R, P>: Send + Sync,
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
    // Clone the ledger handle and daemon under a brief read guard, then
    // drop the guard before the network-bound anchor await. The rest of
    // this driver follows the same clone-then-drop discipline so daemon
    // I/O never holds the outer `engine_arc` read lock and never blocks
    // a writer for the duration of an RPC round-trip.
    {
        let (ledger, daemon, floor) = {
            let g = engine_arc.read().await;
            (
                std::sync::Arc::clone(&g.ledger),
                g.daemon().clone(),
                g.refresh.scan_start_floor(),
            )
        };
        if let Err(e) = super::scan_floor::ensure_birthday_anchor(&ledger, &daemon, floor).await {
            _ = completion.send(Err(e));
            return;
        }
    }

    // Producer-side observability sink. `TracingDiagnosticSink` is the
    // V3.0 canonical projection per `engine/diagnostics/sink.rs` F9: each
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

        let mut result = match produced.map_err(Into::into) {
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

        // Pending-incoming ("you have received") display summary for this
        // attempt (CT-5 §3.2.1 D3). Detection is decoupled from
        // spendability: these outputs surface on the progress channel as
        // soon as the scan finds them, independent of whether the curve
        // tree can yet prove their membership. `u64`-summed with
        // saturation so a pathological amount set can never panic the
        // refresh task.
        let pending_incoming_count = summary.transfers_detected as u64;
        let pending_incoming_atomic_units = result.new_transfers.iter().fold(0u64, |acc, dt| {
            acc.saturating_add(dt.output.amount().to_raw())
        });
        let merge_height = summary
            .processed_height_range
            .end
            .saturating_sub(1)
            .max(current_synced);

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
        //
        // `rebuilding_membership` is read from the tree cursor *before*
        // the ingest pre-pass below runs: it is the adopting / tree-wiped
        // wallet's state (ledger ahead of a lagging tree) and is the
        // window during which the backfill is in flight. On a long
        // adopting backfill this is the phase a subscriber observes for
        // the entire catch-up, so the "rebuilding membership data" status
        // surfaces here, not after the pre-pass has already healed it.
        let rebuilding_membership = {
            let curve_tree = {
                let g = engine_arc.read().await;
                g.curve_tree.clone()
            };
            let cursor = curve_tree.ingested_tip_height().await;
            // A cursor read failure is not fatal to the display ping
            // (the ingest pre-pass below surfaces a real fault
            // terminally); treat an unreadable cursor as not-rebuilding
            // so a transient actor hiccup cannot flip the UI to a
            // spurious "rebuilding" state.
            cursor
                .ok()
                .is_some_and(|c| membership_rebuilding(c, current_synced))
        };
        _ = progress.send(RefreshProgress {
            height: merge_height,
            blocks_processed: summary.blocks_processed,
            blocks_total: summary.blocks_processed,
            phase: RefreshPhase::Merging,
            pending_incoming_count,
            pending_incoming_atomic_units,
            rebuilding_membership,
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
        // CT-5a §3.2 (R1-Q2): feed the curve tree this result's height
        // range (genesis/birthday catch-up + per-range ingest, cursor-
        // driven) BEFORE the ledger merge, so the ledger tip never
        // advances past the tree (ack-before-commit, O2). The ingest is
        // idempotent under the retry loop — a re-produced result is
        // skipped up to the tree's own cursor — and terminal on failure
        // (the loop retries only `ConcurrentMutation`). Clone the
        // curve-tree handle and daemon under a brief read guard, then
        // drop the guard before the long-running ingest `.await`s so
        // close / mutation paths are not blocked during backfill.
        let (curve_tree, daemon) = {
            let g = engine_arc.read().await;
            (g.curve_tree.clone(), g.daemon.clone())
        };
        let producer_leaves =
            match super::merge::index_block_leaves(std::mem::take(&mut result.block_leaves)) {
                Ok(map) => map,
                Err(e) => {
                    _ = completion.send(Err(e));
                    return;
                }
            };
        if let Err(e) = super::merge::curve_tree_ingest_scan_result_with_respawn(
            &curve_tree,
            &daemon,
            &result,
            &producer_leaves,
        )
        .await
        {
            _ = completion.send(Err(e));
            return;
        }

        let merge = {
            let g = engine_arc.read().await;
            g.apply_scan_result(result)
        };

        match merge {
            Ok(()) => {
                // Final `Merging`-phase frame carrying the per-attempt
                // pending-incoming summary with `rebuilding_membership:
                // false` — the ingest pre-pass above acked the full range
                // before this merge (ack-before-commit), so the tree is
                // now caught up to the ledger and any rebuild window has
                // closed. This lets a subscriber that samples only the
                // terminal frame still observe "you received X" without a
                // stale rebuilding flag. The completion oneshot remains
                // the authoritative success signal; there is no terminal
                // `Done` phase (dropping `progress` on return yields
                // `RecvError`, the watch idiom for "no further updates").
                _ = progress.send(RefreshProgress {
                    height: merge_height,
                    blocks_processed: summary.blocks_processed,
                    blocks_total: summary.blocks_processed,
                    phase: RefreshPhase::Merging,
                    pending_incoming_count,
                    pending_incoming_atomic_units,
                    rebuilding_membership: false,
                });
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
                _ = progress.send(RefreshProgress::phase_only(
                    current_synced,
                    0,
                    0,
                    RefreshPhase::Retrying,
                ));
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
        E: super::traits::EconomicsEngine,
        R: RefreshEngine + super::scan_floor::ScanStartFloorProvider,
        P: super::traits::PendingTxEngine,
    > Engine<S, D, LocalLedger, E, R, P>
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

        Ok(Self::spawn_refresh_producer(
            self_arc,
            opts,
            slot_guard,
            synced_height,
        ))
    }

    /// Spawn the refresh producer task and assemble its [`RefreshHandle`].
    ///
    /// Shared by [`Self::start_refresh`] and
    /// [`Engine::start_rescan`](Self::start_rescan): both run the **same**
    /// producer over the **same** single-flight slot, so the tail of the two
    /// entry points is one implementation rather than two that drift. Only
    /// the state each hands the producer differs — rescan empties the
    /// scan-derived ledger first (see `engine/rescan.rs`).
    ///
    /// Takes the already-claimed [`SlotGuard`] by value: the guard moves into
    /// the spawned task and releases the slot when the task winds down, so a
    /// caller cannot claim the slot and then forget to spawn.
    ///
    /// `synced_height` seeds the progress watch channel with the wallet
    /// baseline that [`RefreshProgress::height`]'s contract promises ("on
    /// initial publish this is `synced_height` itself"), so a caller that
    /// reads `progress().borrow()` before the producer's first per-attempt
    /// update sees a real baseline rather than a misleading `0`.
    pub(super) fn spawn_refresh_producer(
        self_arc: std::sync::Arc<tokio::sync::RwLock<Self>>,
        opts: RefreshOptions,
        slot_guard: SlotGuard,
        synced_height: u64,
    ) -> RefreshHandle
    where
        S: EngineSignerKind + Send + Sync + 'static,
        Self: Send + Sync,
    {
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
        let (progress_tx, progress_rx) = tokio::sync::watch::channel(RefreshProgress::phase_only(
            synced_height,
            0,
            0,
            RefreshPhase::Scanning,
        ));
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        let cancel_token = CancellationToken::new();

        let task_cancel = cancel_token.clone();
        // `self_arc` and `progress_tx` both move into the task. The producer
        // is the sole progress `Sender`; the handle keeps only a `Receiver`,
        // so when the task exits its `Sender` drops and downstream
        // `Receiver::changed().await` returns `Err(_)` to signal "no more
        // progress." Taking the arc by value (rather than cloning a borrow)
        // makes the handoff explicit: after this call the caller has no
        // engine reference left to accidentally use.
        let producer_join = tokio::spawn(run_refresh_task(
            self_arc,
            opts.clone(),
            task_cancel,
            progress_tx,
            completion_tx,
            slot_guard,
        ));

        RefreshHandle {
            completion_rx: Some(completion_rx),
            cancel_token,
            progress_rx,
            producer_join,
            opts,
        }
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
        E: super::traits::EconomicsEngine,
        R: RefreshEngine + super::scan_floor::ScanStartFloorProvider,
        P: super::traits::PendingTxEngine,
    > Engine<S, D, LocalLedger, E, R, P>
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
        let (progress_tx, _progress_rx) = tokio::sync::watch::channel(RefreshProgress::phase_only(
            0,
            0,
            0,
            RefreshPhase::Scanning,
        ));

        self.refresh_with(opts, |_attempt, snapshot| {
            let mut result = runtime
                .block_on(self.refresh.produce_scan_result(
                    snapshot.clone(),
                    &self.daemon,
                    opts.clone(),
                    cancel.clone(),
                    progress_tx.clone(),
                    &sink,
                ))
                .map_err(Into::<RefreshError>::into)?;
            // CT-5a §3.2 (R1-Q2): feed the curve tree this result's range
            // before `refresh_with` merges it (ack-before-commit, O2).
            // Cursor-driven + idempotent, so re-running it on a retried
            // attempt is safe. Mirrors the async `run_refresh_task` path,
            // including the R1-Q4 respawn-and-retry on a fail-stop / poison.
            runtime.block_on(self.ingest_scan_result_with_respawn(&mut result))?;
            Ok(result)
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

#[cfg(test)]
#[path = "refresh_driver_tests.rs"]
mod refresh_driver_tests;

#[cfg(test)]
#[path = "refresh_handle_tests.rs"]
mod refresh_handle_tests;

#[cfg(test)]
#[path = "start_refresh_integration_tests.rs"]
mod start_refresh_integration_tests;
