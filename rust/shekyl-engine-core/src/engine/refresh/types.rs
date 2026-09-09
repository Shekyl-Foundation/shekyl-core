// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Refresh vocabulary: snapshot, options, summary, progress, and the
//! merge-retry budget that makes a race-less exhaustion unrepresentable.

use std::num::NonZeroU32;
use std::ops::Range;

use shekyl_engine_state::{LedgerBlock, ReorgBlocks};

use crate::engine::pending::SnapshotId;
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
pub(crate) fn snapshot_id_preimage(snapshot: &LedgerSnapshot) -> Vec<u8> {
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
/// `pub(crate)`: callers in [`crate::engine::pending`] derive `SnapshotId` from an
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

/// Configuration for [`crate::engine::Engine::refresh`].
///
/// The retry budget is the only knob today; future settings (per-call
/// height ceiling, custom cancellation token, progress hook) live on
/// [`crate::engine::RefreshHandle`]'s upcoming branch-2 surface, not
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

/// Outcome of a successful [`crate::engine::Engine::refresh`] call.
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

/// Detail of a reorg detected during a single [`crate::engine::Engine::refresh`]
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
// [`crate::engine::Engine::refresh`] / `Engine::refresh_with` primitives and add
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
///   ([`crate::engine::error::SendError::SpendUnavailableRebuilding`])
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
/// ([`crate::engine::curve_tree_actor::CurveTreeHandle::ingested_tip_height`]),
/// `None` when the tree is fresh; `ledger_synced` is the ledger's
/// confirmed tip. The tree is behind iff its covered height (treating a
/// fresh tree as `0`) is strictly below the ledger tip — i.e. there are
/// confirmed blocks whose leaves the tree has not yet ingested. A fresh
/// wallet syncing from genesis (`ledger_synced == 0`) is not rebuilding;
/// only an adopting / tree-wiped wallet (ledger ahead of a lagging tree)
/// is.
pub(crate) fn membership_rebuilding(
    tree_cursor: Option<shekyl_curve_tree::BlockHeight>,
    ledger_synced: u64,
) -> bool {
    let covered = tree_cursor.map_or(0, |h| h.0);
    covered < ledger_synced
}

/// Snapshot-merge retry state: a 1-indexed attempt plus the remaining
/// extra retries from [`RefreshOptions::max_retries`].
///
/// The first attempt always exists ([`Self::new`]). After a
/// [`crate::engine::RefreshError::ConcurrentMutation`], [`Self::after_race`]
/// is `Some(next)` while retries remain and `None` when the race just
/// observed exhausted the budget. Exhaustion therefore always has a
/// race in hand — the `Option<RefreshError>` +
/// `InternalInvariantViolation` fallback the two retry loops used to
/// carry is unrepresentable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MergeRetry {
    attempt: NonZeroU32,
    retries_left: u32,
}

impl MergeRetry {
    pub(crate) const fn new(opts: &RefreshOptions) -> Self {
        Self {
            attempt: NonZeroU32::MIN,
            retries_left: opts.max_retries,
        }
    }

    /// 1-indexed attempt number of the try about to run.
    pub(crate) const fn attempt(self) -> u32 {
        self.attempt.get()
    }

    /// Same value as [`Self::attempt`], typed so [`summarize`] cannot
    /// record a zero `merge_attempts`.
    pub(crate) const fn attempt_nz(self) -> NonZeroU32 {
        self.attempt
    }

    /// After a snapshot race: another try, or `None` = surface this race.
    #[must_use]
    pub(crate) const fn after_race(self) -> Option<Self> {
        match self.retries_left.checked_sub(1) {
            Some(retries_left) => Some(Self {
                attempt: self.attempt.saturating_add(1),
                retries_left,
            }),
            None => None,
        }
    }
}

/// Build a [`RefreshSummary`] from a producer-emitted [`ScanResult`]
/// (just before the merge consumes it) and the loop bookkeeping. The
/// merge takes the value by-move; this helper runs first so the merge
/// never has to clone the result for summary purposes.
///
/// `merge_attempts` is [`NonZeroU32`]: a successful summary always
/// records at least the initial attempt. Zero is unrepresentable.
pub(crate) fn summarize(result: &ScanResult, merge_attempts: NonZeroU32) -> RefreshSummary {
    RefreshSummary {
        processed_height_range: result.processed_height_range.clone(),
        blocks_processed: result.block_hashes.len() as u64,
        transfers_detected: result.new_transfers.len(),
        key_images_observed: result.spent_key_images.len(),
        reorg: result.reorg_rewind.as_ref().map(|r| RefreshReorgEvent {
            fork_height: r.fork_height,
        }),
        merge_attempts: merge_attempts.get(),
    }
}

#[cfg(test)]
mod merge_retry_tests {
    use super::*;

    #[test]
    fn zero_retries_exhausts_on_the_first_race() {
        let opts = RefreshOptions { max_retries: 0 };
        let retry = MergeRetry::new(&opts);
        assert_eq!(retry.attempt(), 1);
        assert!(retry.after_race().is_none());
    }

    #[test]
    fn eight_retries_allow_nine_attempts() {
        let opts = RefreshOptions { max_retries: 8 };
        let mut retry = MergeRetry::new(&opts);
        for expected in 1..=8 {
            assert_eq!(retry.attempt(), expected);
            retry = retry.after_race().expect("retry still in budget");
        }
        assert_eq!(retry.attempt(), 9);
        assert!(retry.after_race().is_none());
    }
}
