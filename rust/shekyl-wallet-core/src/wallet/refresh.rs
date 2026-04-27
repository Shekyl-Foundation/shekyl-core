// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Snapshot-merge refresh **producer**.
//!
//! [`produce_scan_result`] is the read-only counterpart to
//! [`crate::wallet::merge::apply_scan_result_to_state`]: it walks the
//! daemon's blocks for a given height range, runs them through the
//! [`shekyl_scanner::Scanner`], and accumulates the findings into a
//! [`crate::scan::ScanResult`] value **without holding any borrow on
//! `Wallet<S>`** during the long network/scan section. The wallet's
//! own state is consumed only via a cheap [`LedgerSnapshot`] taken
//! before the producer runs.
//!
//! This split is the core of the snapshot-merge-with-retry pattern
//! pinned in `docs/V3_WALLET_DECISION_LOG.md`
//! (`Snapshot-merge-with-retry semantics for Wallet::refresh`,
//! 2026-04-26):
//!
//! 1. [`Wallet::refresh`](super::Wallet) (Phase 2a, commit 4) takes a
//!    brief read borrow, builds a [`LedgerSnapshot`].
//! 2. The borrow is dropped; the producer runs against the snapshot,
//!    free of any wallet-side lock.
//! 3. The result is merged back via
//!    [`Wallet::apply_scan_result`](super::Wallet) under `&mut self`.
//!    If the wallet moved between snapshot and merge, the merge
//!    returns [`RefreshError::ConcurrentMutation`](crate::wallet::RefreshError)
//!    and the refresh loop pulls a fresh snapshot and retries.
//!
//! The producer does not mutate wallet state. The merge is the single
//! audited mutation point; see the merge module's docstring for the
//! invariant gates.
//!
//! # Errors classification
//!
//! [`ProduceError`] separates three failure modes that the
//! [`Wallet::refresh`] retry loop must distinguish:
//!
//! - [`ProduceError::Cancelled`] — the cancellation token fired
//!   between blocks. Becomes [`RefreshError::Cancelled`](crate::wallet::RefreshError)
//!   in commit 4.
//! - [`ProduceError::MaxRetriesExhausted`] — every block fetch retry
//!   bucket emptied without success. Becomes
//!   [`RefreshError::Io`](crate::wallet::RefreshError) (wrapping
//!   [`crate::wallet::IoError::Daemon`]) in commit 4. The retry loop
//!   does **not** attempt further snapshots; this is a daemon-IO
//!   ceiling, not a snapshot race.
//! - [`ProduceError::Scan`] — the scanner rejected a block as
//!   structurally invalid. Surfaces a producer / daemon defect
//!   (malformed block on-wire, scanner contract violation). Becomes
//!   [`RefreshError::Io`](crate::wallet::RefreshError) (wrapping
//!   [`crate::wallet::IoError::Scanner`]). Not retried — re-fetching
//!   the same height will re-encounter the same scanner error.
//!
//! # Status
//!
//! Branch 1 commit 4 wired [`Wallet::refresh`] as the production
//! caller. The producer ([`produce_scan_result`]) remains
//! `pub(crate)`: callers outside `shekyl-wallet-core` go through the
//! `Wallet::refresh` entry point, which owns the snapshot-take +
//! merge-with-retry loop. The `RefreshHandle` async-driver path
//! (cancel-on-drop, single-flight enforcement, progress watch
//! channel) ships in branch 2 on top of this synchronous baseline.

use std::collections::HashSet;
use std::ops::Range;
use std::time::Duration;

use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use shekyl_crypto_pq::account::AllKeysBlob;
use shekyl_oxide::transaction::Input;
use shekyl_rpc::{Rpc, RpcError, ScannableBlock};
use shekyl_scanner::{ScanError, Scanner, ViewPair};
use shekyl_wallet_state::{LedgerBlock, ReorgBlocks};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};
use zeroize::Zeroizing;

use super::error::{IoError, RefreshError};
use super::signer::WalletSignerKind;
use super::Wallet;
use crate::scan::{DetectedTransfer, KeyImageObserved, ReorgRewind, ScanResult, StakeEvent};

/// Maximum retries for transient per-block RPC failures. Mirrors the
/// legacy `shekyl-scanner::sync` ceiling so the operational surface
/// (network flakes recover, persistent failures are surfaced in
/// bounded time) is unchanged across the migration.
const MAX_BLOCK_FETCH_RETRIES: u32 = 5;

/// Initial backoff for block-fetch retries; doubles per attempt up to
/// [`MAX_RETRY_DELAY`].
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Upper bound on the per-attempt backoff. 30 s matches the legacy
/// loop; the producer's caller is the binary-layer refresh, which
/// already has its own outer retry budget on top.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

/// Read-only snapshot of the wallet ledger taken at the start of a
/// refresh.
///
/// The producer ([`produce_scan_result`]) consumes a snapshot for two
/// purposes:
///
/// - parent-hash lookup for the result's
///   [`ScanResult::parent_hash`] field;
/// - reorg-walk-back ([`find_fork_point`]) to locate the height at
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
///   producer needs for parent-hash compare and `find_fork_point`.
///
/// The wallet's transfer set, key-image map, pubkey map, and staker
/// pool are deliberately **not** snapshotted: the producer collects
/// every spend-side key image unfiltered into
/// [`ScanResult::spent_key_images`], and
/// [`crate::wallet::merge::apply_scan_result_to_state`] calls
/// [`shekyl_wallet_state::LedgerIndexes::detect_spends`] against the
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
pub(crate) struct LedgerSnapshot {
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

/// Failures from [`produce_scan_result`].
///
/// Distinct from
/// [`crate::wallet::RefreshError`](crate::wallet::error::RefreshError):
/// `ProduceError` is the producer's local error type, mapped into
/// `RefreshError` by the [`Wallet::refresh`](super::Wallet) caller in
/// commit 4. Keeping it separate keeps the producer free of any
/// `Wallet<S>` dependency and lets the retry loop pattern-match on
/// the failure class without unwrapping a wrapper.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProduceError {
    /// A block-fetch RPC call failed and the
    /// [`MAX_BLOCK_FETCH_RETRIES`] budget exhausted. `last` carries
    /// the final transient failure for diagnostics.
    #[error("RPC failure after {attempts} attempts: {last}")]
    MaxRetriesExhausted {
        /// The last [`RpcError`] observed before giving up.
        last: RpcError,
        /// Number of attempts made (always equals
        /// [`MAX_BLOCK_FETCH_RETRIES`]; carried for log clarity).
        attempts: u32,
    },

    /// The scanner rejected a fetched block as structurally invalid.
    /// Indicates either a malformed daemon response or a scanner
    /// contract violation; not retried because re-fetching the same
    /// height returns the same bytes.
    #[error("scanner rejected block at height {height}: {source}")]
    Scan {
        /// The height of the rejected block.
        height: u64,
        /// Underlying scanner error.
        #[source]
        source: ScanError,
    },

    /// The cancellation token fired before the producer completed the
    /// requested range. The producer returns immediately at the next
    /// inter-block checkpoint without inspecting further heights.
    #[error("scan cancelled before completing the requested range")]
    Cancelled,
}

/// Configuration for [`Wallet::refresh`].
///
/// The retry budget is the only knob today; future settings (per-call
/// height ceiling, custom cancellation token, progress hook) live on
/// [`RefreshHandle`](super::Wallet)'s upcoming branch-2 surface, not
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
    /// `Snapshot-merge-with-retry semantics for Wallet::refresh`
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

/// Outcome of a successful [`Wallet::refresh`] call.
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
    /// merge ingests every entry into [`shekyl_wallet_state::LedgerIndexes`].
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

/// Detail of a reorg detected during a single [`Wallet::refresh`]
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

/// Walk the requested height range, scanning each block and
/// accumulating the findings into a [`ScanResult`].
///
/// # Contract
///
/// - `snapshot` is a read-only view of the wallet ledger at the time
///   the caller decided to refresh. The producer does not mutate it.
/// - `height_range` is the inclusive-exclusive range to scan,
///   `start..end`. Empty ranges (`start >= end`) return immediately
///   with a no-op [`ScanResult::empty_at`].
/// - `cancel` is checked between blocks and during the retry-backoff
///   `select!`. A cancellation fires returns
///   [`ProduceError::Cancelled`].
///
/// # Reorg handling
///
/// On a parent-hash mismatch at the first block of the range
/// (or any subsequent block before a reorg has been recorded for
/// this call), the producer:
///
/// 1. Walks backward via [`find_fork_point`] against `snapshot` until
///    it finds a height at which the daemon and the snapshot agree.
/// 2. Sets [`ScanResult::reorg_rewind`] to
///    `Some(ReorgRewind { fork_height })`.
/// 3. Adjusts the result's `processed_height_range.start` to the
///    fork height and discards any per-height events accumulated
///    above it.
/// 4. Continues scanning forward from the fork height.
///
/// At most one reorg is recorded per producer call. A second reorg
/// landing during the same call (the daemon's tip moves twice while
/// we scan the new chain) is caught by the merge's
/// [`RefreshError::ConcurrentMutation`](crate::wallet::RefreshError)
/// gate and re-driven by the [`Wallet::refresh`] retry loop.
///
/// # Spent-key-image collection
///
/// Every `Input::ToKey` and `Input::StakeClaim` key image is pushed
/// into [`ScanResult::spent_key_images`] unfiltered. The merge
/// matches against the live wallet's owned-output set; this is the
/// "filter at merge, not at produce" choice that keeps the snapshot
/// free of the wallet's transfer / key-image maps.
pub(crate) async fn produce_scan_result<R: Rpc>(
    rpc: &R,
    scanner: &mut Scanner,
    snapshot: &LedgerSnapshot,
    height_range: Range<u64>,
    cancel: &CancellationToken,
) -> Result<ScanResult, ProduceError> {
    let original_start = height_range.start;
    let end = height_range.end;

    // Empty range — return a typed no-op. Use the snapshot's recorded
    // hash at start - 1 for the parent_hash field so the merge's
    // parent-hash invariant validates regardless of where the wallet
    // is in its block window.
    if original_start >= end {
        let parent_hash = parent_hash_for_start(snapshot, original_start);
        return Ok(ScanResult::empty_at(original_start, parent_hash));
    }

    // Effective start advances to `fork_height` if a reorg fires.
    let mut effective_start = original_start;
    let mut effective_parent_hash = parent_hash_for_start(snapshot, original_start);

    let mut block_hashes: Vec<(u64, [u8; 32])> = Vec::new();
    let mut new_transfers: Vec<DetectedTransfer> = Vec::new();
    let mut spent_key_images: Vec<KeyImageObserved> = Vec::new();
    let stake_events: Vec<StakeEvent> = Vec::new();
    let mut reorg_rewind: Option<ReorgRewind> = None;

    let mut h = original_start;
    while h < end {
        if cancel.is_cancelled() {
            return Err(ProduceError::Cancelled);
        }

        let scannable = fetch_block_with_retry(rpc, h, cancel).await?;

        // Reorg detection: only when no reorg has been recorded yet
        // for this call. Once we've decided on a fork height and
        // started re-scanning, all subsequent heights are the new
        // chain — the snapshot's recorded hashes there are stale by
        // construction and a re-check would always (incorrectly)
        // re-trigger.
        if reorg_rewind.is_none() && h > 1 {
            if let Some(stored_parent) = snapshot.block_hash_at(h - 1) {
                if stored_parent != scannable.block.header.previous {
                    warn!(
                        height = h,
                        "produce_scan_result: chain reorg detected at parent of {h}, walking fork point",
                    );

                    let fork_height = find_fork_point(rpc, snapshot, h - 1, cancel).await?;
                    reorg_rewind = Some(ReorgRewind { fork_height });
                    effective_start = fork_height;
                    effective_parent_hash = parent_hash_for_start(snapshot, fork_height);

                    // Discard everything we accumulated at-or-above
                    // the fork height; restart scanning from there.
                    block_hashes.retain(|(bh, _)| *bh < fork_height);
                    new_transfers.retain(|t| t.block_height < fork_height);
                    spent_key_images.retain(|k| k.block_height < fork_height);

                    h = fork_height;
                    continue;
                }
            }
        }

        let block_hash = scannable.block.hash();
        block_hashes.push((h, block_hash));

        // Collect every input's key image unfiltered. The merge
        // matches against the live wallet's owned-output set; we do
        // not pre-filter here because the snapshot deliberately does
        // not carry the wallet's owned-output index.
        let miner_tx = scannable.block.miner_transaction();
        for input in &miner_tx.prefix().inputs {
            if let Input::ToKey { key_image, .. } | Input::StakeClaim { key_image, .. } = input {
                spent_key_images.push(KeyImageObserved {
                    block_height: h,
                    key_image: key_image.0,
                });
            }
        }
        for tx in &scannable.transactions {
            for input in &tx.prefix().inputs {
                if let Input::ToKey { key_image, .. } | Input::StakeClaim { key_image, .. } = input
                {
                    spent_key_images.push(KeyImageObserved {
                        block_height: h,
                        key_image: key_image.0,
                    });
                }
            }
        }

        // The scanner takes ownership of the scannable; pass a clone
        // so we can keep the original around for `block.hash()` /
        // input traversal above. (`ScannableBlock: Clone`.)
        let timelocked = scanner
            .scan(scannable)
            .map_err(|source| ProduceError::Scan { height: h, source })?;
        for output in timelocked.into_inner() {
            new_transfers.push(DetectedTransfer {
                block_height: h,
                output,
            });
        }

        h += 1;
    }

    // Defensive: a producer that emitted any per-height entry above
    // a reorg's fork height by accident would trip the merge's
    // strict-contract gate. Drop a debug assertion in the producer so
    // tests catch the inconsistency before it ever reaches the merge.
    debug_assert!(consistent_against_range(
        &block_hashes,
        &new_transfers,
        &spent_key_images,
        effective_start,
        end,
    ));

    Ok(ScanResult {
        processed_height_range: effective_start..end,
        parent_hash: effective_parent_hash,
        block_hashes,
        new_transfers,
        spent_key_images,
        stake_events,
        reorg_rewind,
    })
}

/// Resolve the `parent_hash` field for a result whose
/// `processed_height_range.start == start`. Returns `None` for
/// genesis (`start <= 1`) and the snapshot's recorded hash at
/// `start - 1` otherwise. A `None` for `start > 1` means the
/// snapshot's reorg window does not extend that far back; the merge
/// will reject this case as `ConcurrentMutation` if the wallet has
/// since recorded a hash there, which is the correct behavior.
fn parent_hash_for_start(snapshot: &LedgerSnapshot, start: u64) -> Option<[u8; 32]> {
    if start <= 1 {
        None
    } else {
        snapshot.block_hash_at(start - 1)
    }
}

/// Walk backwards from `from_height` to find the highest height at
/// which the daemon's reported block hash matches the wallet's
/// snapshot. Returns `(matching_height + 1)` so the caller can use
/// it directly as the fork-rewind point: heights `>= fork_height`
/// are dropped by the merge, heights `< fork_height` are kept.
///
/// Stops at height `1` (genesis) if no match is found in the window:
/// the snapshot's reorg window is bounded, so a deep enough reorg
/// will eventually walk past the window's earliest recorded entry.
/// Returning `1` in that case forces the merge to rewind to genesis,
/// which is the correct behavior (the wallet's recorded chain is
/// entirely orphaned from the daemon's view).
async fn find_fork_point<R: Rpc>(
    rpc: &R,
    snapshot: &LedgerSnapshot,
    from_height: u64,
    cancel: &CancellationToken,
) -> Result<u64, ProduceError> {
    // Pre-collect the snapshot's recorded heights so we can stop the
    // walk as soon as we drop below the window's earliest entry.
    let snapshot_heights: HashSet<u64> = snapshot
        .reorg_blocks
        .blocks
        .iter()
        .map(|(h, _)| *h)
        .collect();

    let mut h = from_height;
    loop {
        if cancel.is_cancelled() {
            return Err(ProduceError::Cancelled);
        }

        if h == 0 {
            return Ok(1);
        }

        let Some(stored_hash) = snapshot.block_hash_at(h) else {
            // Walked past the snapshot's reorg window. The wallet
            // cannot decide where the fork is from snapshot alone;
            // rewinding to `h + 1` (the deepest height the snapshot
            // still recorded) is the safe fallback — the merge will
            // surface this as a deep-reorg case if the rewind exceeds
            // the wallet's safe limits.
            return Ok(h + 1);
        };

        // Defensive: the membership check is redundant with
        // `block_hash_at` (which already returns `None` for
        // out-of-window heights). Kept as a debug-only check.
        debug_assert!(snapshot_heights.contains(&h));

        let daemon_block = fetch_block_with_retry(rpc, h, cancel).await?;
        if daemon_block.block.hash() == stored_hash {
            return Ok(h + 1);
        }

        debug!(height = h, "find_fork_point: hash mismatch, walking back");
        h -= 1;
    }
}

/// Fetch a block at `height` with exponential backoff on transient
/// RPC failures. Cancellation is honoured both before each attempt
/// and during the inter-attempt backoff.
async fn fetch_block_with_retry<R: Rpc>(
    rpc: &R,
    height: u64,
    cancel: &CancellationToken,
) -> Result<ScannableBlock, ProduceError> {
    let height_usize =
        usize::try_from(height).expect("block height fits in usize on 64-bit targets");

    let mut delay = INITIAL_RETRY_DELAY;
    for attempt in 0..MAX_BLOCK_FETCH_RETRIES {
        if cancel.is_cancelled() {
            return Err(ProduceError::Cancelled);
        }

        match rpc.get_scannable_block_by_number(height_usize).await {
            Ok(b) => return Ok(b),
            Err(e) if attempt + 1 < MAX_BLOCK_FETCH_RETRIES => {
                warn!(
                    height,
                    attempt = attempt + 1,
                    max = MAX_BLOCK_FETCH_RETRIES,
                    error = %e,
                    "produce_scan_result: block fetch failed, retrying after backoff",
                );
                tokio::select! {
                    () = cancel.cancelled() => return Err(ProduceError::Cancelled),
                    () = tokio::time::sleep(delay) => {}
                }
                delay = std::cmp::min(delay * 2, MAX_RETRY_DELAY);
            }
            Err(e) => {
                error!(
                    height,
                    error = %e,
                    "produce_scan_result: block fetch failed after {} attempts",
                    MAX_BLOCK_FETCH_RETRIES,
                );
                return Err(ProduceError::MaxRetriesExhausted {
                    last: e,
                    attempts: MAX_BLOCK_FETCH_RETRIES,
                });
            }
        }
    }

    unreachable!("fetch_block_with_retry: loop body always returns within MAX_BLOCK_FETCH_RETRIES");
}

/// Debug-only consistency check used by [`produce_scan_result`]'s
/// `debug_assert!`. Verifies that every accumulated entry lies inside
/// `[start, end)`. Production builds skip the work entirely.
fn consistent_against_range(
    block_hashes: &[(u64, [u8; 32])],
    new_transfers: &[DetectedTransfer],
    spent_key_images: &[KeyImageObserved],
    start: u64,
    end: u64,
) -> bool {
    let in_range = |h: u64| h >= start && h < end;
    block_hashes.iter().all(|(h, _)| in_range(*h))
        && new_transfers.iter().all(|t| in_range(t.block_height))
        && spent_key_images.iter().all(|k| in_range(k.block_height))
}

/// Build a [`Scanner`] from the wallet's [`AllKeysBlob`]. Each refresh
/// attempt builds a fresh scanner so the snapshot-merge retry loop
/// holds no scanner state across retries.
///
/// The scanner takes ownership of the spend secret (boxed in a
/// `Zeroizing`) and a `ViewPair` over `(spend_pub, view_secret,
/// x25519_sk, ml_kem_dk)`. `x25519_sk` and `view_sk` are the same
/// 32-byte material — the wallet's view secret double-duties as the
/// X25519 private scalar — so we only carry one copy through.
///
/// `AllKeysBlob` already wipes its own copy on drop; the
/// `Zeroizing<…>` wrappers we hand to `Scanner` / `ViewPair` ensure
/// the scanner's local copies do the same when this `Scanner` is
/// dropped at the end of the refresh attempt.
fn build_scanner_from_keys(keys: &AllKeysBlob) -> Result<Scanner, RefreshError> {
    let spend_pub = CompressedEdwardsY::from_slice(&keys.spend_pk)
        .map_err(|e| {
            RefreshError::Io(IoError::Scanner {
                detail: format!("AllKeysBlob.spend_pk is not a valid CompressedEdwardsY: {e}"),
            })
        })?
        .decompress()
        .ok_or_else(|| {
            RefreshError::Io(IoError::Scanner {
                detail: "AllKeysBlob.spend_pk does not decompress to a curve point".to_string(),
            })
        })?;

    // `view_sk` and `spend_sk` are stored as canonical 32-byte
    // little-endian scalars (`Scalar::as_bytes`); reduction is a
    // no-op on canonical input but `from_bytes_mod_order` is
    // documented as the safe choice for round-tripping serialized
    // scalars and it costs nothing on the canonical path.
    let view_scalar = Zeroizing::new(Scalar::from_bytes_mod_order(keys.view_sk));
    let x25519_sk: Zeroizing<[u8; 32]> = Zeroizing::new(keys.view_sk);
    let ml_kem_dk: Zeroizing<Vec<u8>> = Zeroizing::new(keys.ml_kem_dk.to_vec());

    let view_pair = ViewPair::new(spend_pub, view_scalar, x25519_sk, ml_kem_dk).map_err(|e| {
        RefreshError::Io(IoError::Scanner {
            detail: format!("ViewPair construction failed: {e}"),
        })
    })?;

    let spend_secret: Zeroizing<[u8; 32]> = Zeroizing::new(keys.spend_sk);
    Ok(Scanner::new(view_pair, spend_secret))
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

impl<S: WalletSignerKind> Wallet<S> {
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
    /// `Wallet::refresh` is `&mut self` because the merge mutates
    /// wallet state under the cross-cutting locking discipline (lock
    /// 3): mutators take `&mut self`, queries take `&self`. An
    /// `async fn refresh(&mut self, …)` would mean callers could
    /// `await` other futures while the borrow is held — including
    /// futures that already hold the wallet lock — which trivially
    /// deadlocks `Arc<RwLock<Wallet<S>>>` topologies.
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
    /// progress channels. `Wallet::refresh` (this method) remains the
    /// underlying primitive.
    ///
    /// # Errors
    ///
    /// - [`RefreshError::ConcurrentMutation`] — `opts.max_retries`
    ///   exhausted on snapshot races.
    /// - [`RefreshError::MalformedScanResult`] — producer-contract
    ///   violation; not retried.
    /// - [`RefreshError::Cancelled`] — the cancellation token fired.
    ///   This signature does not yet expose a token argument; the
    ///   variant exists for branch 2's `RefreshHandle`. In branch 1,
    ///   this method always uses an internal token that never fires.
    /// - [`RefreshError::Io`] — daemon RPC budget exhausted, or
    ///   scanner rejected a block as structurally invalid.
    ///
    /// # Cancellation (branch 2)
    ///
    /// This synchronous signature does not take a cancellation token.
    /// The internal token is created fresh per call and never fires;
    /// callers that need cooperative cancellation will use
    /// `RefreshHandle::start_refresh` from branch 2, which threads a
    /// caller-provided token through the producer.
    pub fn refresh(
        &mut self,
        opts: &RefreshOptions,
        runtime: &tokio::runtime::Handle,
    ) -> Result<RefreshSummary, RefreshError> {
        let cancel = CancellationToken::new();
        let mut last_concurrent_mutation: Option<RefreshError> = None;

        // Attempts are 1-indexed in the summary; the loop allows
        // `1 + max_retries` total tries (the initial attempt plus
        // `max_retries` retries on `ConcurrentMutation`).
        for attempt in 1..=opts.max_retries.saturating_add(1) {
            let snapshot = LedgerSnapshot::from_ledger(&self.ledger.ledger);

            let daemon_tip = runtime
                .block_on(self.daemon.inner().get_height())
                .map_err(|e| {
                    RefreshError::Io(IoError::Daemon {
                        detail: format!("get_height failed: {e}"),
                    })
                })?;
            let daemon_tip_u64 =
                u64::try_from(daemon_tip).expect("daemon height fits in u64 on 64-bit targets");

            // `get_height` is the count of blocks; tip height is
            // `count - 1` for a non-empty chain, else 0. The producer
            // range is exclusive-end, so we scan
            // `synced_height + 1 .. daemon_tip_count`.
            let start = snapshot.synced_height.saturating_add(1);
            let end = daemon_tip_u64;
            let height_range = start..end;

            let mut scanner = build_scanner_from_keys(self.keys())?;

            let result = match runtime.block_on(produce_scan_result(
                self.daemon.inner(),
                &mut scanner,
                &snapshot,
                height_range,
                &cancel,
            )) {
                Ok(r) => r,
                Err(ProduceError::Cancelled) => return Err(RefreshError::Cancelled),
                Err(ProduceError::MaxRetriesExhausted { last, attempts }) => {
                    return Err(RefreshError::Io(IoError::Daemon {
                        detail: format!("block fetch exhausted {attempts} retries: {last}"),
                    }));
                }
                Err(ProduceError::Scan { height, source }) => {
                    return Err(RefreshError::Io(IoError::Scanner {
                        detail: format!("scanner rejected block at height {height}: {source}"),
                    }));
                }
            };

            let summary = summarize(&result, attempt);

            match self.apply_scan_result(result) {
                Ok(()) => return Ok(summary),
                Err(RefreshError::ConcurrentMutation { wallet, result }) => {
                    debug!(
                        attempt,
                        max_retries = opts.max_retries,
                        wallet,
                        result,
                        "Wallet::refresh: snapshot race, retrying with fresh snapshot",
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
        // the loop body itself is broken, which we surface as a
        // `MalformedScanResult` so audit reads a typed contract
        // failure rather than a silent retry exhaustion.
        Err(
            last_concurrent_mutation.unwrap_or(RefreshError::MalformedScanResult {
                reason: "Wallet::refresh retry loop exited without an observed ConcurrentMutation",
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    //! Test suite for [`produce_scan_result`].
    //!
    //! Organized by failure-mode class so reviewers can map each test
    //! to the producer's contract surface:
    //!
    //! - **Smoke tests**: empty range, pre-cancellation. The two
    //!   trivial paths the function must short-circuit before any
    //!   RPC traffic.
    //! - **Linear-scan structural tests**: long-range coverage,
    //!   range-end honouring, key-image accumulation. These exercise
    //!   the per-block accumulation loop on the no-reorg path.
    //! - **Reorg detection tests**: parent-hash mismatch,
    //!   walk-back to fork point, snapshot-window-edge fallback.
    //! - **RPC-failure tests**: transient-recover-within-budget,
    //!   persistent-exhaust-budget, daemon-too-short. These exercise
    //!   `fetch_block_with_retry` and the `MaxRetriesExhausted`
    //!   surface.
    //! - **Scanner-failure tests**: malformed `ScannableBlock`
    //!   triggers `ProduceError::Scan`.
    //! - **Cancellation tests**: cancel-observed-between-blocks
    //!   exercises the inter-block check distinct from the
    //!   pre-call check.
    //!
    //! # What this suite does not cover
    //!
    //! Real owned-output recovery (a non-empty `Timelocked` from
    //! `Scanner::scan` accumulating into [`ScanResult::new_transfers`])
    //! requires a `ViewPair`-aligned fixture (PQC keys, encapsulated
    //! shared secret, and a real on-chain output). That fixture is
    //! substantial enough that it belongs to commit 5's full
    //! [`super::super::Wallet::refresh`]-driven integration tests,
    //! built on top of the existing `shekyl-scanner::test-utils`
    //! constructors. The producer's transfer-accumulation logic is
    //! a single `for output in timelocked.into_inner() { ... }`
    //! loop; the structural correctness — that every recovered
    //! output gets a `block_height` matching its source block — is
    //! self-evident from inspection and exercised end-to-end at the
    //! refresh-driver level.

    use std::future::Future;
    use std::sync::{Arc, Mutex};

    use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};
    use shekyl_oxide::block::{Block, BlockHeader};
    use shekyl_oxide::io::CompressedPoint;
    use shekyl_oxide::transaction::{Input, Timelock, Transaction, TransactionPrefix};
    use shekyl_scanner::{Scanner, ViewPair};
    use zeroize::Zeroizing;

    use super::*;
    use crate::wallet::test_support::{make_synthetic_block, MockRpc};

    // ── Helpers ────────────────────────────────────────────────

    /// Build a deterministic [`Scanner`] for tests that exercise
    /// the producer's structural behaviour (block-fetch, reorg
    /// detection, key-image accumulation, cancellation) without
    /// triggering real owned-output recovery.
    ///
    /// The synthetic blocks below carry no recoverable outputs
    /// (`output_index_for_first_ringct_output: None` skips the
    /// scanner's recovery loop entirely), so the keys here exist
    /// only to satisfy [`Scanner::new`]'s type signature. End-to-end
    /// recovery tests live in commit 5 (see module docs above).
    fn dummy_scanner() -> Scanner {
        let view_secret = Zeroizing::new([0xAAu8; 32]);
        let spend_secret = Zeroizing::new([0xBBu8; 32]);
        let view_scalar = Scalar::from_bytes_mod_order(*view_secret);
        let spend_scalar = Scalar::from_bytes_mod_order(*spend_secret);
        let spend_pub = &spend_scalar * ED25519_BASEPOINT_TABLE;
        // ML-KEM-768 dk is 2400 bytes; an all-zero buffer is fine
        // because the scanner's recovery path is unreachable for
        // every test block in this module.
        let x25519_sk = Zeroizing::new([0u8; 32]);
        let ml_kem_dk = Zeroizing::new(vec![0u8; 2400]);
        let view_pair = ViewPair::new(spend_pub, Zeroizing::new(view_scalar), x25519_sk, ml_kem_dk)
            .expect("dummy view pair construction");
        Scanner::new(view_pair, spend_secret)
    }

    /// Build a linear chain of `n` synthetic blocks, parented as
    /// `make_synthetic_block(h, prev_hash)` for `h = 1..=n`.
    fn linear_chain(n: u64) -> Vec<ScannableBlock> {
        let mut chain = Vec::new();
        let mut parent = [0u8; 32];
        for h in 1..=n {
            let block = make_synthetic_block(h, parent);
            parent = block.block.hash();
            chain.push(block);
        }
        chain
    }

    /// Build a fresh-wallet [`LedgerSnapshot`] (synced_height = 0,
    /// empty reorg window). Used by tests where the wallet has not
    /// recorded any blocks yet.
    fn snapshot_at_height_zero() -> LedgerSnapshot {
        LedgerSnapshot {
            synced_height: 0,
            reorg_blocks: ReorgBlocks::default(),
        }
    }

    /// Build a [`LedgerSnapshot`] whose `reorg_blocks` records every
    /// `(height, hash)` pair from `chain`. Used by reorg tests where
    /// the producer needs the full snapshot window to walk back the
    /// fork point.
    fn snapshot_recording_chain(chain: &[ScannableBlock]) -> LedgerSnapshot {
        let blocks: Vec<(u64, [u8; 32])> = chain
            .iter()
            .enumerate()
            .map(|(i, b)| (i as u64 + 1, b.block.hash()))
            .collect();
        let synced_height = chain.len() as u64;
        LedgerSnapshot {
            synced_height,
            reorg_blocks: ReorgBlocks { blocks },
        }
    }

    /// Build a synthetic block at `height` parented at
    /// `parent_hash`, with a non-default `timestamp` so its hash
    /// differs from [`make_synthetic_block`]'s output (which uses
    /// `timestamp = height`). Reorg tests use this to construct
    /// "alternate-chain" blocks that share a parent prefix but
    /// diverge in hash from the original chain.
    fn make_alt_block(height: u64, parent_hash: [u8; 32]) -> ScannableBlock {
        let mut sb = make_synthetic_block(height, parent_hash);
        sb.block.header.timestamp = 9_000 + height;
        sb
    }

    /// Build a block at `height` whose miner transaction is
    /// standard (`Input::Gen`) and whose body contains one
    /// non-miner V2 transaction with a single `Input::ToKey` whose
    /// `key_image` is `key_image`. The non-miner tx has no outputs.
    /// The producer's key-image accumulation walks both miner and
    /// non-miner inputs; this block exercises the non-miner path.
    fn make_block_with_spending_tx(
        height: u64,
        parent_hash: [u8; 32],
        key_image: [u8; 32],
    ) -> ScannableBlock {
        let header = BlockHeader {
            hardfork_version: 1,
            hardfork_signal: 0,
            timestamp: height,
            previous: parent_hash,
            nonce: 0,
        };
        let miner_prefix = TransactionPrefix {
            additional_timelock: Timelock::None,
            inputs: vec![Input::Gen(
                usize::try_from(height).expect("height fits in usize"),
            )],
            outputs: vec![],
            extra: vec![],
        };
        let miner_tx = Transaction::V2 {
            prefix: miner_prefix,
            proofs: None,
        };
        let spending_prefix = TransactionPrefix {
            additional_timelock: Timelock::None,
            inputs: vec![Input::ToKey {
                amount: None,
                key_offsets: vec![],
                key_image: CompressedPoint(key_image),
            }],
            outputs: vec![],
            extra: vec![],
        };
        let spending_tx = Transaction::V2 {
            prefix: spending_prefix,
            proofs: None,
        };
        let tx_hash = spending_tx.hash();
        let block = Block::new(header, miner_tx, vec![tx_hash])
            .expect("Block::new accepts V2 miner-tx + 1 tx-hash");
        // `ScannableBlock::transactions` holds `Transaction<Pruned>`
        // (the on-wire view: prefix + pruned proofs). Synthetic
        // construction starts in `Transaction<NotPruned>` and
        // demotes via `Into`.
        ScannableBlock {
            block,
            transactions: vec![spending_tx.into()],
            output_index_for_first_ringct_output: None,
        }
    }

    /// Build a [`ScannableBlock`] whose `block.transactions.len()`
    /// disagrees with `transactions.len()` — the scanner's
    /// `InvalidScannableBlock` precondition. This is the only way
    /// to make `Scanner::scan` return [`ScanError`] from a synthetic
    /// fixture (the alternative paths require malformed PQC
    /// material that itself requires a real `ViewPair` setup).
    fn make_malformed_scannable(height: u64, parent_hash: [u8; 32]) -> ScannableBlock {
        let mut sb = make_synthetic_block(height, parent_hash);
        // Add a tx hash to the block but no Transaction in the
        // scannable's `transactions` vec — count mismatch.
        sb.block.transactions.push([0x42u8; 32]);
        sb
    }

    /// `Rpc` wrapper that fires the supplied [`CancellationToken`]
    /// once `n` block fetches have completed. Lets the
    /// `cancel_observed_between_blocks` test deterministically check
    /// the producer's inter-block cancellation gate without racing
    /// real timing.
    #[derive(Clone)]
    struct CancelAfterNFetches {
        inner: MockRpc,
        cancel: CancellationToken,
        counter: Arc<Mutex<u32>>,
        cancel_after: u32,
    }

    impl Rpc for CancelAfterNFetches {
        fn post(
            &self,
            _route: &str,
            _body: Vec<u8>,
        ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
            async move { panic!("CancelAfterNFetches::post unreachable") }
        }

        fn get_height(&self) -> impl Send + Future<Output = Result<usize, RpcError>> {
            self.inner.get_height()
        }

        fn get_scannable_block_by_number(
            &self,
            number: usize,
        ) -> impl Send + Future<Output = Result<ScannableBlock, RpcError>> {
            let inner = self.inner.clone();
            let cancel = self.cancel.clone();
            let counter = self.counter.clone();
            let cancel_after = self.cancel_after;
            async move {
                let result = inner.get_scannable_block_by_number(number).await;
                let mut n = counter
                    .lock()
                    .expect("CancelAfterNFetches counter poisoned");
                *n += 1;
                if *n >= cancel_after {
                    cancel.cancel();
                }
                result
            }
        }
    }

    // ── Smoke tests ────────────────────────────────────────────

    /// Empty range short-circuits before any RPC traffic, returning
    /// a typed no-op result.
    #[tokio::test]
    async fn empty_range_returns_typed_noop() {
        let rpc = MockRpc::with_chain(linear_chain(3));
        let mut scanner = dummy_scanner();
        let snapshot = snapshot_at_height_zero();
        let cancel = CancellationToken::new();

        let result = match produce_scan_result(&rpc, &mut scanner, &snapshot, 5..5, &cancel).await {
            Ok(r) => r,
            Err(e) => panic!("empty range returns Ok, got {e:?}"),
        };

        assert_eq!(result.processed_height_range, 5..5);
        assert!(result.block_hashes.is_empty());
        assert!(result.new_transfers.is_empty());
        assert!(result.spent_key_images.is_empty());
        assert!(result.reorg_rewind.is_none());
    }

    /// Cancellation observed before any block is fetched returns
    /// the typed `Cancelled` variant.
    #[tokio::test]
    async fn pre_cancel_returns_cancelled() {
        let rpc = MockRpc::with_chain(linear_chain(3));
        let mut scanner = dummy_scanner();
        let snapshot = snapshot_at_height_zero();
        let cancel = CancellationToken::new();
        cancel.cancel();

        match produce_scan_result(&rpc, &mut scanner, &snapshot, 1..3, &cancel).await {
            Err(ProduceError::Cancelled) => {}
            Err(other) => panic!("expected Cancelled, got {other:?}"),
            Ok(_) => panic!("expected Cancelled, got Ok"),
        }
    }

    // ── Linear-scan structural tests ───────────────────────────

    /// 100-block linear scan: every block hash flows through to
    /// `block_hashes`, no transfers/key-images on synthetic blocks,
    /// no reorg rewind.
    #[tokio::test]
    async fn linear_scan_100_blocks_accumulates_block_hashes() {
        let chain = linear_chain(100);
        let expected: Vec<(u64, [u8; 32])> = chain
            .iter()
            .enumerate()
            .map(|(i, b)| (i as u64 + 1, b.block.hash()))
            .collect();

        let rpc = MockRpc::with_chain(chain);
        let mut scanner = dummy_scanner();
        let snapshot = snapshot_at_height_zero();
        let cancel = CancellationToken::new();

        let result = match produce_scan_result(&rpc, &mut scanner, &snapshot, 1..101, &cancel).await
        {
            Ok(r) => r,
            Err(e) => panic!("expected Ok, got {e:?}"),
        };

        assert_eq!(result.processed_height_range, 1..101);
        assert_eq!(result.block_hashes, expected);
        assert!(result.new_transfers.is_empty());
        assert!(result.spent_key_images.is_empty());
        assert!(result.reorg_rewind.is_none());
        assert_eq!(result.parent_hash, None, "start = 1 → genesis parent");
    }

    /// `height_range.end` is honoured even when the daemon's chain
    /// extends further. The producer scans `[start, end)` and stops.
    #[tokio::test]
    async fn range_truncation_respects_end_bound() {
        let chain = linear_chain(100);
        let rpc = MockRpc::with_chain(chain);
        let mut scanner = dummy_scanner();
        let snapshot = snapshot_at_height_zero();
        let cancel = CancellationToken::new();

        let result = match produce_scan_result(&rpc, &mut scanner, &snapshot, 1..51, &cancel).await
        {
            Ok(r) => r,
            Err(e) => panic!("expected Ok, got {e:?}"),
        };

        assert_eq!(result.processed_height_range, 1..51);
        assert_eq!(result.block_hashes.len(), 50);
        assert_eq!(result.block_hashes.last().expect("non-empty").0, 50);
    }

    /// Producer iterates both miner and non-miner inputs, and
    /// records every `Input::ToKey { key_image, .. }` into
    /// `spent_key_images`. Verifies the non-miner path with a
    /// synthetic spending transaction.
    #[tokio::test]
    async fn key_image_collected_from_non_miner_input() {
        let key_image_bytes = [0xAB; 32];
        let block = make_block_with_spending_tx(1, [0u8; 32], key_image_bytes);
        let rpc = MockRpc::with_chain(vec![block]);
        let mut scanner = dummy_scanner();
        let snapshot = snapshot_at_height_zero();
        let cancel = CancellationToken::new();

        let result = match produce_scan_result(&rpc, &mut scanner, &snapshot, 1..2, &cancel).await {
            Ok(r) => r,
            Err(e) => panic!("expected Ok, got {e:?}"),
        };

        assert_eq!(result.spent_key_images.len(), 1);
        let observed = &result.spent_key_images[0];
        assert_eq!(observed.block_height, 1);
        assert_eq!(observed.key_image, key_image_bytes);
    }

    // ── Reorg detection tests ──────────────────────────────────

    /// Snapshot recorded an original chain h1..h10; daemon has
    /// reorged from height 8. Producer asked to scan h11..h13:
    ///
    /// 1. Fetches daemon's h=11; its parent (daemon's h=10) does
    ///    not match the snapshot's h=10.
    /// 2. Walks back via `find_fork_point` and finds h=7 still
    ///    matches.
    /// 3. Sets `reorg_rewind = Some(ReorgRewind { fork_height: 8 })`,
    ///    restarts scanning from h=8 on the new chain.
    ///
    /// Result covers `8..13` (5 blocks of new chain), not the
    /// originally requested `11..13`.
    #[tokio::test]
    async fn reorg_at_depth_3_walks_back_to_fork_point() {
        // Shared prefix h1..=h7 (identical between original and new).
        let mut shared = Vec::new();
        let mut parent = [0u8; 32];
        for h in 1..=7u64 {
            let block = make_synthetic_block(h, parent);
            parent = block.block.hash();
            shared.push(block);
        }
        let h7_hash = parent;

        // Original tail h8..=h10: timestamp = height (default).
        let mut orig_tail = Vec::new();
        let mut p = h7_hash;
        for h in 8..=10u64 {
            let block = make_synthetic_block(h, p);
            p = block.block.hash();
            orig_tail.push(block);
        }
        let mut original = shared.clone();
        original.extend(orig_tail);

        // New tail h8..=h12: timestamp disambiguated → distinct hashes.
        let mut new_tail = Vec::new();
        let mut p = h7_hash;
        for h in 8..=12u64 {
            let block = make_alt_block(h, p);
            p = block.block.hash();
            new_tail.push(block);
        }
        let mut new_chain = shared.clone();
        new_chain.extend(new_tail.clone());

        // Snapshot = wallet's view of the ORIGINAL chain through h=10.
        let snapshot = snapshot_recording_chain(&original);

        // Daemon serves the NEW chain.
        let rpc = MockRpc::with_chain(new_chain);
        let mut scanner = dummy_scanner();
        let cancel = CancellationToken::new();

        let result = match produce_scan_result(&rpc, &mut scanner, &snapshot, 11..13, &cancel).await
        {
            Ok(r) => r,
            Err(e) => panic!("expected Ok, got {e:?}"),
        };

        assert_eq!(
            result.reorg_rewind,
            Some(ReorgRewind { fork_height: 8 }),
            "reorg should walk back to fork height 8 (last shared block)"
        );
        assert_eq!(
            result.processed_height_range,
            8..13,
            "rewind extends the scanned range down to fork_height"
        );
        assert_eq!(result.block_hashes.len(), 5);
        assert_eq!(result.block_hashes[0].0, 8);
        assert_eq!(
            result.block_hashes[0].1,
            new_tail[0].block.hash(),
            "first emitted hash must be the NEW chain's h=8"
        );
        // Every per-height entry stays inside the result's range.
        assert!(result.block_hashes.iter().all(|(h, _)| (8..13).contains(h)));
    }

    /// When the reorg's fork point lies below the snapshot's
    /// recorded reorg window, [`find_fork_point`] returns
    /// `(window_edge + 1)` rather than walking off the end. The
    /// producer treats this as "rewind to the deepest height we
    /// still recorded" — the merge surfaces the deep-reorg case
    /// to the caller in commit 4.
    #[tokio::test]
    async fn reorg_below_snapshot_window_rewinds_to_window_edge() {
        // Snapshot only records h5..=h10 (window length 6).
        let mut shared_5 = Vec::new();
        let mut parent = [0u8; 32];
        for h in 1..=4u64 {
            let block = make_synthetic_block(h, parent);
            parent = block.block.hash();
            shared_5.push(block);
        }
        // Original h5..=h10 — but the snapshot disagrees with the
        // daemon at every recorded height because the daemon serves
        // the alt chain from h=5 upwards.
        let mut original_tail = Vec::new();
        let mut p_orig = parent;
        for h in 5..=10u64 {
            let block = make_synthetic_block(h, p_orig);
            p_orig = block.block.hash();
            original_tail.push(block);
        }
        // The "window only covers h=5..=h=10" snapshot.
        let snapshot_blocks: Vec<(u64, [u8; 32])> = original_tail
            .iter()
            .enumerate()
            .map(|(i, b)| (5 + i as u64, b.block.hash()))
            .collect();
        let snapshot = LedgerSnapshot {
            synced_height: 10,
            reorg_blocks: ReorgBlocks {
                blocks: snapshot_blocks,
            },
        };

        // Daemon serves an alt chain h1..=h11 where the divergence
        // point is at h=2 — far below the snapshot window's earliest
        // entry (h=5).
        let mut alt = Vec::new();
        let mut p_alt = [0u8; 32];
        for h in 1..=11u64 {
            let block = make_alt_block(h, p_alt);
            p_alt = block.block.hash();
            alt.push(block);
        }
        let rpc = MockRpc::with_chain(alt);
        let mut scanner = dummy_scanner();
        let cancel = CancellationToken::new();

        let result = match produce_scan_result(&rpc, &mut scanner, &snapshot, 11..12, &cancel).await
        {
            Ok(r) => r,
            Err(e) => panic!("expected Ok, got {e:?}"),
        };

        assert_eq!(
            result.reorg_rewind,
            Some(ReorgRewind { fork_height: 5 }),
            "with snapshot window starting at h=5, walk-back exits at h=4 \
             (`block_hash_at(4)` returns None — past the window's earliest \
             entry) and yields fork_height = 4+1 = 5: rewind everything \
             at-or-above h=5"
        );
    }

    // ── RPC-failure tests ──────────────────────────────────────

    /// Two transient errors at h=2 followed by a successful fetch
    /// recover within the [`MAX_BLOCK_FETCH_RETRIES`] budget. Time
    /// is paused so the exponential backoff is virtual.
    #[tokio::test(start_paused = true)]
    async fn transient_rpc_errors_recover_within_budget() {
        let chain = linear_chain(3);
        let rpc = MockRpc::with_chain(chain);
        rpc.inject_block_fetch_failure(2, RpcError::ConnectionError("flake-1".into()));
        rpc.inject_block_fetch_failure(2, RpcError::ConnectionError("flake-2".into()));
        let mut scanner = dummy_scanner();
        let snapshot = snapshot_at_height_zero();
        let cancel = CancellationToken::new();

        let result = match produce_scan_result(&rpc, &mut scanner, &snapshot, 1..4, &cancel).await {
            Ok(r) => r,
            Err(e) => panic!("expected Ok after transient recovery, got {e:?}"),
        };

        assert_eq!(result.processed_height_range, 1..4);
        assert_eq!(result.block_hashes.len(), 3);
    }

    /// Five back-to-back transient errors at h=2 exhaust the
    /// [`MAX_BLOCK_FETCH_RETRIES`] budget, surfacing
    /// [`ProduceError::MaxRetriesExhausted`] with the final error
    /// preserved.
    #[tokio::test(start_paused = true)]
    async fn persistent_rpc_errors_yield_max_retries_exhausted() {
        let chain = linear_chain(3);
        let rpc = MockRpc::with_chain(chain);
        for i in 0..MAX_BLOCK_FETCH_RETRIES {
            rpc.inject_block_fetch_failure(2, RpcError::ConnectionError(format!("persist-{i}")));
        }
        let mut scanner = dummy_scanner();
        let snapshot = snapshot_at_height_zero();
        let cancel = CancellationToken::new();

        let err = produce_scan_result(&rpc, &mut scanner, &snapshot, 1..4, &cancel)
            .await
            .err()
            .expect("expected MaxRetriesExhausted");

        match err {
            ProduceError::MaxRetriesExhausted { attempts, last } => {
                assert_eq!(attempts, MAX_BLOCK_FETCH_RETRIES);
                assert!(matches!(last, RpcError::ConnectionError(_)));
            }
            other => panic!("expected MaxRetriesExhausted, got {other:?}"),
        }
    }

    /// A daemon whose chain ends below the requested `height_range`
    /// returns `RpcError::InvalidNode` for every fetch at the
    /// missing height; the producer surfaces this as
    /// [`ProduceError::MaxRetriesExhausted`] (transient-class for
    /// retry, terminal at the budget). Models the
    /// "daemon-height-shrinks-mid-loop" path.
    #[tokio::test(start_paused = true)]
    async fn daemon_chain_too_short_yields_max_retries_exhausted() {
        let rpc = MockRpc::with_chain(linear_chain(2));
        let mut scanner = dummy_scanner();
        let snapshot = snapshot_at_height_zero();
        let cancel = CancellationToken::new();

        let err = produce_scan_result(&rpc, &mut scanner, &snapshot, 1..4, &cancel)
            .await
            .err()
            .expect("expected MaxRetriesExhausted");

        match err {
            ProduceError::MaxRetriesExhausted { last, attempts } => {
                assert_eq!(attempts, MAX_BLOCK_FETCH_RETRIES);
                assert!(matches!(last, RpcError::InvalidNode(_)));
            }
            other => panic!("expected MaxRetriesExhausted, got {other:?}"),
        }
    }

    // ── Scanner-failure tests ──────────────────────────────────

    /// A `ScannableBlock` with mismatched
    /// `block.transactions.len() != transactions.len()` triggers
    /// `Scanner::scan` → `ScanError::InvalidScannableBlock` →
    /// `ProduceError::Scan { height, source }`. Unlike RPC errors,
    /// this is **not retried** — re-fetching returns the same bytes.
    #[tokio::test]
    async fn malformed_scannable_yields_scan_error() {
        let block = make_malformed_scannable(1, [0u8; 32]);
        let rpc = MockRpc::with_chain(vec![block]);
        let mut scanner = dummy_scanner();
        let snapshot = snapshot_at_height_zero();
        let cancel = CancellationToken::new();

        let err = produce_scan_result(&rpc, &mut scanner, &snapshot, 1..2, &cancel)
            .await
            .err()
            .expect("expected ProduceError::Scan");

        match err {
            ProduceError::Scan { height, .. } => assert_eq!(height, 1),
            other => panic!("expected Scan {{ height: 1, .. }}, got {other:?}"),
        }
    }

    // ── Cancellation tests ─────────────────────────────────────

    /// Cancellation between blocks: the producer fetches block 1
    /// successfully, the [`CancelAfterNFetches`] wrapper fires the
    /// token, and the next iteration's top-of-loop check returns
    /// [`ProduceError::Cancelled`] before fetching block 2.
    #[tokio::test]
    async fn cancel_observed_between_blocks() {
        let inner = MockRpc::with_chain(linear_chain(5));
        let cancel = CancellationToken::new();
        let rpc = CancelAfterNFetches {
            inner,
            cancel: cancel.clone(),
            counter: Arc::new(Mutex::new(0)),
            cancel_after: 1,
        };
        let mut scanner = dummy_scanner();
        let snapshot = snapshot_at_height_zero();

        let err = produce_scan_result(&rpc, &mut scanner, &snapshot, 1..6, &cancel)
            .await
            .err()
            .expect("expected Cancelled after first block fetch");

        match err {
            ProduceError::Cancelled => {}
            other => panic!("expected Cancelled, got {other:?}"),
        }
    }
}
