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
//! This commit (Branch 1, commit 2) lands the producer in isolation:
//! the function is `pub(crate)` and is called only from the
//! producer's own tests. The `Wallet::refresh` caller and its retry
//! loop ship in commit 4, after the producer's full failure-mode
//! test suite (commit 3). The `dead_code` allows below cover the
//! gap between "producer compiles and tests pass" and "first non-test
//! call site exists."

#![allow(dead_code)]

use std::collections::HashSet;
use std::ops::Range;
use std::time::Duration;

use shekyl_oxide::transaction::Input;
use shekyl_rpc::{Rpc, RpcError, ScannableBlock};
use shekyl_scanner::{ScanError, Scanner};
use shekyl_wallet_state::{LedgerBlock, ReorgBlocks};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

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

#[cfg(test)]
mod tests {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};
    use shekyl_scanner::{Scanner, ViewPair};
    use zeroize::Zeroizing;

    use super::*;
    use crate::wallet::test_support::{make_synthetic_block, MockRpc};

    /// Build a deterministic [`Scanner`] for tests that never need
    /// the scanner to actually recover an owned output. The empty-range
    /// and pre-cancel smoke tests below return before the producer
    /// reaches [`Scanner::scan`], so the keys are never used in
    /// anger; they exist only to satisfy the producer's type
    /// signature.
    ///
    /// The full producer test suite (commit 3) builds a richer
    /// fixture on top of `shekyl-scanner::test-utils` so it can
    /// assert on real `RecoveredWalletOutput` shape.
    fn dummy_scanner() -> Scanner {
        let view_secret = Zeroizing::new([0xAAu8; 32]);
        let spend_secret = Zeroizing::new([0xBBu8; 32]);
        let view_scalar = Scalar::from_bytes_mod_order(*view_secret);
        let spend_scalar = Scalar::from_bytes_mod_order(*spend_secret);
        let spend_pub = &spend_scalar * ED25519_BASEPOINT_TABLE;
        // ML-KEM-768 dk is 2400 bytes; an all-zero buffer is fine
        // for the tests below because the scanner is never invoked.
        let x25519_sk = Zeroizing::new([0u8; 32]);
        let ml_kem_dk = Zeroizing::new(vec![0u8; 2400]);
        let view_pair = ViewPair::new(spend_pub, Zeroizing::new(view_scalar), x25519_sk, ml_kem_dk)
            .expect("dummy view pair construction");
        Scanner::new(view_pair, spend_secret)
    }

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

    fn snapshot_at_height_zero() -> LedgerSnapshot {
        LedgerSnapshot {
            synced_height: 0,
            reorg_blocks: ReorgBlocks::default(),
        }
    }

    /// Empty-range smoke test. The full suite (linear scan, reorg,
    /// retry, cancellation) lands in commit 3 against the same
    /// `MockRpc` scaffold.
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
}
