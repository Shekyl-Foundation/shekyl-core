// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet birthday scan floor: resolution, ledger anchor, and refresh
//! preflight.
//!
//! Per `docs/WALLET_PREFS.md` §3.1 / §3.3 and
//! `docs/design/REFRESH_DESIGN_LANDSCAPE.md` §7, the producer must not
//! scan blocks below the effective birthday floor. The merge gate
//! requires `processed_height_range.start == synced_height + 1`, so a
//! floor above `synced_height + 1` is satisfied by **Shape A**: advance
//! `ledger.synced_height` to `floor - 1` with the daemon parent hash at
//! that height before the scan snapshot is taken.

use shekyl_engine_state::{BlockchainTip, LedgerBlock};

use super::error::{IoError, RefreshError};
use super::local_ledger::LocalLedger;
use super::local_refresh::LocalRefresh;
use super::traits::ledger::LedgerEngine;
use super::traits::DaemonEngine;

/// Types that carry the wallet open-time scan floor into refresh.
pub(crate) trait ScanStartFloorProvider {
    /// Minimum height for the producer scan loop (`0` = none).
    fn scan_start_floor(&self) -> u64;
}

impl ScanStartFloorProvider for LocalRefresh {
    fn scan_start_floor(&self) -> u64 {
        LocalRefresh::scan_start_floor(self)
    }
}

/// Resolve the effective scan floor from persisted and session hints.
///
/// Each argument is already resolved against network defaults where
/// applicable (`WalletFile::effective_skip_to_height`, etc.). Zero
/// means "no contribution" for override fields; `persisted_restore` is
/// always taken from `SyncStateBlock.restore_from_height` (may be 0).
///
/// The floor is the maximum of all non-zero contributions. When every
/// input is zero the floor is zero and refresh behaves as today (scan
/// from `synced_height + 1` only).
pub(crate) fn effective_scan_floor(
    persisted_restore: u64,
    skip_to_height: u64,
    refresh_from_block_height: u64,
) -> u64 {
    let mut floor = persisted_restore;
    if skip_to_height > 0 {
        floor = floor.max(skip_to_height);
    }
    if refresh_from_block_height > 0 {
        floor = floor.max(refresh_from_block_height);
    }
    floor
}

/// Whether the ledger must be anchored before scanning so the merge gate
/// sees `synced_height + 1 == scan_start_floor`.
pub(crate) const fn needs_birthday_anchor(synced_height: u64, scan_start_floor: u64) -> bool {
    scan_start_floor > 0 && scan_start_floor > synced_height.saturating_add(1)
}

/// Block height to anchor at, given the floor and the daemon's current
/// height (block count; a genesis-only chain has height 1).
///
/// The natural anchor sits at `floor - 1`, but the daemon may not have
/// that block yet — a restored wallet whose birthday is above a
/// still-syncing or behind daemon's current height. Anchoring to a
/// nonexistent block would fail refresh with daemon I/O even though there
/// is simply nothing at or above the floor to scan yet. The anchor is
/// clamped to the daemon's highest block (`daemon_height - 1`); a later
/// refresh advances it once the daemon reaches the floor.
///
/// Returns `None` when the daemon has no blocks (`daemon_height == 0`), in
/// which case there is nothing to anchor against and refresh is a clean
/// no-op. Callers must only invoke this when [`needs_birthday_anchor`]
/// holds, so `scan_start_floor >= 2` and `scan_start_floor - 1 >= 1`.
pub(crate) fn anchor_target(scan_start_floor: u64, daemon_height: u64) -> Option<u64> {
    if daemon_height == 0 {
        return None;
    }
    let highest_block = daemon_height - 1;
    Some((scan_start_floor - 1).min(highest_block))
}

/// Advance an empty ledger's tip to `anchor_synced` with `tip_hash`.
///
/// Used when jumping over a genesis→birthday prefix without ingesting
/// intermediate blocks. Requires an empty transfer set; callers must
/// not anchor across existing scanner state.
pub(crate) fn anchor_ledger_block(
    ledger: &mut LedgerBlock,
    anchor_synced: u64,
    tip_hash: [u8; 32],
) -> Result<(), RefreshError> {
    // The ledger already being past the anchor height is a satisfied
    // anchor with nothing to do. This must be checked *before* the
    // empty-transfer precondition: a concurrent refresh may have advanced
    // the ledger past `anchor_synced` and inserted transfers between this
    // preflight's unlocked `synced_height` read and the write guard. That
    // is a benign stale-preflight race, not an invariant violation, so it
    // must short-circuit to a no-op rather than reject the non-empty
    // transfer set.
    let current = ledger.height();
    if current > anchor_synced {
        return Ok(());
    }

    if !ledger.transfers.is_empty() {
        return Err(RefreshError::InternalInvariantViolation {
            context: "birthday anchor requires an empty transfer set",
        });
    }

    if current == anchor_synced {
        // Fast path: the anchor already matches the daemon.
        if ledger.tip.tip_hash == Some(tip_hash)
            && ledger.block_hash_at(anchor_synced) == Some(&tip_hash)
        {
            return Ok(());
        }
        // The transfer set is verified empty above, so the anchor carries
        // no scanned outputs. A stored hash that disagrees with the daemon
        // (a reorg at `anchor_synced` since an earlier anchor) is therefore
        // safe to overwrite with the freshly fetched hash. Treating it as
        // an unrecoverable `ConcurrentMutation` instead would wedge every
        // subsequent refresh at the merge gate, because the producer has no
        // block below the anchor to rewind the stale hash against.
        ledger.tip.tip_hash = Some(tip_hash);
        if let Some(entry) = ledger
            .reorg_blocks
            .blocks
            .iter_mut()
            .find(|(h, _)| *h == anchor_synced)
        {
            entry.1 = tip_hash;
        } else {
            ledger.reorg_blocks.blocks.push((anchor_synced, tip_hash));
        }
        return Ok(());
    }

    ledger.tip = BlockchainTip::new(anchor_synced, tip_hash);
    ledger.reorg_blocks.blocks = vec![(anchor_synced, tip_hash)];
    Ok(())
}

/// Fetch the canonical block hash at `height` from the daemon.
pub(crate) async fn fetch_block_hash_at<D: DaemonEngine>(
    daemon: &D,
    height: u64,
) -> Result<[u8; 32], RefreshError> {
    let number = usize::try_from(height).map_err(|_| RefreshError::MalformedScanResult {
        reason: "block height exceeds usize",
    })?;
    let block = daemon
        .get_scannable_block_by_number(number)
        .await
        .map_err(|e| {
            RefreshError::Io(IoError::Daemon {
                detail: e.to_string(),
            })
        })?;
    Ok(block.block.hash())
}

/// If the wallet's scan floor is above `synced_height + 1`, anchor the
/// ledger at `floor - 1` using the daemon's block hash.
pub(crate) async fn ensure_birthday_anchor<D: DaemonEngine>(
    ledger: &LocalLedger,
    daemon: &D,
    scan_start_floor: u64,
) -> Result<(), RefreshError> {
    let synced = ledger.synced_height();
    if !needs_birthday_anchor(synced, scan_start_floor) {
        return Ok(());
    }

    // Gate the anchor on the daemon's current height so a floor above the
    // chain end does not request a nonexistent `floor - 1` block.
    let daemon_height = daemon.get_height().await.map_err(|e| {
        RefreshError::Io(IoError::Daemon {
            detail: e.to_string(),
        })
    })? as u64;
    let Some(anchor_synced) = anchor_target(scan_start_floor, daemon_height) else {
        return Ok(());
    };
    if synced >= anchor_synced {
        return Ok(());
    }

    let tip_hash = fetch_block_hash_at(daemon, anchor_synced).await?;

    let mut guard = ledger.write();
    anchor_ledger_block(&mut guard.ledger.ledger, anchor_synced, tip_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_scan_floor_maxes_non_zero_hints() {
        assert_eq!(effective_scan_floor(1000, 0, 0), 1000);
        assert_eq!(effective_scan_floor(1000, 1200, 0), 1200);
        assert_eq!(effective_scan_floor(1000, 0, 900), 1000);
        assert_eq!(effective_scan_floor(1000, 500, 1200), 1200);
        assert_eq!(effective_scan_floor(1000, 1500, 900), 1500);
        assert_eq!(effective_scan_floor(0, 500, 0), 500);
        assert_eq!(effective_scan_floor(0, 0, 0), 0);
    }

    #[test]
    fn anchor_target_clamps_to_daemon_highest_block() {
        // Floor below the daemon tip: anchor at floor - 1.
        assert_eq!(anchor_target(1000, 1010), Some(999));
        // Floor at the daemon tip exactly: floor - 1 is the highest block.
        assert_eq!(anchor_target(500, 500), Some(499));
        // Floor above the daemon tip: clamp to the highest available block.
        assert_eq!(anchor_target(1000, 500), Some(499));
        // Empty chain: nothing to anchor against.
        assert_eq!(anchor_target(1000, 0), None);
    }

    #[test]
    fn needs_anchor_only_when_floor_above_incremental() {
        assert!(!needs_birthday_anchor(0, 0));
        assert!(!needs_birthday_anchor(0, 1));
        assert!(!needs_birthday_anchor(999, 1000));
        assert!(needs_birthday_anchor(0, 1000));
    }

    #[test]
    fn anchor_ledger_block_sets_tip_and_reorg_window() {
        let mut ledger = LedgerBlock::empty();
        anchor_ledger_block(&mut ledger, 999, [0xAB; 32]).expect("anchor");
        assert_eq!(ledger.height(), 999);
        assert_eq!(ledger.tip.tip_hash, Some([0xAB; 32]));
        assert_eq!(ledger.block_hash_at(999), Some(&[0xAB; 32]));
    }

    #[test]
    fn anchor_ledger_block_overwrites_stale_hash_at_anchor_height() {
        // An empty anchor at `999` reorgs to a new hash at the same height.
        // The transfer set is empty, so re-anchoring must overwrite the
        // stale hash rather than fail with `ConcurrentMutation`.
        let mut ledger = LedgerBlock::empty();
        anchor_ledger_block(&mut ledger, 999, [0xAB; 32]).expect("first anchor");
        anchor_ledger_block(&mut ledger, 999, [0xCD; 32]).expect("re-anchor overwrites");
        assert_eq!(ledger.height(), 999);
        assert_eq!(ledger.tip.tip_hash, Some([0xCD; 32]));
        assert_eq!(ledger.block_hash_at(999), Some(&[0xCD; 32]));
        // No duplicate reorg-window entry for the anchor height.
        assert_eq!(
            ledger
                .reorg_blocks
                .blocks
                .iter()
                .filter(|(h, _)| *h == 999)
                .count(),
            1
        );
    }
}
