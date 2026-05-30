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

/// Ledger implementors that support pre-scan birthday anchoring.
pub(crate) trait BirthdayAnchorHost {
    /// Advance an empty ledger to `floor - 1` when required. No-op
    /// when `floor` does not exceed `synced_height + 1`.
    fn ensure_birthday_anchor<D: DaemonEngine>(
        &self,
        daemon: &D,
        scan_start_floor: u64,
    ) -> impl std::future::Future<Output = Result<(), RefreshError>> + Send;
}

impl BirthdayAnchorHost for LocalLedger {
    async fn ensure_birthday_anchor<D: DaemonEngine>(
        &self,
        daemon: &D,
        scan_start_floor: u64,
    ) -> Result<(), RefreshError> {
        ensure_birthday_anchor(self, daemon, scan_start_floor).await
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

/// First block height the producer should scan given the wallet tip and
/// floor. When `scan_start_floor` is zero, returns `synced_height + 1`.
pub(crate) fn scan_range_start(synced_height: u64, scan_start_floor: u64) -> u64 {
    let incremental = synced_height.saturating_add(1);
    if scan_start_floor > 0 && incremental < scan_start_floor {
        scan_start_floor
    } else {
        incremental
    }
}

/// Whether the ledger must be anchored before scanning so the merge gate
/// sees `synced_height + 1 == scan_start_floor`.
pub(crate) const fn needs_birthday_anchor(synced_height: u64, scan_start_floor: u64) -> bool {
    scan_start_floor > 0 && scan_start_floor > synced_height.saturating_add(1)
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
    if !ledger.transfers.is_empty() {
        return Err(RefreshError::InternalInvariantViolation {
            context: "birthday anchor requires an empty transfer set",
        });
    }

    let current = ledger.height();
    if current > anchor_synced {
        return Ok(());
    }

    if current == anchor_synced {
        match ledger.tip.tip_hash {
            Some(stored) if stored == tip_hash => return Ok(()),
            Some(_stored) => {
                return Err(RefreshError::ConcurrentMutation {
                    wallet: current,
                    result: anchor_synced,
                });
            }
            None => {
                ledger.tip.tip_hash = Some(tip_hash);
                if ledger.block_hash_at(anchor_synced).is_none() {
                    ledger.reorg_blocks.blocks.push((anchor_synced, tip_hash));
                }
                return Ok(());
            }
        }
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

    let anchor_synced = scan_start_floor - 1;
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
    fn scan_range_start_respects_floor_and_steady_state() {
        assert_eq!(scan_range_start(0, 1000), 1000);
        assert_eq!(
            scan_range_start(500, 1000),
            1000,
            "below floor starts at floor"
        );
        assert_eq!(
            scan_range_start(999, 1000),
            1000,
            "one below floor starts at floor"
        );
        assert_eq!(
            scan_range_start(1000, 1000),
            1001,
            "at floor stays incremental"
        );
        assert_eq!(
            scan_range_start(1500, 1000),
            1501,
            "past floor stays incremental"
        );
        assert_eq!(scan_range_start(0, 0), 1);
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
}
