// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet-side merge of [`crate::scan::ScanResult`] into the
//! persisted ledger plus the runtime indexes.
//!
//! [`Wallet::apply_scan_result`] is the only audited code path that
//! mutates `WalletLedger`'s scanner-derived slice and the runtime
//! `LedgerIndexes` during refresh. It runs under the wallet's
//! `&mut self` borrow (which is the type-layer single-flight
//! enforcement; the JSON-RPC binary additionally wraps `Wallet<S>`
//! in `Arc<RwLock<…>>` for cross-thread access).
//!
//! # Three-stage merge
//!
//! 1. **Snapshot invariants.** Reject with
//!    [`RefreshError::ConcurrentMutation`] if the scan result was
//!    produced against a wallet snapshot that no longer matches the
//!    current `Wallet<S>` state. Two checks fire:
//!
//!    - `processed_height_range.start == self.synced_height() + 1`
//!    - `parent_hash == self.ledger.ledger.block_hash_at(start - 1)`
//!      (or `None` matching `start == 1` for genesis)
//!
//!    The two checks together cover both racing-mutation and
//!    silent-reorg gaps; see
//!    `docs/V3_WALLET_DECISION_LOG.md`
//!    (`Wallet::apply_scan_result invariants`, 2026-04-26) for the
//!    full rationale.
//!
//! 2. **Producer-contract invariants.** Reject with
//!    [`RefreshError::MalformedScanResult`] if the result's internal
//!    shape disagrees with itself: `block_hashes` carries an
//!    out-of-range height, a duplicate height, or a height count that
//!    does not match the range length; or `new_transfers` /
//!    `spent_key_images` carry a height outside
//!    `processed_height_range`. These are scanner-bug signals, not
//!    races; the [`super::Wallet::refresh`] retry loop does not retry
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
//!    c. Apply staker-pool aggregate events (`StakeEvent::Accrual`).
//!
//! # Internal helper for tests
//!
//! [`apply_scan_result_to_state`] is the same merge body, exposed
//! `pub(crate)` so tests can drive it against a free
//! `(LedgerBlock, LedgerIndexes)` pair without standing up a full
//! `Wallet<S>` (whose lifecycle methods land in a later commit).
//! `Wallet::apply_scan_result` is a one-line wrapper that calls it
//! against `&mut self.ledger.ledger` and `&mut self.indexes`.

use std::collections::BTreeMap;

use shekyl_scanner::{LedgerIndexesExt, RecoveredWalletOutput, Timelocked};
use shekyl_wallet_state::{LedgerBlock, LedgerIndexes};

use crate::{
    scan::{ScanResult, StakeEvent},
    wallet::{RefreshError, Wallet, WalletSignerKind},
};

impl<S: WalletSignerKind> Wallet<S> {
    /// Current scanned-chain height: the highest block height the
    /// wallet's persisted ledger has fully ingested. `0` for a
    /// freshly-created wallet that has never refreshed.
    pub fn synced_height(&self) -> u64 {
        self.ledger.ledger.height()
    }

    /// Apply a scanner-produced [`ScanResult`] to the wallet's
    /// persisted ledger and runtime indexes.
    ///
    /// This is the single audited mutation point for the
    /// scanner-derived slice of [`WalletLedger`](shekyl_wallet_state::WalletLedger)
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
    /// will produce the same contract violation. [`super::Wallet::refresh`]'s
    /// retry loop honours this distinction.
    ///
    /// # Atomicity
    ///
    /// The merge is all-or-nothing only against the invariant
    /// gates: if both gates pass, the merge proceeds and applies
    /// every event. Per-event errors do not currently exist —
    /// every `LedgerIndexes` mutator the merge calls is infallible
    /// once both invariants have been verified.
    pub fn apply_scan_result(&mut self, result: ScanResult) -> Result<(), RefreshError> {
        apply_scan_result_to_state(&mut self.ledger.ledger, &mut self.indexes, result)
    }
}

/// Merge body shared between [`Wallet::apply_scan_result`] and the
/// in-crate tests that operate on a free
/// `(LedgerBlock, LedgerIndexes)` pair.
///
/// `pub(crate)`: callers outside `shekyl-wallet-core` go through
/// [`Wallet::apply_scan_result`].
pub(crate) fn apply_scan_result_to_state(
    ledger: &mut LedgerBlock,
    indexes: &mut LedgerIndexes,
    result: ScanResult,
) -> Result<(), RefreshError> {
    let synced = ledger.height();

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
        stake_events,
        reorg_rewind,
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
        apply_stake_events(indexes, stake_events);
        return Ok(());
    }

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
    let range_len_u64 = processed_height_range
        .end
        .checked_sub(processed_height_range.start)
        .expect("start <= end checked above");
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

    let mut key_images_by_height: BTreeMap<u64, Vec<[u8; 32]>> = BTreeMap::new();
    for ki in spent_key_images {
        if !processed_height_range.contains(&ki.block_height) {
            return Err(RefreshError::MalformedScanResult {
                reason: "spent_key_images entry outside processed_height_range",
            });
        }
        key_images_by_height
            .entry(ki.block_height)
            .or_default()
            .push(ki.key_image);
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
        let _added = indexes.process_scanned_outputs(ledger, h, block_hash, timelocked);

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

    apply_stake_events(indexes, stake_events);

    Ok(())
}

fn apply_stake_events(indexes: &mut LedgerIndexes, events: Vec<StakeEvent>) {
    for event in events {
        match event {
            StakeEvent::Accrual { height, record } => {
                indexes.insert_accrual(height, record);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};
    use shekyl_oxide::primitives::Commitment;
    use shekyl_scanner::{
        staker_pool::AccrualRecord, LedgerBlock, LedgerIndexes, RecoveredWalletOutput, WalletOutput,
    };

    use crate::scan::{DetectedTransfer, KeyImageObserved, ReorgRewind, ScanResult, StakeEvent};
    use crate::wallet::RefreshError;

    use super::apply_scan_result_to_state;

    fn make_recovered_output(seed: u8, global_index: u64) -> RecoveredWalletOutput {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&global_index.to_le_bytes());
        bytes[8] = seed;
        let scalar = Scalar::from_bytes_mod_order(bytes);
        let key = &scalar * ED25519_BASEPOINT_TABLE;
        let base = WalletOutput::new_for_test(
            [seed; 32],
            0,
            global_index,
            key,
            Scalar::ZERO,
            Commitment {
                mask: Scalar::ONE,
                amount: 1_000,
            },
            None,
        );
        RecoveredWalletOutput::new_for_test(base, 1_000)
    }

    fn empty_state() -> (LedgerBlock, LedgerIndexes) {
        (LedgerBlock::empty(), LedgerIndexes::empty())
    }

    #[test]
    fn apply_empty_at_start_one_succeeds() {
        let (mut ledger, mut indexes) = empty_state();
        let result = ScanResult::empty_at(1, None);
        apply_scan_result_to_state(&mut ledger, &mut indexes, result).expect("empty result merges");
        assert_eq!(ledger.height(), 0);
    }

    #[test]
    fn apply_rejects_wrong_start_height() {
        let (mut ledger, mut indexes) = empty_state();
        let result = ScanResult::empty_at(5, None);
        let err = apply_scan_result_to_state(&mut ledger, &mut indexes, result).unwrap_err();
        match err {
            RefreshError::ConcurrentMutation { wallet, result } => {
                assert_eq!(wallet, 0);
                assert_eq!(result, 5);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn apply_rejects_some_parent_hash_at_genesis() {
        let (mut ledger, mut indexes) = empty_state();
        let result = ScanResult::empty_at(1, Some([0xAA; 32]));
        let err = apply_scan_result_to_state(&mut ledger, &mut indexes, result).unwrap_err();
        assert!(matches!(err, RefreshError::ConcurrentMutation { .. }));
    }

    #[test]
    fn apply_advances_synced_height_for_blocks_without_events() {
        let (mut ledger, mut indexes) = empty_state();
        let result = ScanResult {
            processed_height_range: 1..4,
            parent_hash: None,
            block_hashes: vec![(1, [0x11; 32]), (2, [0x22; 32]), (3, [0x33; 32])],
            new_transfers: Vec::new(),
            spent_key_images: Vec::new(),
            stake_events: Vec::new(),
            reorg_rewind: None,
        };
        apply_scan_result_to_state(&mut ledger, &mut indexes, result).expect("merge ok");
        assert_eq!(ledger.height(), 3);
        assert_eq!(ledger.block_hash_at(1), Some(&[0x11; 32]));
        assert_eq!(ledger.block_hash_at(2), Some(&[0x22; 32]));
        assert_eq!(ledger.block_hash_at(3), Some(&[0x33; 32]));
    }

    #[test]
    fn apply_detects_parent_hash_mismatch() {
        let (mut ledger, mut indexes) = empty_state();
        let first = ScanResult {
            processed_height_range: 1..2,
            parent_hash: None,
            block_hashes: vec![(1, [0x11; 32])],
            new_transfers: Vec::new(),
            spent_key_images: Vec::new(),
            stake_events: Vec::new(),
            reorg_rewind: None,
        };
        apply_scan_result_to_state(&mut ledger, &mut indexes, first).expect("first merge ok");

        // Second batch claims a different parent hash for height 1 — must be rejected.
        let second = ScanResult {
            processed_height_range: 2..3,
            parent_hash: Some([0xFF; 32]),
            block_hashes: vec![(2, [0x22; 32])],
            new_transfers: Vec::new(),
            spent_key_images: Vec::new(),
            stake_events: Vec::new(),
            reorg_rewind: None,
        };
        let err = apply_scan_result_to_state(&mut ledger, &mut indexes, second).unwrap_err();
        assert!(matches!(err, RefreshError::ConcurrentMutation { .. }));
        assert_eq!(ledger.height(), 1, "ledger unchanged on rejection");
    }

    #[test]
    fn apply_accepts_matching_parent_hash() {
        let (mut ledger, mut indexes) = empty_state();
        let first = ScanResult {
            processed_height_range: 1..2,
            parent_hash: None,
            block_hashes: vec![(1, [0x11; 32])],
            new_transfers: Vec::new(),
            spent_key_images: Vec::new(),
            stake_events: Vec::new(),
            reorg_rewind: None,
        };
        apply_scan_result_to_state(&mut ledger, &mut indexes, first).expect("first merge ok");

        let second = ScanResult {
            processed_height_range: 2..3,
            parent_hash: Some([0x11; 32]),
            block_hashes: vec![(2, [0x22; 32])],
            new_transfers: Vec::new(),
            spent_key_images: Vec::new(),
            stake_events: Vec::new(),
            reorg_rewind: None,
        };
        apply_scan_result_to_state(&mut ledger, &mut indexes, second).expect("second merge ok");
        assert_eq!(ledger.height(), 2);
    }

    #[test]
    fn apply_ingests_detected_transfer_and_marks_spent() {
        let (mut ledger, mut indexes) = empty_state();
        let output = make_recovered_output(1, 100);
        let result = ScanResult {
            processed_height_range: 1..3,
            parent_hash: None,
            block_hashes: vec![(1, [0x11; 32]), (2, [0x22; 32])],
            new_transfers: vec![DetectedTransfer {
                block_height: 1,
                output,
            }],
            spent_key_images: Vec::new(),
            stake_events: Vec::new(),
            reorg_rewind: None,
        };
        apply_scan_result_to_state(&mut ledger, &mut indexes, result).expect("merge ok");
        assert_eq!(ledger.transfers().len(), 1);
        assert_eq!(ledger.transfers()[0].block_height, 1);

        // The test fixture's `RecoveredWalletOutput` carries a zeroed
        // key image (see `RecoveredWalletOutput::new_for_test`), so
        // the merge leaves `td.key_image == None`. A view-only wallet
        // would land its key image via the offline-derivation path;
        // here we use `LedgerIndexes::set_key_image` to put a known
        // value in place so we can drive `detect_spends` through the
        // `ScanResult` surface.
        let key_image = [0xCC; 32];
        indexes.set_key_image(&mut ledger, 0, key_image);

        let result = ScanResult {
            processed_height_range: 3..4,
            parent_hash: Some([0x22; 32]),
            block_hashes: vec![(3, [0x33; 32])],
            new_transfers: Vec::new(),
            spent_key_images: vec![KeyImageObserved {
                block_height: 3,
                key_image,
            }],
            stake_events: Vec::new(),
            reorg_rewind: None,
        };
        apply_scan_result_to_state(&mut ledger, &mut indexes, result).expect("spend merge ok");
        assert!(ledger.transfers()[0].spent);
        assert_eq!(ledger.transfers()[0].spent_height, Some(3));
    }

    #[test]
    fn apply_handles_reorg_rewind_before_per_height_events() {
        let (mut ledger, mut indexes) = empty_state();
        // Build wallet up to height 5 with one output at height 3.
        let output = make_recovered_output(2, 200);
        let first = ScanResult {
            processed_height_range: 1..6,
            parent_hash: None,
            block_hashes: (1u64..6)
                .map(|h| (h, [u8::try_from(h).unwrap(); 32]))
                .collect(),
            new_transfers: vec![DetectedTransfer {
                block_height: 3,
                output,
            }],
            spent_key_images: Vec::new(),
            stake_events: Vec::new(),
            reorg_rewind: None,
        };
        apply_scan_result_to_state(&mut ledger, &mut indexes, first).expect("first ok");
        assert_eq!(ledger.height(), 5);
        assert_eq!(ledger.transfers().len(), 1);

        // Reorg rewinds to fork_height = 3 (drops the height-3 output and
        // heights ≥ 3), then re-ingests heights 3..6 with new hashes.
        let new_output = make_recovered_output(3, 201);
        let second = ScanResult {
            processed_height_range: 3..6,
            parent_hash: Some([2u8; 32]),
            block_hashes: vec![(3, [0xA3; 32]), (4, [0xA4; 32]), (5, [0xA5; 32])],
            new_transfers: vec![DetectedTransfer {
                block_height: 4,
                output: new_output,
            }],
            spent_key_images: Vec::new(),
            stake_events: Vec::new(),
            reorg_rewind: Some(ReorgRewind { fork_height: 3 }),
        };
        apply_scan_result_to_state(&mut ledger, &mut indexes, second).expect("reorg ok");
        assert_eq!(ledger.height(), 5);
        assert_eq!(ledger.transfers().len(), 1);
        assert_eq!(ledger.transfers()[0].block_height, 4);
        assert_eq!(ledger.block_hash_at(3), Some(&[0xA3; 32]));
        assert_eq!(ledger.block_hash_at(4), Some(&[0xA4; 32]));
    }

    #[test]
    fn apply_records_stake_accrual_events() {
        let (mut ledger, mut indexes) = empty_state();
        let result = ScanResult {
            processed_height_range: 1..2,
            parent_hash: None,
            block_hashes: vec![(1, [0x11; 32])],
            new_transfers: Vec::new(),
            spent_key_images: Vec::new(),
            stake_events: vec![StakeEvent::Accrual {
                height: 1,
                record: AccrualRecord {
                    staker_emission: 100,
                    staker_fee_pool: 0,
                    total_weighted_stake: 1_000,
                },
            }],
            reorg_rewind: None,
        };
        apply_scan_result_to_state(&mut ledger, &mut indexes, result).expect("merge ok");
        assert_eq!(ledger.height(), 1);
        // Sanity: the accrual was inserted; the staker pool exposes
        // `estimate_reward_with_splitting` which reads from the same
        // map, so we only assert the merge didn't panic and advanced
        // synced_height; deeper accrual semantics are covered by
        // staker_pool's own test suite.
        let _pool = indexes.staker_pool();
    }

    #[test]
    fn apply_rejects_short_block_hashes_as_malformed() {
        // Range [1..3) demands two entries; only one supplied.
        let (mut ledger, mut indexes) = empty_state();
        let result = ScanResult {
            processed_height_range: 1..3,
            parent_hash: None,
            block_hashes: vec![(1, [0x11; 32])],
            new_transfers: Vec::new(),
            spent_key_images: Vec::new(),
            stake_events: Vec::new(),
            reorg_rewind: None,
        };
        let err = apply_scan_result_to_state(&mut ledger, &mut indexes, result).unwrap_err();
        assert!(matches!(err, RefreshError::MalformedScanResult { .. }));
    }

    #[test]
    fn apply_rejects_duplicate_block_hash_height() {
        // Two entries at the same height; second `BTreeMap::insert`
        // would silently overwrite without the duplicate check.
        let (mut ledger, mut indexes) = empty_state();
        let result = ScanResult {
            processed_height_range: 1..3,
            parent_hash: None,
            block_hashes: vec![(1, [0x11; 32]), (1, [0x99; 32])],
            new_transfers: Vec::new(),
            spent_key_images: Vec::new(),
            stake_events: Vec::new(),
            reorg_rewind: None,
        };
        let err = apply_scan_result_to_state(&mut ledger, &mut indexes, result).unwrap_err();
        match err {
            RefreshError::MalformedScanResult { reason } => {
                assert!(
                    reason.contains("duplicate"),
                    "expected duplicate-height reason, got {reason}",
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn apply_rejects_out_of_range_block_hash() {
        // Range [1..3) but a block_hashes entry is at height 5.
        let (mut ledger, mut indexes) = empty_state();
        let result = ScanResult {
            processed_height_range: 1..3,
            parent_hash: None,
            block_hashes: vec![(1, [0x11; 32]), (5, [0x55; 32])],
            new_transfers: Vec::new(),
            spent_key_images: Vec::new(),
            stake_events: Vec::new(),
            reorg_rewind: None,
        };
        let err = apply_scan_result_to_state(&mut ledger, &mut indexes, result).unwrap_err();
        assert!(matches!(err, RefreshError::MalformedScanResult { .. }));
    }

    #[test]
    fn apply_rejects_out_of_range_transfer() {
        // Range [1..3) but a transfer claims height 7.
        let (mut ledger, mut indexes) = empty_state();
        let output = make_recovered_output(4, 400);
        let result = ScanResult {
            processed_height_range: 1..3,
            parent_hash: None,
            block_hashes: vec![(1, [0x11; 32]), (2, [0x22; 32])],
            new_transfers: vec![DetectedTransfer {
                block_height: 7,
                output,
            }],
            spent_key_images: Vec::new(),
            stake_events: Vec::new(),
            reorg_rewind: None,
        };
        let err = apply_scan_result_to_state(&mut ledger, &mut indexes, result).unwrap_err();
        assert!(matches!(err, RefreshError::MalformedScanResult { .. }));
    }

    #[test]
    fn apply_rejects_out_of_range_key_image() {
        // Range [1..3) but a key image claims height 9.
        let (mut ledger, mut indexes) = empty_state();
        let result = ScanResult {
            processed_height_range: 1..3,
            parent_hash: None,
            block_hashes: vec![(1, [0x11; 32]), (2, [0x22; 32])],
            new_transfers: Vec::new(),
            spent_key_images: vec![KeyImageObserved {
                block_height: 9,
                key_image: [0xCC; 32],
            }],
            stake_events: Vec::new(),
            reorg_rewind: None,
        };
        let err = apply_scan_result_to_state(&mut ledger, &mut indexes, result).unwrap_err();
        assert!(matches!(err, RefreshError::MalformedScanResult { .. }));
    }

    #[test]
    fn apply_rejects_events_against_empty_range() {
        // start == end but events are present — producer contract
        // says an empty range carries no events.
        let (mut ledger, mut indexes) = empty_state();
        let result = ScanResult {
            processed_height_range: 1..1,
            parent_hash: None,
            block_hashes: vec![(1, [0x11; 32])],
            new_transfers: Vec::new(),
            spent_key_images: Vec::new(),
            stake_events: Vec::new(),
            reorg_rewind: None,
        };
        let err = apply_scan_result_to_state(&mut ledger, &mut indexes, result).unwrap_err();
        assert!(matches!(err, RefreshError::MalformedScanResult { .. }));
    }
}
