// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the scan-result merge (`engine/merge.rs`).
//!
//! Wired as a `#[path]` child of `merge::tests`, so `use super::*`
//! resolves into the workflow module and private items stay testable;
//! the sibling file exists so the decomposition ratchet counts the
//! workflow file, not its test suite (the
//! `transfer/transfer_pending_tx_tests.rs` pattern).

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};
use shekyl_curve_primitives::Commitment;
use shekyl_scanner::{LedgerBlock, LedgerIndexes, RecoveredWalletOutput, WalletOutput};

use crate::engine::RefreshError;
use crate::scan::{DetectedTransfer, KeyImageObserved, ReorgRewind, ScanResult};

use super::{apply_scan_result_to_state, index_block_leaves};

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
    );
    RecoveredWalletOutput::new_for_test(base, 1_000)
}

fn empty_state() -> (LedgerBlock, LedgerIndexes) {
    (LedgerBlock::empty(), LedgerIndexes::empty())
}

#[test]
fn apply_scan_result_accepts_birthday_anchored_start() {
    let (mut ledger, mut indexes) = empty_state();
    let parent = [0x55; 32];
    super::super::scan_floor::anchor_ledger_block(&mut ledger, 999, parent)
        .expect("anchor at birthday boundary");

    let result = ScanResult {
        processed_height_range: 1000..1001,
        parent_hash: Some(parent),
        block_hashes: vec![(1000, [0x66; 32])],
        new_transfers: vec![],
        spent_key_images: vec![],
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
    };
    apply_scan_result_to_state(&mut ledger, &mut indexes, result).expect("birthday merge");
    assert_eq!(ledger.height(), 1000);
}

#[test]
fn apply_empty_at_start_one_succeeds() {
    let (mut ledger, mut indexes) = empty_state();
    let result = ScanResult::empty_at(1, None);
    apply_scan_result_to_state(&mut ledger, &mut indexes, result).expect("empty result merges");
    assert_eq!(ledger.height(), 0);
}

/// A `ScanResult` reaching the LedgerBlock-scoped body with sightings
/// still attached is a caller that bypassed the engine seam (validate +
/// take + adopt) — refused loudly, tip untouched. This bites against a
/// future direct caller silently discarding chain evidence; it does NOT
/// cover the seam's own validate/adopt behavior (engine-level tests).
#[test]
fn apply_refuses_a_result_with_attached_bond_sightings() {
    let (mut ledger, mut indexes) = empty_state();
    let mut result = ScanResult::empty_at(1, None);
    result.processed_height_range = 1..2;
    result.block_hashes = vec![(1, [0x11; 32])];
    result
        .bond_sightings
        .push(crate::scan::BondSightingObserved {
            block_height: 1,
            slot: 0,
        });
    let err = apply_scan_result_to_state(&mut ledger, &mut indexes, result).unwrap_err();
    assert!(
        matches!(err, RefreshError::MalformedScanResult { .. }),
        "got {err:?}"
    );
    assert_eq!(ledger.height(), 0, "refusal must not advance the tip");
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
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
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
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
    };
    apply_scan_result_to_state(&mut ledger, &mut indexes, first).expect("first merge ok");

    // Second batch claims a different parent hash for height 1 — must be rejected.
    let second = ScanResult {
        processed_height_range: 2..3,
        parent_hash: Some([0xFF; 32]),
        block_hashes: vec![(2, [0x22; 32])],
        new_transfers: Vec::new(),
        spent_key_images: Vec::new(),
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
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
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
    };
    apply_scan_result_to_state(&mut ledger, &mut indexes, first).expect("first merge ok");

    let second = ScanResult {
        processed_height_range: 2..3,
        parent_hash: Some([0x11; 32]),
        block_hashes: vec![(2, [0x22; 32])],
        new_transfers: Vec::new(),
        spent_key_images: Vec::new(),
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
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
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
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
    let key_image = shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes([0xCC; 32]);
    indexes.set_key_image(&mut ledger, 0, key_image);

    let result = ScanResult {
        processed_height_range: 3..4,
        parent_hash: Some([0x22; 32]),
        block_hashes: vec![(3, [0x33; 32])],
        new_transfers: Vec::new(),
        spent_key_images: vec![KeyImageObserved {
            block_height: 3,
            key_image,
            containing_tx_hash: shekyl_types::TxHash::from_bytes([0xDD; 32]),
        }],
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
    };
    apply_scan_result_to_state(&mut ledger, &mut indexes, result).expect("spend merge ok");
    assert!(ledger.transfers()[0].spent);
    assert_eq!(ledger.transfers()[0].spent_height, Some(3));
}

/// Cross-batch invariant pin (PERF_MERGE_INSERTION_INDICES_PREFLIGHT
/// §5.2): a multi-height `ScanResult` with k₁ + k₂ new transfers
/// produces an inserted-indices Vec of length k₁ + k₂ whose
/// entries are monotonically increasing and disjoint from any
/// prior-merge indices. The post-pass at
/// `populate_engine_handle_fields` consumes this Vec to walk only
/// the freshly-merged transfers in O(k) rather than scanning the
/// full ledger in O(n).
#[test]
fn apply_scan_result_to_state_returns_indices_of_new_transfers() {
    let (mut ledger, mut indexes) = empty_state();

    // First merge: 3 new transfers across two heights (2 at h=1,
    // 1 at h=2). Returned Vec must be the 3 freshly appended
    // indices, monotonically increasing.
    let first = ScanResult {
        processed_height_range: 1..3,
        parent_hash: None,
        block_hashes: vec![(1, [0x11; 32]), (2, [0x22; 32])],
        new_transfers: vec![
            DetectedTransfer {
                block_height: 1,
                output: make_recovered_output(1, 100),
            },
            DetectedTransfer {
                block_height: 1,
                output: make_recovered_output(2, 101),
            },
            DetectedTransfer {
                block_height: 2,
                output: make_recovered_output(3, 102),
            },
        ],
        spent_key_images: Vec::new(),
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
    };
    let inserted =
        apply_scan_result_to_state(&mut ledger, &mut indexes, first).expect("first merge ok");
    assert_eq!(inserted, vec![0, 1, 2]);
    assert_eq!(ledger.transfers().len(), 3);

    // Second merge: 1 transfer at h=3 over a tip claiming the
    // previous merge's hash. Returned Vec must reflect the
    // post-prior-merge offset (start at 3, not 0).
    let second = ScanResult {
        processed_height_range: 3..4,
        parent_hash: Some([0x22; 32]),
        block_hashes: vec![(3, [0x33; 32])],
        new_transfers: vec![DetectedTransfer {
            block_height: 3,
            output: make_recovered_output(4, 103),
        }],
        spent_key_images: Vec::new(),
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
    };
    let inserted =
        apply_scan_result_to_state(&mut ledger, &mut indexes, second).expect("second merge ok");
    assert_eq!(inserted, vec![3]);
    assert_eq!(ledger.transfers().len(), 4);

    // Third merge: no new transfers, just an empty bookkeeping
    // advance. Returned Vec is empty.
    let third = ScanResult {
        processed_height_range: 4..5,
        parent_hash: Some([0x33; 32]),
        block_hashes: vec![(4, [0x44; 32])],
        new_transfers: Vec::new(),
        spent_key_images: Vec::new(),
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
    };
    let inserted =
        apply_scan_result_to_state(&mut ledger, &mut indexes, third).expect("third merge ok");
    assert!(inserted.is_empty());
    assert_eq!(ledger.transfers().len(), 4);
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
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
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
        reorg_rewind: Some(ReorgRewind { fork_height: 3 }),
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
    };
    apply_scan_result_to_state(&mut ledger, &mut indexes, second).expect("reorg ok");
    assert_eq!(ledger.height(), 5);
    assert_eq!(ledger.transfers().len(), 1);
    assert_eq!(ledger.transfers()[0].block_height, 4);
    assert_eq!(ledger.block_hash_at(3), Some(&[0xA3; 32]));
    assert_eq!(ledger.block_hash_at(4), Some(&[0xA4; 32]));
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
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
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
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
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
fn index_block_leaves_rejects_duplicate_height() {
    // Two entries at the same height: a `collect()` into `BTreeMap` would
    // silently keep the last and feed the curve tree an unintended leaf
    // set; the explicit check surfaces it as `MalformedScanResult` (O5
    // untrusted-`ScanResult` defense, mirroring the `block_hashes` check).
    let dup = vec![(4u64, Vec::new()), (4u64, Vec::new())];
    let err = index_block_leaves(dup).unwrap_err();
    match err {
        RefreshError::MalformedScanResult { reason } => {
            assert!(
                reason.contains("block_leaves") && reason.contains("duplicate"),
                "expected block_leaves duplicate reason, got {reason}",
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn index_block_leaves_accepts_distinct_heights() {
    let ok = vec![(1u64, Vec::new()), (2u64, Vec::new()), (3u64, Vec::new())];
    let map = index_block_leaves(ok).expect("distinct heights index cleanly");
    assert_eq!(map.len(), 3);
}

#[test]
fn apply_rejects_reorg_fork_height_zero_as_malformed() {
    // `fork_height` is the first divergent height; genesis can never be
    // orphaned, so the honest producer never emits 0. A malformed/hostile
    // `ScanResult` with `fork_height == 0` must surface as
    // `MalformedScanResult` rather than silently wiping the ledger via
    // `handle_reorg(.., 0)` (O5 untrusted-`ScanResult` defense).
    let (mut ledger, mut indexes) = empty_state();
    let result = ScanResult {
        processed_height_range: 0..1,
        parent_hash: None,
        block_hashes: vec![(0, [0x00; 32])],
        new_transfers: Vec::new(),
        spent_key_images: Vec::new(),
        reorg_rewind: Some(ReorgRewind { fork_height: 0 }),
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
    };
    let err = apply_scan_result_to_state(&mut ledger, &mut indexes, result).unwrap_err();
    match err {
        RefreshError::MalformedScanResult { reason } => {
            assert!(
                reason.contains("fork_height"),
                "expected fork_height reason, got {reason}",
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
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
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
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
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
            key_image: shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes([0xCC; 32]),
            containing_tx_hash: shekyl_types::TxHash::from_bytes([0xDD; 32]),
        }],
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
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
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
    };
    let err = apply_scan_result_to_state(&mut ledger, &mut indexes, result).unwrap_err();
    assert!(matches!(err, RefreshError::MalformedScanResult { .. }));
}

// ── Engine post-pass (M3b §3 reroute) ──────────────────────────────

use std::collections::HashMap;

use shekyl_crypto_pq::{handle::derive_output_handle, kem::HybridCiphertext};

use super::populate_engine_handle_fields;

fn ciphertext_for_seed(seed: u8) -> HybridCiphertext {
    let mut x25519 = [0u8; 32];
    x25519[0] = seed;
    x25519[31] = 0xC1;
    // The post-pass treats the ciphertext as opaque bytes — it
    // does not re-decap at M3b. Use a non-empty `ml_kem` so the
    // round-trip preserves the structural shape under postcard
    // serialization downstream.
    HybridCiphertext {
        x25519,
        ml_kem: vec![seed; 16],
    }
}

#[test]
fn populate_engine_handle_fields_sets_both_fields_on_match() {
    // Seed the ledger via a real merge, then run the post-pass
    // against a residue map that matches the merged transfer.
    let (mut ledger, mut indexes) = empty_state();
    let output = make_recovered_output(0xAA, 7);
    let tx_hash = output.wallet_output().transaction();
    let internal_idx = output.wallet_output().index_in_transaction();

    let result = ScanResult {
        processed_height_range: 1..2,
        parent_hash: None,
        block_hashes: vec![(1, [0x11; 32])],
        new_transfers: vec![DetectedTransfer {
            block_height: 1,
            output,
        }],
        spent_key_images: Vec::new(),
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
    };
    let inserted = apply_scan_result_to_state(&mut ledger, &mut indexes, result).expect("merge ok");

    // Pre-condition: the merge populated the legacy fields but
    // not the engine-derived ones.
    let td = ledger
        .transfers()
        .iter()
        .find(|t| t.tx_hash.as_bytes() == &tx_hash && t.internal_output_index == internal_idx)
        .expect("merged transfer present");
    assert!(td.source_ciphertext.is_none());
    assert!(td.output_handle.is_none());

    let view_secret = [0x55u8; 32];
    let ct = ciphertext_for_seed(0xAA);
    let mut residue = HashMap::new();
    residue.insert((tx_hash, internal_idx), ct.clone());

    populate_engine_handle_fields(&mut ledger, &view_secret, &residue, &inserted);

    let td = ledger
        .transfers()
        .iter()
        .find(|t| t.tx_hash.as_bytes() == &tx_hash && t.internal_output_index == internal_idx)
        .expect("merged transfer still present");
    let stored_ct = td
        .source_ciphertext
        .as_ref()
        .expect("source_ciphertext set");
    assert_eq!(stored_ct.x25519, ct.x25519);
    assert_eq!(stored_ct.ml_kem, ct.ml_kem);

    let stored_handle = td.output_handle.as_ref().expect("output_handle set");
    let expected_handle = derive_output_handle(&view_secret, &tx_hash, internal_idx);
    assert_eq!(*stored_handle, expected_handle);
}

#[test]
fn populate_engine_handle_fields_skips_unmatched_transfers() {
    // Two merged transfers; the residue map matches only one. The
    // unmatched transfer's engine-derived fields stay `None`.
    let (mut ledger, mut indexes) = empty_state();
    let matched = make_recovered_output(0x01, 1);
    let matched_tx = matched.wallet_output().transaction();
    let matched_idx = matched.wallet_output().index_in_transaction();
    let unmatched = make_recovered_output(0x02, 2);
    let unmatched_tx = unmatched.wallet_output().transaction();
    let unmatched_idx = unmatched.wallet_output().index_in_transaction();

    let result = ScanResult {
        processed_height_range: 1..2,
        parent_hash: None,
        block_hashes: vec![(1, [0x11; 32])],
        new_transfers: vec![
            DetectedTransfer {
                block_height: 1,
                output: matched,
            },
            DetectedTransfer {
                block_height: 1,
                output: unmatched,
            },
        ],
        spent_key_images: Vec::new(),
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
    };
    let inserted = apply_scan_result_to_state(&mut ledger, &mut indexes, result).expect("merge ok");

    let view_secret = [0x77u8; 32];
    let mut residue = HashMap::new();
    residue.insert((matched_tx, matched_idx), ciphertext_for_seed(0x01));
    populate_engine_handle_fields(&mut ledger, &view_secret, &residue, &inserted);

    let m = ledger
        .transfers()
        .iter()
        .find(|t| t.tx_hash.as_bytes() == &matched_tx && t.internal_output_index == matched_idx)
        .expect("matched transfer present");
    assert!(m.source_ciphertext.is_some());
    assert!(m.output_handle.is_some());

    let u = ledger
        .transfers()
        .iter()
        .find(|t| t.tx_hash.as_bytes() == &unmatched_tx && t.internal_output_index == unmatched_idx)
        .expect("unmatched transfer present");
    assert!(u.source_ciphertext.is_none());
    assert!(u.output_handle.is_none());
}

#[test]
fn populate_engine_handle_fields_is_idempotent() {
    // A second invocation against an already-populated transfer
    // does not overwrite the existing fields.
    let (mut ledger, mut indexes) = empty_state();
    let output = make_recovered_output(0x33, 3);
    let tx_hash = output.wallet_output().transaction();
    let internal_idx = output.wallet_output().index_in_transaction();
    let result = ScanResult {
        processed_height_range: 1..2,
        parent_hash: None,
        block_hashes: vec![(1, [0x11; 32])],
        new_transfers: vec![DetectedTransfer {
            block_height: 1,
            output,
        }],
        spent_key_images: Vec::new(),
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
    };
    let inserted = apply_scan_result_to_state(&mut ledger, &mut indexes, result).expect("merge ok");

    let view_secret = [0xAAu8; 32];
    let ct1 = ciphertext_for_seed(0x33);
    let mut residue = HashMap::new();
    residue.insert((tx_hash, internal_idx), ct1.clone());
    populate_engine_handle_fields(&mut ledger, &view_secret, &residue, &inserted);

    // Second call with a different ciphertext for the same key
    // must not overwrite — the helper's idempotency contract is
    // per-field: each `Option` field is set only when `None`.
    // Both fields populated by call 1 ⇒ both skipped by call 2.
    let ct2 = ciphertext_for_seed(0xBB);
    let mut residue2 = HashMap::new();
    residue2.insert((tx_hash, internal_idx), ct2);
    populate_engine_handle_fields(&mut ledger, &view_secret, &residue2, &inserted);

    let td = ledger
        .transfers()
        .iter()
        .find(|t| t.tx_hash.as_bytes() == &tx_hash && t.internal_output_index == internal_idx)
        .expect("merged transfer present");
    let stored_ct = td
        .source_ciphertext
        .as_ref()
        .expect("source_ciphertext set");
    // Stable on the first ciphertext.
    assert_eq!(stored_ct.x25519, ct1.x25519);
}

#[test]
fn populate_engine_handle_fields_respects_partial_population() {
    // Per-field idempotency: each `Option` field is populated only
    // when its current value is `None`. A transfer that already
    // has `source_ciphertext` set but `output_handle` still `None`
    // must have only `output_handle` filled in by the post-pass —
    // and vice versa. This is the tighter contract that the
    // function-level docs describe ("leaves populated fields
    // untouched"); without it, a reader who pre-populated one
    // field would see the other field's write silently clobber
    // their value when the helper happens to also populate the
    // first.
    let (mut ledger, mut indexes) = empty_state();
    let output_a = make_recovered_output(0x55, 5);
    let tx_hash_a = output_a.wallet_output().transaction();
    let internal_idx_a = output_a.wallet_output().index_in_transaction();
    let output_b = make_recovered_output(0x66, 6);
    let tx_hash_b = output_b.wallet_output().transaction();
    let internal_idx_b = output_b.wallet_output().index_in_transaction();
    let result = ScanResult {
        processed_height_range: 1..2,
        parent_hash: None,
        block_hashes: vec![(1, [0x11; 32])],
        new_transfers: vec![
            DetectedTransfer {
                block_height: 1,
                output: output_a,
            },
            DetectedTransfer {
                block_height: 1,
                output: output_b,
            },
        ],
        spent_key_images: Vec::new(),
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
    };
    let inserted = apply_scan_result_to_state(&mut ledger, &mut indexes, result).expect("merge ok");

    // Pre-populate one field on each transfer with a sentinel
    // value that the post-pass must NOT overwrite. Use distinct
    // sentinels per transfer so a misdirected overwrite is
    // visible regardless of iteration order.
    let sentinel_ct = ciphertext_for_seed(0xEE);
    let sentinel_handle = derive_output_handle(&[0xCC; 32], &[0xCC; 32], 0xCC);
    for td in &mut ledger.transfers {
        if td.tx_hash.as_bytes() == &tx_hash_a && td.internal_output_index == internal_idx_a {
            // Transfer A: source_ciphertext pre-populated, output_handle still None.
            td.source_ciphertext = Some(sentinel_ct.clone());
            td.output_handle = None;
        } else if td.tx_hash.as_bytes() == &tx_hash_b && td.internal_output_index == internal_idx_b
        {
            // Transfer B: output_handle pre-populated, source_ciphertext still None.
            td.source_ciphertext = None;
            td.output_handle = Some(sentinel_handle);
        }
    }

    let view_secret = [0xAAu8; 32];
    let real_ct_a = ciphertext_for_seed(0x55);
    let real_ct_b = ciphertext_for_seed(0x66);
    let mut residue = HashMap::new();
    residue.insert((tx_hash_a, internal_idx_a), real_ct_a.clone());
    residue.insert((tx_hash_b, internal_idx_b), real_ct_b.clone());
    populate_engine_handle_fields(&mut ledger, &view_secret, &residue, &inserted);

    let td_a = ledger
        .transfers()
        .iter()
        .find(|t| t.tx_hash.as_bytes() == &tx_hash_a && t.internal_output_index == internal_idx_a)
        .expect("transfer A present");
    // A: source_ciphertext kept (sentinel, not real_ct_a); output_handle filled.
    let stored_ct_a = td_a
        .source_ciphertext
        .as_ref()
        .expect("source_ciphertext stable");
    assert_eq!(
        stored_ct_a.x25519, sentinel_ct.x25519,
        "pre-populated source_ciphertext must not be overwritten"
    );
    let derived_handle_a = derive_output_handle(&view_secret, &tx_hash_a, internal_idx_a);
    assert_eq!(
        td_a.output_handle.expect("output_handle filled"),
        derived_handle_a,
        "output_handle must be derived for the previously-None field"
    );

    let td_b = ledger
        .transfers()
        .iter()
        .find(|t| t.tx_hash.as_bytes() == &tx_hash_b && t.internal_output_index == internal_idx_b)
        .expect("transfer B present");
    // B: output_handle kept (sentinel, not derived); source_ciphertext filled.
    assert_eq!(
        td_b.output_handle.expect("output_handle stable"),
        sentinel_handle,
        "pre-populated output_handle must not be overwritten"
    );
    let stored_ct_b = td_b
        .source_ciphertext
        .as_ref()
        .expect("source_ciphertext filled");
    assert_eq!(
        stored_ct_b.x25519, real_ct_b.x25519,
        "source_ciphertext must be filled for the previously-None field"
    );
}

/// Perf-regression pin (PERF_MERGE_INSERTION_INDICES_PREFLIGHT
/// §5.3): the post-pass walks ONLY the inserted indices, not
/// the full ledger.
///
/// The test pins iteration domain by reading the prior
/// transfers' `(tx_hash, internal_output_index)` keys from
/// the ledger after the first merge, then building a residue
/// map that matches BOTH every prior AND the new transfer.
/// Under an O(n) implementation, the helper would visit
/// every transfer and the residue lookup would succeed for
/// every prior, populating their `source_ciphertext` and
/// `output_handle`. Under the O(k) implementation, the
/// helper visits only `inserted` (which is `[100]`), so the
/// prior transfers stay untouched regardless of whether the
/// residue would have matched them.
///
/// A future change that accidentally restores O(n) iteration
/// would visit the priors and populate their fields against
/// the matching residue entries, breaking this test. This is
/// the load-bearing distinction Copilot's two PR #37 reviews
/// flagged: the original residue (key only the new transfer)
/// admitted O(n) regressions silently; the second iteration
/// (single hard-coded prior key) coupled the test to
/// `make_recovered_output`'s internal shape; this third
/// iteration reads keys from observed ledger state, decoupling
/// the test from helper internals.
#[test]
fn populate_engine_handle_fields_visits_only_inserted_indices() {
    let (mut ledger, mut indexes) = empty_state();

    // Pre-populate: 100 transfers across a single height. Their
    // `output_handle` fields stay `None` after the merge — the
    // residue map will be empty for the first merge so the
    // post-pass is a no-op.
    let prior_outputs: Vec<RecoveredWalletOutput> = (0..100)
        .map(|i| make_recovered_output(0xA0, i + 100))
        .collect();
    let first = ScanResult {
        processed_height_range: 1..2,
        parent_hash: None,
        block_hashes: vec![(1, [0x11; 32])],
        new_transfers: prior_outputs
            .into_iter()
            .map(|output| DetectedTransfer {
                block_height: 1,
                output,
            })
            .collect(),
        spent_key_images: Vec::new(),
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
    };
    let _ = apply_scan_result_to_state(&mut ledger, &mut indexes, first).expect("first merge ok");
    assert_eq!(ledger.transfers().len(), 100);

    // Sentinel: capture the prior transfers' field state. A
    // correct O(k) post-pass must leave these untouched even
    // though the helper iterates them in the O(n) implementation.
    for td in ledger.transfers() {
        assert!(td.source_ciphertext.is_none());
        assert!(td.output_handle.is_none());
    }

    // Second merge: 1 new transfer at height 2. The returned
    // `inserted` Vec is `[100]`; the post-pass must visit only
    // index 100, not 0..100.
    let new_output = make_recovered_output(0xB0, 200);
    let new_tx = new_output.wallet_output().transaction();
    let new_idx = new_output.wallet_output().index_in_transaction();
    let second = ScanResult {
        processed_height_range: 2..3,
        parent_hash: Some([0x11; 32]),
        block_hashes: vec![(2, [0x22; 32])],
        new_transfers: vec![DetectedTransfer {
            block_height: 2,
            output: new_output,
        }],
        spent_key_images: Vec::new(),
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
    };
    let inserted =
        apply_scan_result_to_state(&mut ledger, &mut indexes, second).expect("second merge ok");
    assert_eq!(inserted, vec![100]);
    assert_eq!(ledger.transfers().len(), 101);

    let view_secret = [0xCCu8; 32];
    let mut residue = HashMap::new();
    residue.insert((new_tx, new_idx), ciphertext_for_seed(0xB0));
    // Prior-key residue entries: read the ACTUAL prior
    // transfers' `(tx_hash, internal_output_index)` keys from
    // the ledger after the first merge, rather than relying
    // on `make_recovered_output`'s internal shape (Copilot
    // PR #37 review finding: the test would silently stop
    // validating O(k) if that helper changed its `tx_hash`
    // or `internal_output_index` defaults). Build the
    // residue from observed state: every prior transfer
    // gets a residue entry. Under O(n), every prior matches
    // and gets populated; under O(k), priors are never
    // visited so the residue match is unreachable.
    let prior_keys: Vec<([u8; 32], u64)> = ledger
        .transfers()
        .iter()
        .take(100)
        .map(|td| (td.tx_hash.to_bytes(), td.internal_output_index))
        .collect();
    for (i, key) in prior_keys.iter().enumerate() {
        residue.insert(*key, ciphertext_for_seed(u8::try_from(i & 0xFF).unwrap()));
    }
    populate_engine_handle_fields(&mut ledger, &view_secret, &residue, &inserted);

    // Iteration-domain assertion: every prior transfer's
    // engine-derived fields stay `None` despite the residue
    // map carrying entries for every one of their
    // `(tx_hash, internal_output_index)` keys (built above
    // by reading observed ledger state, decoupling the test
    // from `make_recovered_output`'s internal shape). Under
    // an O(n) implementation, the helper would visit the
    // priors and the residue lookup would succeed for each,
    // populating their fields. Under O(k), the helper never
    // visits indices 0..100, so the residue match is
    // unreachable. This is the load-bearing distinguishing
    // assertion (Copilot PR #37 review): an O(n) regression
    // breaks here directly, without relying on
    // lookup-probe-count side effects.
    for (i, td) in ledger.transfers().iter().enumerate().take(100) {
        assert!(
            td.source_ciphertext.is_none(),
            "prior transfer {i} source_ciphertext must remain None (O(k) iteration domain)",
        );
        assert!(
            td.output_handle.is_none(),
            "prior transfer {i} output_handle must remain None (O(k) iteration domain)",
        );
    }

    // Positive-path assertion: the new transfer's fields are
    // populated as expected.
    let new = &ledger.transfers()[100];
    assert!(new.source_ciphertext.is_some());
    assert!(new.output_handle.is_some());
    assert_eq!(
        new.output_handle.expect("output_handle filled"),
        derive_output_handle(&view_secret, &new_tx, new_idx),
    );
}

#[test]
fn populate_engine_handle_fields_no_op_on_empty_residue() {
    let (mut ledger, mut indexes) = empty_state();
    let output = make_recovered_output(0x44, 4);
    let tx_hash = output.wallet_output().transaction();
    let internal_idx = output.wallet_output().index_in_transaction();
    let result = ScanResult {
        processed_height_range: 1..2,
        parent_hash: None,
        block_hashes: vec![(1, [0x11; 32])],
        new_transfers: vec![DetectedTransfer {
            block_height: 1,
            output,
        }],
        spent_key_images: Vec::new(),
        reorg_rewind: None,
        block_leaves: Vec::new(),
        block_curve_tree_roots: Vec::new(),
        bond_sightings: Vec::new(),
    };
    let inserted = apply_scan_result_to_state(&mut ledger, &mut indexes, result).expect("merge ok");

    let view_secret = [0u8; 32];
    let residue: HashMap<([u8; 32], u64), HybridCiphertext> = HashMap::new();
    populate_engine_handle_fields(&mut ledger, &view_secret, &residue, &inserted);

    let td = ledger
        .transfers()
        .iter()
        .find(|t| t.tx_hash.as_bytes() == &tx_hash && t.internal_output_index == internal_idx)
        .expect("merged transfer present");
    assert!(td.source_ciphertext.is_none());
    assert!(td.output_handle.is_none());
}
