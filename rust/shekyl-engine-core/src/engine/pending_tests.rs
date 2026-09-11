// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit suite for the `PendingTx` lifecycle (`engine/pending.rs`).
//!
//! Extracted to a `#[path]` sibling so the engine-decomposition ratchet
//! measures the workflow file rather than its tests — the same move the
//! conf records for `merge_tests.rs` / `lifecycle_tests.rs`. A growing
//! test harness is not a re-forming god-object; the split keeps that
//! distinction structural instead of a judgement call in the conf.

use std::num::NonZeroU64;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};
use shekyl_address::Network;
use shekyl_curve_primitives::Commitment;
use shekyl_scanner::{
    LedgerBlock, LedgerIndexes, LedgerIndexesExt, RecoveredWalletOutput, Timelocked, WalletOutput,
};
use shekyl_units::AtomicUnits;

use super::{
    build_pending_tx_in_state, discard_pending_tx_in_state, submit_pending_tx_in_state,
    FeePriority, PendingTxError, Reservation, ReservationId, SendError, TxRecipient, TxRequest,
    STUB_FEE_ATOMIC_UNITS,
};

fn make_recovered_output(seed: u8, global_index: u64, amount: u64) -> RecoveredWalletOutput {
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
            amount,
        },
    );
    RecoveredWalletOutput::new_for_test(base, amount)
}

/// Ingest `outputs` at `block_height` (single-block batch), then
/// keep advancing the ledger by empty blocks up to `final_height`.
fn populate(
    ledger: &mut LedgerBlock,
    indexes: &mut LedgerIndexes,
    block_height: u64,
    outputs: Vec<RecoveredWalletOutput>,
    final_height: u64,
) {
    let timelocked = Timelocked::from_vec(outputs);
    let block_hash = [u8::try_from(block_height & 0xFF).unwrap(); 32];
    let inserted_range =
        indexes.process_scanned_outputs(ledger, block_height, block_hash, timelocked);
    assert!(!inserted_range.is_empty() || ledger.transfer_count() == 0);
    for h in (block_height + 1)..=final_height {
        let hash = [u8::try_from(h & 0xFF).unwrap(); 32];
        let _ = indexes.process_scanned_outputs(ledger, h, hash, Timelocked::from_vec(Vec::new()));
    }
}

fn standard_request(amount: u64) -> TxRequest {
    TxRequest {
        recipients: vec![TxRecipient {
            address: "test_address".to_string(),
            amount_atomic_units: AtomicUnits::from_raw(amount),
        }],
        priority: FeePriority::Standard,
    }
}

#[test]
fn build_reserves_outputs_and_advances_id_counter() {
    let mut ledger = LedgerBlock::empty();
    let mut indexes = LedgerIndexes::empty();
    populate(
        &mut ledger,
        &mut indexes,
        1,
        vec![
            make_recovered_output(1, 100, 10_000),
            make_recovered_output(2, 101, 5_000),
        ],
        20,
    );
    assert_eq!(ledger.height(), 20);

    let mut reservations = std::collections::BTreeMap::new();
    let mut next_id = 0u64;

    let pending = build_pending_tx_in_state(
        &ledger,
        &mut reservations,
        &mut next_id,
        &standard_request(7_000),
    )
    .expect("build ok");

    assert_eq!(pending.id.raw(), 0);
    assert_eq!(next_id, 1);
    assert_eq!(pending.fee_atomic_units, STUB_FEE_ATOMIC_UNITS);
    assert_eq!(pending.built_at_height, 20);
    assert!(
        pending.tx_bytes.is_empty(),
        "the reference body leaves tx_bytes empty; production fills it"
    );
    assert_eq!(reservations.len(), 1);
    let r = reservations.get(&pending.id).unwrap();
    // 10_000 alone covers 7_000 + 1_000 fee, so the algorithm
    // selects exactly the 10_000 output.
    assert_eq!(r.selected_transfer_indices.len(), 1);
}

#[test]
fn build_filters_outputs_already_reserved_by_another_build() {
    let mut ledger = LedgerBlock::empty();
    let mut indexes = LedgerIndexes::empty();
    populate(
        &mut ledger,
        &mut indexes,
        1,
        vec![
            make_recovered_output(1, 100, 10_000),
            make_recovered_output(2, 101, 6_000),
        ],
        20,
    );

    let mut reservations = std::collections::BTreeMap::new();
    let mut next_id = 0u64;

    // First build reserves the 10_000 output.
    let _first = build_pending_tx_in_state(
        &ledger,
        &mut reservations,
        &mut next_id,
        &standard_request(7_000),
    )
    .expect("first build");

    // Second build needs more than 5_000 (the only remaining
    // output is 6_000, which can cover 4_000 + fee). Asking for
    // 5_000 exhausts available because 5_000 + 1_000 fee = 6_000.
    let second_ok = build_pending_tx_in_state(
        &ledger,
        &mut reservations,
        &mut next_id,
        &standard_request(5_000),
    )
    .expect("second build covers exactly 6_000");
    let r = reservations.get(&second_ok.id).unwrap();
    assert_eq!(r.selected_transfer_indices.len(), 1);

    // Third build cannot cover anything — every output is
    // reserved.
    let err = build_pending_tx_in_state(
        &ledger,
        &mut reservations,
        &mut next_id,
        &standard_request(1),
    )
    .unwrap_err();
    assert!(
        matches!(err, SendError::InsufficientFunds { available: 0, .. }),
        "got {err:?}"
    );
}

#[test]
fn build_rejects_empty_recipients() {
    let mut ledger = LedgerBlock::empty();
    let mut indexes = LedgerIndexes::empty();
    populate(
        &mut ledger,
        &mut indexes,
        1,
        vec![make_recovered_output(1, 100, 10_000)],
        20,
    );
    let mut reservations = std::collections::BTreeMap::new();
    let mut next_id = 0u64;
    let req = TxRequest {
        recipients: Vec::new(),
        priority: FeePriority::Economy,
    };
    let err =
        build_pending_tx_in_state(&ledger, &mut reservations, &mut next_id, &req).unwrap_err();
    assert!(matches!(err, SendError::InvalidRecipient { .. }));
    assert!(reservations.is_empty());
    assert_eq!(next_id, 0);
}

#[test]
fn build_rejects_when_no_block_ingested_yet() {
    // Empty ledger: synced = 0, no recorded block hash at 0.
    let ledger = LedgerBlock::empty();
    let mut reservations = std::collections::BTreeMap::new();
    let mut next_id = 0u64;
    let err = build_pending_tx_in_state(
        &ledger,
        &mut reservations,
        &mut next_id,
        &standard_request(1),
    )
    .unwrap_err();
    assert!(matches!(err, SendError::CannotSign { .. }));
}

#[test]
fn build_returns_insufficient_funds_when_balance_short() {
    let mut ledger = LedgerBlock::empty();
    let mut indexes = LedgerIndexes::empty();
    populate(
        &mut ledger,
        &mut indexes,
        1,
        vec![make_recovered_output(1, 100, 5_000)],
        20,
    );
    let mut reservations = std::collections::BTreeMap::new();
    let mut next_id = 0u64;
    let err = build_pending_tx_in_state(
        &ledger,
        &mut reservations,
        &mut next_id,
        &standard_request(10_000),
    )
    .unwrap_err();
    match err {
        SendError::InsufficientFunds { needed, available } => {
            assert_eq!(needed, 11_000);
            assert_eq!(available, 5_000);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn submit_unknown_handle_returns_unknown_handle() {
    let mut ledger = LedgerBlock::empty();
    let mut reservations: std::collections::BTreeMap<ReservationId, Reservation> =
        std::collections::BTreeMap::new();
    let err = submit_pending_tx_in_state(
        &mut ledger,
        &mut reservations,
        Network::Testnet,
        ReservationId(42),
    )
    .unwrap_err();
    assert!(matches!(err, PendingTxError::UnknownHandle));
}

#[test]
fn submit_too_old_when_built_height_outside_reorg_window() {
    let mut ledger = LedgerBlock::empty();
    let mut indexes = LedgerIndexes::empty();
    populate(
        &mut ledger,
        &mut indexes,
        1,
        vec![make_recovered_output(1, 100, 10_000)],
        20,
    );
    let mut reservations = std::collections::BTreeMap::new();
    let mut next_id = 0u64;
    let pending = build_pending_tx_in_state(
        &ledger,
        &mut reservations,
        &mut next_id,
        &standard_request(1_000),
    )
    .expect("build");

    // Advance ledger so synced - built_at_height > max_reorg_depth.
    // Testnet's max_reorg_depth = 6.
    for h in 21..=40 {
        let hash = [u8::try_from(h & 0xFF).unwrap(); 32];
        let _ =
            indexes.process_scanned_outputs(&mut ledger, h, hash, Timelocked::from_vec(Vec::new()));
    }

    let err =
        submit_pending_tx_in_state(&mut ledger, &mut reservations, Network::Testnet, pending.id)
            .unwrap_err();
    match err {
        PendingTxError::TooOld {
            built,
            current,
            max_reorg,
        } => {
            assert_eq!(built, 20);
            assert_eq!(current, 40);
            assert_eq!(max_reorg, 6);
        }
        other => panic!("unexpected error: {other:?}"),
    }
    // Reservation is preserved on TooOld so the caller can
    // discard it explicitly.
    assert_eq!(reservations.len(), 1);
}

#[test]
fn submit_chain_state_changed_when_tip_hash_at_built_height_no_longer_matches() {
    let mut ledger = LedgerBlock::empty();
    let mut indexes = LedgerIndexes::empty();
    populate(
        &mut ledger,
        &mut indexes,
        1,
        vec![make_recovered_output(1, 100, 10_000)],
        5,
    );
    let mut reservations = std::collections::BTreeMap::new();
    let mut next_id = 0u64;

    // Drive the build at height 5 (well past the spendable_age
    // cutoff so the output qualifies).
    for h in 6..=15 {
        let hash = [u8::try_from(h & 0xFF).unwrap(); 32];
        let _ =
            indexes.process_scanned_outputs(&mut ledger, h, hash, Timelocked::from_vec(Vec::new()));
    }
    let pending = build_pending_tx_in_state(
        &ledger,
        &mut reservations,
        &mut next_id,
        &standard_request(1_000),
    )
    .expect("build");
    assert_eq!(pending.built_at_height, 15);

    // Reorg: rewind to fork height 15, replay 15..=20 with new
    // hashes. After rewind, `block_hash_at(15)` differs from
    // `pending.built_at_tip_hash`.
    indexes.handle_reorg(&mut ledger, 15);
    for h in 15..=20 {
        let hash = [u8::try_from(0xA0 ^ (h & 0xFF)).unwrap(); 32];
        let _ =
            indexes.process_scanned_outputs(&mut ledger, h, hash, Timelocked::from_vec(Vec::new()));
    }

    let err =
        submit_pending_tx_in_state(&mut ledger, &mut reservations, Network::Testnet, pending.id)
            .unwrap_err();
    match err {
        PendingTxError::ChainStateChanged { height } => {
            assert_eq!(height, 15);
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(reservations.len(), 1, "reservation preserved on error");
}

#[test]
fn submit_marks_inputs_spent_and_consumes_reservation() {
    let mut ledger = LedgerBlock::empty();
    let mut indexes = LedgerIndexes::empty();
    populate(
        &mut ledger,
        &mut indexes,
        1,
        vec![make_recovered_output(1, 100, 10_000)],
        20,
    );
    let mut reservations = std::collections::BTreeMap::new();
    let mut next_id = 0u64;
    let pending = build_pending_tx_in_state(
        &ledger,
        &mut reservations,
        &mut next_id,
        &standard_request(5_000),
    )
    .expect("build");

    let tx_hash =
        submit_pending_tx_in_state(&mut ledger, &mut reservations, Network::Testnet, pending.id)
            .expect("submit");

    assert_eq!(reservations.len(), 0);
    // Output was marked locally spent by the reference body.
    assert!(ledger.transfers()[0].spent);
    assert_eq!(
        ledger.transfers()[0].spent_height,
        None,
        "the reference body leaves spent_height None until refresh confirms"
    );

    // Stub TxHash encodes the reservation id in the first 8 bytes.
    assert_eq!(&tx_hash.as_bytes()[..8], &pending.id.raw().to_le_bytes());
}

#[test]
fn discard_releases_reservation_and_outputs_become_selectable_again() {
    let mut ledger = LedgerBlock::empty();
    let mut indexes = LedgerIndexes::empty();
    populate(
        &mut ledger,
        &mut indexes,
        1,
        vec![make_recovered_output(1, 100, 10_000)],
        20,
    );
    let mut reservations = std::collections::BTreeMap::new();
    let mut next_id = 0u64;
    let pending = build_pending_tx_in_state(
        &ledger,
        &mut reservations,
        &mut next_id,
        &standard_request(1_000),
    )
    .expect("build");

    assert!(discard_pending_tx_in_state(&mut reservations, pending.id));
    assert_eq!(reservations.len(), 0);

    // Re-build picks up the same output: it is no longer reserved.
    let again = build_pending_tx_in_state(
        &ledger,
        &mut reservations,
        &mut next_id,
        &standard_request(1_000),
    )
    .expect("rebuild");
    let r = reservations.get(&again.id).unwrap();
    assert_eq!(r.selected_transfer_indices, vec![0]);
}

#[test]
fn discard_is_idempotent_on_unknown_handle() {
    let mut reservations: std::collections::BTreeMap<ReservationId, Reservation> =
        std::collections::BTreeMap::new();
    let was_present = discard_pending_tx_in_state(&mut reservations, ReservationId(99));
    assert!(!was_present);
    // No state change, no panic.
    assert!(reservations.is_empty());
}

#[test]
fn priority_custom_is_accepted_and_preserved() {
    let mut ledger = LedgerBlock::empty();
    let mut indexes = LedgerIndexes::empty();
    populate(
        &mut ledger,
        &mut indexes,
        1,
        vec![make_recovered_output(1, 100, 10_000)],
        20,
    );
    let mut reservations = std::collections::BTreeMap::new();
    let mut next_id = 0u64;
    let req = TxRequest {
        recipients: vec![TxRecipient {
            address: "addr".into(),
            amount_atomic_units: AtomicUnits::from_raw(1_000),
        }],
        priority: FeePriority::Custom(NonZeroU64::new(42).unwrap()),
    };
    let pending =
        build_pending_tx_in_state(&ledger, &mut reservations, &mut next_id, &req).unwrap();
    let r = reservations.get(&pending.id).unwrap();
    assert!(matches!(r.priority, FeePriority::Custom(_)));
}
