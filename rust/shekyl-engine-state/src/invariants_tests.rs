// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One positive ledger plus one negative per invariant. Each negative
//! constructs the minimum [`WalletLedger`](crate::WalletLedger) that trips
//! exactly one check and asserts on the stable invariant name.

use super::*;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
use shekyl_curve_primitives::Commitment;

use crate::{
    bookkeeping_block::BookkeepingBlock,
    ledger_block::{BlockchainTip, LedgerBlock, ReorgBlocks},
    staking_block::StakingBlock,
    sync_state_block::SyncStateBlock,
    transfer::{TransferDetails, SPENDABLE_AGE},
    tx_meta_block::{ScannedPoolTx, TxMetaBlock, TxSecretKey, TxSecretKeys},
};
use shekyl_types::{BlockHash, BlockHeight};
use std::collections::BTreeMap;

/// Minimum-viable transfer at a chosen `block_height`. Returns a
/// not-yet-spent output with no key image; individual tests
/// override whatever field(s) they need.
fn mk_transfer(seed: u8, block_height: u64) -> TransferDetails {
    TransferDetails {
        tx_hash: shekyl_types::TxHash::from_bytes([seed; 32]),
        internal_output_index: shekyl_types::OutputIndexInTx::from_raw(u64::from(seed)),
        global_output_index: shekyl_types::GlobalOutputIndex::from_raw(u64::from(seed)),
        block_height: shekyl_types::BlockHeight::from_raw(block_height),
        key: ED25519_BASEPOINT_POINT,
        key_offset: Scalar::ONE,
        commitment: Commitment::new(Scalar::ONE, 1_000),
        payment_id: None,
        spent: false,
        spent_height: None,
        key_image: None,
        spending_tx_hash: None,
        source_ciphertext: None,
        output_handle: None,
        eligible_height: shekyl_types::BlockHeight::from_raw(block_height) + SPENDABLE_AGE,
        unspendable: None,
        fcmp_precomputed_path: None,
        receive_attribution: crate::ReceiveAttribution::default(),
    }
}

fn assert_invariant(err: WalletLedgerError, expected: &'static str) {
    match err {
        WalletLedgerError::InvariantFailed { invariant, detail } => {
            assert_eq!(
                invariant, expected,
                "unexpected invariant name (detail: {detail})"
            );
        }
        other => panic!("expected InvariantFailed({expected}), got {other:?}"),
    }
}

#[test]
fn default_bundle_passes_all_invariants() {
    let w = WalletLedger::empty();
    w.check_invariants().expect("empty bundle is consistent");
    w.preflight_save().expect("empty bundle is save-safe");
}

#[test]
fn populated_consistent_bundle_passes() {
    let transfers = vec![mk_transfer(1, 10), mk_transfer(2, 15), mk_transfer(3, 20)];
    let ledger = LedgerBlock::new(
        transfers,
        BlockchainTip::new(BlockHeight::from_raw(30), BlockHash::from_bytes([0xAA; 32])),
        ReorgBlocks {
            blocks: vec![
                (BlockHeight::from_raw(28), BlockHash::from_bytes([1; 32])),
                (BlockHeight::from_raw(29), BlockHash::from_bytes([2; 32])),
                (BlockHeight::from_raw(30), BlockHash::from_bytes([0xAA; 32])),
            ],
        },
    );
    let w = WalletLedger::new(
        ledger,
        BookkeepingBlock::empty(),
        TxMetaBlock::empty(),
        SyncStateBlock::empty(),
        StakingBlock::empty(),
    );
    w.check_invariants().expect("populated-consistent bundle");
}

#[test]
fn tip_below_transfer_height_is_refused() {
    let transfers = vec![mk_transfer(1, 1_000)];
    let ledger = LedgerBlock::new(
        transfers,
        BlockchainTip::new(
            BlockHeight::from_raw(500),
            BlockHash::from_bytes([0xAA; 32]),
        ),
        ReorgBlocks::default(),
    );
    let w = WalletLedger::new(
        ledger,
        BookkeepingBlock::empty(),
        TxMetaBlock::empty(),
        SyncStateBlock::empty(),
        StakingBlock::empty(),
    );
    assert_invariant(
        w.check_invariants().unwrap_err(),
        INV_TIP_NOT_BELOW_TRANSFER,
    );
}

#[test]
fn orphan_tx_key_is_refused() {
    // tx_keys entry for a hash that appears nowhere else.
    let mut tx_keys = BTreeMap::new();
    tx_keys.insert(
        [0x77; 32],
        TxSecretKeys {
            primary: TxSecretKey::new(shekyl_crypto_pq::TxKey::seeded([0; 32]).store()),
        },
    );
    let tx_meta = TxMetaBlock::new(tx_keys, BTreeMap::new());
    let w = WalletLedger::new(
        LedgerBlock::empty(),
        BookkeepingBlock::empty(),
        tx_meta,
        SyncStateBlock::empty(),
        StakingBlock::empty(),
    );
    assert_invariant(w.check_invariants().unwrap_err(), INV_TX_KEYS_NO_ORPHANS);
}

#[test]
fn tx_key_referenced_by_pending_is_accepted() {
    let txid = [0x77; 32];
    let mut tx_keys = BTreeMap::new();
    tx_keys.insert(
        txid,
        TxSecretKeys {
            primary: TxSecretKey::new(shekyl_crypto_pq::TxKey::seeded([0; 32]).store()),
        },
    );
    let tx_meta = TxMetaBlock::new(tx_keys, BTreeMap::new());
    let mut sync = SyncStateBlock::empty();
    sync.pending_tx_hashes = vec![txid];
    let w = WalletLedger::new(
        LedgerBlock::empty(),
        BookkeepingBlock::empty(),
        tx_meta,
        sync,
        StakingBlock::empty(),
    );
    w.check_invariants().expect("pending ref satisfies I-2");
}

/// P3-4 journal leg: after `abandon_send` migrates the pending
/// entry, a tx key whose *only* reference is an `Abandoned` journal
/// row satisfies I-2 — while a terminal (`TerminalRejected`) row
/// does not carry retention.
#[test]
fn tx_key_referenced_by_abandoned_journal_row_is_accepted() {
    use crate::send_journal_block::{SendRecord, SendState};

    let txid = [0x77; 32];
    let mut tx_keys = BTreeMap::new();
    tx_keys.insert(
        txid,
        TxSecretKeys {
            primary: TxSecretKey::new(shekyl_crypto_pq::TxKey::seeded([0; 32]).store()),
        },
    );
    let tx_meta = TxMetaBlock::new(tx_keys, BTreeMap::new());
    let mut w = WalletLedger::new(
        LedgerBlock::empty(),
        BookkeepingBlock::empty(),
        tx_meta,
        SyncStateBlock::empty(),
        StakingBlock::empty(),
    );
    let row = |state| SendRecord {
        dispatched_at_height: BlockHeight::from_raw(20),
        fee: 5,
        recipients: Vec::new(),
        change_amount: 0,
        inputs: Vec::new(),
        lock_baseline: None,
        state,
        tx_bytes: None,
    };
    w.send_journal.rows.insert(txid, row(SendState::Abandoned));
    w.check_invariants()
        .expect("abandoned journal row satisfies I-2");

    w.send_journal
        .rows
        .insert(txid, row(SendState::TerminalRejected));
    assert_invariant(w.check_invariants().unwrap_err(), INV_TX_KEYS_NO_ORPHANS);
}

#[test]
fn tx_key_referenced_by_pool_is_accepted() {
    let txid = [0x77; 32];
    let mut tx_keys = BTreeMap::new();
    tx_keys.insert(
        txid,
        TxSecretKeys {
            primary: TxSecretKey::new(shekyl_crypto_pq::TxKey::seeded([0; 32]).store()),
        },
    );
    let mut pool = BTreeMap::new();
    pool.insert(txid, ScannedPoolTx::default());
    let tx_meta = TxMetaBlock::new(tx_keys, pool);
    let w = WalletLedger::new(
        LedgerBlock::empty(),
        BookkeepingBlock::empty(),
        tx_meta,
        SyncStateBlock::empty(),
        StakingBlock::empty(),
    );
    w.check_invariants().expect("pool ref satisfies I-2");
}

/// WI-RPC-3 F-9 spend-quadruple: a no-change outbound tx produces no
/// owned output, so after confirmation its *only* live references
/// are the spent rows' `spending_tx_hash`. The retained secret must
/// stay I-2-live through that leg alone.
#[test]
fn tx_key_referenced_by_spending_tx_hash_is_accepted() {
    let txid = [0x77; 32];
    let mut tx_keys = BTreeMap::new();
    tx_keys.insert(
        txid,
        TxSecretKeys {
            primary: TxSecretKey::new(shekyl_crypto_pq::TxKey::seeded([0; 32]).store()),
        },
    );
    let tx_meta = TxMetaBlock::new(tx_keys, BTreeMap::new());
    // The spent row's own tx_hash differs from `txid`; only the
    // `spending_tx_hash` leg satisfies I-2 here.
    let mut spent_row = mk_transfer(0x11, 10);
    spent_row.spent = true;
    spent_row.spent_height = Some(shekyl_types::BlockHeight::from_raw(20));
    spent_row.key_image = Some(shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes(
        [0x33; 32],
    ));
    spent_row.spending_tx_hash = Some(shekyl_types::TxHash::from_bytes(txid));
    let ledger = LedgerBlock::new(
        vec![spent_row],
        BlockchainTip::new(BlockHeight::from_raw(30), BlockHash::from_bytes([0xAA; 32])),
        ReorgBlocks::default(),
    );
    let w = WalletLedger::new(
        ledger,
        BookkeepingBlock::empty(),
        tx_meta,
        SyncStateBlock::empty(),
        StakingBlock::empty(),
    );
    w.check_invariants()
        .expect("spending_tx_hash ref satisfies I-2");
}

/// Broadcast-accept window: a network-exposed spend awaiting
/// confirmation is a tracked tx; its secret must not be orphaned
/// between accept and refresh-observed confirmation. Since
/// PR-SJ-1b the journal leg carries this window — the lock-bearing
/// `Dispatched` row is the I-2 reference (the former F14-lock leg).
#[test]
fn tx_key_referenced_by_dispatched_journal_row_is_accepted() {
    let txid = [0x77; 32];
    let mut tx_keys = BTreeMap::new();
    tx_keys.insert(
        txid,
        TxSecretKeys {
            primary: TxSecretKey::new(shekyl_crypto_pq::TxKey::seeded([0; 32]).store()),
        },
    );
    let tx_meta = TxMetaBlock::new(tx_keys, BTreeMap::new());
    let ledger = LedgerBlock::new(
        vec![mk_transfer(0x11, 10)],
        BlockchainTip::new(BlockHeight::from_raw(30), BlockHash::from_bytes([0xAA; 32])),
        ReorgBlocks::default(),
    );
    let mut w = WalletLedger::new(
        ledger,
        BookkeepingBlock::empty(),
        tx_meta,
        SyncStateBlock::empty(),
        StakingBlock::empty(),
    );
    {
        use crate::send_journal_block::{SendInputRef, SendRecord, SendState};
        w.send_journal.rows.insert(
            txid,
            SendRecord {
                dispatched_at_height: BlockHeight::from_raw(20),
                fee: 5,
                recipients: Vec::new(),
                change_amount: 0,
                inputs: vec![SendInputRef {
                    gindex: 0x11,
                    amount: 1,
                }],
                lock_baseline: Some(25),
                state: SendState::Dispatched,
                tx_bytes: None,
            },
        );
    }
    w.check_invariants()
        .expect("dispatched journal row satisfies I-2");
}

#[test]
fn reorg_trail_out_of_order_is_refused() {
    let ledger = LedgerBlock::new(
        Vec::new(),
        BlockchainTip::new(
            BlockHeight::from_raw(100),
            BlockHash::from_bytes([0xAA; 32]),
        ),
        ReorgBlocks {
            blocks: vec![
                (BlockHeight::from_raw(10), BlockHash::from_bytes([1; 32])),
                (BlockHeight::from_raw(9), BlockHash::from_bytes([2; 32])),
            ],
        },
    );
    let w = WalletLedger::new(
        ledger,
        BookkeepingBlock::empty(),
        TxMetaBlock::empty(),
        SyncStateBlock::empty(),
        StakingBlock::empty(),
    );
    assert_invariant(w.check_invariants().unwrap_err(), INV_REORG_TRAIL_MONOTONIC);
}

#[test]
fn reorg_trail_duplicate_height_is_refused() {
    let ledger = LedgerBlock::new(
        Vec::new(),
        BlockchainTip::new(
            BlockHeight::from_raw(100),
            BlockHash::from_bytes([0xAA; 32]),
        ),
        ReorgBlocks {
            blocks: vec![
                (BlockHeight::from_raw(10), BlockHash::from_bytes([1; 32])),
                (BlockHeight::from_raw(10), BlockHash::from_bytes([2; 32])),
            ],
        },
    );
    let w = WalletLedger::new(
        ledger,
        BookkeepingBlock::empty(),
        TxMetaBlock::empty(),
        SyncStateBlock::empty(),
        StakingBlock::empty(),
    );
    assert_invariant(w.check_invariants().unwrap_err(), INV_REORG_TRAIL_MONOTONIC);
}

#[test]
fn reorg_trail_above_tip_is_refused() {
    let ledger = LedgerBlock::new(
        Vec::new(),
        BlockchainTip::new(BlockHeight::from_raw(10), BlockHash::from_bytes([0xAA; 32])),
        ReorgBlocks {
            blocks: vec![(BlockHeight::from_raw(11), BlockHash::from_bytes([1; 32]))],
        },
    );
    let w = WalletLedger::new(
        ledger,
        BookkeepingBlock::empty(),
        TxMetaBlock::empty(),
        SyncStateBlock::empty(),
        StakingBlock::empty(),
    );
    assert_invariant(w.check_invariants().unwrap_err(), INV_REORG_TRAIL_MONOTONIC);
}

#[test]
fn spent_in_flight_without_height_is_allowed() {
    // The in-flight (optimistically-spent) shape: marked spent at submit, with a
    // key image, but no confirming height until a refresh scans the block. This is
    // the state `finalize_submit_accept` produces; the invariant must admit it.
    let mut t = mk_transfer(1, 10);
    t.spent = true;
    t.spent_height = None;
    t.key_image = Some(KeyImage::from_canonical_bytes([1; 32]));
    let ledger = LedgerBlock::new(
        vec![t],
        BlockchainTip::new(
            BlockHeight::from_raw(100),
            BlockHash::from_bytes([0xAA; 32]),
        ),
        ReorgBlocks::default(),
    );
    let w = WalletLedger::new(
        ledger,
        BookkeepingBlock::empty(),
        TxMetaBlock::empty(),
        SyncStateBlock::empty(),
        StakingBlock::empty(),
    );
    assert!(
        w.check_invariants().is_ok(),
        "in-flight spend (spent, no height, key_image present) must be valid"
    );
}

#[test]
fn spent_in_flight_without_key_image_is_refused() {
    // In flight or confirmed, a spent output must carry the key image it was spent
    // by — relaxing the height requirement must not relax the key-image one.
    let mut t = mk_transfer(1, 10);
    t.spent = true;
    t.spent_height = None;
    t.key_image = None;
    let ledger = LedgerBlock::new(
        vec![t],
        BlockchainTip::new(
            BlockHeight::from_raw(100),
            BlockHash::from_bytes([0xAA; 32]),
        ),
        ReorgBlocks::default(),
    );
    let w = WalletLedger::new(
        ledger,
        BookkeepingBlock::empty(),
        TxMetaBlock::empty(),
        SyncStateBlock::empty(),
        StakingBlock::empty(),
    );
    assert_invariant(
        w.check_invariants().unwrap_err(),
        INV_SPENT_STATE_CONSISTENT,
    );
}

#[test]
fn spent_without_key_image_is_refused() {
    let mut t = mk_transfer(1, 10);
    t.spent = true;
    t.spent_height = Some(shekyl_types::BlockHeight::from_raw(20));
    t.key_image = None;
    let ledger = LedgerBlock::new(
        vec![t],
        BlockchainTip::new(
            BlockHeight::from_raw(100),
            BlockHash::from_bytes([0xAA; 32]),
        ),
        ReorgBlocks::default(),
    );
    let w = WalletLedger::new(
        ledger,
        BookkeepingBlock::empty(),
        TxMetaBlock::empty(),
        SyncStateBlock::empty(),
        StakingBlock::empty(),
    );
    assert_invariant(
        w.check_invariants().unwrap_err(),
        INV_SPENT_STATE_CONSISTENT,
    );
}

#[test]
fn not_spent_with_spent_height_is_refused() {
    let mut t = mk_transfer(1, 10);
    t.spent = false;
    t.spent_height = Some(shekyl_types::BlockHeight::from_raw(20));
    let ledger = LedgerBlock::new(
        vec![t],
        BlockchainTip::new(
            BlockHeight::from_raw(100),
            BlockHash::from_bytes([0xAA; 32]),
        ),
        ReorgBlocks::default(),
    );
    let w = WalletLedger::new(
        ledger,
        BookkeepingBlock::empty(),
        TxMetaBlock::empty(),
        SyncStateBlock::empty(),
        StakingBlock::empty(),
    );
    assert_invariant(
        w.check_invariants().unwrap_err(),
        INV_SPENT_STATE_CONSISTENT,
    );
}

#[test]
fn duplicate_key_image_is_refused() {
    let mut t1 = mk_transfer(1, 10);
    let mut t2 = mk_transfer(2, 15);
    t1.spent = true;
    t1.spent_height = Some(shekyl_types::BlockHeight::from_raw(20));
    t1.key_image = Some(KeyImage::from_canonical_bytes([0xCC; 32]));
    t2.spent = true;
    t2.spent_height = Some(shekyl_types::BlockHeight::from_raw(30));
    t2.key_image = Some(KeyImage::from_canonical_bytes([0xCC; 32]));
    let ledger = LedgerBlock::new(
        vec![t1, t2],
        BlockchainTip::new(
            BlockHeight::from_raw(100),
            BlockHash::from_bytes([0xAA; 32]),
        ),
        ReorgBlocks::default(),
    );
    let w = WalletLedger::new(
        ledger,
        BookkeepingBlock::empty(),
        TxMetaBlock::empty(),
        SyncStateBlock::empty(),
        StakingBlock::empty(),
    );
    assert_invariant(
        w.check_invariants().unwrap_err(),
        INV_SPENT_STATE_CONSISTENT,
    );
}

fn paying_a_group(fingerprint: crate::GroupFingerprint) -> WalletLedger {
    let mut w = WalletLedger::empty();
    w.send_journal.record_dispatched(
        [0x71; 32],
        BlockHeight::from_raw(0),
        1,
        vec![crate::SendRecipient {
            destination: crate::SendDestination::Group(fingerprint),
            amount: 2,
            rid: None,
        }],
        vec![crate::SendInputRef {
            gindex: 9,
            amount: 3,
        }],
        vec![0xAB],
    );
    w
}

#[test]
fn a_group_paid_and_stored_passes() {
    let address = crate::group_payee::tests::group(0x21);
    let mut w = paying_a_group(crate::GroupFingerprint::of(&address));
    w.send_journal.store_group_payee(&address);
    w.check_invariants()
        .expect("the group a row pays is stored");
}

#[test]
fn a_group_paid_and_not_stored_is_refused() {
    let address = crate::group_payee::tests::group(0x21);
    let w = paying_a_group(crate::GroupFingerprint::of(&address));
    assert_invariant(w.check_invariants().unwrap_err(), INV_GROUP_PAYEES_STORED);
}

/// A stored group no row pays is not refused: an address the wallet
/// keeps without a row that names it costs nothing, and refusing it
/// would refuse the whole wallet. `undo_dispatch` drops one anyway.
#[test]
fn a_group_stored_and_not_paid_passes() {
    let paid = crate::group_payee::tests::group(0x21);
    let mut w = paying_a_group(crate::GroupFingerprint::of(&paid));
    w.send_journal.store_group_payee(&paid);
    w.send_journal
        .store_group_payee(&crate::group_payee::tests::group(0x22));
    w.check_invariants()
        .expect("an address no row pays is kept, not refused");
}

#[test]
fn a_group_stored_under_another_groups_fingerprint_is_refused() {
    let paid = crate::group_payee::tests::group(0x21);
    let fingerprint = crate::GroupFingerprint::of(&paid);
    let mut w = paying_a_group(fingerprint);
    w.send_journal.insert_group_payee_as_read(
        fingerprint,
        crate::StoredGroupAddress::new(&crate::group_payee::tests::group(0x22)),
    );
    assert_invariant(w.check_invariants().unwrap_err(), INV_GROUP_PAYEES_STORED);
}

#[test]
fn a_stored_group_that_does_not_parse_is_refused() {
    let paid = crate::group_payee::tests::group(0x21);
    let fingerprint = crate::GroupFingerprint::of(&paid);
    let mut w = paying_a_group(fingerprint);
    w.send_journal.insert_group_payee_as_read(
        fingerprint,
        crate::StoredGroupAddress::from_file_bytes(vec![0x5A; 40]),
    );
    assert_invariant(w.check_invariants().unwrap_err(), INV_GROUP_PAYEES_STORED);
}

/// The load path runs the check: a file whose journal names a group
/// it does not store is refused when it is read, not when it is next
/// saved.
#[test]
fn a_file_naming_a_group_it_does_not_store_is_refused_at_load() {
    let address = crate::group_payee::tests::group(0x21);
    let w = paying_a_group(crate::GroupFingerprint::of(&address));
    let bytes = postcard::to_allocvec(&w).expect("serialize");
    assert_invariant(
        WalletLedger::from_postcard_bytes(&bytes).unwrap_err(),
        INV_GROUP_PAYEES_STORED,
    );
}

#[test]
fn preflight_save_returns_typed_error_without_panicking() {
    // Construct a ledger that violates I-1. In release builds the
    // debug_assert is compiled out, so this assertion verifies the
    // typed-error return. The debug-build path is exercised by the
    // same check_invariants() call via `assert_invariant` above.
    let transfers = vec![mk_transfer(1, 100)];
    let ledger = LedgerBlock::new(
        transfers,
        BlockchainTip::new(BlockHeight::from_raw(50), BlockHash::from_bytes([0; 32])),
        ReorgBlocks::default(),
    );
    let w = WalletLedger::new(
        ledger,
        BookkeepingBlock::empty(),
        TxMetaBlock::empty(),
        SyncStateBlock::empty(),
        StakingBlock::empty(),
    );
    // preflight_save runs debug_assert! in debug builds; skip the
    // assertion there to keep the test identical across profiles.
    #[cfg(debug_assertions)]
    let outcome = w.check_invariants();
    #[cfg(not(debug_assertions))]
    let outcome = w.preflight_save();
    assert_invariant(outcome.unwrap_err(), INV_TIP_NOT_BELOW_TRANSFER);
}
