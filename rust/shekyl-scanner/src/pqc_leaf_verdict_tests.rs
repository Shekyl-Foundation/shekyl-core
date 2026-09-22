// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `PL-D3` §6.2 scan-time verification (`FCMP_SPEND_LINKABILITY.md`): the
//! scanner compares the transaction's published `0x07` entry (`CM ‖ record`)
//! for each owned output with the wallet's own derivation and classifies a
//! mismatch — or a missing entry — as received-but-unspendable. The verdict
//! reaches the persisted row (`TransferDetails::unspendable`), which
//! `is_spendable` and the balance projection read.
//!
//! Three variants of one real, recoverable output: the honest entry (the
//! fixture writes the real `CM ‖ record`), a tampered entry (one byte of the
//! record flipped), and no `0x07` field at all.

use shekyl_engine_state::{
    InFlightSpendLocks, LedgerBlock, LedgerIndexes, SendJournalBlock, UnspendableReason,
};
use shekyl_units::AtomicUnits;

use crate::{
    balance::BalanceSummary,
    bench_fixtures::{make_bench_wallet, scannable_block_for_recipient, BenchWalletKeys},
    extra::{Extra, ExtraField},
    ledger_ext::LedgerIndexesExt,
    scan::{ScannableBlock, Timelocked},
    Scanner,
};

/// One block whose sole transaction pays one output to `wallet`, with the
/// real `0x07` entry the production writer would publish.
fn honest_block(wallet: &BenchWalletKeys) -> ScannableBlock {
    let spend_pub = wallet.view_pair.spend().compress().to_bytes();
    scannable_block_for_recipient(1, &wallet.wallet_kem_pk, &spend_pub)
}

/// Rewrite the transaction's `0x07` field through `f` (or drop it when `f`
/// returns `None`), re-serializing through the production writer.
fn rewrite_leaf_field(block: &mut ScannableBlock, f: impl FnOnce(Vec<u8>) -> Option<Vec<u8>>) {
    let tx = &mut block.transactions[0];
    let extra = Extra::read(&mut tx.prefix.extra.as_slice()).expect("fixture extra parses");
    let mut fields = extra.0;
    let pos = fields
        .iter()
        .position(|field| matches!(field, ExtraField::PqcLeafEntries(_)))
        .expect("fixture publishes a 0x07 field");
    let ExtraField::PqcLeafEntries(blob) = fields.remove(pos) else {
        unreachable!("position found a PqcLeafEntries field")
    };
    if let Some(new_blob) = f(blob) {
        fields.insert(pos, ExtraField::PqcLeafEntries(new_blob));
    }
    tx.prefix.extra = Extra(fields).serialize();
}

/// Consumes the wallet: `ViewPair` is wipe-on-drop and not `Clone`, and the
/// scanner takes it by value.
fn scan(wallet: BenchWalletKeys, block: ScannableBlock) -> Timelocked {
    let BenchWalletKeys {
        view_pair,
        spend_secret,
        wallet_kem_pk: _,
    } = wallet;
    let mut scanner = Scanner::new(view_pair, spend_secret);
    scanner.scan(block).expect("scan succeeds")
}

fn scan_one(wallet: BenchWalletKeys, block: ScannableBlock) -> Option<UnspendableReason> {
    let outputs = scan(wallet, block).into_inner();
    assert_eq!(
        outputs.len(),
        1,
        "the output is the wallet's in every variant"
    );
    outputs[0].unspendable()
}

fn no_locks() -> InFlightSpendLocks {
    SendJournalBlock::empty().spend_locks()
}

#[test]
fn honest_entry_is_spendable() {
    let wallet = make_bench_wallet();
    let block = honest_block(&wallet);
    assert_eq!(scan_one(wallet, block), None);
}

#[test]
fn tampered_record_is_received_but_unspendable() {
    let wallet = make_bench_wallet();
    let mut block = honest_block(&wallet);
    rewrite_leaf_field(&mut block, |mut blob| {
        // Flip one byte of the record half; the point half stays admissible
        // so consensus would still carry this transaction.
        blob[63] ^= 0x01;
        Some(blob)
    });
    assert_eq!(
        scan_one(wallet, block),
        Some(UnspendableReason::PqcLeafMismatch)
    );
}

#[test]
fn tampered_point_is_received_but_unspendable() {
    let wallet = make_bench_wallet();
    let mut block = honest_block(&wallet);
    rewrite_leaf_field(&mut block, |mut blob| {
        // A different (valid) point in the `CM` half: the basepoint.
        blob[..32].copy_from_slice(
            &curve25519_dalek::constants::ED25519_BASEPOINT_POINT
                .compress()
                .to_bytes(),
        );
        Some(blob)
    });
    assert_eq!(
        scan_one(wallet, block),
        Some(UnspendableReason::PqcLeafMismatch)
    );
}

#[test]
fn absent_entry_is_received_but_unspendable() {
    let wallet = make_bench_wallet();
    let mut block = honest_block(&wallet);
    rewrite_leaf_field(&mut block, |_| None);
    assert_eq!(
        scan_one(wallet, block),
        Some(UnspendableReason::PqcLeafEntryAbsent)
    );
}

#[test]
fn short_entry_is_received_but_unspendable() {
    let wallet = make_bench_wallet();
    let mut block = honest_block(&wallet);
    rewrite_leaf_field(&mut block, |blob| Some(blob[..32].to_vec()));
    assert_eq!(
        scan_one(wallet, block),
        Some(UnspendableReason::PqcLeafEntryAbsent)
    );
}

/// The verdict lands on the persisted row and governs spendability and the
/// balance projection: retained (in `total`, its transaction named), never
/// spendable.
#[test]
fn verdict_reaches_the_ledger_row_and_the_balance() {
    let wallet = make_bench_wallet();
    let mut block = honest_block(&wallet);
    rewrite_leaf_field(&mut block, |mut blob| {
        blob[40] ^= 0x80;
        Some(blob)
    });
    let sender_tx_hash = block.block.transaction_hashes[0];
    let outputs = scan(wallet, block);

    let mut ledger = LedgerBlock::empty();
    let mut indexes = LedgerIndexes::default();
    indexes.process_scanned_outputs(
        &mut ledger,
        shekyl_types::BlockHeight::from_raw(7),
        [0x22u8; 32],
        outputs,
    );
    assert_eq!(ledger.transfers.len(), 1);
    let td = &ledger.transfers[0];
    assert_eq!(td.unspendable, Some(UnspendableReason::PqcLeafMismatch));
    assert_eq!(
        td.tx_hash, sender_tx_hash,
        "the row names the sender's transaction (rule 82)"
    );
    assert!(!td.is_spendable(shekyl_types::BlockHeight::from_raw(u64::MAX), &no_locks()));

    let amount = td.amount();
    let summary = BalanceSummary::compute(
        &ledger.transfers,
        shekyl_types::BlockHeight::from_raw(u64::MAX),
        &no_locks(),
    );
    assert_eq!(summary.total, amount);
    assert_eq!(summary.unspendable, amount);
    assert_eq!(summary.unlocked, AtomicUnits::ZERO);
}
