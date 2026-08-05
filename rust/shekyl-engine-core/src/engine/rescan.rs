// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Full-wallet rescan: reset scan-derived ledger state, then reuse refresh.
//!
//! Contract pin (`docs/api/wallet_rpc.yaml` `rescan_blockchain`,
//! `docs/FOLLOWUPS.md` Phase 4b rescan item): rescan is a **named** Engine
//! API that destroys and rebuilds scan-derived state from
//! `sync_state.restore_from_height`. It is not a silent "set height +
//! refresh" shim.
//!
//! # Preserve vs clear
//!
//! **Preserve (RESCAN-SURVIVING / user-authored):**
//! - `sync_state.restore_from_height`, `creation_anchor_hash`, prefs
//! - `tx_meta.tx_keys` (+ `pending_tx_hashes` — I-2 live set with keys)
//! - `tx_meta.tx_notes`, `attributes`
//! - bookkeeping rows (primary label, address book, payment-request
//!   **records** — matches are unwound so replay can re-match)
//! - `staking.staking_enabled`, `staking.p_slot`
//!
//! **Clear / reset (scan-derived):**
//! - `ledger.transfers`, tip, reorg window
//! - runtime `LedgerIndexes`
//! - `sync_state.scan_completed`
//! - `tx_meta.scanned_pool_txs`
//! - payment-request match fields (via attribution rewind)
//! - `staking.bonded_slots` hint (reconcilable)

use shekyl_engine_state::{BlockchainTip, LedgerIndexes, ReorgBlocks, WalletLedger};

use crate::attribution::rewind_matched_payment_requests_after_reorg;

/// Reset scan-derived fields on an in-memory ledger aggregate.
///
/// Leaves key material, restore height, retained tx keys, payment-request
/// invoices, and staking config intact. Callers must also roll the
/// curve-tree tip back and persist before scanning.
pub(crate) fn reset_scan_derived_state(wallet: &mut WalletLedger, indexes: &mut LedgerIndexes) {
    wallet.ledger.transfers.clear();
    wallet.ledger.tip = BlockchainTip::default();
    wallet.ledger.reorg_blocks = ReorgBlocks::default();

    *indexes = LedgerIndexes::empty();

    wallet.sync_state.scan_completed = false;
    wallet.tx_meta.scanned_pool_txs.clear();
    wallet.staking.bonded_slots.clear();

    // Preserve payment-request *rows*; unwind matches against the emptied
    // transfer set so a subsequent scan can re-attribute.
    rewind_matched_payment_requests_after_reorg(
        &mut wallet.bookkeeping.payment_requests,
        &wallet.ledger,
    );
}

/// Tip height after reset — always the unscanned bootstrap tip.
#[cfg(test)]
fn assert_unscanned(ledger: &shekyl_engine_state::LedgerBlock) {
    assert!(
        ledger.tip.is_unscanned(),
        "rescan reset must leave an unscanned tip"
    );
    assert!(ledger.transfers.is_empty());
    assert!(ledger.reorg_blocks.is_empty());
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
    use shekyl_curve_primitives::Commitment;
    use shekyl_engine_state::{
        transfer::TransferDetails, BlockchainTip, LedgerIndexes, LocalLabel, PaymentRequest,
        PaymentRequestId, PaymentRequestState, ReceiveAttribution, ReorgBlocks, ScannedPoolTx,
        SyncStateBlock, TxSecretKey, TxSecretKeys, WalletLedger,
    };
    use shekyl_types::TxHash;
    use shekyl_units::AtomicUnits;
    use zeroize::Zeroizing;

    use super::{assert_unscanned, reset_scan_derived_state};

    fn sample_transfer(seed: u8) -> TransferDetails {
        TransferDetails {
            tx_hash: TxHash::from_bytes([seed; 32]),
            internal_output_index: 0,
            global_output_index: 0,
            block_height: 10,
            key: ED25519_BASEPOINT_POINT,
            key_offset: Scalar::ONE,
            commitment: Commitment::new(Scalar::ONE, 1000),
            payment_id: None,
            spent: false,
            spent_height: None,
            key_image: None,
            awaiting_confirmation: None,
            spending_tx_hash: None,
            source_ciphertext: None,
            output_handle: None,
            eligible_height: 0,
            frozen: false,
            fcmp_precomputed_path: None,
            receive_attribution: ReceiveAttribution::Unattributed,
        }
    }

    #[test]
    fn reset_clears_scan_derived_and_preserves_retention() {
        let mut wallet = WalletLedger::empty();
        wallet.sync_state.restore_from_height = 42;
        wallet.sync_state.creation_anchor_hash = Some([7u8; 32]);
        wallet.sync_state.scan_completed = true;
        wallet.sync_state.pending_tx_hashes.push([9u8; 32]);
        wallet.sync_state.confirmations_required = 10;
        wallet.sync_state.trusted_daemon = true;

        wallet.ledger.transfers.push(sample_transfer(1));
        wallet.ledger.tip = BlockchainTip::new(50, [1u8; 32]);
        wallet.ledger.reorg_blocks = ReorgBlocks {
            blocks: vec![(40, [2u8; 32])],
        };

        let txid = [3u8; 32];
        wallet.tx_meta.tx_keys.insert(
            txid,
            TxSecretKeys {
                primary: TxSecretKey::new(Zeroizing::new([4u8; 32])),
            },
        );
        wallet.tx_meta.scanned_pool_txs.insert(
            [5u8; 32],
            ScannedPoolTx {
                first_seen_unix_secs: 1,
                double_spend_seen: false,
            },
        );

        wallet.bookkeeping.payment_requests.push(PaymentRequest {
            id: PaymentRequestId(0x00_00_00_00_00_06),
            label: LocalLabel::from_str("invoice"),
            amount_atomic: AtomicUnits::from_raw(100),
            created_at: 1,
            expiry: None,
            state: PaymentRequestState::Matched,
            matched_tx_hash: Some(TxHash::from_bytes([1u8; 32])),
            matched_output_index: Some(0),
        });

        wallet.staking.staking_enabled = true;
        wallet.staking.p_slot = 3;
        wallet.staking.bonded_slots = vec![1, 2];

        let mut indexes = LedgerIndexes::empty();
        reset_scan_derived_state(&mut wallet, &mut indexes);

        assert_unscanned(&wallet.ledger);
        assert!(!wallet.sync_state.scan_completed);
        assert_eq!(wallet.sync_state.restore_from_height, 42);
        assert_eq!(wallet.sync_state.creation_anchor_hash, Some([7u8; 32]));
        assert_eq!(wallet.sync_state.pending_tx_hashes, vec![[9u8; 32]]);
        assert_eq!(wallet.sync_state.confirmations_required, 10);
        assert!(wallet.sync_state.trusted_daemon);
        assert!(wallet.tx_meta.tx_keys.contains_key(&txid));
        assert!(wallet.tx_meta.scanned_pool_txs.is_empty());
        assert!(wallet.staking.staking_enabled);
        assert_eq!(wallet.staking.p_slot, 3);
        assert!(wallet.staking.bonded_slots.is_empty());

        let req = &wallet.bookkeeping.payment_requests[0];
        assert_eq!(req.state, PaymentRequestState::Pending);
        assert!(req.matched_tx_hash.is_none());
        assert!(req.matched_output_index.is_none());
    }

    #[test]
    fn reset_is_idempotent_on_empty_ledger() {
        let mut wallet = WalletLedger::empty();
        wallet.sync_state = SyncStateBlock {
            restore_from_height: 7,
            ..SyncStateBlock::empty()
        };
        let mut indexes = LedgerIndexes::empty();
        reset_scan_derived_state(&mut wallet, &mut indexes);
        reset_scan_derived_state(&mut wallet, &mut indexes);
        assert_eq!(wallet.sync_state.restore_from_height, 7);
        assert_unscanned(&wallet.ledger);
    }
}
