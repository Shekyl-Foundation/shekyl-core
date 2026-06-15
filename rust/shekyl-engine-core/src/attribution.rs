// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Receive attribution matching after scan merge (FA-8b).

use std::collections::HashMap;

use shekyl_crypto_pq::label::{
    classify_label_plaintext, hash_label_plaintext_for_display, LabelPlaintextKind,
};
use shekyl_engine_state::{
    LedgerBlock, PaymentRequest, PaymentRequestId, PaymentRequestState, ReceiveAttribution,
};
use shekyl_types::TxHash;
use shekyl_units::AtomicUnits;

type LabelResidue = HashMap<([u8; 32], u64), [u8; 8]>;

/// Lift decrypted label plaintext from a scan result before merge consumes it.
pub(crate) fn collect_label_residue(
    new_transfers: &[crate::scan::DetectedTransfer],
) -> LabelResidue {
    let mut map = HashMap::with_capacity(new_transfers.len());
    for dt in new_transfers {
        let wo = dt.output.wallet_output();
        map.insert(
            (wo.transaction(), wo.index_in_transaction()),
            *dt.output.label_plaintext(),
        );
    }
    map
}

/// After a chain reorg drops transfers at `fork_height` and above, unwind
/// `PaymentRequest` rows that matched transfers that no longer exist so a
/// replay can re-match them.
pub(crate) fn rewind_matched_payment_requests_after_reorg(
    payment_requests: &mut [PaymentRequest],
    ledger: &LedgerBlock,
) {
    let current_height = ledger.height();
    for req in payment_requests.iter_mut() {
        if req.state != PaymentRequestState::Matched {
            continue;
        }
        let (Some(tx_hash), Some(out_idx)) = (req.matched_tx_hash, req.matched_output_index) else {
            continue;
        };
        let still_matched = ledger
            .transfers
            .iter()
            .any(|td| td.tx_hash == tx_hash && td.internal_output_index == out_idx);
        if still_matched {
            continue;
        }
        req.matched_tx_hash = None;
        req.matched_output_index = None;
        req.state = if req.is_expired_at(current_height) {
            PaymentRequestState::Expired
        } else {
            PaymentRequestState::Pending
        };
    }
}

/// Populate `receive_attribution` on freshly merged transfers and update requests.
pub(crate) fn apply_receive_attributions(
    payment_requests: &mut [PaymentRequest],
    ledger: &mut LedgerBlock,
    residue: &LabelResidue,
    inserted: &[usize],
) {
    if inserted.is_empty() {
        return;
    }
    for &idx in inserted {
        let Some(td) = ledger.transfer_mut(idx) else {
            continue;
        };
        // `residue` is keyed by the scanner's raw `[u8; 32]` txid; convert.
        let key = (td.tx_hash.to_bytes(), td.internal_output_index);
        let label_pt = residue
            .get(&key)
            .copied()
            .unwrap_or_else(shekyl_crypto_pq::label::sentinel_plaintext);
        let attribution = match_inbound_attribution(
            &label_pt,
            td.amount(),
            td.block_height,
            td.tx_hash,
            td.internal_output_index,
            payment_requests,
        );
        td.receive_attribution = attribution;
    }
}

/// Core matching rules per `SUBADDRESS_UNDER_PQC.md` §5.7.9 (rid + amount).
///
/// Ungated (R2-F8 wallet flag retired 2026-06-15): a sentinel plaintext maps
/// to `Unattributed`, so always classifying is a no-op for non-cooperative
/// senders and the natural behavior for cooperative ones.
pub fn match_inbound_attribution(
    label_plaintext: &[u8; 8],
    amount_atomic: AtomicUnits,
    _block_height: u64,
    tx_hash: TxHash,
    output_index: u64,
    payment_requests: &mut [PaymentRequest],
) -> ReceiveAttribution {
    match classify_label_plaintext(label_plaintext) {
        LabelPlaintextKind::Sentinel => ReceiveAttribution::Unattributed,
        LabelPlaintextKind::Unknown(pt) => ReceiveAttribution::LabelUnknown {
            echoed_label_hash: hash_label_plaintext_for_display(&pt),
        },
        LabelPlaintextKind::Request(rid) => {
            let id = PaymentRequestId(rid);
            let mut match_idx = None;
            for (i, req) in payment_requests.iter().enumerate() {
                if req.id != id {
                    continue;
                }
                if req.amount_atomic != amount_atomic {
                    continue;
                }
                if !matches!(
                    req.state,
                    PaymentRequestState::Pending | PaymentRequestState::Expired
                ) {
                    continue;
                }
                if match_idx.is_some() {
                    return ReceiveAttribution::LabelUnknown {
                        echoed_label_hash: hash_label_plaintext_for_display(label_plaintext),
                    };
                }
                match_idx = Some(i);
            }
            if let Some(i) = match_idx {
                payment_requests[i].state = PaymentRequestState::Matched;
                payment_requests[i].matched_tx_hash = Some(tx_hash);
                payment_requests[i].matched_output_index = Some(output_index);
                return ReceiveAttribution::Matched(id);
            }
            ReceiveAttribution::LabelUnknown {
                echoed_label_hash: hash_label_plaintext_for_display(label_plaintext),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_crypto_pq::label::encode_request_plaintext;
    use shekyl_engine_state::LocalLabel;

    fn sample_request(id: u64, amount: u64) -> PaymentRequest {
        PaymentRequest {
            id: PaymentRequestId(id),
            label: LocalLabel::from_str("inv"),
            amount_atomic: AtomicUnits::from_raw(amount),
            created_at: 1,
            expiry: None,
            state: PaymentRequestState::Pending,
            matched_tx_hash: None,
            matched_output_index: None,
        }
    }

    #[test]
    fn sentinel_yields_unattributed() {
        let mut reqs = vec![sample_request(1, 100)];
        let attr = match_inbound_attribution(
            &shekyl_crypto_pq::label::sentinel_plaintext(),
            AtomicUnits::from_raw(100),
            10,
            shekyl_types::TxHash::from_bytes([1u8; 32]),
            0,
            &mut reqs,
        );
        assert_eq!(attr, ReceiveAttribution::Unattributed);
        assert_eq!(reqs[0].state, PaymentRequestState::Pending);
    }

    #[test]
    fn rid_match_tier1() {
        let rid = 0x00_00_00_00_12_34_u64;
        let pt = encode_request_plaintext(rid).unwrap();
        let mut reqs = vec![sample_request(rid, 500)];
        let attr =
            match_inbound_attribution(&pt, AtomicUnits::from_raw(500), 10, [2u8; 32], 1, &mut reqs);
        assert_eq!(attr, ReceiveAttribution::Matched(PaymentRequestId(rid)));
        assert_eq!(reqs[0].state, PaymentRequestState::Matched);
        assert_eq!(reqs[0].matched_output_index, Some(1));
    }

    #[test]
    fn rid_echo_without_matching_request_is_label_unknown() {
        let rid = 99;
        let pt = encode_request_plaintext(rid).unwrap();
        let mut reqs = vec![sample_request(rid, 1)];
        // Amount mismatch (echo carries rid=99 but request expects amount 1,
        // transfer is for 2) ⇒ no match, but the echo is still classified.
        let attr =
            match_inbound_attribution(&pt, AtomicUnits::from_raw(2), 0, [0u8; 32], 0, &mut reqs);
        assert!(matches!(attr, ReceiveAttribution::LabelUnknown { .. }));
        assert_eq!(reqs[0].state, PaymentRequestState::Pending);
    }

    #[test]
    fn expired_request_rid_echo_still_matches() {
        let rid = 42;
        let pt = encode_request_plaintext(rid).unwrap();
        let mut reqs = vec![sample_request(rid, 100)];
        reqs[0].state = PaymentRequestState::Expired;
        let attr =
            match_inbound_attribution(&pt, AtomicUnits::from_raw(100), 10, [3u8; 32], 0, &mut reqs);
        assert_eq!(attr, ReceiveAttribution::Matched(PaymentRequestId(rid)));
        assert_eq!(reqs[0].state, PaymentRequestState::Matched);
    }

    #[test]
    fn rewind_matched_request_when_transfer_reorged_out() {
        use shekyl_engine_state::LedgerBlock;

        let rid = 7;
        let tx_hash = shekyl_types::TxHash::from_bytes([0xAB; 32]);
        let mut reqs = vec![sample_request(rid, 50)];
        reqs[0].state = PaymentRequestState::Matched;
        reqs[0].matched_tx_hash = Some(tx_hash);
        reqs[0].matched_output_index = Some(0);

        let ledger = LedgerBlock::empty();
        rewind_matched_payment_requests_after_reorg(&mut reqs, &ledger);
        assert_eq!(reqs[0].state, PaymentRequestState::Pending);
        assert!(reqs[0].matched_tx_hash.is_none());
    }

    #[test]
    fn rewind_keeps_match_when_transfer_survives() {
        use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
        use shekyl_engine_state::{transfer::TransferDetails, LedgerBlock};
        use shekyl_oxide::primitives::Commitment;

        let rid = 8;
        let tx_hash = shekyl_types::TxHash::from_bytes([0xCD; 32]);
        let mut reqs = vec![sample_request(rid, 50)];
        reqs[0].state = PaymentRequestState::Matched;
        reqs[0].matched_tx_hash = Some(tx_hash);
        reqs[0].matched_output_index = Some(1);

        let mut ledger = LedgerBlock::empty();
        ledger.transfers.push(TransferDetails {
            tx_hash,
            internal_output_index: 1,
            global_output_index: 0,
            block_height: 5,
            key: ED25519_BASEPOINT_POINT,
            key_offset: Scalar::ONE,
            commitment: Commitment::new(Scalar::ONE, 50),
            payment_id: None,
            spent: false,
            spent_height: None,
            key_image: None,
            staked: false,
            stake_tier: 0,
            stake_lock_until: 0,
            last_claimed_height: 0,
            source_ciphertext: None,
            output_handle: None,
            eligible_height: 0,
            frozen: false,
            fcmp_precomputed_path: None,
            receive_attribution: ReceiveAttribution::Matched(PaymentRequestId(rid)),
        });

        rewind_matched_payment_requests_after_reorg(&mut reqs, &ledger);
        assert_eq!(reqs[0].state, PaymentRequestState::Matched);
        assert_eq!(reqs[0].matched_tx_hash, Some(tx_hash));
    }
}
