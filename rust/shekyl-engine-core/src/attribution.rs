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
use shekyl_types::{OutputIndexInTx, TxHash};
use shekyl_units::AtomicUnits;

type LabelResidue = HashMap<(TxHash, OutputIndexInTx), [u8; 8]>;

/// Lift decrypted label plaintext from a scan result before merge consumes it.
pub(crate) fn collect_label_residue(
    new_transfers: &[crate::scan::DetectedTransfer],
) -> LabelResidue {
    let mut map = HashMap::with_capacity(new_transfers.len());
    for dt in new_transfers {
        let wo = dt.output.wallet_output();
        map.insert(
            (
                wo.transaction(),
                OutputIndexInTx::from_raw(wo.index_in_transaction()),
            ),
            *dt.output.label_plaintext(),
        );
    }
    map
}

/// Wall-clock Unix seconds for invoice-expiry classification (RTN-6).
pub(crate) fn unix_now() -> shekyl_types::Timestamp {
    shekyl_types::Timestamp::from_raw(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

/// After a chain reorg drops transfers at `fork_height` and above — or after
/// a rescan empties the transfer set outright — unwind `PaymentRequest` rows
/// that matched transfers that no longer exist so a replay can re-match them.
///
/// `now` is wall-clock Unix seconds an unwound request's expiry is classified
/// against. Invoice expiry is a human/off-chain deadline (`Timestamp`), not a
/// chain height: passing the scanner tip here used to classify invoices
/// against the wrong clock (RTN-6). The parameter is explicit rather than
/// read from `ledger` so tests can pin `now` independently of tip state.
///
/// [`reset_scan_derived_state`]: crate::engine::rescan::reset_scan_derived_state
pub(crate) fn rewind_matched_payment_requests_after_reorg(
    payment_requests: &mut [PaymentRequest],
    ledger: &LedgerBlock,
    now: shekyl_types::Timestamp,
) {
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
        req.state = if req.is_expired_at(now) {
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
        let key = (td.tx_hash, td.internal_output_index);
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
    _block_height: shekyl_types::BlockHeight,
    tx_hash: TxHash,
    output_index: shekyl_types::OutputIndexInTx,
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

    fn h(raw: u64) -> shekyl_types::BlockHeight {
        shekyl_types::BlockHeight::from_raw(raw)
    }
    fn o(raw: u64) -> shekyl_types::OutputIndexInTx {
        shekyl_types::OutputIndexInTx::from_raw(raw)
    }
    fn ts(raw: u64) -> shekyl_types::Timestamp {
        shekyl_types::Timestamp::from_raw(raw)
    }

    fn sample_request(id: u64, amount: u64) -> PaymentRequest {
        PaymentRequest {
            id: PaymentRequestId(id),
            label: LocalLabel::from_str("inv"),
            amount_atomic: AtomicUnits::from_raw(amount),
            created_at: shekyl_types::Timestamp::from_raw(1),
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
            h(10),
            shekyl_types::TxHash::from_bytes([1u8; 32]),
            o(0),
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
        let attr = match_inbound_attribution(
            &pt,
            AtomicUnits::from_raw(500),
            h(10),
            shekyl_types::TxHash::from_bytes([2u8; 32]),
            o(1),
            &mut reqs,
        );
        assert_eq!(attr, ReceiveAttribution::Matched(PaymentRequestId(rid)));
        assert_eq!(reqs[0].state, PaymentRequestState::Matched);
        assert_eq!(reqs[0].matched_output_index, Some(o(1)));
    }

    #[test]
    fn rid_echo_without_matching_request_is_label_unknown() {
        let rid = 99;
        let pt = encode_request_plaintext(rid).unwrap();
        let mut reqs = vec![sample_request(rid, 1)];
        // Amount mismatch (echo carries rid=99 but request expects amount 1,
        // transfer is for 2) ⇒ no match, but the echo is still classified.
        let attr = match_inbound_attribution(
            &pt,
            AtomicUnits::from_raw(2),
            h(0),
            shekyl_types::TxHash::from_bytes([0u8; 32]),
            o(0),
            &mut reqs,
        );
        assert!(matches!(attr, ReceiveAttribution::LabelUnknown { .. }));
        assert_eq!(reqs[0].state, PaymentRequestState::Pending);
    }

    #[test]
    fn expired_request_rid_echo_still_matches() {
        let rid = 42;
        let pt = encode_request_plaintext(rid).unwrap();
        let mut reqs = vec![sample_request(rid, 100)];
        reqs[0].state = PaymentRequestState::Expired;
        let attr = match_inbound_attribution(
            &pt,
            AtomicUnits::from_raw(100),
            h(10),
            shekyl_types::TxHash::from_bytes([3u8; 32]),
            o(0),
            &mut reqs,
        );
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
        reqs[0].matched_output_index = Some(o(0));

        let ledger = LedgerBlock::empty();
        rewind_matched_payment_requests_after_reorg(&mut reqs, &ledger, ts(0));
        assert_eq!(reqs[0].state, PaymentRequestState::Pending);
        assert!(reqs[0].matched_tx_hash.is_none());
    }

    /// An unwound request whose expiry has already passed is classified
    /// `Expired`, not `Pending` — invoice expiry is wall-clock `Timestamp`.
    #[test]
    fn rewind_expires_request_past_its_expiry() {
        use shekyl_engine_state::LedgerBlock;

        let mut reqs = vec![sample_request(9, 50)];
        reqs[0].state = PaymentRequestState::Matched;
        reqs[0].matched_tx_hash = Some(shekyl_types::TxHash::from_bytes([0xEF; 32]));
        reqs[0].matched_output_index = Some(o(0));
        reqs[0].expiry = Some(ts(100));

        let ledger = LedgerBlock::empty();
        rewind_matched_payment_requests_after_reorg(&mut reqs, &ledger, ts(0));
        assert_eq!(reqs[0].state, PaymentRequestState::Pending);

        reqs[0].state = PaymentRequestState::Matched;
        reqs[0].matched_tx_hash = Some(shekyl_types::TxHash::from_bytes([0xEF; 32]));
        reqs[0].matched_output_index = Some(o(0));
        rewind_matched_payment_requests_after_reorg(&mut reqs, &ledger, ts(101));
        assert_eq!(reqs[0].state, PaymentRequestState::Expired);
    }

    #[test]
    fn rewind_keeps_match_when_transfer_survives() {
        use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
        use shekyl_curve_primitives::Commitment;
        use shekyl_engine_state::{transfer::TransferDetails, LedgerBlock};

        let rid = 8;
        let tx_hash = shekyl_types::TxHash::from_bytes([0xCD; 32]);
        let mut reqs = vec![sample_request(rid, 50)];
        reqs[0].state = PaymentRequestState::Matched;
        reqs[0].matched_tx_hash = Some(tx_hash);
        reqs[0].matched_output_index = Some(o(1));

        let mut ledger = LedgerBlock::empty();
        ledger.transfers.push(TransferDetails {
            tx_hash,
            internal_output_index: shekyl_types::OutputIndexInTx::from_raw(1),
            global_output_index: shekyl_types::GlobalOutputIndex::from_raw(0),
            block_height: shekyl_types::BlockHeight::from_raw(5),
            key: ED25519_BASEPOINT_POINT,
            key_offset: Scalar::ONE,
            commitment: Commitment::new(Scalar::ONE, 50),
            payment_id: None,
            spent: false,
            spent_height: None,
            key_image: None,
            spending_tx_hash: None,
            source_ciphertext: None,
            output_handle: None,
            eligible_height: shekyl_types::BlockHeight::from_raw(0),
            frozen: false,
            unspendable: None,
            fcmp_precomputed_path: None,
            receive_attribution: ReceiveAttribution::Matched(PaymentRequestId(rid)),
        });

        rewind_matched_payment_requests_after_reorg(&mut reqs, &ledger, ts(0));
        assert_eq!(reqs[0].state, PaymentRequestState::Matched);
        assert_eq!(reqs[0].matched_tx_hash, Some(tx_hash));
    }
}
