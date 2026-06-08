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

/// Populate `receive_attribution` on freshly merged transfers and update requests.
pub(crate) fn apply_receive_attributions(
    payment_requests: &mut [PaymentRequest],
    ledger: &mut LedgerBlock,
    cooperative_enabled: bool,
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
            cooperative_enabled,
            &label_pt,
            td.amount().to_raw(),
            td.block_height,
            td.tx_hash,
            td.internal_output_index,
            payment_requests,
        );
        td.receive_attribution = attribution;
    }
}

/// Core matching rules per `SUBADDRESS_UNDER_PQC.md` §5.7.9 (rid + amount).
pub fn match_inbound_attribution(
    cooperative_enabled: bool,
    label_plaintext: &[u8; 8],
    amount_atomic: u64,
    _block_height: u64,
    tx_hash: [u8; 32],
    output_index: u64,
    payment_requests: &mut [PaymentRequest],
) -> ReceiveAttribution {
    if !cooperative_enabled {
        return ReceiveAttribution::Unattributed;
    }

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
            amount_atomic: amount,
            created_at: 1,
            expiry: None,
            state: PaymentRequestState::Pending,
            matched_tx_hash: None,
            matched_output_index: None,
        }
    }

    #[test]
    fn sentinel_yields_unattributed_when_cooperative_on() {
        let mut reqs = vec![sample_request(1, 100)];
        let attr = match_inbound_attribution(
            true,
            &shekyl_crypto_pq::label::sentinel_plaintext(),
            100,
            10,
            [1u8; 32],
            0,
            &mut reqs,
        );
        assert_eq!(attr, ReceiveAttribution::Unattributed);
        assert_eq!(reqs[0].state, PaymentRequestState::Pending);
    }

    #[test]
    fn cooperative_rid_match_tier1() {
        let rid = 0x00_00_00_00_12_34_u64;
        let pt = encode_request_plaintext(rid).unwrap();
        let mut reqs = vec![sample_request(rid, 500)];
        let attr = match_inbound_attribution(true, &pt, 500, 10, [2u8; 32], 1, &mut reqs);
        assert_eq!(attr, ReceiveAttribution::Matched(PaymentRequestId(rid)));
        assert_eq!(reqs[0].state, PaymentRequestState::Matched);
        assert_eq!(reqs[0].matched_output_index, Some(1));
    }

    #[test]
    fn feature_off_ignores_request_tag() {
        let rid = 99;
        let pt = encode_request_plaintext(rid).unwrap();
        let mut reqs = vec![sample_request(rid, 1)];
        let attr = match_inbound_attribution(false, &pt, 1, 0, [0u8; 32], 0, &mut reqs);
        assert_eq!(attr, ReceiveAttribution::Unattributed);
    }

    #[test]
    fn expired_request_rid_echo_still_matches() {
        let rid = 42;
        let pt = encode_request_plaintext(rid).unwrap();
        let mut reqs = vec![sample_request(rid, 100)];
        reqs[0].state = PaymentRequestState::Expired;
        let attr = match_inbound_attribution(true, &pt, 100, 10, [3u8; 32], 0, &mut reqs);
        assert_eq!(attr, ReceiveAttribution::Matched(PaymentRequestId(rid)));
        assert_eq!(reqs[0].state, PaymentRequestState::Matched);
    }
}
