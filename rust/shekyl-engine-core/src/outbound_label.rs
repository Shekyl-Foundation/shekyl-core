// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Outbound `enc_label` plaintext selection for payment-request sends.
//!
//! Ungated: the `enc_label` indistinguishability invariant
//! (`SUBADDRESS_UNDER_PQC.md` §5.7.10) makes real-label wire octets
//! indistinguishable from sentinel octets to any non-recipient, so populating a
//! `rid` echo withholds nothing from an observer. The de-facto feature
//! boundary is whether the `shekyl:` URI carries a `rid` — a product/GUI
//! choice, not a privacy one (the R2-F8 wallet gate was retired 2026-06-15).
//!
//! The caller is the sign pass (`sign_bridge::sign_tx`): a `TxRecipient`
//! composed from such a link carries the `rid` through `OutputDestination`
//! to [`label_plaintext_for_recipient`]; every other output encrypts the
//! sentinel.

use shekyl_crypto_pq::label::{encode_request_plaintext, sentinel_plaintext};
use shekyl_engine_state::PaymentRequestId;

/// A `rid` the u48 label field cannot carry (zero, or above u48) reached
/// output construction. Unreachable for a request `build_pending_tx`
/// admitted; typed rather than `expect`ed because it sits on the money path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("payment request id {} cannot be echoed on the wire (must be non-zero and fit u48)", .0.as_u64())]
pub struct RidNotEncodable(pub PaymentRequestId);

/// Label plaintext to encrypt into a payment output's `enc_label`.
///
/// Echoes the REQUEST tag for a `rid` (`SUBADDRESS_UNDER_PQC.md` §5.7.11);
/// `None` is the normative sentinel. A `rid` the wire cannot carry is an
/// error, never a silent sentinel: the payer asked for attribution.
pub fn label_plaintext_for_recipient(
    rid: Option<PaymentRequestId>,
) -> Result<[u8; 8], RidNotEncodable> {
    match rid {
        None => Ok(sentinel_plaintext()),
        Some(rid) => encode_request_plaintext(rid.as_u64()).ok_or(RidNotEncodable(rid)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_crypto_pq::label::{classify_label_plaintext, LabelPlaintextKind};
    use shekyl_engine_state::payment_request::PAYMENT_REQUEST_RID_U48_MAX;

    #[test]
    fn no_rid_is_sentinel() {
        let pt = label_plaintext_for_recipient(None).unwrap();
        assert_eq!(classify_label_plaintext(&pt), LabelPlaintextKind::Sentinel);
    }

    #[test]
    fn rid_is_echoed() {
        let pt = label_plaintext_for_recipient(Some(PaymentRequestId(12345))).unwrap();
        assert_eq!(
            classify_label_plaintext(&pt),
            LabelPlaintextKind::Request(12345)
        );
    }

    #[test]
    fn a_rid_the_wire_cannot_carry_is_an_error_not_a_sentinel() {
        for raw in [0, PAYMENT_REQUEST_RID_U48_MAX + 1, u64::MAX] {
            let rid = PaymentRequestId(raw);
            assert_eq!(
                label_plaintext_for_recipient(Some(rid)),
                Err(RidNotEncodable(rid))
            );
        }
        assert!(PaymentRequestId::from_wire_rid(0).is_none());
        assert!(PaymentRequestId::from_wire_rid(PAYMENT_REQUEST_RID_U48_MAX + 1).is_none());
        assert_eq!(
            PaymentRequestId::from_wire_rid(PAYMENT_REQUEST_RID_U48_MAX),
            Some(PaymentRequestId(PAYMENT_REQUEST_RID_U48_MAX))
        );
    }
}
