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

use shekyl_address::PaymentUri;
use shekyl_crypto_pq::label::{encode_request_plaintext, sentinel_plaintext};

/// Label plaintext to encrypt in `construct_output` for a destination.
///
/// Echoes the REQUEST tag when `uri.rid` is present and u48-encodable (per
/// `SUBADDRESS_UNDER_PQC.md` §5.7.11); a missing or out-of-range `rid` yields
/// the normative sentinel.
#[must_use]
pub fn label_plaintext_for_payment_uri(uri: &PaymentUri) -> [u8; 8] {
    let Some(rid) = uri.rid else {
        return sentinel_plaintext();
    };
    encode_request_plaintext(rid).unwrap_or_else(sentinel_plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_address::parse_payment_uri;
    use shekyl_crypto_pq::label::{classify_label_plaintext, LabelPlaintextKind};

    #[test]
    fn no_rid_is_sentinel() {
        let uri = parse_payment_uri("shekyl:addr?amount=1").unwrap();
        let pt = label_plaintext_for_payment_uri(&uri);
        assert_eq!(classify_label_plaintext(&pt), LabelPlaintextKind::Sentinel);
    }

    #[test]
    fn rid_is_echoed() {
        let uri = parse_payment_uri("shekyl:addr?rid=12345").unwrap();
        let pt = label_plaintext_for_payment_uri(&uri);
        assert_eq!(
            classify_label_plaintext(&pt),
            LabelPlaintextKind::Request(12345)
        );
    }
}
