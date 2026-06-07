// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Outbound `enc_label` plaintext selection for cooperative sends (FA-8c).

use shekyl_address::PaymentUri;
use shekyl_crypto_pq::label::{encode_request_plaintext, sentinel_plaintext};

/// Label plaintext to encrypt in `construct_output` for a destination.
///
/// When cooperative payment requests are disabled, always returns the
/// normative sentinel. When enabled and `uri.rid` is present, echoes the
/// REQUEST tag per `SUBADDRESS_UNDER_PQC.md` §5.7.11.
#[must_use]
pub fn label_plaintext_for_payment_uri(cooperative_enabled: bool, uri: &PaymentUri) -> [u8; 8] {
    if !cooperative_enabled {
        return sentinel_plaintext();
    }
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
    fn cooperative_off_always_sentinel() {
        let uri = parse_payment_uri("shekyl:addr?rid=42").unwrap();
        let pt = label_plaintext_for_payment_uri(false, &uri);
        assert_eq!(classify_label_plaintext(&pt), LabelPlaintextKind::Sentinel);
    }

    #[test]
    fn cooperative_on_echoes_rid() {
        let uri = parse_payment_uri("shekyl:addr?rid=12345").unwrap();
        let pt = label_plaintext_for_payment_uri(true, &uri);
        assert_eq!(
            classify_label_plaintext(&pt),
            LabelPlaintextKind::Request(12345)
        );
    }
}
