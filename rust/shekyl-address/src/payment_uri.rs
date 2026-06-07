// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Payment-request URI parsing (`shekyl:…?amount=&label=&rid=&expiry=`).
//!
//! Normative: `docs/design/SUBADDRESS_UNDER_PQC.md` §5.7.9.

use thiserror::Error;

/// Parsed cooperative payment URI (query parameters are optional except address).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentUri {
    /// Bech32m-encoded primary address (may include `shekyl1` / segment separator).
    pub address: String,
    pub amount_atomic: Option<u64>,
    pub label: Option<String>,
    pub rid: Option<u64>,
    pub expiry: Option<u64>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PaymentUriError {
    #[error("empty URI")]
    Empty,
    #[error("missing shekyl: scheme")]
    MissingScheme,
    #[error("invalid amount")]
    InvalidAmount,
    #[error("invalid rid")]
    InvalidRid,
    #[error("invalid expiry")]
    InvalidExpiry,
}

/// Parse `shekyl:<address>?amount=&label=&rid=&expiry=`.
pub fn parse_payment_uri(uri: &str) -> Result<PaymentUri, PaymentUriError> {
    let uri = uri.trim();
    if uri.is_empty() {
        return Err(PaymentUriError::Empty);
    }
    let rest = uri
        .strip_prefix("shekyl:")
        .ok_or(PaymentUriError::MissingScheme)?;
    let (address_part, query) = match rest.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (rest, None),
    };
    let address = address_part.trim().to_string();
    if address.is_empty() {
        return Err(PaymentUriError::Empty);
    }

    let mut amount_atomic = None;
    let mut label = None;
    let mut rid = None;
    let mut expiry = None;

    if let Some(q) = query {
        for pair in q.split('&') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair
                .split_once('=')
                .map(|(k, v)| (k.trim(), v.trim()))
                .unwrap_or((pair, ""));
            match key {
                "amount" => {
                    amount_atomic = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| PaymentUriError::InvalidAmount)?,
                    );
                }
                "label" if !value.is_empty() => {
                    label = Some(value.to_string());
                }
                "rid" => {
                    let parsed = value
                        .parse::<u64>()
                        .map_err(|_| PaymentUriError::InvalidRid)?;
                    if parsed == 0 {
                        return Err(PaymentUriError::InvalidRid);
                    }
                    rid = Some(parsed);
                }
                "expiry" => {
                    expiry = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| PaymentUriError::InvalidExpiry)?,
                    );
                }
                _ => {}
            }
        }
    }

    Ok(PaymentUri {
        address,
        amount_atomic,
        label,
        rid,
        expiry,
    })
}

/// Format a payment URI for display / QR encoding.
pub fn format_payment_uri(
    address: &str,
    amount_atomic: Option<u64>,
    label: Option<&str>,
    rid: Option<u64>,
    expiry: Option<u64>,
) -> String {
    let mut out = format!("shekyl:{address}");
    let mut params = Vec::new();
    if let Some(a) = amount_atomic {
        params.push(format!("amount={a}"));
    }
    if let Some(l) = label.filter(|s| !s.is_empty()) {
        params.push(format!("label={l}"));
    }
    if let Some(r) = rid {
        params.push(format!("rid={r}"));
    }
    if let Some(e) = expiry {
        params.push(format!("expiry={e}"));
    }
    if !params.is_empty() {
        out.push('?');
        out.push_str(&params.join("&"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_address_only() {
        let p = parse_payment_uri("shekyl:shekyl1abc").unwrap();
        assert_eq!(p.address, "shekyl1abc");
        assert!(p.amount_atomic.is_none());
    }

    #[test]
    fn parse_full_query() {
        let p = parse_payment_uri(
            "shekyl:shekyl1abc?amount=150000000000&label=INV-42&rid=9001&expiry=500",
        )
        .unwrap();
        assert_eq!(p.amount_atomic, Some(150_000_000_000));
        assert_eq!(p.label.as_deref(), Some("INV-42"));
        assert_eq!(p.rid, Some(9001));
        assert_eq!(p.expiry, Some(500));
    }

    #[test]
    fn format_roundtrip_rid() {
        let uri = format_payment_uri("shekyl1test", Some(100), Some("x"), Some(42), None);
        let p = parse_payment_uri(&uri).unwrap();
        assert_eq!(p.rid, Some(42));
        assert_eq!(p.amount_atomic, Some(100));
    }
}
