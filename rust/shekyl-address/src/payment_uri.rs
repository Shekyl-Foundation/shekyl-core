// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Payment-request URI parsing (`shekyl:…?amount=&label=&rid=&expiry=`).
//!
//! Normative: `docs/design/SUBADDRESS_UNDER_PQC.md` §5.7.9.

use thiserror::Error;

/// Maximum `rid` query parameter (u48 LE on wire). Keep in sync with
/// `shekyl_engine_state::PAYMENT_REQUEST_RID_U48_MAX`.
const RID_U48_MAX: u64 = (1u64 << 48) - 1;

/// True when `rid` is non-zero and fits the on-wire u48 LE encoding.
#[must_use]
pub const fn rid_fits_wire(rid: u64) -> bool {
    rid != 0 && rid <= RID_U48_MAX
}

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
    #[error("invalid percent-encoding in query value")]
    InvalidEncoding,
}

fn percent_encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

fn hex_nibble(b: u8) -> Result<u8, PaymentUriError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(PaymentUriError::InvalidEncoding),
    }
}

fn percent_decode_component(s: &str) -> Result<String, PaymentUriError> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(PaymentUriError::InvalidEncoding);
            }
            let hi = hex_nibble(bytes[i + 1])?;
            let lo = hex_nibble(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| PaymentUriError::InvalidEncoding)
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
                    label = Some(percent_decode_component(value)?);
                }
                "rid" => {
                    let parsed = value
                        .parse::<u64>()
                        .map_err(|_| PaymentUriError::InvalidRid)?;
                    if !rid_fits_wire(parsed) {
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
        params.push(format!("label={}", percent_encode_component(l)));
    }
    if let Some(r) = rid.filter(|&r| rid_fits_wire(r)) {
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

    #[test]
    fn parse_rejects_rid_above_u48() {
        let too_large = RID_U48_MAX + 1;
        let err = parse_payment_uri(&format!("shekyl:addr?rid={too_large}")).unwrap_err();
        assert_eq!(err, PaymentUriError::InvalidRid);
    }

    #[test]
    fn label_percent_encoding_roundtrip() {
        let uri = format_payment_uri("shekyl1test", None, Some("INV&42=1"), Some(7), None);
        let p = parse_payment_uri(&uri).unwrap();
        assert_eq!(p.label.as_deref(), Some("INV&42=1"));
        assert_eq!(p.rid, Some(7));
    }
}
