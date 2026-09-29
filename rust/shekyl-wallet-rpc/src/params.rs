// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared JSON-RPC params-shape validation.
//!
//! One copy of each params gate, used by every method module so the
//! not-an-object / extra-params error wording stays uniform.

use serde::Deserialize;
use serde_json::Value;
use shekyl_engine_state::PaymentRequestId;

use crate::error::WalletRpcError;

/// Accept only an omitted (`null`) or empty params object; reject a populated
/// object or a non-object for a method that takes no parameters.
pub(crate) fn require_empty_object(params: &Value, method: &str) -> Result<(), WalletRpcError> {
    match params {
        Value::Null => Ok(()),
        Value::Object(map) if map.is_empty() => Ok(()),
        Value::Object(_) => Err(WalletRpcError::InvalidParams(format!(
            "{method} takes no parameters"
        ))),
        _ => Err(WalletRpcError::InvalidParams(format!(
            "{method} params must be an object or omitted"
        ))),
    }
}

/// Deserialize a required params object; `null` is an error.
pub(crate) fn parse_required_object<T: for<'de> Deserialize<'de>>(
    params: &Value,
    method: &str,
) -> Result<T, WalletRpcError> {
    match params {
        Value::Null => Err(WalletRpcError::InvalidParams(format!(
            "{method} requires a params object"
        ))),
        Value::Object(_) => serde_json::from_value(params.clone())
            .map_err(|e| WalletRpcError::InvalidParams(format!("{method} params: {e}"))),
        _ => Err(WalletRpcError::InvalidParams(format!(
            "{method} params must be an object"
        ))),
    }
}

/// Deserialize an optional params object; `null` yields `T::default()`.
pub(crate) fn parse_optional_object<T: for<'de> Deserialize<'de> + Default>(
    params: &Value,
    method: &str,
) -> Result<T, WalletRpcError> {
    match params {
        Value::Null => Ok(T::default()),
        Value::Object(_) => serde_json::from_value(params.clone())
            .map_err(|e| WalletRpcError::InvalidParams(format!("{method} params: {e}"))),
        _ => Err(WalletRpcError::InvalidParams(format!(
            "{method} params must be an object or omitted"
        ))),
    }
}

/// Parse a `rid` param (the contract's `PaymentRequestId`): a decimal
/// string that is non-zero and fits the u48 wire encoding, through the id
/// type's one door; anything else is rejected rather than silently dropped.
///
/// One home for the rid-string contract shared by `make_uri` and
/// `build_pending_tx`. The messages are stable and never reflect the
/// client-supplied string.
pub(crate) fn parse_rid(s: &str) -> Result<PaymentRequestId, WalletRpcError> {
    let raw: u64 = s.parse().map_err(|_| {
        WalletRpcError::InvalidParams("rid must be a decimal integer string".into())
    })?;
    PaymentRequestId::from_wire_rid(raw).ok_or_else(|| {
        WalletRpcError::InvalidParams("rid must be non-zero and fit the u48 wire encoding".into())
    })
}

/// Parse a contract `Hex32` value (exactly 64 **lowercase** hex chars) into
/// its 32 bytes.
///
/// One home for the canonical-hex rule shared by the txid params surface
/// (`proofs::parse_txid`) and the transfer-id format
/// (`project::parse_transfer_id`). Returns `None` on any non-canonical
/// form; callers shape their own error per surface (the messages there are
/// load-bearing and stable).
pub(crate) fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(s, &mut bytes).ok()?;
    Some(bytes)
}
