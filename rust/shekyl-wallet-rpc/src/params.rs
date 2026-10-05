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

/// Parse a `rid` param (the contract's `PaymentRequestId`): its canonical
/// grammar `^[1-9][0-9]*$` and the u48 wire bound, through the id type's
/// own `FromStr`; anything else is rejected rather than silently dropped.
///
/// One home for the rid-string contract shared by `make_uri` and
/// `build_pending_tx`. The messages are stable and never reflect the
/// client-supplied string.
pub(crate) fn parse_rid(s: &str) -> Result<PaymentRequestId, WalletRpcError> {
    s.parse::<PaymentRequestId>()
        .map_err(|e| WalletRpcError::InvalidParams(e.to_string()))
}

/// Parse a contract `Hex32` value into its 32 bytes.
///
/// The rule lives in [`shekyl_wallet_contract::canonical_hex`]; this is
/// the name the RPC params surface already calls. Returns `None` on any
/// non-canonical form; callers shape their own error per surface.
pub(crate) fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    shekyl_wallet_contract::canonical_hex::parse_lowercase_hex32(s)
}
