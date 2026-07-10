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
