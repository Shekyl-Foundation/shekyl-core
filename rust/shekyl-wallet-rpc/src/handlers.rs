// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! JSON-RPC method dispatch.
//!
//! Phase 4a implements `get_version` only. Every other SPECIFIED name from
//! `docs/api/wallet_rpc.yaml` returns `-32601 method not found` until its
//! 4b sub-PR lands — the method exists in the contract but is not yet
//! callable (rule 21: do not pre-provision fake success responses).

use serde_json::Value;

use crate::error::WalletRpcError;
use crate::types::{GetVersionResult, API_VERSION};
use crate::VERSION;

/// Dispatch a validated JSON-RPC method call.
pub fn dispatch(method: &str, params: &Value) -> Result<Value, WalletRpcError> {
    match method {
        "get_version" => get_version(params),
        // SPECIFIED in the OpenAPI contract but not yet implemented (4b).
        "create_wallet"
        | "open_wallet"
        | "close_wallet"
        | "change_password"
        | "get_balance"
        | "get_primary_address"
        | "build_pending_tx"
        | "submit_pending_tx"
        | "discard_pending_tx"
        | "get_transfers"
        | "get_transfer_by_id"
        | "refresh"
        | "rescan_blockchain"
        | "get_height" => Err(WalletRpcError::MethodNotFound(method.to_owned())),
        other => Err(WalletRpcError::MethodNotFound(other.to_owned())),
    }
}

fn get_version(params: &Value) -> Result<Value, WalletRpcError> {
    // Spec: GetVersionParams is an empty object (or omitted). Reject
    // unexpected non-object / non-null params so clients cannot smuggle
    // fields that later become load-bearing.
    match params {
        Value::Null => {}
        Value::Object(map) if map.is_empty() => {}
        Value::Object(_) => {
            return Err(WalletRpcError::InvalidParams(
                "get_version takes no parameters".into(),
            ));
        }
        _ => {
            return Err(WalletRpcError::InvalidParams(
                "get_version params must be an object or omitted".into(),
            ));
        }
    }

    let result = GetVersionResult {
        version: VERSION.to_owned(),
        api_version: API_VERSION,
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_version: {e}")))
}

/// Convenience for tests / docs: the success payload shape.
pub fn get_version_result() -> GetVersionResult {
    GetVersionResult {
        version: VERSION.to_owned(),
        api_version: API_VERSION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WalletRpcErrorCode;
    use serde_json::json;

    #[test]
    fn get_version_null_params() {
        let v = dispatch("get_version", &Value::Null).expect("ok");
        assert_eq!(v["api_version"], API_VERSION);
        assert_eq!(v["version"], VERSION);
    }

    #[test]
    fn get_version_empty_object() {
        let v = dispatch("get_version", &json!({})).expect("ok");
        assert_eq!(v["api_version"], API_VERSION);
    }

    #[test]
    fn get_version_rejects_extra_fields() {
        let err = dispatch("get_version", &json!({"x": 1})).unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::InvalidParams);
    }

    #[test]
    fn unimplemented_specified_method_is_method_not_found() {
        let err = dispatch("create_wallet", &json!({})).unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::MethodNotFound);
    }

    #[test]
    fn unknown_method_is_method_not_found() {
        let err = dispatch("getbalance", &Value::Null).unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::MethodNotFound);
    }
}
