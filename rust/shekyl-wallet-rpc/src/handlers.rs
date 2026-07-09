// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! JSON-RPC method dispatch.
//!
//! Phase 4b: `get_version`, lifecycle, read queries, `refresh`, and
//! send lifecycle. `rescan_blockchain` stays `-32601`.

use serde_json::Value;
use shekyl_crypto_pq::wallet_envelope::KdfParams;

use crate::error::WalletRpcError;
use crate::lifecycle;
use crate::queries;
use crate::send;
use crate::sync;
use crate::tenant::TenantState;
use crate::types::{GetVersionResult, API_VERSION};
use crate::VERSION;

/// Dispatch a validated JSON-RPC method call.
pub async fn dispatch(
    tenants: &tokio::sync::Mutex<TenantState>,
    method: &str,
    params: &Value,
    kdf: KdfParams,
) -> Result<Value, WalletRpcError> {
    match method {
        "get_version" => get_version(params),
        "create_wallet" | "open_wallet" | "close_wallet" | "change_password" => {
            lifecycle::dispatch(tenants, method, params, kdf).await
        }
        "get_balance"
        | "get_primary_address"
        | "get_transfers"
        | "get_transfer_by_id"
        | "get_height" => queries::dispatch(tenants, method, params).await,
        "refresh" | "rescan_blockchain" => sync::dispatch(tenants, method, params).await,
        "build_pending_tx" | "submit_pending_tx" | "discard_pending_tx" => {
            send::dispatch(tenants, method, params).await
        }
        other => Err(WalletRpcError::MethodNotFound(other.to_owned())),
    }
}

fn get_version(params: &Value) -> Result<Value, WalletRpcError> {
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
    use crate::tenant::TenantState;
    use serde_json::json;
    use shekyl_engine_core::Network;

    fn test_tenants() -> tokio::sync::Mutex<TenantState> {
        tokio::sync::Mutex::new(TenantState::new(
            std::env::temp_dir(),
            Network::Stagenet,
            "http://127.0.0.1:1".into(),
        ))
    }

    #[tokio::test]
    async fn get_version_null_params() {
        let tenants = test_tenants();
        let v = dispatch(&tenants, "get_version", &Value::Null, KdfParams::default())
            .await
            .expect("ok");
        assert_eq!(v["api_version"], API_VERSION);
        assert_eq!(v["version"], VERSION);
    }

    #[tokio::test]
    async fn get_version_empty_object() {
        let tenants = test_tenants();
        let v = dispatch(&tenants, "get_version", &json!({}), KdfParams::default())
            .await
            .expect("ok");
        assert_eq!(v["api_version"], API_VERSION);
    }

    #[tokio::test]
    async fn get_version_rejects_extra_fields() {
        let tenants = test_tenants();
        let err = dispatch(
            &tenants,
            "get_version",
            &json!({"x": 1}),
            KdfParams::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::InvalidParams);
    }

    #[tokio::test]
    async fn unimplemented_specified_method_is_method_not_found() {
        let tenants = test_tenants();
        let err = dispatch(
            &tenants,
            "rescan_blockchain",
            &json!({}),
            KdfParams::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::MethodNotFound);
    }

    #[tokio::test]
    async fn send_without_open_wallet_is_wallet_not_open() {
        let tenants = test_tenants();
        let err = dispatch(
            &tenants,
            "discard_pending_tx",
            &json!({ "pending_tx_id": "1" }),
            KdfParams::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::WalletNotOpen);
    }

    #[tokio::test]
    async fn refresh_without_open_wallet_is_wallet_not_open() {
        let tenants = test_tenants();
        let err = dispatch(&tenants, "refresh", &json!({}), KdfParams::default())
            .await
            .unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::WalletNotOpen);
    }

    #[tokio::test]
    async fn unknown_method_is_method_not_found() {
        let tenants = test_tenants();
        let err = dispatch(&tenants, "getbalance", &Value::Null, KdfParams::default())
            .await
            .unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::MethodNotFound);
    }

    #[tokio::test]
    async fn query_without_open_wallet_is_wallet_not_open() {
        let tenants = test_tenants();
        let err = dispatch(&tenants, "get_balance", &json!({}), KdfParams::default())
            .await
            .unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::WalletNotOpen);
    }
}
