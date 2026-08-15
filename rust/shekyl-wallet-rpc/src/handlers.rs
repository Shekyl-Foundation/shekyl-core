// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! JSON-RPC method dispatch.
//!
//! Phase 4b + WI-RPC-1/2a/3/4 + Phase 4c `rescan_blockchain`.

use serde_json::Value;
use shekyl_crypto_pq::wallet_envelope::KdfParams;

use crate::error::WalletRpcError;
use crate::fees;
use crate::lifecycle;
use crate::message_signing;
use crate::notes;
use crate::proofs;
use crate::queries;
use crate::receiving;
use crate::send;
use crate::staking;
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
    // Single routing table: method name → leaf handler. Keeping this the only
    // place method names are matched avoids the drift a per-module second
    // dispatch would invite (a new method silently 404ing on a missed arm).
    match method {
        "get_version" => get_version(params),
        "create_wallet" => lifecycle::create_wallet(tenants, params, kdf).await,
        "restore_wallet" => lifecycle::restore_wallet(tenants, params, kdf).await,
        "open_wallet" => lifecycle::open_wallet(tenants, params).await,
        "close_wallet" => lifecycle::close_wallet(tenants, params).await,
        "change_password" => lifecycle::change_password(tenants, params).await,
        "get_balance" => queries::get_balance(tenants, params).await,
        "get_primary_address" => queries::get_primary_address(tenants, params).await,
        "get_wallet_info" => queries::get_wallet_info(tenants, params).await,
        "get_transfers" => queries::get_transfers(tenants, params).await,
        "get_transfer_by_id" => queries::get_transfer_by_id(tenants, params).await,
        "get_height" => queries::get_height(tenants, params).await,
        "refresh" => sync::refresh(tenants, params).await,
        "rescan_blockchain" => sync::rescan_blockchain(tenants, params).await,
        "build_pending_tx" => send::build_pending_tx(tenants, params).await,
        "stake" => lifecycle::stake(tenants, params).await,
        "submit_pending_tx" => send::submit_pending_tx(tenants, params).await,
        "discard_pending_tx" => send::discard_pending_tx(tenants, params).await,
        "abandon_tx" => send::abandon_tx(tenants, params).await,
        "set_tx_note" => notes::set_tx_note(tenants, params).await,
        "get_tx_note" => notes::get_tx_note(tenants, params).await,
        // WI-RPC-1 receiving (FA-8d projection; `rid` on the URI — no
        // subaddress/account model exists in Shekyl).
        "create_payment_request" => receiving::create_payment_request(tenants, params).await,
        "list_payment_requests" => receiving::list_payment_requests(tenants, params).await,
        "make_uri" => receiving::make_uri(tenants, params).await,
        "parse_uri" => receiving::parse_uri(tenants, params),
        // WI-RPC-1 fees (projection of the one Phase-2a byte/fee model).
        "estimate_tx_size_and_weight" => fees::estimate_tx_size_and_weight(tenants, params).await,
        "get_default_fee_priority" => fees::get_default_fee_priority(tenants, params).await,
        // WI-RPC-1 staking reads (authoritative pscan/pending aggregation —
        // never the `bonded_slots` hint). Staking actions stay `-32601`.
        "get_staked_balance" => staking::get_staked_balance(tenants, params).await,
        "get_staked_outputs" => staking::get_staked_outputs(tenants, params).await,
        "staking_info" => staking::staking_info(tenants, params).await,
        // WI-RPC-3 proofs. The `get_*` pair requires an open wallet; the
        // `check_*` pair is WALLET-LESS by contract (a verifier checks
        // someone else's proof against the chain).
        "get_tx_proof" => proofs::get_tx_proof(tenants, params).await,
        "check_tx_proof" => proofs::check_tx_proof(tenants, params).await,
        "get_reserve_proof" => proofs::get_reserve_proof(tenants, params).await,
        "check_reserve_proof" => proofs::check_reserve_proof(tenants, params).await,
        // PR-SM-2 message signing. `sign_message` requires the open
        // wallet; `verify_message` is SESSION-LESS by contract (SM-R-6) —
        // all its inputs are public and caller-supplied.
        "sign_message" => message_signing::sign_message(tenants, params).await,
        "verify_message" => message_signing::verify_message(tenants, params).await,
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
    use crate::tenant::{DaemonEndpoint, TenantState};
    use serde_json::json;
    use shekyl_engine_core::Network;

    fn test_tenants() -> tokio::sync::Mutex<TenantState> {
        tokio::sync::Mutex::new(TenantState::new(
            std::env::temp_dir(),
            Network::Stagenet,
            DaemonEndpoint {
                address: "http://127.0.0.1:1".into(),
                proxy: None,
            },
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
    async fn rescan_without_open_wallet_is_wallet_not_open() {
        let tenants = test_tenants();
        let err = dispatch(
            &tenants,
            "rescan_blockchain",
            &json!({}),
            KdfParams::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::WalletNotOpen);
    }

    /// A RESERVED-but-unimplemented method still falls through to
    /// `MethodNotFound`. Kept alongside the rescan case above: routing
    /// new methods must not blur the line between "designed but not
    /// built" (`-32601`) and "built, but the call is refused". (The
    /// example was `sign_message` until PR-SM-2 implemented it.)
    #[tokio::test]
    async fn unimplemented_reserved_method_is_method_not_found() {
        let tenants = test_tenants();
        let err = dispatch(&tenants, "unstake", &json!({}), KdfParams::default())
            .await
            .unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::MethodNotFound);
    }

    /// `sign_message` is routed: with no wallet open the answer is the
    /// wallet gate, never the `-32601` fallthrough. Params must be valid —
    /// parsing runs ahead of the gate.
    #[tokio::test]
    async fn sign_message_without_open_wallet_is_wallet_not_open() {
        let tenants = test_tenants();
        let err = dispatch(
            &tenants,
            "sign_message",
            &json!({ "message": "m" }),
            KdfParams::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::WalletNotOpen);
    }

    /// `verify_message` is SESSION-LESS (SM-R-6): with no wallet open it
    /// must never answer `WalletNotOpen`. A malformed signature string is
    /// the shape-first `-32602` refusal.
    ///
    /// Multi-thread flavor: the handler wraps the verify pipeline in
    /// `block_in_place`, which panics on a current-thread runtime.
    #[tokio::test(flavor = "multi_thread")]
    async fn verify_message_is_session_less_and_shape_gates_first() {
        let tenants = test_tenants();
        let err = dispatch(
            &tenants,
            "verify_message",
            &json!({ "address": "x", "message": "m", "signature": "junk" }),
            KdfParams::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::InvalidParams);
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
    async fn get_tx_proof_without_open_wallet_is_wallet_not_open() {
        // Params parse before the wallet gate, so supply valid ones.
        let tenants = test_tenants();
        let err = dispatch(
            &tenants,
            "get_tx_proof",
            &json!({ "txid": "ab".repeat(32), "address": "x" }),
            KdfParams::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::WalletNotOpen);
    }

    #[tokio::test]
    async fn check_tx_proof_is_wallet_less_and_gates_on_params_first() {
        // No wallet is open; the wallet-less check must NOT answer
        // WalletNotOpen. With an undecodable address it refuses -29100
        // before dialing the (unreachable) test daemon.
        let tenants = test_tenants();
        let err = dispatch(
            &tenants,
            "check_tx_proof",
            &json!({ "txid": "ab".repeat(32), "address": "junk", "proof": "junk" }),
            KdfParams::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::InvalidRecipient);
    }

    /// Both note methods are routed, not RESERVED.
    ///
    /// The pin that matters is `WalletNotOpen` rather than `MethodNotFound`:
    /// dropping either arm from the table above sends the call to the
    /// `other =>` fallthrough, and every client loses the ability to annotate
    /// or read back a transaction while the crate's tests stay green. The
    /// `set_tx_note` params must be *valid* — parsing and the length bound run
    /// ahead of the wallet gate, so junk params would answer `InvalidParams`
    /// and pin nothing about routing.
    #[tokio::test]
    async fn tx_note_methods_without_open_wallet_are_wallet_not_open() {
        let tenants = test_tenants();

        let err = dispatch(
            &tenants,
            "set_tx_note",
            &json!({ "tx_hash": "ab".repeat(32), "note": "rent" }),
            KdfParams::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), WalletRpcErrorCode::WalletNotOpen);

        let err = dispatch(
            &tenants,
            "get_tx_note",
            &json!({ "tx_hash": "ab".repeat(32) }),
            KdfParams::default(),
        )
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
