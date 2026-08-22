// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! HTTP-level conformance tests for `abandon_tx` (PR-SJ-3).
//!
//! Same shape as `http_rescan.rs`: these pin the transport-visible half
//! — routing, params validation, and error codes. Engine-side behaviour
//! (the P3-4 edge, the I-2 reference migration, the drop-then-confirm
//! crash ordering) is covered in
//! `shekyl-engine-core::engine::local_ledger_ops::abandon_tx`.

use std::sync::Arc;

use axum::body::Body;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_core::Network;
use shekyl_wallet_rpc::auth::AuthConfig;
use shekyl_wallet_rpc::server::{build_router, AppState};
use shekyl_wallet_rpc::tenant::{DaemonEndpoint, TenantState};
use tokio::sync::Notify;
use tower::ServiceExt;

/// Fast Argon2id for tests (matches engine-core lifecycle tests).
fn test_kdf() -> KdfParams {
    KdfParams {
        m_log2: 0x08,
        t: 1,
        p: 1,
    }
}

fn test_state() -> Arc<AppState> {
    Arc::new(AppState {
        tenants: tokio::sync::Mutex::new(TenantState::new(
            std::env::temp_dir(),
            Network::Stagenet,
            DaemonEndpoint {
                address: "http://127.0.0.1:1".into(),
                proxy: None,
            },
        )),
        auth: AuthConfig::Disabled,
        kdf: test_kdf(),
        shutdown: Arc::new(Notify::new()),
    })
}

async fn post_json(body: Value) -> (StatusCode, Value) {
    let app = build_router(test_state());
    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header("host", "127.0.0.1")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

/// `abandon_tx` is routed, not RESERVED: with valid params and no wallet
/// open it answers the lifecycle refusal `-29001`, never `-32601`. This
/// is the assertion that would regress if the dispatch arm were dropped.
#[tokio::test]
async fn abandon_without_wallet_is_wallet_not_open() {
    let (status, json) = post_json(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "abandon_tx",
        "params": { "tx_hash": "ab".repeat(32) }
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.get("result").is_none());
    assert_eq!(json["error"]["code"], -29001);
}

/// Shape before tenant state: a `tx_hash` this wallet could never have
/// emitted is a malformed request (`-32602`), checked before the
/// wallet-open refusal — and the stable message never echoes the
/// client's string.
#[tokio::test]
async fn abandon_with_malformed_txid_is_invalid_params() {
    let (status, json) = post_json(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "abandon_tx",
        "params": { "tx_hash": "not-a-txid" }
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.get("result").is_none());
    assert_eq!(json["error"]["code"], -32602);
    assert!(
        !json["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not-a-txid"),
        "the error message must not echo the client string"
    );
}

/// Missing / empty params fail the schema check, same code.
#[tokio::test]
async fn abandon_without_params_is_invalid_params() {
    let (status, json) = post_json(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "abandon_tx"
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["error"]["code"], -32602);
}
