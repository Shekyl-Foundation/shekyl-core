// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! HTTP-level conformance tests for `rescan_blockchain` (Phase 4c).
//!
//! Lives in its own file rather than riding along in `http_get_version.rs`:
//! the wire contract for a destructive method is worth finding by name.
//! Engine-side behaviour (what the reset preserves, what refuses it) is
//! covered in `shekyl-engine-core::engine::rescan`; these tests pin the
//! transport-visible half — routing, params validation, and error codes.

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

/// `rescan_blockchain` is routed, not RESERVED: with no wallet open it
/// answers the lifecycle refusal `-29001`, never `-32601`. This is the
/// assertion that would regress if the dispatch arm were dropped.
#[tokio::test]
async fn rescan_without_wallet_is_wallet_not_open() {
    let (status, json) = post_json(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "rescan_blockchain",
        "params": {}
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.get("result").is_none());
    assert_eq!(json["error"]["code"], -29001);
}

/// Params are contractually an empty object; anything else is `-32602`.
/// Pinned so that the `-32602` code stays attached to genuinely malformed
/// requests — the reason a rescan blocked by in-flight transactions gets
/// `-29202` (a state conflict) instead of being folded in here.
#[tokio::test]
async fn rescan_with_non_empty_params_is_invalid_params() {
    let (status, json) = post_json(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "rescan_blockchain",
        "params": { "hard": true }
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.get("result").is_none());
    assert_eq!(json["error"]["code"], -32602);
}

/// Omitted `params` is accepted the same way `refresh` accepts it — a
/// no-parameter method should not require the client to send `{}`.
#[tokio::test]
async fn rescan_without_params_still_reaches_the_wallet_check() {
    let (status, json) = post_json(json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "rescan_blockchain"
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["error"]["code"], -29001);
}
