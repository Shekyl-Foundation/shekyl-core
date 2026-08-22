// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! HTTP-level conformance tests for the `set_tx_note` / `get_tx_note` pair
//! (PR-SA-4 / SJ-DQ-7).
//!
//! Same shape and scope as `http_abandon_tx.rs`: these pin the
//! transport-visible half — routing, params validation, and error codes.
//! Engine-side behaviour (crash-atomic write, fail-closed rollback, the
//! empty-clears contract, durability across reopen) is covered in
//! `shekyl-engine-core::engine::local_ledger_ops::set_tx_note`.
//!
//! The over-length case is pinned *here*, at the boundary, and not only as a
//! unit test on the pre-check: the promise the OpenAPI document makes is about
//! the wire — `-32602` with byte counts and no note content — and only a
//! transport test can observe the message a client actually receives.

use std::sync::Arc;

use axum::body::Body;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_core::Network;
use shekyl_engine_state::TX_NOTE_MAX_BYTES;
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

/// Both note methods are routed, not RESERVED: with valid params and no
/// wallet open they answer the lifecycle refusal `-29001`, never `-32601`.
/// This is the assertion that regresses if either dispatch arm is dropped.
#[tokio::test]
async fn tx_note_methods_without_wallet_are_wallet_not_open() {
    let (status, json) = post_json(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "set_tx_note",
        "params": { "tx_hash": "ab".repeat(32), "note": "rent — March" }
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.get("result").is_none());
    assert_eq!(json["error"]["code"], -29001);

    let (status, json) = post_json(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "get_tx_note",
        "params": { "tx_hash": "ab".repeat(32) }
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.get("result").is_none());
    assert_eq!(json["error"]["code"], -29001);
}

/// A malformed `tx_hash` is a schema refusal (`-32602`) on both methods,
/// checked before the wallet-open refusal, and the message never echoes the
/// client's string.
#[tokio::test]
async fn malformed_txid_is_invalid_params_on_both_methods() {
    for (id, method) in [(3, "set_tx_note"), (4, "get_tx_note")] {
        let mut params = json!({ "tx_hash": "not-a-txid" });
        if method == "set_tx_note" {
            params["note"] = json!("rent");
        }
        let (status, json) = post_json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }))
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json.get("result").is_none(), "{method}");
        assert_eq!(json["error"]["code"], -32602, "{method}");
        assert!(
            !json["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("not-a-txid"),
            "{method}: the error message must not echo the client string"
        );
    }
}

/// An over-length note is refused at the boundary with `-32602`, before the
/// wallet-open gate — and the wire message carries byte counts only.
///
/// The canary is the point (rules 35/36): a note is counterparty-bearing free
/// text, so the one thing this refusal must never do is quote it back. The
/// assertion fires if anyone "improves" the message to include the note,
/// whether here or in the engine-owned `TxNoteTooLong` this delegates to.
#[tokio::test]
async fn over_length_note_is_invalid_params_and_never_echoes_the_note() {
    let over = format!("CANARY{}", "x".repeat(TX_NOTE_MAX_BYTES));
    let (status, json) = post_json(json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "set_tx_note",
        "params": { "tx_hash": "ab".repeat(32), "note": over }
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.get("result").is_none());
    assert_eq!(
        json["error"]["code"], -32602,
        "the length bound refuses before the wallet gate"
    );
    let message = json["error"]["message"].as_str().unwrap_or_default();
    assert!(
        !message.contains("CANARY"),
        "the refusal must not echo note content: {message}"
    );
    assert!(
        message.contains("maximum"),
        "the refusal should name the limit: {message}"
    );
}

/// Missing / empty params fail the schema check, same code, on both methods.
#[tokio::test]
async fn missing_params_is_invalid_params_on_both_methods() {
    for (id, method) in [(6, "set_tx_note"), (7, "get_tx_note")] {
        let (status, json) = post_json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method
        }))
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["error"]["code"], -32602, "{method}");
    }
}
