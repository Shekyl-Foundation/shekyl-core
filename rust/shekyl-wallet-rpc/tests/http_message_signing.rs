// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! HTTP-level conformance tests for the PR-SM-2 message-signing surface:
//! `sign_message` / `verify_message` dispatch wiring, wire shapes, and the
//! SM-R-6 error taxonomy end to end.
//!
//! These bite against routing, param validation, and the `-29800`-band
//! code mapping; they do NOT re-verify the construction itself (the
//! `shekyl-crypto-pq` KATs, tamper battery, and the engine workflow tests
//! own that). The one crypto fact they do pin is deliberate: **every
//! in-tree address answers `-29803`** on verify (SM-R-6 R6-a) — when the
//! fork-(ii) v2 address layout lands, the R6-a assertion inside
//! `sign_and_the_full_verify_taxonomy` is what must flip to a round-trip
//! success.

use std::sync::Arc;

use axum::body::Body;
use base64::Engine as _;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_core::Network;
use shekyl_wallet_rpc::auth::AuthConfig;
use shekyl_wallet_rpc::server::{build_router, AppState};
use shekyl_wallet_rpc::tenant::{DaemonEndpoint, TenantState};
use tempfile::TempDir;
use tokio::sync::Notify;

const SIG_PREFIX: &str = "shekylmsgsig1.";

/// Fast Argon2id for tests (matches engine-core lifecycle tests).
fn test_kdf() -> KdfParams {
    KdfParams {
        m_log2: 0x08,
        t: 1,
        p: 1,
    }
}

fn state(dir: &TempDir) -> Arc<AppState> {
    Arc::new(AppState {
        tenants: tokio::sync::Mutex::new(TenantState::new(
            dir.path().to_path_buf(),
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

async fn rpc(state: Arc<AppState>, method: &str, params: Value) -> Value {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = tower::ServiceExt::oneshot(app, req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn error_code(v: &Value) -> i64 {
    v["error"]["code"]
        .as_i64()
        .unwrap_or_else(|| panic!("expected an error response, got {v}"))
}

/// One wallet, one real signature: the multi-second SLH-DSA sign runs
/// once and every wire-taxonomy case below reuses the artifact.
async fn signed_fixture(state: &Arc<AppState>) -> (String, String) {
    let created = rpc(
        state.clone(),
        "create_wallet",
        json!({ "name": "signer", "password": "pw" }),
    )
    .await;
    assert!(created.get("error").is_none(), "create_wallet failed");

    let addr = rpc(state.clone(), "get_primary_address", json!({})).await;
    let address = addr["result"]["address"]
        .as_str()
        .expect("address")
        .to_owned();

    let signed = rpc(
        state.clone(),
        "sign_message",
        json!({ "message": "hello shekyl" }),
    )
    .await;
    let signature = signed["result"]["signature"]
        .as_str()
        .unwrap_or_else(|| panic!("sign_message failed: {signed}"))
        .to_owned();
    (address, signature)
}

// Multi-thread flavor: the sign path hops through `spawn_blocking` and
// the key actor the same way the engine's own workflow test does
// (`message_signing_tests.rs`, same annotation).
#[tokio::test(flavor = "multi_thread")]
async fn sign_and_the_full_verify_taxonomy() {
    let dir = TempDir::new().unwrap();
    let state = state(&dir);
    let (address, signature) = signed_fixture(&state).await;

    // ── The signed artifact is the canonical armored form (SM-R-5). ──
    assert!(signature.starts_with(SIG_PREFIX));
    assert!(!signature.contains('='), "unpadded is pinned");
    assert!(
        !signature.contains(char::is_whitespace),
        "emission is single-line"
    );

    // ── R6-a: the wallet's own v1 address cannot anchor verification —
    // -29803, not a success and not a params error. When the v2 layout
    // lands, THIS assertion is what changes into a round-trip success.
    let v = rpc(
        state.clone(),
        "verify_message",
        json!({ "address": address, "message": "hello shekyl", "signature": signature }),
    )
    .await;
    assert_eq!(error_code(&v), -29803);

    // ── Malformed string: shape-first -32602 (SM-R-6). ──
    let v = rpc(
        state.clone(),
        "verify_message",
        json!({ "address": address, "message": "m", "signature": "not-a-signature" }),
    )
    .await;
    assert_eq!(error_code(&v), -32602);

    // ── Corrupted paste: one flipped base64 character mid-body decodes
    // canonically but fails the checksum — -29801, judged BEFORE the
    // address (the string taxonomy is a property of the paste alone).
    let mut corrupted: Vec<char> = signature.chars().collect();
    let idx = SIG_PREFIX.len() + 100;
    corrupted[idx] = if corrupted[idx] == 'A' { 'B' } else { 'A' };
    let corrupted: String = corrupted.into_iter().collect();
    assert_ne!(corrupted, signature, "fixture must actually corrupt");
    let v = rpc(
        state.clone(),
        "verify_message",
        json!({ "address": address, "message": "m", "signature": corrupted }),
    )
    .await;
    assert_eq!(error_code(&v), -29801);

    // ── Unknown scheme: re-checksummed is not needed at a foreign
    // length — the scheme byte decides, -29802, with the byte in
    // error.data (SM-R-5's forward-compat field doing its job).
    let engine = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut canonical = engine
        .decode(signature.strip_prefix(SIG_PREFIX).unwrap())
        .unwrap();
    canonical[1] = 0x02;
    canonical.truncate(3 + 128);
    let foreign = format!("{SIG_PREFIX}{}", engine.encode(&canonical));
    let v = rpc(
        state.clone(),
        "verify_message",
        json!({ "address": address, "message": "m", "signature": foreign }),
    )
    .await;
    assert_eq!(error_code(&v), -29802);
    assert_eq!(v["error"]["data"]["scheme"], 2);

    // ── Bad address with a WELL-FORMED signature: -32602 by ruling
    // (shape-first), and the address is judged after the string — a
    // corrupt paste above never reached this refusal.
    let v = rpc(
        state.clone(),
        "verify_message",
        json!({ "address": "not-an-address", "message": "m", "signature": signature }),
    )
    .await;
    assert_eq!(error_code(&v), -32602);

    // ── Classical-only display form: valid address, wrong shape for
    // this operation — -32602 with the full-address remedy. Built with
    // `encode_classical_display()` (the form users actually hold), NOT
    // by splitting the full string at the segment separator: the first
    // bech32m segment of a full address is the 81-byte BOUND payload,
    // which fails plain address decode as InvalidAddress and would
    // leave the ClassicalOnly arm of the engine taxonomy unexercised
    // end to end.
    let classical = shekyl_address::ShekylAddress::decode_for_network(
        &address,
        shekyl_address::Network::Stagenet,
    )
    .expect("fixture address decodes")
    .encode_classical_display()
    .expect("classical display form");
    let v = rpc(
        state.clone(),
        "verify_message",
        json!({ "address": classical, "message": "m", "signature": signature }),
    )
    .await;
    assert_eq!(error_code(&v), -32602);
}

/// `verify_message` needs no wallet: a fresh tenant with nothing open
/// answers the taxonomy, never `-29001` (SM-R-6 session-less pin).
///
/// Multi-thread flavor: the handler runs the verify pipeline through
/// `block_in_place` (crate convention, `staking::read_view_under_guard`),
/// which panics on a current-thread runtime — production runtimes are
/// all multi-threaded.
#[tokio::test(flavor = "multi_thread")]
async fn verify_message_works_with_no_wallet_open() {
    let dir = TempDir::new().unwrap();
    let state = state(&dir);
    let v = rpc(
        state.clone(),
        "verify_message",
        json!({ "address": "x", "message": "m", "signature": "junk" }),
    )
    .await;
    let code = error_code(&v);
    assert_ne!(
        code, -29001,
        "session-less verify must not gate on a wallet"
    );
    assert_eq!(code, -32602);
}
