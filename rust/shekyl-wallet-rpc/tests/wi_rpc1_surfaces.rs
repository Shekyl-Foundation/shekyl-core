// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! HTTP-level conformance tests for the WI-RPC-1 surfaces: receiving
//! (payment requests / URIs), fee estimates, and staking reads.
//!
//! These exercise the full dispatch + JSON wire shape per family (one seeded
//! wallet, unreachable daemon). They bite against dispatch wiring, param
//! validation, and wire-shape drift; they do NOT re-verify the Engine-side
//! aggregation semantics (the `staking_read` / `tx_fee_model` unit KATs and
//! the `attribution.rs` reorg-rewind tests cover those).

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
use tempfile::TempDir;
use tokio::sync::Notify;

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

async fn create_wallet(state: &Arc<AppState>, name: &str) {
    let created = rpc(
        state.clone(),
        "create_wallet",
        json!({ "name": name, "password": "pw" }),
    )
    .await;
    assert!(created.get("error").is_none(), "create_wallet failed");
}

/// One `rid` past the u48 wire ceiling (`2^48`).
const RID_OVERSIZE: u64 = 1 << 48;

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

/// A created payment request round-trips through `list_payment_requests`,
/// its composed URI parses back to the same `rid`/amount/label, and the
/// request survives a close/reopen cycle (persists via the normal ledger
/// save path — pin 3's persistence half; the reorg-rewind half lives in
/// `attribution.rs` and gains no new path from the RPC).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn payment_request_create_list_uri_round_trip_and_persistence() {
    let dir = TempDir::new().expect("tempdir");
    let state = state(&dir);
    create_wallet(&state, "recv").await;

    let created = rpc(
        state.clone(),
        "create_payment_request",
        json!({ "label": "invoice-7", "amount": "12345", "expiry": 9_000 }),
    )
    .await;
    assert!(created.get("error").is_none(), "{created}");
    let id = created["result"]["id"].as_str().expect("id").to_owned();
    let uri = created["result"]["uri"].as_str().expect("uri").to_owned();
    assert!(!id.is_empty() && id != "0", "rid must be non-zero: {id}");

    // The composed URI parses back to the stored request's fields (rid
    // cannot drift from bookkeeping — it was composed via format_request_uri).
    let parsed = rpc(state.clone(), "parse_uri", json!({ "uri": uri })).await;
    assert!(parsed.get("error").is_none(), "{parsed}");
    assert_eq!(parsed["result"]["rid"], id);
    assert_eq!(parsed["result"]["amount"], "12345");
    assert_eq!(parsed["result"]["label"], "invoice-7");
    assert_eq!(parsed["result"]["expiry"], 9_000);

    // ALL and PENDING contain it; MATCHED does not (nothing paid it).
    for filter in ["ALL", "PENDING"] {
        let listed = rpc(
            state.clone(),
            "list_payment_requests",
            json!({ "filter": filter }),
        )
        .await;
        assert!(listed.get("error").is_none(), "{listed}");
        let reqs = listed["result"]["payment_requests"].as_array().unwrap();
        assert_eq!(reqs.len(), 1, "filter={filter}: {listed}");
        assert_eq!(reqs[0]["id"], id);
        assert_eq!(reqs[0]["amount"], "12345");
        assert_eq!(reqs[0]["label"], "invoice-7");
        assert_eq!(reqs[0]["state"], "PENDING");
        assert!(reqs[0]["matched_tx_hash"].is_null());
    }
    let matched = rpc(
        state.clone(),
        "list_payment_requests",
        json!({ "filter": "MATCHED" }),
    )
    .await;
    assert_eq!(
        matched["result"]["payment_requests"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    // Unknown filter is a params error, not silently ALL.
    let bad = rpc(
        state.clone(),
        "list_payment_requests",
        json!({ "filter": "PAID" }),
    )
    .await;
    assert_eq!(bad["error"]["code"], -32602, "{bad}");

    // Persistence: close, reopen, and the request is still there.
    let closed = rpc(state.clone(), "close_wallet", json!({})).await;
    assert!(closed.get("error").is_none(), "{closed}");
    let opened = rpc(
        state.clone(),
        "open_wallet",
        json!({ "name": "recv", "password": "pw" }),
    )
    .await;
    assert!(opened.get("error").is_none(), "{opened}");
    let listed = rpc(state.clone(), "list_payment_requests", json!({})).await;
    let reqs = listed["result"]["payment_requests"].as_array().unwrap();
    assert_eq!(reqs.len(), 1, "request lost across reopen: {listed}");
    assert_eq!(reqs[0]["id"], id);
}

/// `make_uri` ↔ `parse_uri` round-trip with an explicit address (no open
/// wallet needed), and the `rid` wire bounds: zero and >u48 are rejected as
/// invalid params, never silently dropped or clamped.
#[tokio::test]
async fn make_uri_parse_uri_round_trip_and_rid_bounds() {
    let dir = TempDir::new().expect("tempdir");
    let state = state(&dir);

    let made = rpc(
        state.clone(),
        "make_uri",
        json!({
            "address": "shekylstubaddress1",
            "amount": "777",
            "label": "till 4",
            "rid": "281474976710655", // u48::MAX — largest wire-valid rid
            "expiry": 42
        }),
    )
    .await;
    assert!(made.get("error").is_none(), "{made}");
    let uri = made["result"]["uri"].as_str().expect("uri");

    let parsed = rpc(state.clone(), "parse_uri", json!({ "uri": uri })).await;
    assert!(parsed.get("error").is_none(), "{parsed}");
    assert_eq!(parsed["result"]["address"], "shekylstubaddress1");
    assert_eq!(parsed["result"]["amount"], "777");
    assert_eq!(parsed["result"]["label"], "till 4");
    assert_eq!(parsed["result"]["rid"], "281474976710655");
    assert_eq!(parsed["result"]["expiry"], 42);

    // rid == 0 → invalid params.
    let zero = rpc(
        state.clone(),
        "make_uri",
        json!({ "address": "a", "rid": "0" }),
    )
    .await;
    assert_eq!(zero["error"]["code"], -32602, "{zero}");

    // rid > u48::MAX → invalid params.
    let oversize = rpc(
        state.clone(),
        "make_uri",
        json!({ "address": "a", "rid": RID_OVERSIZE.to_string() }),
    )
    .await;
    assert_eq!(oversize["error"]["code"], -32602, "{oversize}");

    // Garbage URI → invalid params.
    let garbage = rpc(state.clone(), "parse_uri", json!({ "uri": "http://x" })).await;
    assert_eq!(garbage["error"]["code"], -32602, "{garbage}");

    // Whitespace in a provided address → invalid params, never embedded
    // into the composed URI (padding and internal whitespace alike).
    for bad_address in [" shekylstubaddress1", "shekyl stub", "\taddr\n", "  "] {
        let ws = rpc(state.clone(), "make_uri", json!({ "address": bad_address })).await;
        assert_eq!(ws["error"]["code"], -32602, "{bad_address:?}: {ws}");
    }

    // Receiving methods that need the engine refuse without an open wallet.
    let no_wallet = rpc(
        state,
        "create_payment_request",
        json!({ "label": "x", "amount": "1" }),
    )
    .await;
    assert_eq!(no_wallet["error"]["code"], -29001, "{no_wallet}");
}

// ---------------------------------------------------------------------------
// Fees
// ---------------------------------------------------------------------------

/// `estimate_tx_size_and_weight` is offline-capable (tree-depth fallback),
/// returns a plausible size/weight pair (weight ≥ size — the clawback is
/// non-negative), and rejects out-of-range counts. With the daemon
/// unreachable, `get_default_fee_priority` fails as `-29102` — the same code
/// the build path uses for a failed fee snapshot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fee_estimate_shape_bounds_and_daemon_failure() {
    let dir = TempDir::new().expect("tempdir");
    let state = state(&dir);
    create_wallet(&state, "fees").await;

    let est = rpc(
        state.clone(),
        "estimate_tx_size_and_weight",
        json!({ "n_inputs": 2, "n_outputs": 2 }),
    )
    .await;
    assert!(est.get("error").is_none(), "{est}");
    let size = est["result"]["size"].as_i64().expect("size");
    let weight = est["result"]["weight"].as_i64().expect("weight");
    let depth = est["result"]["tree_depth"].as_i64().expect("tree_depth");
    assert!(size > 0, "{est}");
    assert!(weight >= size, "{est}");
    assert!(depth >= 1, "{est}");

    // Zero inputs is not a valid tx shape → invalid params, not a clamp.
    let zero_in = rpc(
        state.clone(),
        "estimate_tx_size_and_weight",
        json!({ "n_inputs": 0, "n_outputs": 2 }),
    )
    .await;
    assert_eq!(zero_in["error"]["code"], -32602, "{zero_in}");

    // Oversize output count → invalid params.
    let oversize_out = rpc(
        state.clone(),
        "estimate_tx_size_and_weight",
        json!({ "n_inputs": 1, "n_outputs": 10_000 }),
    )
    .await;
    assert_eq!(oversize_out["error"]["code"], -32602, "{oversize_out}");

    // A single output is below the contract minimum (a valid transfer always
    // carries a payment/change pair, `n_outputs >= 2`) → invalid params, not a
    // silent estimate for an unbuildable shape.
    let one_out = rpc(
        state.clone(),
        "estimate_tx_size_and_weight",
        json!({ "n_inputs": 2, "n_outputs": 1 }),
    )
    .await;
    assert_eq!(one_out["error"]["code"], -32602, "{one_out}");

    // Unreachable daemon → fee snapshot fails → -29102.
    let quote = rpc(state, "get_default_fee_priority", json!({})).await;
    assert_eq!(quote["error"]["code"], -29102, "{quote}");
}

// ---------------------------------------------------------------------------
// Staking reads
// ---------------------------------------------------------------------------

/// A fresh non-staker wallet reads as all-zero staked balance, an empty
/// staked-output list, staking disabled, and no P-scan frontier — and all
/// three methods succeed offline (no daemon round-trip on the read path).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn staking_reads_on_fresh_wallet_are_zero_and_offline() {
    let dir = TempDir::new().expect("tempdir");
    let state = state(&dir);
    create_wallet(&state, "staker0").await;

    let bal = rpc(state.clone(), "get_staked_balance", json!({})).await;
    assert!(bal.get("error").is_none(), "{bal}");
    assert_eq!(bal["result"]["bonded_principal_confirmed"], "0");
    assert_eq!(bal["result"]["bonded_principal_pending"], "0");
    assert_eq!(bal["result"]["rewards_received_unspent"], "0");

    let outs = rpc(state.clone(), "get_staked_outputs", json!({})).await;
    assert!(outs.get("error").is_none(), "{outs}");
    assert_eq!(
        outs["result"]["staked_outputs"].as_array().unwrap().len(),
        0
    );

    let info = rpc(state.clone(), "staking_info", json!({})).await;
    assert!(info.get("error").is_none(), "{info}");
    assert_eq!(info["result"]["staking_enabled"], false);
    assert_eq!(info["result"]["staked_output_count"], 0);
    assert!(info["result"]["pscan_synced_height"].is_null(), "{info}");

    // All three refuse without an open wallet.
    let _ = rpc(state.clone(), "close_wallet", json!({})).await;
    for method in ["get_staked_balance", "get_staked_outputs", "staking_info"] {
        let r = rpc(state.clone(), method, json!({})).await;
        assert_eq!(r["error"]["code"], -29001, "{method}: {r}");
    }
}
