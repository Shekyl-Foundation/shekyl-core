// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! HTTP-level conformance tests for the WI-RPC-5 archival staking actions:
//! `stake_in`, `get_drain_balance`, `drain`, and `get_balance`'s live
//! staking-field semantics.
//!
//! These exercise the full dispatch + JSON wire shape (one seeded wallet,
//! unreachable daemon). They bite against dispatch wiring, the F-1
//! `deny_unknown_fields` enforcement, the pinned refusal codes, and
//! wire-shape drift; they do NOT re-verify the Engine-side drain semantics
//! (the `drain_facade` / `drain_read` / `principal_stake` unit suites cover
//! the reserve gate, the two-armed read taxonomy, and the cover draw). The
//! syncing arm of `get_drain_balance` needs a staker whose curve tree lags
//! its scan — not constructible offline — so its "never a zero" shape is
//! pinned structurally in `staking_actions::tests` (the syncing variant has
//! no `spendable` field at the type level).

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
        auth: Arc::new(AuthConfig::Disabled),
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
        .header("host", "127.0.0.1")
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

// ---------------------------------------------------------------------------
// F-1: extra-field rejection is enforcement, not yaml prose
// ---------------------------------------------------------------------------

/// A client steering `drain` with `fee` / `destination` / `p_slot`, or
/// `stake_in` with `fee`, or sending any key at all on `get_drain_balance`,
/// is answered `-32602` — the extra key is never silently dropped (the
/// anti-fingerprint pin: a caller must not *believe* it steered a drain it
/// did not). Params parse ahead of the wallet gate, so no wallet is opened.
#[tokio::test]
async fn staking_actions_reject_steering_params_with_invalid_params() {
    let dir = TempDir::new().expect("tempdir");
    let state = state(&dir);

    for (method, params) in [
        ("stake_in", json!({ "amount": "5", "fee": "1" })),
        ("drain", json!({ "amount": "5", "fee": "1" })),
        ("drain", json!({ "amount": "5", "destination": "shekyl1x" })),
        ("drain", json!({ "amount": "5", "p_slot": 0 })),
        ("get_drain_balance", json!({ "p_slot": 0 })),
    ] {
        let r = rpc(state.clone(), method, params.clone()).await;
        assert_eq!(r["error"]["code"], -32602, "{method} {params}: {r}");
    }

    // The amount-string contract is the shared one (decimal atomic units).
    let bad_amount = rpc(state.clone(), "drain", json!({ "amount": "1.5" })).await;
    assert_eq!(bad_amount["error"]["code"], -32602, "{bad_amount}");

    // And with no wallet open, well-formed params reach the wallet gate.
    for (method, params) in [
        ("stake_in", json!({ "amount": "5" })),
        ("get_drain_balance", json!({})),
        ("drain", json!({ "amount": "5" })),
    ] {
        let r = rpc(state.clone(), method, params).await;
        assert_eq!(r["error"]["code"], -29001, "{method}: {r}");
    }
}

// ---------------------------------------------------------------------------
// Refusal codes on a non-staker (offline: both refuse before any daemon I/O)
// ---------------------------------------------------------------------------

/// The pinned code split for "this wallet has no persona to fund/drain":
/// `stake_in` mints no new codes and reuses `-29500` (`STAKE_NOT_READY`,
/// F-2 pin) with its scalar-free `data.detail`; `drain` refuses `-29507`
/// (`DRAIN_NOT_STAKER`) — the drain path does not exist on a non-staker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_staker_stake_in_is_29500_and_drain_is_29507() {
    let dir = TempDir::new().expect("tempdir");
    let state = state(&dir);
    create_wallet(&state, "plain").await;

    let stake = rpc(state.clone(), "stake_in", json!({ "amount": "50000" })).await;
    assert_eq!(stake["error"]["code"], -29500, "{stake}");
    assert_eq!(
        stake["error"]["data"]["detail"], "wallet is not staking; no persona to fund",
        "{stake}"
    );

    let drain = rpc(state.clone(), "drain", json!({ "amount": "50000" })).await;
    assert_eq!(drain["error"]["code"], -29507, "{drain}");
    // Scalar-free refusal: the requested amount never echoes back.
    let msg = drain["error"]["message"].as_str().expect("message");
    assert!(!msg.contains("50000"), "{drain}");
}

// ---------------------------------------------------------------------------
// Drain-balance read: honest zero vs the fail-closed arms
// ---------------------------------------------------------------------------

/// A fresh non-staker wallet answers `ready` with `"0"` — a **true** zero
/// (nothing is staked, there is no pool), not a placeholder: the engine
/// short-circuits on "no sealed P-scan state" before any anchoring, so no
/// spurious `syncing` fires against an empty tree, and the read succeeds
/// offline (no daemon round-trip).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drain_balance_on_a_fresh_wallet_is_an_honest_ready_zero() {
    let dir = TempDir::new().expect("tempdir");
    let state = state(&dir);
    create_wallet(&state, "fresh").await;

    let r = rpc(state.clone(), "get_drain_balance", json!({})).await;
    assert!(r.get("error").is_none(), "{r}");
    assert_eq!(r["result"]["status"], "ready", "{r}");
    assert_eq!(r["result"]["spendable"], "0", "{r}");
    // The ready arm never carries the syncing arm's field (and vice versa —
    // the two-armed contract keeps "0" and "syncing" unconflatable).
    assert!(r["result"].get("detail").is_none(), "{r}");
}

// ---------------------------------------------------------------------------
// get_balance staking-field semantics (WI-RPC-5: live values, never "0" hint)
// ---------------------------------------------------------------------------

/// `get_balance.staked` equals the sum of `get_staked_balance`'s two bonded
/// legs and `claimable_rewards` equals `rewards_received_unspent` — asserted
/// cross-method from the two live responses (never against literals), so the
/// one-glance scalar cannot drift from the authoritative three-leg view.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_balance_staking_fields_match_the_staked_balance_legs() {
    let dir = TempDir::new().expect("tempdir");
    let state = state(&dir);
    create_wallet(&state, "legs").await;

    let legs = rpc(state.clone(), "get_staked_balance", json!({})).await;
    assert!(legs.get("error").is_none(), "{legs}");
    let confirmed: u64 = legs["result"]["bonded_principal_confirmed"]
        .as_str()
        .expect("confirmed")
        .parse()
        .expect("decimal");
    let pending: u64 = legs["result"]["bonded_principal_pending"]
        .as_str()
        .expect("pending")
        .parse()
        .expect("decimal");
    let rewards = legs["result"]["rewards_received_unspent"]
        .as_str()
        .expect("rewards");

    let bal = rpc(state.clone(), "get_balance", json!({})).await;
    assert!(bal.get("error").is_none(), "{bal}");
    assert_eq!(
        bal["result"]["staked"],
        (confirmed + pending).to_string(),
        "{bal}"
    );
    assert_eq!(bal["result"]["claimable_rewards"], rewards, "{bal}");

    // And `get_wallet_info.balance` projects the same fields (one source).
    let info = rpc(state.clone(), "get_wallet_info", json!({})).await;
    assert!(info.get("error").is_none(), "{info}");
    assert_eq!(
        info["result"]["balance"]["staked"], bal["result"]["staked"],
        "{info}"
    );
    assert_eq!(
        info["result"]["balance"]["claimable_rewards"], bal["result"]["claimable_rewards"],
        "{info}"
    );
}
