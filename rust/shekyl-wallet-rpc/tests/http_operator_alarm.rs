// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `operator_alarm` and `operator_alarm_acknowledge` over HTTP (OA-1): the
//! wallet's own board, read and acknowledged through the server a client
//! talks to.
//!
//! Conditions are raised onto the open wallet's board through the producers
//! that raise them in production (the board's raise is crate-private), with
//! the daemon unreachable so the cadence driver never fires and writes over
//! what a test set.

use std::sync::Arc;

use axum::body::Body;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_core::Network;
use shekyl_operator_alarm::cadence::{
    apply_chain_progress, apply_pending_outcomes, ChainProgressObservation, CONDITIONS,
};
use shekyl_operator_alarm::OperatorAlarms;
use shekyl_wallet_rpc::auth::{AuthConfig, BasicCredential};
use shekyl_wallet_rpc::server::{build_router, AppState};
use shekyl_wallet_rpc::tenant::{DaemonTarget, TenantState};
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

fn state(dir: &TempDir, auth: AuthConfig) -> Arc<AppState> {
    Arc::new(AppState {
        tenants: tokio::sync::Mutex::new(TenantState::new(
            dir.path().to_path_buf(),
            Network::Stagenet,
            DaemonTarget::fixture_with_proxy("http://127.0.0.1:1".into(), None),
            shekyl_wallet_rpc::server::TorFile::discover(),
        )),
        auth: Arc::new(auth),
        kdf: test_kdf(),
        shutdown: Arc::new(Notify::new()),
        closed: Arc::new(Notify::new()),
    })
}

async fn post(
    state: Arc<AppState>,
    authorization: Option<&str>,
    method: &str,
    params: Value,
) -> (StatusCode, Value) {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let mut req = Request::builder()
        .method("POST")
        .uri("/json_rpc")
        .header("host", "127.0.0.1")
        .header("content-type", "application/json");
    if let Some(authorization) = authorization {
        req = req.header("authorization", authorization);
    }
    let req = req
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = tower::ServiceExt::oneshot(build_router(state), req)
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn rpc(state: &Arc<AppState>, method: &str, params: Value) -> Value {
    let (status, reply) = post(state.clone(), None, method, params).await;
    assert_eq!(status, StatusCode::OK);
    assert!(reply.get("error").is_none(), "{method} failed: {reply}");
    reply["result"].clone()
}

async fn open_wallet(state: &Arc<AppState>) -> Arc<OperatorAlarms> {
    rpc(
        state,
        "create_wallet",
        json!({ "name": "alarms", "password": "pw" }),
    )
    .await;
    let engine = state
        .tenants
        .lock()
        .await
        .tenant
        .engine()
        .expect("the created wallet is open");
    let alarms = engine.read().await.operator_alarms();
    alarms
}

fn row<'a>(reply: &'a Value, condition: &str) -> &'a Value {
    reply["conditions"]
        .as_array()
        .expect("conditions is a list")
        .iter()
        .find(|r| r["condition"] == condition)
        .unwrap_or_else(|| panic!("no row for {condition}: {reply}"))
}

/// An open wallet whose checks have not reported reads every row "not
/// checked" through the RPC, the onion's row among them, and never a
/// missing row. Red edit: start the board empty again (`AlarmBoard::default`
/// with no rows), or skip a disarmed row in the projection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unchecked_wallet_reads_every_row_not_checked() {
    let dir = TempDir::new().unwrap();
    let state = state(&dir, AuthConfig::Disabled);
    open_wallet(&state).await;

    let reply = rpc(&state, "operator_alarm", json!({})).await;
    let rows = reply["conditions"].as_array().expect("conditions");
    assert_eq!(rows.len(), 10, "every condition has a row: {reply}");
    for row in rows {
        assert!(
            row["arming"].get("disarmed").is_some(),
            "nothing has reported, so nothing is checked: {row}"
        );
        assert_eq!(row["fault"], Value::Null, "{row}");
    }
    assert_eq!(
        row(&reply, "onion-reachability")["arming"],
        json!({"disarmed": "unreported"})
    );
    assert_eq!(reply["unacknowledged"], json!([]));
}

/// A latched fault survives its condition clearing and stays on the reply
/// until it is acknowledged by its own incident; acknowledging another
/// incident changes nothing, and a second acknowledgment is harmless. Red
/// edit: have `clear` drop a `LatchedRederived` alarm, or have
/// `operator_alarm_acknowledge` ignore the incident it names.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_latched_fault_stays_until_its_incident_is_acknowledged() {
    let dir = TempDir::new().unwrap();
    let state = state(&dir, AuthConfig::Disabled);
    let alarms = open_wallet(&state).await;

    apply_pending_outcomes(&alarms, 1, 0);
    let live = rpc(&state, "operator_alarm", json!({})).await;
    let incident = row(&live, "pending-funds-integrity")["fault"]["incident"]
        .as_u64()
        .expect("a live fault names its incident");

    // The condition clears; the damage stands.
    apply_pending_outcomes(&alarms, 0, 0);
    let cleared = rpc(&state, "operator_alarm", json!({})).await;
    assert_eq!(
        row(&cleared, "pending-funds-integrity")["fault"],
        Value::Null
    );
    assert_eq!(
        cleared["unacknowledged"],
        json!([{
            "incident": incident,
            "condition": "pending-funds-integrity",
            "alarm": {"reservation-spent-elsewhere": {"record_count": 1, "held_count": 0}},
        }]),
    );

    let other = rpc(
        &state,
        "operator_alarm_acknowledge",
        json!({ "incident": incident + 1 }),
    )
    .await;
    assert_eq!(other, json!({"acknowledged": false}));
    assert_eq!(
        rpc(&state, "operator_alarm", json!({})).await["unacknowledged"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "an acknowledgment naming another incident clears nothing"
    );

    let acknowledged = rpc(
        &state,
        "operator_alarm_acknowledge",
        json!({ "incident": incident }),
    )
    .await;
    assert_eq!(acknowledged, json!({"acknowledged": true}));
    assert_eq!(
        rpc(&state, "operator_alarm", json!({})).await["unacknowledged"],
        json!([])
    );
    assert_eq!(
        rpc(
            &state,
            "operator_alarm_acknowledge",
            json!({ "incident": incident })
        )
        .await,
        json!({"acknowledged": false}),
        "a repeated acknowledgment is harmless"
    );
}

/// A flap of an episode — raised and cleared between two reads — leaves
/// nothing: no live fault and nothing to acknowledge. The coalescing is the
/// design for an episode (one fault that ended), and the latched test
/// above is its counterpart. Red edit: queue `Episode` alarms on `clear`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_episode_that_flaps_between_reads_leaves_nothing() {
    let dir = TempDir::new().unwrap();
    let state = state(&dir, AuthConfig::Disabled);
    let alarms = open_wallet(&state).await;

    apply_chain_progress(
        &alarms,
        ChainProgressObservation::Stalled {
            last_height: 9,
            stalled_for_secs: 600,
        },
    );
    apply_chain_progress(&alarms, ChainProgressObservation::Advancing);

    let reply = rpc(&state, "operator_alarm", json!({})).await;
    assert_eq!(
        row(&reply, "chain-progress")["arming"],
        json!({"armed": null})
    );
    assert_eq!(row(&reply, "chain-progress")["fault"], Value::Null);
    assert_eq!(reply["unacknowledged"], json!([]));
}

/// A check that stops without saying so reads "check stopped" through the
/// RPC, never armed and quiet. Red edit: make `CheckGuard::drop` a no-op.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_check_that_died_reads_check_stopped() {
    let dir = TempDir::new().unwrap();
    let state = state(&dir, AuthConfig::Disabled);
    let alarms = open_wallet(&state).await;

    let guard = alarms.check_guard(&CONDITIONS);
    apply_chain_progress(&alarms, ChainProgressObservation::Advancing);
    assert_eq!(
        row(
            &rpc(&state, "operator_alarm", json!({})).await,
            "chain-progress"
        )["arming"],
        json!({"armed": null})
    );
    drop(guard);

    assert_eq!(
        row(
            &rpc(&state, "operator_alarm", json!({})).await,
            "chain-progress"
        )["arming"],
        json!({"disarmed": "check-stopped"})
    );
}

/// A caller without the wallet RPC's credential gets no board: the request
/// is refused before dispatch, and the reply carries no row. The credential
/// is the grant (`operator_alarm.rs`, "Who may read it"). Red edit: route
/// `operator_alarm` ahead of the authentication layer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_caller_without_the_credential_gets_no_board() {
    let dir = TempDir::new().unwrap();
    let state = state(
        &dir,
        AuthConfig::Basic(BasicCredential::new("operator", "secret").expect("credential")),
    );
    let (status, reply) = post(state, None, "operator_alarm", json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        !reply.to_string().contains("conditions"),
        "a refused caller sees no row: {reply}"
    );
}
