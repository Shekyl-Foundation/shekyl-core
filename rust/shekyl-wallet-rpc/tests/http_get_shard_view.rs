// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `get_shard_view` (SV-D) over the router: the wallet forwards `shard_id`
//! to its daemon's `request_archival_shard`, returns the aggregate without
//! the daemon's `status`, and keeps each daemon refusal on its own wallet
//! code — still open, could not be retrieved, not offered — so a viewer
//! shows a state and never an empty picture.
//!
//! Driven end to end: a real `DaemonClient` (identity handshake included)
//! over a loopback socket against a daemon that answers `get_version`
//! from the real response type and `request_archival_shard` as the case
//! dictates.

use std::io::{Read as _, Write as _};
use std::sync::Arc;

use axum::body::Body;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_core::Network;
use shekyl_rpc_types::{
    genesis_hash_for, DaemonNetwork, GetVersionResponse, HashHex, RequestArchivalShardResponse,
    RpcStatus, CONSENSUS_CONSTANTS_DIGEST_HASH, CORE_RPC_VERSION,
};
use shekyl_wallet_rpc::auth::AuthConfig;
use shekyl_wallet_rpc::server::{build_router, AppState};
use shekyl_wallet_rpc::tenant::{DaemonEndpoint, TenantState};
use tempfile::TempDir;
use tokio::sync::Notify;
use tower::ServiceExt;

const SERVED: DaemonNetwork = DaemonNetwork::Stagenet;

fn version_reply() -> String {
    let reply = GetVersionResponse {
        status: RpcStatus::ok(),
        version: CORE_RPC_VERSION,
        release: false,
        current_height: 1,
        target_height: 0,
        consensus_constants_digest: CONSENSUS_CONSTANTS_DIGEST_HASH,
        nettype: SERVED,
        genesis_hash: HashHex::from_bytes(genesis_hash_for(SERVED)),
    };
    json!({"jsonrpc": "2.0", "id": "0", "result": reply}).to_string()
}

/// A daemon that passes the identity handshake and answers
/// `request_archival_shard` with `shard_reply` (a full JSON-RPC envelope).
fn fake_daemon(shard_reply: String) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let address = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        let version = version_reply();
        let other = refusal(-32601, "not served by this fake");
        while let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            let Ok(n) = stream.read(&mut buf) else { return };
            if n == 0 {
                continue;
            }
            let request = String::from_utf8_lossy(&buf[..n]);
            // Anything else the wallet asks in the background (an opened
            // wallet's own reads) is refused, not served: this daemon is
            // only here to answer the view.
            let reply = if request.contains("\"get_version\"") {
                &version
            } else if request.contains("\"request_archival_shard\"") {
                &shard_reply
            } else {
                &other
            };
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                reply.len()
            );
            drop(stream.write_all(head.as_bytes()));
            drop(stream.write_all(reply.as_bytes()));
        }
    });
    format!("http://{address}")
}

fn state(dir: &TempDir, daemon_address: String) -> Arc<AppState> {
    Arc::new(AppState {
        tenants: tokio::sync::Mutex::new(TenantState::new(
            dir.path().to_path_buf(),
            Network::Stagenet,
            DaemonEndpoint {
                address: daemon_address,
                proxy: None,
            },
        )),
        auth: Arc::new(AuthConfig::Disabled),
        kdf: KdfParams {
            m_log2: 0x08,
            t: 1,
            p: 1,
        },
        shutdown: Arc::new(Notify::new()),
    })
}

async fn rpc(state: Arc<AppState>, method: &str, params: Value) -> Value {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let request = Request::builder()
        .method("POST")
        .uri("/")
        .header("host", "127.0.0.1")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).expect("encode")))
        .expect("request");
    let response = build_router(state).oneshot(request).await.expect("router");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("json")
}

/// Create a wallet (no daemon contact), then ask for shard 7's view.
async fn shard_view(daemon_address: String) -> Value {
    let dir = TempDir::new().expect("tempdir");
    let state = state(&dir, daemon_address);
    let created = rpc(
        state.clone(),
        "create_wallet",
        json!({ "name": "viewer", "password": "pw" }),
    )
    .await;
    assert!(
        created.get("error").is_none(),
        "create_wallet failed: {}",
        created["error"]
    );
    rpc(state, "get_shard_view", json!({ "shard_id": 7 })).await
}

fn refusal(code: i64, message: &str) -> String {
    json!({"jsonrpc": "2.0", "id": "0", "error": {"code": code, "message": message}}).to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_served_shard_is_the_daemons_aggregate_without_its_status() {
    let daemon_answer = RequestArchivalShardResponse {
        status: RpcStatus::ok(),
        shard_id: 7,
        shard_hash: HashHex::from_bytes([0x5a; 32]),
        archival_len: 4_000_000,
        block_count: 33,
        tx_count: 1_200,
        output_count: 2_433,
        coinbase_output_count: 33,
        time_range_seconds: 3_900,
        close_height: 20_481,
    };
    let reply = shard_view(fake_daemon(
        json!({"jsonrpc": "2.0", "id": "0", "result": daemon_answer}).to_string(),
    ))
    .await;
    assert!(reply.get("error").is_none(), "{reply}");
    let result = &reply["result"];
    assert_eq!(
        *result,
        json!({
            "shard_id": 7,
            "shard_hash": "5a".repeat(32),
            "archival_len": 4_000_000,
            "block_count": 33,
            "tx_count": 1_200,
            "output_count": 2_433,
            "coinbase_output_count": 33,
            "time_range_seconds": 3_900,
            "close_height": 20_481,
        }),
        "exactly the contract's GetShardViewResult: {result}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_open_shard_is_still_open_not_a_picture() {
    let reply = shard_view(fake_daemon(refusal(-24, "shard 7 is open"))).await;
    let error = &reply["error"];
    assert_eq!(error["code"], -29534, "{reply}");
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|m| m.contains("still open")),
        "{reply}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_miss_is_could_not_be_retrieved() {
    let reply = shard_view(fake_daemon(refusal(-22, "no holder served shard 7"))).await;
    assert_eq!(reply["error"]["code"], -29535, "{reply}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_public_listener_and_a_skeletonless_store_are_each_not_offered() {
    let restricted = shard_view(fake_daemon(refusal(-19, "restricted"))).await;
    assert_eq!(restricted["error"]["code"], -29536, "{restricted}");
    assert_eq!(
        restricted["error"]["data"]["cause"], "restricted",
        "{restricted}"
    );

    let absent = shard_view(fake_daemon(refusal(-25, "no skeleton"))).await;
    assert_eq!(absent["error"]["code"], -29536, "{absent}");
    assert_eq!(
        absent["error"]["data"]["cause"], "skeleton_absent",
        "{absent}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_params_are_exactly_a_shard_id() {
    let dir = TempDir::new().expect("tempdir");
    let state = state(&dir, "http://127.0.0.1:1".to_owned());
    let missing = rpc(state.clone(), "get_shard_view", json!({})).await;
    assert_eq!(missing["error"]["code"], -32602, "{missing}");
    let extra = rpc(
        state,
        "get_shard_view",
        json!({ "shard_id": 1, "size": 512 }),
    )
    .await;
    assert_eq!(
        extra["error"]["code"], -32602,
        "a render size is never on this wire: {extra}"
    );
}
