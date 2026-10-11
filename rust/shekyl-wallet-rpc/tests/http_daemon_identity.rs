// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A wallet RPC pointed at a daemon that is not the one it was built for
//! answers with the identity axis that disagreed, each on its own code
//! (`-29205..-29208`), not "daemon unreachable".
//!
//! Driven end to end: a real `refresh` over the router, a real
//! `DaemonClient` handshake over a loopback socket, and a daemon that
//! answers `get_version` from the real response type. Each case disagrees
//! on exactly one axis, and a daemon that does not answer at all is the
//! control that keeps `-29201`.

use std::io::{Read as _, Write as _};
use std::sync::Arc;

use axum::body::Body;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_core::Network;
use shekyl_rpc_types::{
    genesis_hash_for, DaemonNetwork, GetVersionResponse, HashHex, RpcStatus,
    CONSENSUS_CONSTANTS_DIGEST_HASH, CORE_RPC_VERSION,
};
use shekyl_wallet_rpc::auth::AuthConfig;
use shekyl_wallet_rpc::server::{build_router, AppState};
use shekyl_wallet_rpc::tenant::{DaemonEndpoint, TenantState};
use tempfile::TempDir;
use tokio::sync::Notify;
use tower::ServiceExt;

/// The network the wallet RPC under test serves.
const SERVED: DaemonNetwork = DaemonNetwork::Stagenet;

/// A port nothing listens on: the "no answer" control.
const SILENT_DAEMON: &str = "http://127.0.0.1:1";

/// A `get_version` reply agreeing with this build on `SERVED` except where
/// `edit` says otherwise.
fn version_reply(edit: impl FnOnce(&mut GetVersionResponse)) -> String {
    let mut reply = GetVersionResponse {
        status: RpcStatus::ok(),
        version: CORE_RPC_VERSION,
        release: false,
        current_height: 1,
        target_height: shekyl_rpc_types::Nullable::NULL,
        consensus_constants_digest: CONSENSUS_CONSTANTS_DIGEST_HASH,
        nettype: SERVED,
        genesis_hash: HashHex::from_bytes(genesis_hash_for(SERVED)),
    };
    edit(&mut reply);
    json!({"jsonrpc": "2.0", "id": "0", "result": reply}).to_string()
}

/// A daemon that answers every request with `reply`.
fn fake_daemon(reply: String) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let address = listener.local_addr().expect("local addr");
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            let Ok(n) = stream.read(&mut buf) else { return };
            if n == 0 {
                continue;
            }
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

/// Create a wallet (which does not contact the daemon), then refresh
/// against `daemon_address` and return the refusal.
async fn refresh_error(daemon_address: String) -> Value {
    let dir = TempDir::new().expect("tempdir");
    let state = state(&dir, daemon_address);
    let created = rpc(
        state.clone(),
        "create_wallet",
        json!({ "name": "identity", "password": "pw" }),
    )
    .await;
    // Only the error is printed: a created wallet's result carries its seed.
    assert!(
        created.get("error").is_none(),
        "create_wallet failed: {}",
        created["error"]
    );
    let refreshed = rpc(state, "refresh", json!({})).await;
    refreshed
        .get("error")
        .cloned()
        .unwrap_or_else(|| panic!("refresh against this daemon must be refused: {refreshed}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_daemon_on_another_network_names_both_networks() {
    let error = refresh_error(fake_daemon(version_reply(|r| {
        r.nettype = DaemonNetwork::Mainnet;
        r.genesis_hash = HashHex::from_bytes(genesis_hash_for(DaemonNetwork::Mainnet));
    })))
    .await;
    assert_eq!(error["code"], -29207, "{error}");
    assert_eq!(error["data"]["wallet"], "stagenet", "{error}");
    assert_eq!(error["data"]["daemon"], "mainnet", "{error}");
    let message = error["message"].as_str().expect("message");
    assert!(
        message.contains("mainnet") && message.contains("stagenet"),
        "the remedy names both networks: {message}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_older_daemon_is_told_to_update() {
    let error = refresh_error(fake_daemon(version_reply(|r| r.version -= 1))).await;
    assert_eq!(error["code"], -29205, "{error}");
    assert_eq!(error["data"]["update"], "daemon", "{error}");
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|m| m.contains("update the daemon")),
        "{error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_daemon_on_another_chain_is_not_an_outage() {
    let error = refresh_error(fake_daemon(version_reply(|r| {
        r.genesis_hash = HashHex::from_bytes([0xab; 32]);
    })))
    .await;
    assert_eq!(error["code"], -29208, "{error}");
    assert_eq!(error["data"]["network"], "stagenet", "{error}");
}

/// The version is read before the rest (RK-Q11): a daemon of another RPC
/// version answers in a shape this build cannot decode, and is still named.
/// Before, this was the unreadable case below.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_daemon_of_another_version_is_named_though_its_reply_does_not_decode() {
    let error = refresh_error(fake_daemon(
        json!({"jsonrpc": "2.0", "id": "0", "result": {
            "version": 1, "a_member_this_build_has_never_heard_of": true,
        }})
        .to_string(),
    ))
    .await;
    assert_eq!(error["code"], -29205, "{error}");
    assert_eq!(error["data"]["daemon_version"], "0.1", "{error}");
    assert_eq!(error["data"]["update"], "daemon", "{error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_version_reply_says_the_version_cannot_be_named() {
    let error = refresh_error(fake_daemon(
        json!({"jsonrpc": "2.0", "id": "0", "result": {"status": "OK"}}).to_string(),
    ))
    .await;
    assert_eq!(error["code"], -29205, "{error}");
    assert_eq!(error["data"]["daemon_version"], Value::Null, "{error}");
    assert_eq!(error["data"]["update"], Value::Null, "{error}");
    let message = error["message"].as_str().expect("message");
    assert!(
        !message.contains("missing field"),
        "the daemon's own text stays in the log: {message}"
    );
}

/// The control: a daemon that does not answer is still `-29201`, so the
/// cases above are the handshake's verdict, not a refresh that failed
/// some other way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_daemon_that_does_not_answer_is_unreachable() {
    let error = refresh_error(SILENT_DAEMON.to_string()).await;
    assert_eq!(error["code"], -29201, "{error}");
}
