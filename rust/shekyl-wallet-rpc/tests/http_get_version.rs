// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! HTTP-level conformance tests for Phase 4a (`get_version` + envelope)
//! and Phase 4b lifecycle smoke (create / open / close / change_password).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_core::Network;
use shekyl_wallet_rpc::auth::AuthConfig;
use shekyl_wallet_rpc::server::{build_router, AppState, ListenAddr, ServerConfig};
use shekyl_wallet_rpc::tenant::TenantState;
use shekyl_wallet_rpc::{API_VERSION, VERSION};
use tempfile::TempDir;
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

fn test_state(auth: AuthConfig) -> Arc<AppState> {
    Arc::new(AppState {
        tenants: tokio::sync::Mutex::new(TenantState::new(
            std::env::temp_dir(),
            Network::Stagenet,
            "http://127.0.0.1:1".into(),
        )),
        auth,
        kdf: test_kdf(),
        shutdown: Arc::new(Notify::new()),
    })
}

fn lifecycle_state(dir: &TempDir) -> Arc<AppState> {
    Arc::new(AppState {
        tenants: tokio::sync::Mutex::new(TenantState::new(
            dir.path().to_path_buf(),
            Network::Stagenet,
            "http://127.0.0.1:1".into(),
        )),
        auth: AuthConfig::Disabled,
        kdf: test_kdf(),
        shutdown: Arc::new(Notify::new()),
    })
}

async fn post_json(auth: AuthConfig, body: Value) -> (StatusCode, Value) {
    let state = test_state(auth);
    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn post_raw(auth: AuthConfig, body: &'static [u8]) -> (StatusCode, Value) {
    let state = test_state(auth);
    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn post_json_with_auth(user: &str, pass: &str, body: Value) -> (StatusCode, Value) {
    use base64::Engine as _;
    let cred = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    let state = test_state(AuthConfig::Basic {
        username: user.to_owned(),
        password: pass.to_owned(),
    });
    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header("content-type", "application/json")
        .header("authorization", format!("Basic {cred}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn rpc(state: Arc<AppState>, body: Value) -> Value {
    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Split an HTTP/1.1 response into (headers, body) on the `\r\n\r\n` terminator.
fn http_body(raw: &str) -> &str {
    raw.split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("HTTP response missing header terminator")
}

#[tokio::test]
async fn get_version_success() {
    let (status, json) = post_json(
        AuthConfig::Disabled,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "get_version",
            "params": {}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], 1);
    assert!(json.get("error").is_none());
    assert_eq!(json["result"]["version"], VERSION);
    assert_eq!(json["result"]["api_version"], API_VERSION);
}

#[tokio::test]
async fn get_version_omitted_params() {
    let (status, json) = post_json(
        AuthConfig::Disabled,
        json!({
            "jsonrpc": "2.0",
            "id": "abc",
            "method": "get_version"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["result"]["api_version"], API_VERSION);
    assert_eq!(json["id"], "abc");
}

#[tokio::test]
async fn method_not_found_for_unimplemented_specified() {
    let (status, json) = post_json(
        AuthConfig::Disabled,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "rescan_blockchain",
            "params": {}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.get("result").is_none());
    assert_eq!(json["error"]["code"], -32601);
}

#[tokio::test]
async fn invalid_jsonrpc_version() {
    let (status, json) = post_json(
        AuthConfig::Disabled,
        json!({
            "jsonrpc": "1.0",
            "id": 3,
            "method": "get_version"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["error"]["code"], -32600);
    // Valid id is still echoed on structural invalid-request.
    assert_eq!(json["id"], 3);
}

#[tokio::test]
async fn malformed_json_is_parse_error() {
    let (status, json) = post_raw(AuthConfig::Disabled, b"{not-json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["error"]["code"], -32700);
    assert!(json["id"].is_null());
}

#[tokio::test]
async fn missing_required_fields_is_invalid_request_not_parse_error() {
    // Syntactically valid JSON, structurally incomplete → -32600, not -32700.
    let (status, json) = post_json(
        AuthConfig::Disabled,
        json!({
            "jsonrpc": "2.0",
            "id": 1
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["error"]["code"], -32600);
    assert_eq!(json["id"], 1);
}

#[tokio::test]
async fn invalid_id_type_responds_with_null_id() {
    let (status, json) = post_json(
        AuthConfig::Disabled,
        json!({
            "jsonrpc": "2.0",
            "id": true,
            "method": "get_version"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["error"]["code"], -32600);
    assert!(json["id"].is_null());
}

#[tokio::test]
async fn basic_auth_rejects_missing_header() {
    let state = test_state(AuthConfig::Basic {
        username: "alice".into(),
        password: "secret".into(),
    });
    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "get_version"
            }))
            .unwrap(),
        ))
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn basic_auth_accepts_valid_credentials() {
    let (status, json) = post_json_with_auth(
        "alice",
        "secret",
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "get_version"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["result"]["api_version"], API_VERSION);
}

#[tokio::test]
async fn spawn_in_process_serves_get_version() {
    let handle = shekyl_wallet_rpc::spawn_in_process(std::env::temp_dir())
        .await
        .expect("spawn");

    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "get_version"
    }))
    .unwrap();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );

    let mut stream = tokio::net::TcpStream::connect(handle.local_addr)
        .await
        .expect("connect");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    let json: Value = serde_json::from_str(http_body(&text)).expect("parse body");
    assert_eq!(json["result"]["api_version"], API_VERSION);
    assert_eq!(json["id"], 42);

    handle.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queries_balance_address_transfers_after_create() {
    let dir = TempDir::new().expect("tempdir");
    let state = lifecycle_state(&dir);

    let created = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "create_wallet",
            "params": { "name": "q", "password": "pw" }
        }),
    )
    .await;
    assert!(created.get("error").is_none(), "{created}");

    let bal = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "get_balance",
            "params": {}
        }),
    )
    .await;
    assert!(bal.get("error").is_none(), "{bal}");
    assert_eq!(bal["result"]["unlocked"], "0");
    assert_eq!(bal["result"]["liquid"], "0");
    assert_eq!(bal["result"]["staked"], "0");
    assert_eq!(bal["result"]["claimable_rewards"], "0");
    assert_eq!(bal["result"]["pending"], "0");

    let addr = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "get_primary_address",
            "params": {}
        }),
    )
    .await;
    assert!(addr.get("error").is_none(), "{addr}");
    let address = addr["result"]["address"].as_str().expect("address");
    assert!(!address.is_empty());

    let transfers = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "get_transfers",
            "params": {}
        }),
    )
    .await;
    assert!(transfers.get("error").is_none(), "{transfers}");
    assert_eq!(
        transfers["result"]["transfers"].as_array().unwrap().len(),
        0
    );

    let missing = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "get_transfer_by_id",
            "params": { "id": "deadbeef:0" }
        }),
    )
    .await;
    assert_eq!(missing["error"]["code"], -29400);

    // Unreachable daemon → -29201 for get_height.
    let height = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "get_height",
            "params": {}
        }),
    )
    .await;
    assert_eq!(height["error"]["code"], -29201);

    // Unreachable daemon → -29201 for refresh.
    let refreshed = rpc(
        state,
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "refresh",
            "params": {}
        }),
    )
    .await;
    assert_eq!(refreshed["error"]["code"], -29201);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lifecycle_create_open_close_change_password() {
    let dir = TempDir::new().expect("tempdir");
    let state = lifecycle_state(&dir);

    let created = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "create_wallet",
            "params": {
                "name": "alice",
                "password": "correct horse"
            }
        }),
    )
    .await;
    assert!(created.get("error").is_none(), "{created}");
    assert_eq!(created["result"]["wallet"]["name"], "alice");
    assert_eq!(created["result"]["wallet"]["capability"], "FULL");
    assert_eq!(created["result"]["wallet"]["network"], "STAGENET");
    let mnemonic = created["result"]["mnemonic"]
        .as_str()
        .expect("mnemonic on stagenet");
    assert_eq!(mnemonic.split_whitespace().count(), 24);

    // Second create while open → -29000.
    let already = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "create_wallet",
            "params": { "name": "bob", "password": "x" }
        }),
    )
    .await;
    assert_eq!(already["error"]["code"], -29000);

    let closed = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "close_wallet",
            "params": {}
        }),
    )
    .await;
    assert!(closed.get("error").is_none(), "{closed}");

    // Wrong password → -29004.
    let bad = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "open_wallet",
            "params": { "name": "alice", "password": "wrong" }
        }),
    )
    .await;
    assert_eq!(bad["error"]["code"], -29004);

    let opened = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "open_wallet",
            "params": { "name": "alice", "password": "correct horse" }
        }),
    )
    .await;
    assert!(opened.get("error").is_none(), "{opened}");
    assert_eq!(opened["result"]["wallet"]["name"], "alice");

    let changed = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "change_password",
            "params": {
                "old_password": "correct horse",
                "new_password": "new secret"
            }
        }),
    )
    .await;
    assert!(changed.get("error").is_none(), "{changed}");

    let _ = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "close_wallet",
            "params": {}
        }),
    )
    .await;

    let reopen = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "open_wallet",
            "params": { "name": "alice", "password": "new secret" }
        }),
    )
    .await;
    assert!(reopen.get("error").is_none(), "{reopen}");

    // Missing wallet → -29003.
    let _ = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "close_wallet",
            "params": {}
        }),
    )
    .await;
    let missing = rpc(
        state,
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "open_wallet",
            "params": { "name": "nobody", "password": "x" }
        }),
    )
    .await;
    assert_eq!(missing["error"]["code"], -29003);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_wallet_file_exists() {
    let dir = TempDir::new().expect("tempdir");
    let state = lifecycle_state(&dir);

    let first = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "create_wallet",
            "params": { "name": "dup", "password": "pw" }
        }),
    )
    .await;
    assert!(first.get("error").is_none(), "{first}");
    let _ = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "close_wallet",
            "params": {}
        }),
    )
    .await;

    let second = rpc(
        state,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "create_wallet",
            "params": { "name": "dup", "password": "pw" }
        }),
    )
    .await;
    assert_eq!(second["error"]["code"], -29002);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawn_in_process_with_lifecycle() {
    let dir = TempDir::new().expect("tempdir");
    let handle = shekyl_wallet_rpc::spawn_in_process_with(ServerConfig {
        listen: ListenAddr::Tcp(SocketAddr::from(([127, 0, 0, 1], 0))),
        wallet_dir: dir.path().to_path_buf(),
        network: Network::Stagenet,
        daemon_address: "http://127.0.0.1:1".into(),
        auth: AuthConfig::Disabled,
        kdf: test_kdf(),
    })
    .await
    .expect("spawn");

    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "create_wallet",
        "params": { "name": "cli", "password": "pw" }
    }))
    .unwrap();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut stream = tokio::net::TcpStream::connect(handle.local_addr)
        .await
        .expect("connect");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    let json: Value = serde_json::from_str(http_body(&text)).expect("parse body");
    assert!(json.get("error").is_none(), "{json}");
    assert_eq!(json["result"]["wallet"]["name"], "cli");

    handle.shutdown().await.expect("shutdown");
}
