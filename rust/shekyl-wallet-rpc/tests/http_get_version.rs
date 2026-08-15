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
use shekyl_wallet_rpc::tenant::{DaemonEndpoint, TenantState};
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
            DaemonEndpoint {
                address: "http://127.0.0.1:1".into(),
                proxy: None,
            },
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

/// Redact one-shot backup secrets from a `create_wallet` JSON-RPC response
/// before formatting it into an assertion failure message (CI logs).
fn redact_create_wallet_response(v: &Value) -> Value {
    let mut out = v.clone();
    if let Some(result) = out.get_mut("result") {
        if let Some(obj) = result.as_object_mut() {
            if obj.contains_key("mnemonic") {
                obj.insert("mnemonic".into(), Value::String("[REDACTED]".into()));
            }
            if obj.contains_key("raw_seed_hex") {
                obj.insert("raw_seed_hex".into(), Value::String("[REDACTED]".into()));
            }
        }
    }
    out
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

/// A method the OpenAPI contract SPECIFIES but this build has not
/// implemented still answers `-32601` over the real transport. Pinned at the
/// HTTP layer (not only in the dispatch unit tests) because the wire code is
/// what a conforming client branches on. `unstake` is the current RESERVED
/// stand-in (it was `sign_message` until PR-SM-2 landed it); when it
/// lands, retarget this at another RESERVED method rather than deleting
/// the case — the property is about the RESERVED-but-unimplemented
/// class, not about any one method.
#[tokio::test]
async fn method_not_found_for_unimplemented_specified() {
    let (status, json) = post_json(
        AuthConfig::Disabled,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "unstake",
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
async fn spawn_in_process_serves_get_version_over_private_uds() {
    let handle = shekyl_wallet_rpc::spawn_in_process(
        std::env::temp_dir(),
        Network::Stagenet,
        "http://127.0.0.1:1".into(),
        None,
    )
    .await
    .expect("spawn");

    // The secure default is UDS: socket 0600 in a 0700 private dir. That
    // filesystem gate is the auth story for the auth-disabled in-process
    // server, so the perms are load-bearing, not cosmetic.
    let socket = handle
        .socket_path()
        .expect("default spawn is UDS")
        .to_owned();
    use std::os::unix::fs::PermissionsExt;
    let socket_mode = std::fs::metadata(&socket)
        .expect("socket meta")
        .permissions()
        .mode();
    assert_eq!(socket_mode & 0o777, 0o600, "socket must be owner-only");
    let dir = socket.parent().expect("socket has parent dir").to_owned();
    let dir_mode = std::fs::metadata(&dir)
        .expect("dir meta")
        .permissions()
        .mode();
    assert_eq!(dir_mode & 0o777, 0o700, "socket dir must be owner-only");

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

    let mut stream = tokio::net::UnixStream::connect(&socket)
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
    // Shutdown removes both the socket and its private directory.
    assert!(!socket.exists(), "socket must be unlinked on shutdown");
    assert!(
        !dir.exists(),
        "private socket dir must be removed on shutdown"
    );
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
    assert!(
        created.get("error").is_none(),
        "{:?}",
        redact_create_wallet_response(&created)
    );

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

    // An id shape this wallet never emits is a malformed request, not a
    // missing transfer: `deadbeef` is not a 32-byte hash.
    let malformed = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "get_transfer_by_id",
            "params": { "id": "deadbeef:0" }
        }),
    )
    .await;
    assert_eq!(malformed["error"]["code"], -32602, "{malformed}");

    // A well-formed id that names no row is the unknown-transfer case.
    let missing = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "get_transfer_by_id",
            "params": { "id": format!("{}:0", "de".repeat(32)) }
        }),
    )
    .await;
    assert_eq!(missing["error"]["code"], -29400, "{missing}");

    // The same applies to the bare-txid (OUTGOING) shape.
    let missing_send = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "get_transfer_by_id",
            "params": { "id": "de".repeat(32) }
        }),
    )
    .await;
    assert_eq!(missing_send["error"]["code"], -29400, "{missing_send}");

    // Unreachable daemon → get_height still succeeds, returning the local
    // wallet height with daemon_height=null (an offline/syncing node must not
    // hide the wallet's own status).
    let height = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "get_height",
            "params": {}
        }),
    )
    .await;
    assert!(height.get("error").is_none(), "{height}");
    assert!(
        height["result"]["wallet_height"].is_i64(),
        "wallet_height present: {height}"
    );
    assert!(
        height["result"]["daemon_height"].is_null(),
        "daemon_height null when daemon unreachable: {height}"
    );

    // Unreachable daemon → -29201 for refresh.
    let refreshed = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "refresh",
            "params": {}
        }),
    )
    .await;
    assert_eq!(refreshed["error"]["code"], -29201);

    // Discard unknown id is idempotent success (no open funds needed).
    let discarded = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "discard_pending_tx",
            "params": { "pending_tx_id": "999" }
        }),
    )
    .await;
    assert!(discarded.get("error").is_none(), "{discarded}");

    // Build with invalid recipient → -29100 (or invalid params / funds).
    let build = rpc(
        state,
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "build_pending_tx",
            "params": {
                "recipients": [{ "address": "not-an-address", "amount": "1" }],
                "priority": "STANDARD"
            }
        }),
    )
    .await;
    assert!(build.get("error").is_some(), "{build}");
    let code = build["error"]["code"].as_i64().unwrap();
    // Unreachable daemon → fee estimation fails (-29102); bad address
    // may also surface as -29100 / invalid params / internal.
    assert!(
        code == -29100 || code == -29101 || code == -29102 || code == -32602 || code == -32603,
        "unexpected build error code {code}: {build}"
    );
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
    assert!(
        created.get("error").is_none(),
        "{:?}",
        redact_create_wallet_response(&created)
    );
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
    assert!(
        first.get("error").is_none(),
        "{:?}",
        redact_create_wallet_response(&first)
    );
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

/// Startup refuses a malformed daemon endpoint (here: a port-less --proxy)
/// with an error naming the flag — deferred to first use it would surface on
/// `open_wallet` as a misdiagnosed "daemon unreachable" (rule 82).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawn_refuses_a_malformed_proxy_at_startup() {
    let dir = TempDir::new().expect("tempdir");
    let err = shekyl_wallet_rpc::spawn_in_process_with(ServerConfig {
        listen: ListenAddr::Tcp(SocketAddr::from(([127, 0, 0, 1], 0))),
        wallet_dir: dir.path().to_path_buf(),
        network: Network::Stagenet,
        daemon_address: "http://127.0.0.1:1".into(),
        proxy: Some("socks5://127.0.0.1".into()),
        auth: AuthConfig::Disabled,
        kdf: test_kdf(),
    })
    .await
    .err()
    .expect("a port-less proxy must refuse at startup");
    let rendered = format!("{err}");
    assert!(
        rendered.contains("--proxy"),
        "the startup error names the flag to fix: {rendered}"
    );
}

/// The daemon-address half of the same gate: a URL shape the transport
/// cannot dial refuses at startup with the flag named and the shape cause
/// carried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawn_refuses_a_malformed_daemon_address_at_startup() {
    let dir = TempDir::new().expect("tempdir");
    let err = shekyl_wallet_rpc::spawn_in_process_with(ServerConfig {
        listen: ListenAddr::Tcp(SocketAddr::from(([127, 0, 0, 1], 0))),
        wallet_dir: dir.path().to_path_buf(),
        network: Network::Stagenet,
        daemon_address: "ftp://127.0.0.1:28581".into(),
        proxy: None,
        auth: AuthConfig::Disabled,
        kdf: test_kdf(),
    })
    .await
    .err()
    .expect("a non-http(s) daemon URL must refuse at startup");
    let rendered = format!("{err}");
    assert!(
        rendered.contains("--daemon-address"),
        "the startup error names the flag to fix: {rendered}"
    );
    assert!(
        rendered.contains("daemon URL"),
        "the startup error carries the shape cause: {rendered}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawn_in_process_with_lifecycle() {
    let dir = TempDir::new().expect("tempdir");
    let handle = shekyl_wallet_rpc::spawn_in_process_with(ServerConfig {
        listen: ListenAddr::Tcp(SocketAddr::from(([127, 0, 0, 1], 0))),
        wallet_dir: dir.path().to_path_buf(),
        network: Network::Stagenet,
        daemon_address: "http://127.0.0.1:1".into(),
        proxy: None,
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
    let local_addr = match &handle.listen {
        shekyl_wallet_rpc::InProcessListen::Tcp(addr) => *addr,
        other => panic!("expected TCP listen, got {other:?}"),
    };
    let mut stream = tokio::net::TcpStream::connect(local_addr)
        .await
        .expect("connect");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    let json: Value = serde_json::from_str(http_body(&text)).expect("parse body");
    assert!(
        json.get("error").is_none(),
        "{:?}",
        redact_create_wallet_response(&json)
    );
    assert_eq!(json["result"]["wallet"]["name"], "cli");

    handle.shutdown().await.expect("shutdown");
}

/// Regression: a `close_wallet` that races an in-flight Engine clone (e.g. a
/// running `refresh`) must fail loud WITHOUT evicting the still-live wallet.
/// Before the fix, `close_wallet` cleared the tenant slot before the
/// `Arc::try_unwrap` liveness check, so a failed close permanently orphaned
/// the wallet (subsequent queries returned `-29001 WalletNotOpen`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_wallet_racing_inflight_clone_does_not_evict() {
    let dir = TempDir::new().expect("tempdir");
    let state = lifecycle_state(&dir);

    let created = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "create_wallet",
            "params": { "name": "race", "password": "pw" }
        }),
    )
    .await;
    assert!(
        created.get("error").is_none(),
        "{:?}",
        redact_create_wallet_response(&created)
    );

    // Simulate an in-flight refresh by holding a clone of the shared Engine.
    let inflight = {
        let ts = state.tenants.lock().await;
        ts.tenant.engine().expect("wallet open")
    };

    // close_wallet cannot reclaim sole ownership → fail loud (-32603).
    let closed = rpc(
        state.clone(),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "close_wallet", "params": {} }),
    )
    .await;
    assert_eq!(closed["error"]["code"], -32603, "{closed}");

    // ...but the wallet must remain open and operable (not evicted).
    let bal = rpc(
        state.clone(),
        json!({ "jsonrpc": "2.0", "id": 3, "method": "get_balance", "params": {} }),
    )
    .await;
    assert!(
        bal.get("error").is_none(),
        "wallet was evicted by a failed close: {bal}"
    );

    // Once the in-flight clone drops, close succeeds cleanly.
    drop(inflight);
    let closed2 = rpc(
        state.clone(),
        json!({ "jsonrpc": "2.0", "id": 4, "method": "close_wallet", "params": {} }),
    )
    .await;
    assert!(closed2.get("error").is_none(), "{closed2}");

    // And the wallet is now genuinely closed.
    let after = rpc(
        state.clone(),
        json!({ "jsonrpc": "2.0", "id": 5, "method": "get_balance", "params": {} }),
    )
    .await;
    assert_eq!(after["error"]["code"], -29001, "{after}");
}

/// Regression: while `close_wallet` is unwrapping / persisting outside the
/// tenant mutex (slot temporarily empty), a concurrent `create_wallet` must
/// be refused as busy — not claim the slot. Before the fix, the racing open
/// could `set_open` a new wallet, and the close's failure-path restore then
/// panicked the server on the empty-slot assert.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_during_inflight_close_is_refused_busy() {
    let dir = TempDir::new().expect("tempdir");
    let state = lifecycle_state(&dir);

    let created = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "create_wallet",
            "params": { "name": "closer", "password": "pw" }
        }),
    )
    .await;
    assert!(
        created.get("error").is_none(),
        "{:?}",
        redact_create_wallet_response(&created)
    );

    // Freeze the close at its mid-flight point: slot taken, tenant mutex
    // released, engine not yet persisted/dropped.
    let (name, shared, pscan) = {
        let mut ts = state.tenants.lock().await;
        ts.tenant.take_open().expect("wallet open")
    };

    // A concurrent create must see the closing reservation and refuse busy,
    // not claim the emptied slot.
    let racer = rpc(
        state.clone(),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "create_wallet",
            "params": { "name": "racer", "password": "pw" }
        }),
    )
    .await;
    assert_eq!(racer["error"]["code"], -29000, "{racer}");

    // The close's failure path can therefore restore into a still-empty slot.
    // This "closer" wallet is a non-staker, so `pscan` is `None` (no P-scan task
    // to re-arm); thread it back through faithfully.
    state
        .tenants
        .lock()
        .await
        .tenant
        .restore_open(name, shared, pscan);
    let bal = rpc(
        state.clone(),
        json!({ "jsonrpc": "2.0", "id": 3, "method": "get_balance", "params": {} }),
    )
    .await;
    assert!(bal.get("error").is_none(), "restore failed: {bal}");
}
