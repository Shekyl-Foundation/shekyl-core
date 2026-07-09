// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! HTTP-level conformance tests for Phase 4a (`get_version` + envelope).

use std::sync::Arc;

use axum::body::Body;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use shekyl_wallet_rpc::auth::AuthConfig;
use shekyl_wallet_rpc::server::{build_router, AppState};
use shekyl_wallet_rpc::tenant::TenantState;
use shekyl_wallet_rpc::{API_VERSION, VERSION};
use tokio::sync::Notify;
use tower::ServiceExt;

fn test_state(auth: AuthConfig) -> Arc<AppState> {
    Arc::new(AppState {
        tenants: tokio::sync::Mutex::new(TenantState::new(std::env::temp_dir())),
        auth,
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
            "method": "create_wallet",
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
}

#[tokio::test]
async fn malformed_json_is_parse_error() {
    let state = test_state(AuthConfig::Disabled);
    let app = build_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header("content-type", "application/json")
        .body(Body::from("{not-json"))
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"]["code"], -32700);
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
    let json_start = text.find('{').expect("json body");
    let json: Value = serde_json::from_str(&text[json_start..]).expect("parse");
    assert_eq!(json["result"]["api_version"], API_VERSION);
    assert_eq!(json["id"], 42);

    handle.shutdown().await.expect("shutdown");
}
