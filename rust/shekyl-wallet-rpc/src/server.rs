// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! HTTP JSON-RPC server using axum.
//!
//! Listens on a configurable address and routes `/json_rpc` POST requests
//! to the handler dispatcher. All wallet operations are serialized through
//! a `Mutex<Wallet2>` since wallet2 is single-threaded.
//!
//! When the `rust-scanner` feature is enabled, scanner-backed read methods
//! are routed to the native Rust scanner instead of the C++ FFI.

use crate::handlers;
use crate::types::{JsonRpcRequest, JsonRpcResponse};
use crate::wallet::Wallet2;

#[cfg(feature = "rust-scanner")]
use crate::scanner_state::ScannerState;

#[cfg(feature = "multisig")]
use crate::multisig_handlers::MultisigState;

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use std::sync::Mutex;
use tower_http::cors::CorsLayer;
use tracing::info;

pub struct ServerConfig {
    pub bind_address: String,
    pub wallet_dir: String,
    pub daemon_address: String,
    pub daemon_username: String,
    pub daemon_password: String,
    pub nettype: u8,
    pub trusted_daemon: bool,
}

pub struct AppState {
    pub wallet: Mutex<Wallet2>,
    pub shutdown_requested: Mutex<bool>,
    #[cfg(feature = "rust-scanner")]
    pub scanner: ScannerState,
    #[cfg(feature = "multisig")]
    pub multisig: Mutex<MultisigState>,
}

pub async fn run_server(config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let wallet = Wallet2::new(config.nettype)?;
    wallet.set_wallet_dir(&config.wallet_dir);

    if !config.daemon_address.is_empty() {
        wallet.init(
            &config.daemon_address,
            &config.daemon_username,
            &config.daemon_password,
            config.trusted_daemon,
        )?;
    }

    let state = std::sync::Arc::new(AppState {
        wallet: Mutex::new(wallet),
        shutdown_requested: Mutex::new(false),
        #[cfg(feature = "rust-scanner")]
        scanner: ScannerState::new(),
        #[cfg(feature = "multisig")]
        multisig: Mutex::new(MultisigState::new()),
    });

    let app = Router::new()
        .route("/json_rpc", post(json_rpc_handler))
        .layer(CorsLayer::permissive())
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&config.bind_address).await?;
    info!("shekyl-wallet-rpc listening on {}", config.bind_address);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(state))
        .await?;

    Ok(())
}

async fn json_rpc_handler(
    State(state): State<std::sync::Arc<AppState>>,
    Json(request): Json<JsonRpcRequest>,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let id = request.id.clone();
    let method = request.method.clone();

    #[cfg(feature = "multisig")]
    if crate::multisig_handlers::MULTISIG_METHODS.contains(&method.as_str()) {
        let result = crate::multisig_handlers::dispatch_multisig(
            &state.multisig,
            &method,
            request.params,
        );
        let response = match result {
            Ok(value) => JsonRpcResponse::success(id, value),
            Err(e) => JsonRpcResponse::error(id, e.code, e.message),
        };
        return (StatusCode::OK, Json(response));
    }

    let wallet_guard = match state.wallet.lock() {
        Ok(g) => g,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(
                JsonRpcResponse::error(id, -32603, "wallet lock poisoned".into()),
            ));
        }
    };

    let result = {
        #[cfg(feature = "rust-scanner")]
        {
            handlers::dispatch_with_scanner(&wallet_guard, &state.scanner, &method, request.params)
        }

        #[cfg(not(feature = "rust-scanner"))]
        {
            handlers::dispatch(&wallet_guard, &method, request.params)
        }
    };
    drop(wallet_guard);

    let response = match result {
        Ok(value) => {
            if method == "stop_wallet" {
                if let Ok(mut flag) = state.shutdown_requested.lock() {
                    *flag = true;
                }
            }
            JsonRpcResponse::success(id, value)
        }
        Err(e) => JsonRpcResponse::error(id, e.code, e.message),
    };

    (StatusCode::OK, Json(response))
}

async fn shutdown_signal(state: std::sync::Arc<AppState>) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        if state.shutdown_requested.lock().map(|f| *f).unwrap_or(false) {
            info!("Shutdown requested via stop_wallet RPC");
            break;
        }
    }
}
