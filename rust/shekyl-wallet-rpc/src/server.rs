// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! HTTP JSON-RPC server using axum.
//!
//! Listens on a configurable address and routes `/json_rpc` POST requests
//! to the handler dispatcher. All wallet operations are serialized through
//! a `Mutex<Wallet2>` since wallet2 is single-threaded.

use crate::handlers;
use crate::types::{JsonRpcRequest, JsonRpcResponse};
use crate::wallet::Wallet2;

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

    let result = {
        let wallet = state.wallet.lock().unwrap();
        handlers::dispatch(&wallet, &method, request.params)
    };

    let response = match result {
        Ok(value) => {
            if method == "stop_wallet" {
                *state.shutdown_requested.lock().unwrap() = true;
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
        if *state.shutdown_requested.lock().unwrap() {
            info!("Shutdown requested via stop_wallet RPC");
            break;
        }
    }
}
