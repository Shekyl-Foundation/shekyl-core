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

//! Axum HTTP server replacing epee's http_server_impl_base for daemon RPC.

use crate::core::CoreRpc;
use crate::handlers::{binary, json, json_rpc};
use crate::middleware::DEFAULT_BODY_LIMIT;

use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;
use tokio::sync::Notify;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::info;

pub struct AppState {
    pub core: Arc<CoreRpc>,
    pub restricted: bool,
    pub shutdown: Arc<Notify>,
}

pub struct ServerConfig {
    pub bind_address: String,
    pub restricted: bool,
    pub body_limit: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:21029".into(),
            restricted: false,
            body_limit: DEFAULT_BODY_LIMIT,
        }
    }
}

fn build_router(state: Arc<AppState>) -> Router {
    let restricted = state.restricted;

    // JSON-RPC 2.0 and unrestricted JSON REST routes
    let mut router = Router::new()
        .route("/json_rpc", post(json_rpc::handle))
        // Unrestricted JSON REST (with aliases) -- GET + POST to match epee behavior
        .route("/get_height", get(json::get_height).post(json::get_height))
        .route("/getheight", get(json::get_height).post(json::get_height))
        .route("/get_transactions", get(json::get_transactions).post(json::get_transactions))
        .route("/gettransactions", get(json::get_transactions).post(json::get_transactions))
        .route("/get_alt_blocks_hashes", get(json::get_alt_blocks_hashes).post(json::get_alt_blocks_hashes))
        .route("/is_key_image_spent", get(json::is_key_image_spent).post(json::is_key_image_spent))
        .route("/send_raw_transaction", get(json::send_raw_transaction).post(json::send_raw_transaction))
        .route("/sendrawtransaction", get(json::send_raw_transaction).post(json::send_raw_transaction))
        .route("/get_public_nodes", get(json::get_public_nodes).post(json::get_public_nodes))
        .route("/get_transaction_pool", get(json::get_transaction_pool).post(json::get_transaction_pool))
        .route(
            "/get_transaction_pool_hashes.bin",
            get(json::get_transaction_pool_hashes_bin).post(json::get_transaction_pool_hashes_bin),
        )
        .route(
            "/get_transaction_pool_hashes",
            get(json::get_transaction_pool_hashes).post(json::get_transaction_pool_hashes),
        )
        .route(
            "/get_transaction_pool_stats",
            get(json::get_transaction_pool_stats).post(json::get_transaction_pool_stats),
        )
        .route("/get_info", get(json::get_info).post(json::get_info))
        .route("/getinfo", get(json::get_info).post(json::get_info))
        .route("/get_limit", get(json::get_limit).post(json::get_limit))
        // Binary endpoints (always available)
        .route("/get_blocks.bin", post(binary::get_blocks))
        .route("/getblocks.bin", post(binary::get_blocks))
        .route("/get_blocks_by_height.bin", post(binary::get_blocks_by_height))
        .route(
            "/getblocks_by_height.bin",
            post(binary::get_blocks_by_height),
        )
        .route("/get_hashes.bin", post(binary::get_hashes))
        .route("/gethashes.bin", post(binary::get_hashes))
        .route("/get_o_indexes.bin", post(binary::get_o_indexes))
        .route(
            "/get_output_distribution.bin",
            post(binary::get_output_distribution_bin),
        );

    if !restricted {
        router = router
            .route("/start_mining", get(json::start_mining).post(json::start_mining))
            .route("/stop_mining", get(json::stop_mining).post(json::stop_mining))
            .route("/mining_status", get(json::mining_status).post(json::mining_status))
            .route("/save_bc", get(json::save_bc).post(json::save_bc))
            .route("/get_peer_list", get(json::get_peer_list).post(json::get_peer_list))
            .route("/set_log_hash_rate", get(json::set_log_hash_rate).post(json::set_log_hash_rate))
            .route("/set_log_level", get(json::set_log_level).post(json::set_log_level))
            .route("/set_log_categories", get(json::set_log_categories).post(json::set_log_categories))
            .route("/set_bootstrap_daemon", get(json::set_bootstrap_daemon).post(json::set_bootstrap_daemon))
            .route("/stop_daemon", get(json::stop_daemon).post(json::stop_daemon))
            .route("/get_net_stats", get(json::get_net_stats).post(json::get_net_stats))
            .route("/set_limit", get(json::set_limit).post(json::set_limit))
            .route("/out_peers", get(json::out_peers).post(json::out_peers))
            .route("/in_peers", get(json::in_peers).post(json::in_peers))
            .route("/update", get(json::update).post(json::update))
            .route("/pop_blocks", get(json::pop_blocks).post(json::pop_blocks));
    }

    router
        .layer(RequestBodyLimitLayer::new(state.body_limit()))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

impl AppState {
    fn body_limit(&self) -> usize {
        DEFAULT_BODY_LIMIT
    }
}

/// Start the Axum daemon RPC server. Blocks until the shutdown signal fires.
pub async fn run_server(
    core: Arc<CoreRpc>,
    config: ServerConfig,
    shutdown: Arc<Notify>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(AppState {
        core,
        restricted: config.restricted,
        shutdown: shutdown.clone(),
    });

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&config.bind_address).await?;
    info!(
        "shekyl-daemon-rpc ({}) listening on {}",
        if config.restricted {
            "restricted"
        } else {
            "unrestricted"
        },
        config.bind_address
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.notified().await })
        .await?;

    Ok(())
}
