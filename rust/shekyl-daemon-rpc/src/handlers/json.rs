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

//! Handlers for JSON REST endpoints (MAP_URI_AUTO_JON2 family).
//!
//! Each handler is a thin async wrapper that offloads the blocking C++ FFI call
//! to a Tokio blocking thread.

use crate::server::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use std::sync::Arc;

async fn dispatch_json(state: Arc<AppState>, uri: &'static str, body: String) -> impl IntoResponse {
    let core = state.core.clone();
    let result = tokio::task::spawn_blocking(move || core.json_endpoint(uri, &body)).await;

    match result {
        Ok(Some(json)) => (StatusCode::OK, [("content-type", "application/json")], json),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("content-type", "application/json")],
            r#"{"status":"ERROR","error":"FFI dispatch failed"}"#.to_string(),
        ),
    }
}

macro_rules! json_handler {
    ($fn_name:ident, $uri:expr) => {
        pub async fn $fn_name(
            State(state): State<Arc<AppState>>,
            body: String,
        ) -> impl IntoResponse {
            dispatch_json(state, $uri, body).await
        }
    };
}

// Unrestricted endpoints
json_handler!(get_height, "/get_height");
json_handler!(get_transactions, "/get_transactions");
json_handler!(get_alt_blocks_hashes, "/get_alt_blocks_hashes");
json_handler!(is_key_image_spent, "/is_key_image_spent");
json_handler!(send_raw_transaction, "/send_raw_transaction");
json_handler!(get_public_nodes, "/get_public_nodes");
json_handler!(get_transaction_pool, "/get_transaction_pool");
json_handler!(
    get_transaction_pool_hashes_bin,
    "/get_transaction_pool_hashes.bin"
);
json_handler!(get_transaction_pool_hashes, "/get_transaction_pool_hashes");
json_handler!(get_transaction_pool_stats, "/get_transaction_pool_stats");
json_handler!(get_info, "/get_info");
json_handler!(get_limit, "/get_limit");

// Restricted-only endpoints (restriction enforced at route registration)
json_handler!(start_mining, "/start_mining");
json_handler!(stop_mining, "/stop_mining");
json_handler!(mining_status, "/mining_status");
json_handler!(save_bc, "/save_bc");
json_handler!(get_peer_list, "/get_peer_list");
json_handler!(set_log_hash_rate, "/set_log_hash_rate");
json_handler!(set_log_level, "/set_log_level");
json_handler!(set_log_categories, "/set_log_categories");
json_handler!(set_bootstrap_daemon, "/set_bootstrap_daemon");
json_handler!(stop_daemon, "/stop_daemon");
json_handler!(get_net_stats, "/get_net_stats");
json_handler!(set_limit, "/set_limit");
json_handler!(out_peers, "/out_peers");
json_handler!(in_peers, "/in_peers");
json_handler!(update, "/update");
json_handler!(pop_blocks, "/pop_blocks");
