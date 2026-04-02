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

//! Handler for the `/json_rpc` endpoint (JSON-RPC 2.0 dispatch).

use crate::server::AppState;
use crate::types::{FfiJsonRpcResult, JsonRpcRequest, JsonRpcResponse};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use std::sync::Arc;
use tracing::warn;

/// JSON-RPC methods that require unrestricted access.
const RESTRICTED_METHODS: &[&str] = &[
    "calc_pow",
    "generateblocks",
    "get_connections",
    "set_bans",
    "get_bans",
    "banned",
    "flush_txpool",
    "get_coinbase_tx_sum",
    "get_alternate_chains",
    "relay_tx",
    "sync_info",
    "prune_blockchain",
    "flush_cache",
    "rpc_access_tracking",
    "rpc_access_data",
    "rpc_access_account",
];

pub async fn handle(
    State(state): State<Arc<AppState>>,
    Json(request): Json<JsonRpcRequest>,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let id = request.id.clone();
    let method = request.method.clone();

    if state.restricted && RESTRICTED_METHODS.contains(&method.as_str()) {
        return (
            StatusCode::FORBIDDEN,
            Json(JsonRpcResponse::error(
                id,
                -32601,
                "Method not allowed in restricted mode".into(),
            )),
        );
    }

    let params_str = if request.params.is_null() || request.params.is_object() && request.params.as_object().is_none_or(|m| m.is_empty()) {
        String::new()
    } else {
        serde_json::to_string(&request.params).unwrap_or_default()
    };

    let core = state.core.clone();
    let method_clone = method.clone();
    let result =
        tokio::task::spawn_blocking(move || core.json_rpc(&method_clone, &params_str)).await;

    match result {
        Ok(Some(raw)) => match serde_json::from_str::<FfiJsonRpcResult>(&raw) {
            Ok(ffi_result) if ffi_result.ok => {
                let value = ffi_result.result.unwrap_or(serde_json::Value::Null);
                (StatusCode::OK, Json(JsonRpcResponse::success(id, value)))
            }
            Ok(ffi_result) => (
                StatusCode::OK,
                Json(JsonRpcResponse::error(
                    id,
                    ffi_result.error_code.unwrap_or(-32603),
                    ffi_result
                        .error_message
                        .unwrap_or_else(|| "Internal error".into()),
                )),
            ),
            Err(e) => {
                warn!(method = %method, "Failed to parse FFI JSON-RPC response: {e}");
                (
                    StatusCode::OK,
                    Json(JsonRpcResponse::error(
                        id,
                        -32603,
                        "Internal parse error".into(),
                    )),
                )
            }
        },
        Ok(None) => (
            StatusCode::OK,
            Json(JsonRpcResponse::error(
                id,
                -32601,
                format!("Method not found: {method}"),
            )),
        ),
        Err(e) => {
            warn!(method = %method, "spawn_blocking failed: {e}");
            (
                StatusCode::OK,
                Json(JsonRpcResponse::error(id, -32603, "Internal error".into())),
            )
        }
    }
}
