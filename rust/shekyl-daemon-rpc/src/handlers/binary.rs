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

//! Handlers for binary endpoints (MAP_URI_AUTO_BIN2 family).

use crate::authority::Authority;
use crate::methods::RpcFault;
use crate::server::AppState;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Extension;
use std::sync::Arc;

/// `/get_blocks_by_height.bin` (+ `/getblocks_by_height.bin`) — served
/// natively (RK-4b).
///
/// A height the chain cannot produce keeps the C++ shape: HTTP 200, a
/// non-OK `status`, and the blocks read before it. The bounded caller's
/// height cap is the method's refusal, the JSON-RPC error object on HTTP
/// 200 (RW-Q3), the same object every other surface uses. The cap used to
/// be dead: the C++ gated it on `m_restricted && ctx`, and the bridge
/// always passed `ctx == nullptr`.
pub async fn get_blocks_by_height(
    State(state): State<Arc<AppState>>,
    Extension(authority): Extension<Authority>,
    body: Bytes,
) -> impl IntoResponse {
    let Ok(request) = shekyl_rpc_types::GetBlocksByHeightRequest::from_bin(&body) else {
        return (StatusCode::BAD_REQUEST, "Bad request").into_response();
    };
    let chain = Arc::clone(&state.handles.chain);
    let host = authority.host();
    let out = tokio::task::spawn_blocking(move || {
        crate::read_methods::get_blocks_by_height(chain.as_ref(), &request, host)
    })
    .await;
    match out {
        Ok(Ok(reply)) => octet_stream(reply.to_bin()),
        Ok(Err(RpcFault::Refused(refusal))) => (
            StatusCode::OK,
            [("content-type", "application/json")],
            serde_json::to_string(&refusal.to_json_rpc(serde_json::Value::Null))
                .expect("a refusal serializes"),
        )
            .into_response(),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "facts unavailable").into_response(),
    }
}

fn octet_stream(encoded: Result<Vec<u8>, shekyl_rpc_types::BinError>) -> axum::response::Response {
    match encoded {
        Ok(bytes) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "encode failed").into_response(),
    }
}

/// `/get_o_indexes.bin` — served natively (RK-4a), not dispatched to C++.
///
/// The first `.bin` method to answer from Rust. Every refusal keeps the
/// shape the C++ gave: an unreadable request is a 400, and a transaction
/// the store does not have is a **200 carrying a non-OK `status`**, because
/// that is what the handler did (`res.status = "Failed"; return true`) and
/// what the wallet client reads.
pub async fn get_o_indexes(State(state): State<Arc<AppState>>, body: Bytes) -> impl IntoResponse {
    let Ok(request) = shekyl_rpc_types::GetOIndexesRequest::from_bin(&body) else {
        return (StatusCode::BAD_REQUEST, "Bad request").into_response();
    };
    let chain = Arc::clone(&state.handles.chain);
    let out = tokio::task::spawn_blocking(move || {
        crate::read_methods::get_o_indexes(chain.as_ref(), &request)
    })
    .await;
    let Ok(Ok(reply)) = out else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "facts unavailable").into_response();
    };
    octet_stream(reply.to_bin())
}
