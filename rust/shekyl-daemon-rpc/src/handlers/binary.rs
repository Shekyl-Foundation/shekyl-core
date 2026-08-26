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

use crate::server::AppState;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use std::sync::Arc;

async fn dispatch_bin(state: Arc<AppState>, uri: &'static str, body: Bytes) -> impl IntoResponse {
    let core = state.core.clone();
    let body_vec = body.to_vec();
    let result = tokio::task::spawn_blocking(move || core.bin_endpoint(uri, &body_vec)).await;

    match result {
        Ok(Ok(data)) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            data,
        )
            .into_response(),
        Ok(Err(-1)) => (StatusCode::BAD_REQUEST, "Bad request").into_response(),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "FFI dispatch failed").into_response(),
    }
}

macro_rules! bin_handler {
    ($fn_name:ident, $uri:expr) => {
        pub async fn $fn_name(
            State(state): State<Arc<AppState>>,
            body: Bytes,
        ) -> impl IntoResponse {
            dispatch_bin(state, $uri, body).await
        }
    };
}

bin_handler!(get_blocks_by_height, "/get_blocks_by_height.bin");
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
    let core = state.core.clone();
    let out = tokio::task::spawn_blocking(move || core.tx_output_indices(&request.txid)).await;
    let reply = match out {
        Ok(Ok((o_indexes, true))) => shekyl_rpc_types::GetOIndexesResponse {
            status: shekyl_rpc_types::RpcStatus::ok(),
            o_indexes,
        },
        // No such transaction. The C++ answered 200 with `status: "Failed"`,
        // and the wallet client branches on that; a transport-level error
        // here would be a different reply, not a tidier one.
        Ok(Ok((_, false))) => shekyl_rpc_types::GetOIndexesResponse {
            status: shekyl_rpc_types::RpcStatus("Failed".to_owned()),
            o_indexes: Vec::new(),
        },
        Ok(Err(_)) | Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "facts unavailable").into_response()
        }
    };
    match reply.to_bin() {
        Ok(bytes) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "encode failed").into_response(),
    }
}
