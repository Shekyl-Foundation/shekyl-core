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

/// The restricted listener's block cap. Handler policy, single-sourced here
/// (RK-D6) rather than in the facts export, which answers what it is asked.
const RESTRICTED_BLOCK_COUNT: usize = 1000;

/// `/get_blocks_by_height.bin` (+ `/getblocks_by_height.bin`) — served
/// natively (RK-4b).
///
/// Every refusal keeps the shape the C++ gave, which on this endpoint means
/// a **200 carrying a non-OK `status`** rather than a transport error: too
/// many blocks on the restricted listener, and a height the chain cannot
/// produce, both answered that way and both worded as before.
pub async fn get_blocks_by_height(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> impl IntoResponse {
    let Ok(request) = shekyl_rpc_types::GetBlocksByHeightRequest::from_bin(&body) else {
        return (StatusCode::BAD_REQUEST, "Bad request").into_response();
    };
    if state.restricted && request.heights.len() > RESTRICTED_BLOCK_COUNT {
        return bin_status("Too many blocks requested in restricted mode");
    }
    let core = state.core.clone();
    let out = tokio::task::spawn_blocking(move || core.blocks_by_height(&request.heights)).await;
    let reply = match out {
        Ok(Ok(Ok(entries))) => shekyl_rpc_types::GetBlocksByHeightResponse {
            status: shekyl_rpc_types::RpcStatus::ok(),
            blocks: entries
                .into_iter()
                .map(|(block, txs)| shekyl_rpc_types::BlockEntry { block, txs })
                .collect(),
        },
        Ok(Ok(Err(height))) => {
            return bin_status(&format!("Error retrieving block at height {height}"))
        }
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

/// A 200 carrying only a non-OK `status`, which is how this endpoint reports
/// a refusal — the wallet and the engine branch on the status, so a
/// transport error here would be a different reply, not a tidier one.
fn bin_status(status: &str) -> axum::response::Response {
    let reply = shekyl_rpc_types::GetBlocksByHeightResponse {
        status: shekyl_rpc_types::RpcStatus(status.to_owned()),
        blocks: Vec::new(),
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
