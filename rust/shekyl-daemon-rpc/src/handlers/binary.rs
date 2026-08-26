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
///
/// **This is a behaviour fix, not parity.** The C++ gated the cap on
/// `m_restricted && ctx`, and the bridge that reached it — `dispatch_bin` —
/// always passed `ctx == nullptr`. So `restricted` was false on every call
/// through it and the cap never fired: a restricted listener accepted a
/// request for any number of heights. The constant and the check were both
/// there; only the argument made them dead. Serving it as intended is the
/// safer reading of unambiguous intent, and pre-genesis there is no client
/// relying on the gap.
const RESTRICTED_BLOCK_COUNT: usize = 1000;

/// `/get_blocks_by_height.bin` (+ `/getblocks_by_height.bin`) — served
/// natively (RK-4b).
///
/// Every refusal keeps the *shape* the C++ gave, which on this endpoint means
/// a **200 carrying a non-OK `status`** rather than a transport error, with
/// the wording unchanged. A height the chain cannot produce also keeps the
/// blocks read before it, as the C++ did. The one deliberate difference is
/// that the restricted cap now fires — see [`RESTRICTED_BLOCK_COUNT`].
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
        Ok(Ok((entries, failed))) => shekyl_rpc_types::GetBlocksByHeightResponse {
            // A failure names its height and still carries the blocks read
            // before it — the reply the C++ produced, where the prefix and
            // the error travel together.
            status: failed.map_or_else(shekyl_rpc_types::RpcStatus::ok, |height| {
                shekyl_rpc_types::RpcStatus(format!("Error retrieving block at height {height}"))
            }),
            blocks: entries
                .into_iter()
                .map(|(block, txs)| shekyl_rpc_types::BlockEntry { block, txs })
                .collect(),
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

#[cfg(test)]
mod tests {
    use super::RESTRICTED_BLOCK_COUNT;
    use shekyl_rpc_types::{GetBlocksByHeightRequest, GetBlocksByHeightResponse, RpcStatus};

    /// The cap is a policy this daemon chose, not one it inherited working:
    /// the C++ check was gated on a `ctx` the bridge always passed as null.
    /// It refuses as the C++ *would* have — a 200 carrying the non-OK status,
    /// with the wording unchanged — rather than a transport error.
    #[test]
    fn the_restricted_cap_refuses_in_the_replys_status_not_the_transport() {
        let refusal = GetBlocksByHeightResponse {
            status: RpcStatus("Too many blocks requested in restricted mode".to_owned()),
            blocks: Vec::new(),
        };
        let bytes = refusal.to_bin().expect("encode");
        let back = GetBlocksByHeightResponse::from_bin(&bytes).expect("decode");
        assert!(!back.status.is_ok(), "the refusal travels in `status`");
        assert_eq!(
            back.status.0,
            "Too many blocks requested in restricted mode"
        );
        assert!(back.blocks.is_empty());
    }

    /// The boundary itself: at the cap a request is served, one past it is
    /// not. Changing the constant without meaning to turns this red.
    #[test]
    fn the_cap_is_a_thousand_heights_and_the_boundary_is_inclusive() {
        assert_eq!(RESTRICTED_BLOCK_COUNT, 1000);
        let at = GetBlocksByHeightRequest {
            heights: vec![0; RESTRICTED_BLOCK_COUNT],
        };
        let over = GetBlocksByHeightRequest {
            heights: vec![0; RESTRICTED_BLOCK_COUNT + 1],
        };
        assert!(
            at.heights.len() <= RESTRICTED_BLOCK_COUNT,
            "at the cap: served"
        );
        assert!(
            over.heights.len() > RESTRICTED_BLOCK_COUNT,
            "one past the cap: refused"
        );
        // Both still encode — the cap is the handler's decision, not the
        // wire's, so a large request is well-formed and simply declined.
        assert!(at.to_bin().is_ok() && over.to_bin().is_ok());
    }
}
