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
///
/// The daemon's **second** restricted gate. `/json_rpc` itself is served on
/// both listeners (it is the wallet's main surface), so unlike the REST route
/// table the gate here cannot be listener selection — it is per-method, inside
/// the handler. Same privacy fact, different mechanism, and it needs its own
/// witness: see [`method_is_gated`].
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
];

/// Whether this listener must refuse this JSON-RPC method.
///
/// Pure, and the single place the per-method gate is decided — so a test can
/// call the same function [`handle`] calls, with both arms, without building
/// an `AppState` (which links `core_rpc_ffi_*`). Deleting the `restricted &&`
/// here fails [`admin_methods_are_refused_only_on_the_restricted_listener`].
fn method_is_gated(restricted: bool, method: &str) -> bool {
    restricted && RESTRICTED_METHODS.contains(&method)
}

pub async fn handle(
    State(state): State<Arc<AppState>>,
    Json(request): Json<JsonRpcRequest>,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let id = request.id.clone();
    let method = request.method.clone();

    if method_is_gated(state.restricted, &method) {
        return (
            StatusCode::FORBIDDEN,
            Json(JsonRpcResponse::error(
                id,
                -32601,
                "Method not allowed in restricted mode".into(),
            )),
        );
    }

    // Natively-served methods (RK-1, `docs/design/DAEMON_RPC_KV_CUTOVER.md`)
    // never reach the C++ dispatch table.
    if let Some(native) = native_method(&state, &method).await {
        return match native {
            Ok(value) => (StatusCode::OK, Json(JsonRpcResponse::success(id, value))),
            Err(_) => (
                StatusCode::OK,
                Json(JsonRpcResponse::error(id, -32603, "Internal error".into())),
            ),
        };
    }

    let params_str = if request.params.is_null()
        || request.params.is_object()
            && request
                .params
                .as_object()
                .is_none_or(serde_json::Map::is_empty)
    {
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
                let mut value = ffi_result.result.unwrap_or(serde_json::Value::Null);
                // Rust owns `rpc_connections_count`; fill it on the json_rpc
                // get_info surface too (unrestricted only, matching the REST
                // handler and the C++ restricted-mode policy).
                if method == "get_info" && !state.restricted {
                    if let Some(obj) = value.as_object_mut() {
                        obj.insert(
                            "rpc_connections_count".to_owned(),
                            state.conn_tracker.active_total().into(),
                        );
                    }
                }
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

/// Dispatch `method` natively if Rust owns it; `None` hands it to the C++
/// table. Each arm is one `methods::*` call framed as a JSON value.
async fn native_method(
    state: &Arc<AppState>,
    method: &str,
) -> Option<Result<serde_json::Value, crate::methods::RpcFault>> {
    match method {
        "get_version" => {
            let core = state.core.clone();
            let out = tokio::task::spawn_blocking(move || {
                let facts = crate::chain_facts::FfiChainFacts::new(core);
                crate::methods::get_version(&facts)
            })
            .await;
            Some(match out {
                Ok(Ok(reply)) => serde_json::to_value(reply).map_err(|_| {
                    crate::methods::RpcFault::Facts(crate::chain_facts::FactsFault::Unknown(0))
                }),
                Ok(Err(fault)) => Err(fault),
                Err(_) => Err(crate::methods::RpcFault::Facts(
                    crate::chain_facts::FactsFault::Unknown(0),
                )),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The admin JSON-RPC surface, restated independently of
    /// `RESTRICTED_METHODS`.
    ///
    /// Same discipline as the REST route table's specification: an oracle that
    /// iterates `RESTRICTED_METHODS` re-states whatever that list says and so
    /// stays green when a method is dropped from it — which is the edit that
    /// exposes `get_connections` (this node's live peer set) and the ban/mining
    /// controls to unauthenticated callers on the public listener.
    const SPECIFIED_ADMIN_METHODS: &[&str] = &[
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
    ];

    /// Dual-armed, because *refused when restricted* alone passes for a method
    /// that is refused everywhere — including one that does not exist.
    #[test]
    fn admin_methods_are_refused_only_on_the_restricted_listener() {
        for method in SPECIFIED_ADMIN_METHODS {
            assert!(
                method_is_gated(true, method),
                "{method} is specified admin-only but the public listener \
                 serves it"
            );
            assert!(
                !method_is_gated(false, method),
                "{method} is refused on the admin listener too — the gate is \
                 not the restricted flag"
            );
        }
    }

    /// The gate names exactly the specified methods: one dropped from
    /// `RESTRICTED_METHODS` is caught above, one added without review here.
    #[test]
    fn restricted_method_list_matches_the_specification() {
        let mut gated: Vec<&str> = RESTRICTED_METHODS.to_vec();
        let mut specified: Vec<&str> = SPECIFIED_ADMIN_METHODS.to_vec();
        gated.sort_unstable();
        specified.sort_unstable();
        assert_eq!(
            gated, specified,
            "the restricted JSON-RPC method list diverged from the \
             specification above; change both in the same commit"
        );
    }

    /// Control: the wallet's ordinary traffic is never gated, so the
    /// assertions above are about *these* methods and not about a gate that
    /// refuses everything.
    #[test]
    fn wallet_facing_methods_are_never_gated() {
        for method in [
            "get_info",
            "get_block",
            "get_block_count",
            "get_fee_estimate",
        ] {
            assert!(!method_is_gated(true, method), "{method}");
            assert!(!method_is_gated(false, method), "{method}");
        }
    }
}
