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

use crate::methods::{InternalFault, RpcFault};
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
    if let Some(native) = native_method(&state, &method, &request.params).await {
        return match native {
            Ok(value) => (StatusCode::OK, Json(JsonRpcResponse::success(id, value))),
            // A refusal is the method answering — a bad request, or a height
            // the chain does not hold. Normal traffic: it carries its own
            // code and message and is not logged as a daemon problem.
            Err(RpcFault::Refused(refusal)) => (
                StatusCode::OK,
                Json(JsonRpcResponse::error(id, refusal.code, refusal.message)),
            ),
            Err(fault) => {
                warn!(method = %method, ?fault, "native JSON-RPC method failed");
                (
                    StatusCode::OK,
                    Json(JsonRpcResponse::error(id, -32603, "Internal error".into())),
                )
            }
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
/// A JSON-RPC method this crate serves itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeMethod {
    Version,
    BlockCount,
    BlockHash,
}

/// The names each native method answers to — every alias the C++ dispatch
/// table carried, since dropping one 404s a name the daemon has always
/// answered.
///
/// The single source: [`native_method`] dispatches on what this returns, so a
/// name missing here is not served, and the test that checks the alias set
/// exercises the same function the request path does.
fn native_method_for(method: &str) -> Option<NativeMethod> {
    Some(match method {
        "get_version" => NativeMethod::Version,
        "get_block_count" | "getblockcount" => NativeMethod::BlockCount,
        "on_get_block_hash" | "on_getblockhash" => NativeMethod::BlockHash,
        _ => return None,
    })
}

async fn native_method(
    state: &Arc<AppState>,
    method: &str,
    params: &serde_json::Value,
) -> Option<Result<serde_json::Value, RpcFault>> {
    match native_method_for(method)? {
        NativeMethod::Version => {
            let core = state.core.clone();
            let out = tokio::task::spawn_blocking(move || {
                let facts = crate::chain_facts::FfiChainFacts::new(core);
                crate::methods::get_version(&facts)
            })
            .await;
            Some(frame_native(out))
        }
        NativeMethod::BlockCount => {
            let core = state.core.clone();
            let out = tokio::task::spawn_blocking(move || {
                let facts = crate::chain_facts::FfiChainFacts::new(core);
                crate::methods::get_block_count(&facts)
            })
            .await;
            Some(frame_native(out))
        }
        NativeMethod::BlockHash => {
            // The params parse is pure and its refusal needs no core, so it
            // happens before a worker is taken.
            let height = match crate::methods::get_block_hash_height(params) {
                Ok(height) => height,
                Err(fault) => return Some(Err(fault)),
            };
            let core = state.core.clone();
            let out = tokio::task::spawn_blocking(move || {
                let facts = crate::chain_facts::FfiChainFacts::new(core);
                crate::methods::get_block_hash(&facts, height)
            })
            .await;
            Some(frame_native(out))
        }
    }
}

/// Frame a native method's outcome as a JSON value, keeping the cause of a
/// failure where it belongs: a facts fault stays a facts fault; a reply the
/// transport could not encode, or a handler task that did not complete, is
/// an [`InternalFault`] — never attributed to the core.
fn frame_native<T: serde::Serialize>(
    out: Result<Result<T, RpcFault>, tokio::task::JoinError>,
) -> Result<serde_json::Value, RpcFault> {
    match out {
        Ok(Ok(reply)) => {
            serde_json::to_value(reply).map_err(|_| RpcFault::Internal(InternalFault::Serialize))
        }
        Ok(Err(fault)) => Err(fault),
        Err(_) => Err(RpcFault::Internal(InternalFault::Join)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_facts::FactsFault;

    /// The framing keeps causes apart: a facts code is a facts fault, a join
    /// failure is internal. Collapsing either into the other is the edit this
    /// turns red (it was `FactsFault::Unknown(0)` for both, once).
    #[tokio::test]
    async fn frame_native_keeps_the_cause_of_a_failure() {
        let ok: Result<Result<u64, RpcFault>, tokio::task::JoinError> = Ok(Ok(7));
        assert_eq!(frame_native(ok).unwrap(), serde_json::json!(7));

        let facts: Result<Result<u64, RpcFault>, tokio::task::JoinError> =
            Ok(Err(RpcFault::Facts(FactsFault::NotReady)));
        assert_eq!(
            frame_native(facts).unwrap_err(),
            RpcFault::Facts(FactsFault::NotReady)
        );

        // A task that panicked is the one JoinError we can manufacture.
        let joined =
            tokio::task::spawn_blocking(|| -> Result<u64, RpcFault> { panic!("boom") }).await;
        assert!(joined.is_err());
        assert_eq!(
            frame_native(joined).unwrap_err(),
            RpcFault::Internal(InternalFault::Join)
        );
    }

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

    /// Every name the daemon serves natively, and the method each belongs to.
    const SPECIFIED_NATIVE_METHODS: &[(&str, NativeMethod)] = &[
        ("get_version", NativeMethod::Version),
        ("get_block_count", NativeMethod::BlockCount),
        ("getblockcount", NativeMethod::BlockCount),
        ("on_get_block_hash", NativeMethod::BlockHash),
        ("on_getblockhash", NativeMethod::BlockHash),
    ];

    /// The dispatcher's own recognizer answers every specified name and
    /// nothing else. This calls `native_method_for` — the function
    /// [`native_method`] dispatches on — so deleting or renaming an alias
    /// arm turns it red, which an assertion about the restricted list alone
    /// could not do.
    #[test]
    fn native_dispatch_answers_every_alias_and_no_foreign_name() {
        for (name, expected) in SPECIFIED_NATIVE_METHODS {
            assert_eq!(
                native_method_for(name),
                Some(*expected),
                "{name} must dispatch natively"
            );
        }
        // Still the C++ table's: recognizing one here would serve it from a
        // handler that does not exist yet.
        for name in [
            "get_info",
            "sync_info",
            "hard_fork_info",
            "get_block",
            "get_block_header_by_height",
            "getblockcount2",
            "",
        ] {
            assert!(
                native_method_for(name).is_none(),
                "{name} must fall through to the C++ dispatch table"
            );
        }
    }

    /// None of the natively-served names is admin-only, so the restricted
    /// listener serves them too — asserted through `method_is_gated`, the
    /// function `handle` calls, not through the list it reads.
    #[test]
    fn native_methods_are_never_gated() {
        for (name, _) in SPECIFIED_NATIVE_METHODS {
            assert!(
                !method_is_gated(true, name),
                "{name} must answer on the restricted listener"
            );
        }
    }

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
