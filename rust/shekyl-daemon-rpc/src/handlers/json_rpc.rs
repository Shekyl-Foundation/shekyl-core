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
/// Whether to compute a block's proof-of-work hash: only if the caller asked
/// **and** the listener is unrestricted — the C++ handler's
/// `req.fill_pow_hash && !restricted`.
///
/// Its own function because it is a policy, not an expression: computing the
/// long hash is the expensive part of a header read, and a restricted
/// listener is exactly the one that must not be made to do it on request.
/// Dropping the `!restricted` here fails [`pow_hash_is_never_computed_for_a_restricted_listener`].
fn pow_hash_entitled(requested: bool, restricted: bool) -> bool {
    requested && !restricted
}

/// A JSON-RPC method this crate serves itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeMethod {
    Version,
    BlockCount,
    BlockHash,
    BlockHeaderByHeight,
    Block,
    SyncInfo,
    Connections,
    LastBlockHeader,
    BlockHeaderByHash,
    BlockHeadersRange,
    HardForkInfo,
    FeeEstimate,
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
        "get_block_header_by_height" | "getblockheaderbyheight" => {
            NativeMethod::BlockHeaderByHeight
        }
        "get_block" | "getblock" => NativeMethod::Block,
        "sync_info" => NativeMethod::SyncInfo,
        "get_connections" => NativeMethod::Connections,
        // RK-5b. Both spellings of each, as the C++ table carried them
        // (`core_rpc_ffi.cpp:269-283`); `hard_fork_info` and
        // `get_fee_estimate` had only one apiece there and gain none here.
        "get_last_block_header" | "getlastblockheader" => NativeMethod::LastBlockHeader,
        "get_block_header_by_hash" | "getblockheaderbyhash" => NativeMethod::BlockHeaderByHash,
        "get_block_headers_range" | "getblockheadersrange" => NativeMethod::BlockHeadersRange,
        "hard_fork_info" => NativeMethod::HardForkInfo,
        "get_fee_estimate" => NativeMethod::FeeEstimate,
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
        NativeMethod::Block => {
            let request = match crate::methods::block_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(fault)),
            };
            let fill_pow_hash = pow_hash_entitled(request.fill_pow_hash, state.restricted);
            let core = state.core.clone();
            let out = tokio::task::spawn_blocking(move || {
                let facts = crate::chain_facts::FfiChainFacts::new(core);
                crate::methods::get_block(&facts, &request, fill_pow_hash)
            })
            .await;
            Some(frame_native(out))
        }
        NativeMethod::SyncInfo => {
            // Two fact sources, one worker: `sync_info` is the only native
            // method that reads the chain and the p2p layer, and they are
            // not synchronised with each other — see `methods::sync_info`.
            let core = state.core.clone();
            let out = tokio::task::spawn_blocking(move || {
                let chain = crate::chain_facts::FfiChainFacts::new(Arc::clone(&core));
                let p2p = crate::chain_facts::FfiP2pFacts::new(core);
                crate::methods::sync_info(&chain, &p2p)
            })
            .await;
            Some(frame_native(out))
        }
        NativeMethod::Connections => {
            let core = state.core.clone();
            let out = tokio::task::spawn_blocking(move || {
                let facts = crate::chain_facts::FfiP2pFacts::new(core);
                crate::methods::get_connections(&facts)
            })
            .await;
            Some(frame_native(out))
        }
        // ── RK-5b ───────────────────────────────────────────────────────
        //
        // These five take `state.restricted` itself rather than a
        // pre-computed `fill_pow_hash`, because they **refuse** a restricted
        // caller that asked for a pow hash instead of blanking the field —
        // see `methods::pow_hash_or_refuse`. `pow_hash_entitled` above stays
        // the policy for RK-2's methods, whose C++ shape this slice does not
        // reopen.
        NativeMethod::LastBlockHeader => {
            let request = match crate::methods::last_block_header_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(fault)),
            };
            let core = state.core.clone();
            let restricted = state.restricted;
            let out = tokio::task::spawn_blocking(move || {
                let facts = crate::chain_facts::FfiChainFacts::new(core);
                crate::methods::get_last_block_header(&facts, request.fill_pow_hash, restricted)
            })
            .await;
            Some(frame_native(out))
        }
        NativeMethod::BlockHeaderByHash => {
            let request = match crate::methods::block_header_by_hash_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(fault)),
            };
            let core = state.core.clone();
            let restricted = state.restricted;
            let out = tokio::task::spawn_blocking(move || {
                let facts = crate::chain_facts::FfiChainFacts::new(core);
                crate::methods::get_block_header_by_hash(&facts, &request, restricted)
            })
            .await;
            Some(frame_native(out))
        }
        NativeMethod::BlockHeadersRange => {
            let request = match crate::methods::block_headers_range_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(fault)),
            };
            let core = state.core.clone();
            let restricted = state.restricted;
            let out = tokio::task::spawn_blocking(move || {
                let facts = crate::chain_facts::FfiChainFacts::new(core);
                crate::methods::get_block_headers_range(&facts, &request, restricted)
            })
            .await;
            Some(frame_native(out))
        }
        NativeMethod::HardForkInfo => {
            let request = match crate::methods::hard_fork_info_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(fault)),
            };
            let core = state.core.clone();
            let out = tokio::task::spawn_blocking(move || {
                let facts = crate::chain_facts::FfiChainFacts::new(core);
                crate::methods::hard_fork_info(&facts, &request)
            })
            .await;
            Some(frame_native(out))
        }
        NativeMethod::FeeEstimate => {
            let request = match crate::methods::fee_estimate_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(fault)),
            };
            let core = state.core.clone();
            let out = tokio::task::spawn_blocking(move || {
                let facts = crate::chain_facts::FfiChainFacts::new(core);
                crate::methods::get_fee_estimate(&facts, &request)
            })
            .await;
            Some(frame_native(out))
        }
        NativeMethod::BlockHeaderByHeight => {
            // The params parse is pure and its refusal needs no core, so it
            // happens before a worker is taken — as `on_get_block_hash`'s does.
            let request = match crate::methods::block_header_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(fault)),
            };
            let fill_pow_hash = pow_hash_entitled(request.fill_pow_hash, state.restricted);
            let core = state.core.clone();
            let out = tokio::task::spawn_blocking(move || {
                let facts = crate::chain_facts::FfiChainFacts::new(core);
                crate::methods::get_block_header_by_height(&facts, request.height, fill_pow_hash)
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

    /// Every name the daemon serves natively, the method each belongs to,
    /// and whether the restricted listener must refuse it.
    ///
    /// The third column arrived with RK-5a, which brought the first
    /// **admin-only** native methods. Before it, every native name was public
    /// and the test below could assert a constant; asserting a constant now
    /// would say `sync_info` and `get_connections` are public, which is the
    /// one thing about them that must not become true. `sync_info` lists this
    /// node's peers and `get_connections` is the connection table — both are
    /// the anonymity graph, so a migration that quietly made them public
    /// would be a mission-#2 regression that no other test in this file sees.
    const SPECIFIED_NATIVE_METHODS: &[(&str, NativeMethod, bool)] = &[
        ("get_version", NativeMethod::Version, false),
        ("get_block_count", NativeMethod::BlockCount, false),
        ("getblockcount", NativeMethod::BlockCount, false),
        ("on_get_block_hash", NativeMethod::BlockHash, false),
        ("on_getblockhash", NativeMethod::BlockHash, false),
        (
            "get_block_header_by_height",
            NativeMethod::BlockHeaderByHeight,
            false,
        ),
        (
            "getblockheaderbyheight",
            NativeMethod::BlockHeaderByHeight,
            false,
        ),
        ("get_block", NativeMethod::Block, false),
        ("getblock", NativeMethod::Block, false),
        ("sync_info", NativeMethod::SyncInfo, true),
        ("get_connections", NativeMethod::Connections, true),
        (
            "get_last_block_header",
            NativeMethod::LastBlockHeader,
            false,
        ),
        ("getlastblockheader", NativeMethod::LastBlockHeader, false),
        (
            "get_block_header_by_hash",
            NativeMethod::BlockHeaderByHash,
            false,
        ),
        (
            "getblockheaderbyhash",
            NativeMethod::BlockHeaderByHash,
            false,
        ),
        (
            "get_block_headers_range",
            NativeMethod::BlockHeadersRange,
            false,
        ),
        (
            "getblockheadersrange",
            NativeMethod::BlockHeadersRange,
            false,
        ),
        ("hard_fork_info", NativeMethod::HardForkInfo, false),
        ("get_fee_estimate", NativeMethod::FeeEstimate, false),
    ];

    /// The dispatcher's own recognizer answers every specified name and
    /// nothing else. This calls `native_method_for` — the function
    /// [`native_method`] dispatches on — so deleting or renaming an alias
    /// arm turns it red, which an assertion about the restricted list alone
    /// could not do.
    #[test]
    fn native_dispatch_answers_every_alias_and_no_foreign_name() {
        for (name, expected, _) in SPECIFIED_NATIVE_METHODS {
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
            "get_alternate_chains",
            "mining_status",
            "get_block_by_hash",
            "getblockcount2",
            "",
        ] {
            assert!(
                native_method_for(name).is_none(),
                "{name} must fall through to the C++ dispatch table"
            );
        }
    }

    /// The restricted listener never computes a pow hash, however the request
    /// is phrased — the whole truth table, since only one of its four cells
    /// may be true.
    #[test]
    fn pow_hash_is_never_computed_for_a_restricted_listener() {
        assert!(pow_hash_entitled(true, false), "asked for, unrestricted");
        assert!(!pow_hash_entitled(true, true), "asked for, but restricted");
        assert!(!pow_hash_entitled(false, false), "not asked for");
        assert!(!pow_hash_entitled(false, true), "not asked for, restricted");
    }

    /// Each native name is gated exactly as specified, and none is gated on
    /// the unrestricted listener — asserted through `method_is_gated`, the
    /// function `handle` calls, rather than through the list it reads.
    ///
    /// Both directions matter and for different reasons. A public method that
    /// became gated is a route the wallet loses; a gated one that became
    /// public is peer topology served to anyone who asks. Migrating a method
    /// out of C++ moves it past this gate, so this is the assertion that
    /// notices.
    #[test]
    fn native_methods_are_gated_exactly_as_specified() {
        for (name, _, gated) in SPECIFIED_NATIVE_METHODS {
            assert_eq!(
                method_is_gated(true, name),
                *gated,
                "{name}: restricted-listener gating must match the specification"
            );
            assert!(
                !method_is_gated(false, name),
                "{name} must answer on the unrestricted listener"
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
