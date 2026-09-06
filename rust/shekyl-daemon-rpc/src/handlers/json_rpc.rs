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

use crate::chain_facts::{FfiChainFacts, FfiP2pFacts};
use crate::core::CoreRpc;
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

/// Whether to compute a block's proof-of-work hash: only if the caller asked
/// **and** the listener is unrestricted — the C++ handler's
/// `req.fill_pow_hash && !restricted`.
///
/// Its own function because it is a policy, not an expression: computing the
/// long hash is the expensive part of a header read, and a restricted
/// listener is exactly the one that must not be made to do it on request.
/// Dropping the `!restricted` here fails [`pow_hash_is_never_computed_for_a_restricted_listener`].
///
/// RK-5b's methods do **not** use this. They take `restricted` itself and
/// refuse a restricted caller that asked for the field (`methods::pow_hash_or_refuse`)
/// rather than blanking it. This stays the policy for RK-2's methods, whose
/// C++ shape that slice does not reopen.
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

/// Dispatch `method` natively if Rust owns it; `None` hands it to the C++
/// table. Each arm is one `methods::*` call framed as a JSON value.
async fn native_method(
    state: &Arc<AppState>,
    method: &str,
    params: &serde_json::Value,
) -> Option<Result<serde_json::Value, RpcFault>> {
    match native_method_for(method)? {
        NativeMethod::Version => Some(frame_native(
            run_blocking(state, |core| {
                crate::methods::get_version(&FfiChainFacts::new(core))
            })
            .await,
        )),
        NativeMethod::BlockCount => Some(frame_native(
            run_blocking(state, |core| {
                crate::methods::get_block_count(&FfiChainFacts::new(core))
            })
            .await,
        )),
        NativeMethod::BlockHash => {
            // The params parse is pure and its refusal needs no core, so it
            // happens before a worker is taken.
            let height = match crate::methods::get_block_hash_height(params) {
                Ok(height) => height,
                Err(fault) => return Some(Err(fault)),
            };
            Some(frame_native(
                run_blocking(state, move |core| {
                    crate::methods::get_block_hash(&FfiChainFacts::new(core), height)
                })
                .await,
            ))
        }
        NativeMethod::Block => {
            let request = match crate::methods::block_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(fault)),
            };
            let fill_pow_hash = pow_hash_entitled(request.fill_pow_hash, state.restricted);
            Some(frame_native(
                run_blocking(state, move |core| {
                    crate::methods::get_block(&FfiChainFacts::new(core), &request, fill_pow_hash)
                })
                .await,
            ))
        }
        NativeMethod::SyncInfo => Some(frame_native(
            run_blocking(state, |core| {
                // Two fact sources, one worker: `sync_info` is the only
                // native method that reads the chain and the p2p layer,
                // and they are not synchronised with each other — see
                // `methods::sync_info`.
                let chain = FfiChainFacts::new(Arc::clone(&core));
                let p2p = FfiP2pFacts::new(core);
                crate::methods::sync_info(&chain, &p2p)
            })
            .await,
        )),
        NativeMethod::Connections => Some(frame_native(
            run_blocking(state, |core| {
                crate::methods::get_connections(&FfiP2pFacts::new(core))
            })
            .await,
        )),
        NativeMethod::LastBlockHeader => {
            let request = match crate::methods::last_block_header_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(fault)),
            };
            let restricted = state.restricted;
            Some(frame_native(
                run_blocking(state, move |core| {
                    crate::methods::get_last_block_header(
                        &FfiChainFacts::new(core),
                        request.fill_pow_hash,
                        restricted,
                    )
                })
                .await,
            ))
        }
        NativeMethod::BlockHeaderByHash => {
            let request = match crate::methods::block_header_by_hash_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(fault)),
            };
            let restricted = state.restricted;
            Some(frame_native(
                run_blocking(state, move |core| {
                    crate::methods::get_block_header_by_hash(
                        &FfiChainFacts::new(core),
                        &request,
                        restricted,
                    )
                })
                .await,
            ))
        }
        NativeMethod::BlockHeadersRange => {
            let request = match crate::methods::block_headers_range_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(fault)),
            };
            let restricted = state.restricted;
            Some(frame_native(
                run_blocking(state, move |core| {
                    crate::methods::get_block_headers_range(
                        &FfiChainFacts::new(core),
                        &request,
                        restricted,
                    )
                })
                .await,
            ))
        }
        NativeMethod::HardForkInfo => {
            let request = match crate::methods::hard_fork_info_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(fault)),
            };
            Some(frame_native(
                run_blocking(state, move |core| {
                    crate::methods::hard_fork_info(&FfiChainFacts::new(core), &request)
                })
                .await,
            ))
        }
        NativeMethod::FeeEstimate => {
            let request = match crate::methods::fee_estimate_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(fault)),
            };
            Some(frame_native(
                run_blocking(state, move |core| {
                    crate::methods::get_fee_estimate(&FfiChainFacts::new(core), &request)
                })
                .await,
            ))
        }
        NativeMethod::BlockHeaderByHeight => {
            // The params parse is pure and its refusal needs no core, so it
            // happens before a worker is taken — as `on_get_block_hash`'s does.
            let request = match crate::methods::block_header_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(fault)),
            };
            let fill_pow_hash = pow_hash_entitled(request.fill_pow_hash, state.restricted);
            Some(frame_native(
                run_blocking(state, move |core| {
                    crate::methods::get_block_header_by_height(
                        &FfiChainFacts::new(core),
                        request.height,
                        fill_pow_hash,
                    )
                })
                .await,
            ))
        }
    }
}

/// Run a native method on a worker thread holding the live core.
///
/// Facts reads block on C++; the HTTP task must not. A join failure is an
/// [`InternalFault`], never a fact about the chain.
async fn run_blocking<T, F>(state: &Arc<AppState>, f: F) -> Result<T, RpcFault>
where
    T: Send + 'static,
    F: FnOnce(Arc<CoreRpc>) -> Result<T, RpcFault> + Send + 'static,
{
    let core = state.core.clone();
    join_fault(tokio::task::spawn_blocking(move || f(core)).await)?
}

fn join_fault<T>(out: Result<T, tokio::task::JoinError>) -> Result<T, RpcFault> {
    out.map_err(|_| RpcFault::Internal(InternalFault::Join))
}

/// Frame a native method's outcome as a JSON value. A facts fault stays a
/// facts fault; a reply the transport could not encode is an
/// [`InternalFault`] — never attributed to the core.
fn frame_native<T: serde::Serialize>(
    reply: Result<T, RpcFault>,
) -> Result<serde_json::Value, RpcFault> {
    match reply {
        Ok(value) => {
            serde_json::to_value(value).map_err(|_| RpcFault::Internal(InternalFault::Serialize))
        }
        Err(fault) => Err(fault),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_facts::FactsFault;

    /// The framing keeps causes apart: a facts code is a facts fault, a
    /// serialize failure is internal. Collapsing either into the other is the
    /// edit this turns red (it was `FactsFault::Unknown(0)` for both, once).
    #[test]
    fn frame_native_keeps_the_cause_of_a_failure() {
        assert_eq!(frame_native(Ok(7)).unwrap(), serde_json::json!(7));
        assert_eq!(
            frame_native::<u64>(Err(RpcFault::Facts(FactsFault::NotReady))).unwrap_err(),
            RpcFault::Facts(FactsFault::NotReady)
        );
    }

    /// A worker that panics is an internal join fault, never a facts code.
    #[tokio::test]
    async fn a_panicked_worker_is_an_internal_join_fault() {
        let joined =
            tokio::task::spawn_blocking(|| -> Result<u64, RpcFault> { panic!("boom") }).await;
        assert!(joined.is_err());
        assert_eq!(
            join_fault(joined).unwrap_err(),
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
