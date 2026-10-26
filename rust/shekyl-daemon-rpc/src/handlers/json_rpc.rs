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

use crate::authority::{refusal, Authority};
use crate::chain_facts::{FfiChainFacts, FfiP2pFacts};
use crate::core::CoreRpc;
use crate::methods::{InternalFault, RpcFault};
use crate::server::AppState;
use crate::types::{FfiJsonRpcResult, JsonRpcRequest, JsonRpcResponse};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Extension;
use axum::Json;
use std::sync::Arc;
use tracing::warn;

/// Whether `method` has no row in the method table, on either listener. It
/// is answered as not found and never dispatched: the table is the policy
/// (RW-Q7), so a name it does not list is not served, as an unrouted REST
/// path is not. The gate that every served name is a row keeps every
/// served method off this arm.
fn unrouted(method: &str) -> bool {
    shekyl_rpc_types::methods::json_rpc(method).is_none()
}

pub async fn handle(
    State(state): State<Arc<AppState>>,
    Extension(authority): Extension<Authority>,
    Json(request): Json<JsonRpcRequest>,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let id = request.id.clone();
    let method = request.method.clone();

    if unrouted(&method) {
        return (
            StatusCode::OK,
            Json(JsonRpcResponse::error(
                id,
                -32601,
                format!("Method not found: {method}"),
            )),
        );
    }

    // The daemon's second gate: `/json_rpc` itself serves any connection,
    // and each method is admitted against its own row (§6.1, RT-O32). A
    // refusal is the JSON-RPC error object with its class and diagnostic
    // (RW-Q3), never "method not found".
    if let Some(row) = shekyl_rpc_types::methods::json_rpc(&method) {
        if let Err(error) = authority.admit(row) {
            return (StatusCode::OK, Json(refusal(id, &error)));
        }
    }

    // Natively-served methods (RK-1, `docs/completed/DAEMON_RPC_KV_CUTOVER.md`)
    // never reach the C++ dispatch table.
    if let Some(native) = native_method(&state, authority, &method, &request.params).await {
        return match native {
            Ok(value) => (StatusCode::OK, Json(JsonRpcResponse::success(id, value))),
            Err(fault) => (StatusCode::OK, Json(native_fault(id, &method, fault))),
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
    // The FFI's flag is still the listener posture: restricted is not host.
    let restricted = !authority.host();
    let result =
        tokio::task::spawn_blocking(move || core.json_rpc(&method_clone, &params_str, restricted))
            .await;

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

/// Whether to compute a block's proof-of-work hash: only if the caller asked
/// **and** the caller is not bounded (§6.3) — the C++ handler's
/// `req.fill_pow_hash && !restricted`.
///
/// Its own function because it is a policy, not an expression: computing the
/// long hash is the expensive part of a header read, and a bounded caller is
/// exactly the one that must not be made to do it on request. Dropping the
/// `!bounded` here fails [`pow_hash_is_never_computed_for_a_bounded_caller`].
///
/// RK-5b's methods do **not** use this. They refuse a bounded caller that
/// asked for the field (`methods::pow_hash_or_refuse`) rather than blanking
/// it. RT-W10 step 2 brings RK-2's methods under the same refusal (§6.3:
/// never silently truncated).
fn pow_hash_entitled(requested: bool, bounded: bool) -> bool {
    requested && !bounded
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
    FeeEstimate,
    RequestArchivalShard,
    Info,
    OptionSet,
    OptionShow,
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
        // (`core_rpc_ffi.cpp:269-283`); `get_fee_estimate` had only one
        // there and gains none here.
        "get_last_block_header" | "getlastblockheader" => NativeMethod::LastBlockHeader,
        "get_block_header_by_hash" | "getblockheaderbyhash" => NativeMethod::BlockHeaderByHash,
        "get_block_headers_range" | "getblockheadersrange" => NativeMethod::BlockHeadersRange,
        "get_fee_estimate" => NativeMethod::FeeEstimate,
        // One spelling: the method was born in the Rust registry (3.31)
        // and never had a C++ alias.
        "request_archival_shard" => NativeMethod::RequestArchivalShard,
        // RT-O23: the grammar's own words, one spelling each, no REST path.
        "option_set" => NativeMethod::OptionSet,
        "option_show" => NativeMethod::OptionShow,
        // RK-5c. One spelling on JSON-RPC, as the C++ table carried it; the
        // `/getinfo` alias is a REST path.
        "get_info" => NativeMethod::Info,
        _ => return None,
    })
}

/// Dispatch `method` natively if Rust owns it; `None` hands it to the C++
/// table. Each arm is one `methods::*` call framed as a JSON value.
async fn native_method(
    state: &Arc<AppState>,
    authority: Authority,
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
            let fill_pow_hash = pow_hash_entitled(request.fill_pow_hash, authority.bounded());
            Some(frame_native(
                run_blocking(state, move |core| {
                    crate::methods::get_block(&FfiChainFacts::new(core), &request, fill_pow_hash)
                })
                .await,
            ))
        }
        NativeMethod::Info => {
            // The listener's posture and this server's own connection count
            // are the transport's facts; they are taken here, before the
            // worker, and the method reads only the parts the disclosure
            // shows (RK-D24).
            let disclosure = authority.disclosure();
            let rpc_connections = state.conn_tracker.active_total();
            Some(frame_native(
                run_blocking(state, move |core| {
                    let facts = crate::info_facts::FfiInfoFacts::new(core);
                    crate::info::get_info(&facts, disclosure, rpc_connections)
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
            let bounded = authority.bounded();
            Some(frame_native(
                run_blocking(state, move |core| {
                    crate::methods::get_last_block_header(
                        &FfiChainFacts::new(core),
                        request.fill_pow_hash,
                        bounded,
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
            let bounded = authority.bounded();
            Some(frame_native(
                run_blocking(state, move |core| {
                    crate::methods::get_block_header_by_hash(
                        &FfiChainFacts::new(core),
                        &request,
                        bounded,
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
            let bounded = authority.bounded();
            Some(frame_native(
                run_blocking(state, move |core| {
                    crate::methods::get_block_headers_range(
                        &FfiChainFacts::new(core),
                        &request,
                        bounded,
                    )
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
        NativeMethod::OptionSet => {
            let pairs = match crate::options::option_set_request(params) {
                Ok(pairs) => pairs,
                Err(fault) => return Some(Err(fault)),
            };
            // The handle's set runs under its own lock and applies to the
            // owners; neither touches the core, so no worker is taken.
            Some(frame_native(crate::options::option_set(
                state.options.as_ref(),
                &pairs,
            )))
        }
        NativeMethod::OptionShow => {
            let names = match crate::options::option_show_request(params) {
                Ok(names) => names,
                Err(fault) => return Some(Err(fault)),
            };
            let disclosure = authority.disclosure();
            Some(frame_native(crate::options::option_show(
                state.options.as_ref(),
                names.as_deref(),
                disclosure,
            )))
        }
        NativeMethod::RequestArchivalShard => {
            let request = match crate::shard_view::request_archival_shard_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(fault)),
            };
            // Not `run_blocking`: the facts source is async by contract — a
            // fetch over the network when a composition root supplies one —
            // and holds no C++ core, so no worker is taken.
            Some(frame_native(
                crate::shard_view::request_archival_shard(state.shard_view.as_ref(), request).await,
            ))
        }
        NativeMethod::BlockHeaderByHeight => {
            // The params parse is pure and its refusal needs no core, so it
            // happens before a worker is taken — as `on_get_block_hash`'s does.
            let request = match crate::methods::block_header_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(fault)),
            };
            let fill_pow_hash = pow_hash_entitled(request.fill_pow_hash, authority.bounded());
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

/// What a JSON-RPC caller is told when a native method does not answer.
fn native_fault(id: serde_json::Value, method: &str, fault: RpcFault) -> JsonRpcResponse {
    match fault {
        // A refusal is the method answering — a bad request, or a height
        // the chain does not hold. Normal traffic: it carries its own code
        // and message and is not logged as a daemon problem.
        RpcFault::Refused(refusal) => {
            JsonRpcResponse::error_with_data(id, refusal.code, refusal.message, refusal.data)
        }
        // The store contradicted itself. The caller is told what
        // contradicted what: every operand is a public chain fact, and a
        // bare "Internal error" would send an operator to the wrong place.
        // The handler has already logged the same text.
        RpcFault::Store(store) => JsonRpcResponse::error(
            id,
            shekyl_rpc_types::CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
            store.to_string(),
        ),
        fault => {
            warn!(method = %method, ?fault, "native JSON-RPC method failed");
            JsonRpcResponse::error(id, -32603, "Internal error".into())
        }
    }
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

    /// Whether `authority` is refused the JSON-RPC method `name`, by the gate
    /// [`handle`] calls.
    fn refused_to(authority: Authority, name: &str) -> bool {
        shekyl_rpc_types::methods::json_rpc(name).is_some_and(|row| authority.admit(row).is_err())
    }
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

    /// **A store fault reaches the caller in its own words** (RK-Q9): the
    /// daemon-side error code, and a message carrying the invariant and
    /// every operand. A facts code, beside it, is still the bare internal
    /// error: it has no detail to give.
    #[test]
    fn a_store_fault_tells_the_caller_what_contradicted_what() {
        use crate::methods::StoreFault;
        use shekyl_types::ChainCount;
        use shekyl_units::AtomicUnits;

        let store = StoreFault::SupplyInvariant {
            coins_generated: AtomicUnits::from_raw(1_000),
            total_burned: AtomicUnits::from_raw(1_001),
            chain_height: ChainCount::from_raw(77),
        };
        let reply = serde_json::to_value(native_fault(
            serde_json::json!(7),
            "get_info",
            RpcFault::Store(store),
        ))
        .unwrap();
        assert_eq!(reply["id"], 7);
        assert!(reply.get("result").is_none(), "no partial reply: {reply}");
        assert_eq!(
            reply["error"]["code"],
            shekyl_rpc_types::CORE_RPC_ERROR_CODE_INTERNAL_ERROR
        );
        let message = reply["error"]["message"].as_str().expect("a message");
        assert_eq!(message, store.to_string());
        for operand in ["1001", "1000", "77", "total_burned <= coins_generated"] {
            assert!(message.contains(operand), "`{operand}` in {message}");
        }

        let bare = serde_json::to_value(native_fault(
            serde_json::json!(7),
            "get_info",
            RpcFault::Facts(FactsFault::Inconsistent),
        ))
        .unwrap();
        assert_eq!(bare["error"]["code"], -32603);
        assert_eq!(bare["error"]["message"], "Internal error");
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

    /// The admin JSON-RPC surface, restated independently of the method
    /// table's grant column.
    ///
    /// Same discipline as the REST route table's specification: an oracle that
    /// iterates the table re-states whatever the table says and so
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
        "flush_cache",
        "request_archival_shard",
        "option_set",
        "inject_archival_serve_credit",
    ];

    /// Every name the daemon serves natively, the method each belongs to,
    /// and whether the view listener is refused it.
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
        ("get_fee_estimate", NativeMethod::FeeEstimate, false),
        ("get_info", NativeMethod::Info, false),
        (
            "request_archival_shard",
            NativeMethod::RequestArchivalShard,
            true,
        ),
    ];

    /// The dispatcher's own recognizer answers every specified name and
    /// nothing else. This calls `native_method_for` — the function
    /// [`native_method`] dispatches on — so deleting or renaming an alias
    /// arm turns it red, which an assertion about the refused list alone
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
        // Not dispatched natively. Nothing on this side serves the name, so
        // whether it is answered at all is the C++ table's to say — and that
        // table carries no row for it.
        assert!(native_method_for("hard_fork_info").is_none());
    }

    /// A bounded caller never makes the node compute a pow hash, however the
    /// request is phrased — the whole truth table, since only one of its four
    /// cells may be true.
    #[test]
    fn pow_hash_is_never_computed_for_a_bounded_caller() {
        assert!(pow_hash_entitled(true, false), "asked for, the host");
        assert!(!pow_hash_entitled(true, true), "asked for, but bounded");
        assert!(!pow_hash_entitled(false, false), "not asked for");
        assert!(!pow_hash_entitled(false, true), "not asked for, bounded");
    }

    /// Each native name is gated exactly as specified, and none is gated on
    /// the admin listener — asserted through [`Authority::admit`], the gate
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
                refused_to(Authority::VIEW_LISTENER, name),
                *gated,
                "{name}: the view listener's refusal must match the specification"
            );
            assert!(
                !refused_to(Authority::admin_listener(true), name),
                "{name} must answer on the admin listener"
            );
        }
    }

    /// Dual-armed, because *refused to the view listener* alone passes for a
    /// method
    /// that is refused everywhere — including one that does not exist.
    #[test]
    fn admin_methods_are_refused_only_to_the_view_listener() {
        for method in SPECIFIED_ADMIN_METHODS {
            assert!(
                refused_to(Authority::VIEW_LISTENER, method),
                "{method} is specified admin-only but the public listener \
                 serves it"
            );
            assert!(
                !refused_to(Authority::admin_listener(true), method),
                "{method} is refused on the admin listener too — the gate is \
                 not the connection's authority"
            );
        }
    }

    /// A name with no row is not served on either listener, as an unrouted
    /// REST path is not: it is answered as not found before any dispatch,
    /// so a name the table does not list never reaches the C++ table. A
    /// deleted method stays unrouted (`get_output_histogram`, SOK-Q3). Red
    /// edit: let a name with no row through to dispatch.
    #[test]
    fn a_name_with_no_row_is_not_served_on_either_listener() {
        for name in ["no_such_method", "get_output_histogram"] {
            assert!(shekyl_rpc_types::methods::json_rpc(name).is_none());
            assert!(unrouted(name), "{name}");
        }
        assert!(!unrouted("get_info"));
        assert!(!unrouted("getblockcount"), "an alias is a row's name");
    }

    /// The gate names exactly the specified methods: one dropped from the
    /// table's host-only rows is caught above, one added without review here.
    #[test]
    fn the_view_listeners_refused_methods_match_the_specification() {
        use shekyl_rpc_types::methods::{Surface, METHODS};
        let mut gated: Vec<&str> = METHODS
            .iter()
            .filter(|row| {
                row.surface == Surface::JsonRpc && Authority::VIEW_LISTENER.admit(row).is_err()
            })
            .flat_map(shekyl_rpc_types::methods::Method::names)
            .collect();
        let mut specified: Vec<&str> = SPECIFIED_ADMIN_METHODS.to_vec();
        gated.sort_unstable();
        specified.sort_unstable();
        assert_eq!(
            gated, specified,
            "the view listener's refused JSON-RPC methods diverged from the \
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
            assert!(!refused_to(Authority::VIEW_LISTENER, method), "{method}");
            assert!(
                !refused_to(Authority::admin_listener(true), method),
                "{method}"
            );
        }
    }

    /// The JSON-RPC names the C++ table serves until the flip, read from its
    /// source (`src/rpc/core_rpc_ffi.cpp`, `get_jsonrpc_table`).
    fn cpp_json_rpc_names() -> Vec<String> {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../src/rpc/core_rpc_ffi.cpp");
        let source = std::fs::read_to_string(&path).expect("the C++ JSON-RPC table");
        let start = source
            .find("get_jsonrpc_table()")
            .expect("the table's function");
        let body = &source[start..];
        let body = &body[..body.find("return t;").expect("the table's end")];
        let mut names = Vec::new();
        for line in body.lines() {
            let line = line.trim();
            let quoted = if let Some(rest) = line.strip_prefix("{\"") {
                rest
            } else if let Some(rest) = line.strip_prefix("DJRPC_WE(\"") {
                rest
            } else {
                continue;
            };
            if let Some(end) = quoted.find('"') {
                names.push(quoted[..end].to_owned());
            }
        }
        assert!(names.len() >= 20, "the parse found the table: {names:?}");
        names
    }

    /// RW-Q7's gate for JSON-RPC: every name the daemon serves, natively or
    /// through the C++ table, is a row, and every JSON-RPC row is served.
    #[test]
    fn every_served_json_rpc_name_is_a_row_and_every_row_is_served() {
        use shekyl_rpc_types::methods::{json_rpc, Surface, METHODS};
        let cpp = cpp_json_rpc_names();
        let native: Vec<&str> = SPECIFIED_NATIVE_METHODS
            .iter()
            .map(|(name, _, _)| *name)
            .collect();
        for name in cpp.iter().map(String::as_str).chain(native.iter().copied()) {
            assert!(json_rpc(name).is_some(), "{name} is served but has no row");
        }
        for row in METHODS.iter().filter(|row| row.surface == Surface::JsonRpc) {
            for name in row.names() {
                assert!(
                    native_method_for(name).is_some() || cpp.iter().any(|c| c == name),
                    "{name} is a row that nothing serves"
                );
            }
        }
    }
}
