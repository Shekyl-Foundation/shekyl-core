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

#[cfg(test)]
use super::native::{frame_native, join_fault, native_method_for, pow_hash_entitled, NativeMethod};
use super::native::{native_fault, native_method, NativeFail};
use crate::authority::{refusal, Authority};
#[cfg(test)]
use crate::methods::{InternalFault, RpcFault};
use crate::server::AppState;
use crate::types::{JsonRpcRequest, JsonRpcResponse};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Extension;
use axum::Json;
use std::sync::Arc;

/// Whether `method` has no row in the method table. [`handle`] matches
/// [`shekyl_rpc_types::methods::json_rpc`] once and answers that absence
/// as method-not-found; this names the same absence for the test that
/// pins a deleted method. A row the connection may not call is a grant
/// refusal, which is [`handle`]'s other arm.
#[cfg(test)]
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

    // One lookup, two outcomes. No row: the name is not a method. A row:
    // admit it. `/json_rpc` itself serves any connection; each method
    // carries its own policy (§6.1, RT-O32). A refusal is the JSON-RPC
    // error object with its class and diagnostic (RW-Q3), never
    // "method not found".
    let Some(row) = shekyl_rpc_types::methods::json_rpc(&method) else {
        return (
            StatusCode::OK,
            Json(JsonRpcResponse::error(
                id,
                -32601,
                format!("Method not found: {method}"),
            )),
        );
    };
    if let Err(error) = authority.admit(row) {
        return (StatusCode::OK, Json(refusal(id, &error)));
    }

    // Natively-served methods (RK-1, `docs/completed/DAEMON_RPC_KV_CUTOVER.md`)
    // never reach the C++ dispatch table.
    if let Some(native) = native_method(&state, authority, &method, &request.params).await {
        return match native {
            Ok(value) => (StatusCode::OK, Json(JsonRpcResponse::success(id, value))),
            Err(NativeFail::Fault(fault)) => {
                (StatusCode::OK, Json(native_fault(id, &method, fault)))
            }
            Err(NativeFail::Error(error)) => (StatusCode::OK, Json(refusal(id, &error))),
        };
    }

    // A name in the table that has no native handler is not served.
    // The C++ method table is gone (DRS_X_STORE_FLIP.md DX-Q3).
    (
        StatusCode::OK,
        Json(JsonRpcResponse::error(
            id,
            -32601,
            format!("Method not found: {method}"),
        )),
    )
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
            NativeFail::Fault(RpcFault::Facts(FactsFault::NotReady))
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
        "request_archival_shard",
        "option_set",
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
        ("calc_pow", NativeMethod::CalcPow, true),
        ("get_coinbase_tx_sum", NativeMethod::CoinbaseTxSum, true),
        ("get_alternate_chains", NativeMethod::AlternateChains, true),
        ("get_curve_tree_info", NativeMethod::CurveTreeInfo, false),
        (
            "get_curve_tree_checkpoint",
            NativeMethod::CurveTreeCheckpoint,
            false,
        ),
        (
            "get_archival_emission_claim_source",
            NativeMethod::EmissionClaimSource,
            false,
        ),
        (
            "get_archival_shard_coverage",
            NativeMethod::ShardCoverage,
            false,
        ),
        ("submit_block", NativeMethod::SubmitBlock, false),
        ("submitblock", NativeMethod::SubmitBlock, false),
        ("get_block_template", NativeMethod::BlockTemplate, false),
        ("getblocktemplate", NativeMethod::BlockTemplate, false),
        ("get_miner_data", NativeMethod::MinerData, false),
        ("generateblocks", NativeMethod::GenerateBlocks, true),
        ("set_bans", NativeMethod::SetBans, true),
        ("get_bans", NativeMethod::GetBans, true),
        ("banned", NativeMethod::Banned, true),
        ("flush_txpool", NativeMethod::FlushTxpool, true),
        ("relay_tx", NativeMethod::RelayTx, true),
        ("get_txpool_backlog", NativeMethod::TxpoolBacklog, false),
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
        // Not native handlers. A name with no row is not found before
        // dispatch; these stay unrecognized here.
        for name in [
            "mining_status",
            "flush_cache",
            "inject_archival_serve_credit",
            "getblockcount2",
            "",
        ] {
            assert!(
                native_method_for(name).is_none(),
                "{name} is not a native handler"
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

    /// RW-Q7's gate for JSON-RPC: every name the daemon serves is a row,
    /// and every JSON-RPC row is served natively. The C++ table is gone
    /// (DRS_X_STORE_FLIP.md DX-Q3).
    #[test]
    fn every_served_json_rpc_name_is_a_row_and_every_row_is_served() {
        use shekyl_rpc_types::methods::{json_rpc, Surface, METHODS};
        for (name, _, _) in SPECIFIED_NATIVE_METHODS {
            assert!(json_rpc(name).is_some(), "{name} is served but has no row");
        }
        for row in METHODS.iter().filter(|row| row.surface == Surface::JsonRpc) {
            for name in row.names() {
                assert!(
                    native_method_for(name).is_some(),
                    "{name} is a row that nothing serves"
                );
            }
        }
    }
}
