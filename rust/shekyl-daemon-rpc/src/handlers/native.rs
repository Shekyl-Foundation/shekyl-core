// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Native JSON-RPC methods.
//!
//! [`super::json_rpc`] is the HTTP frame: it admits the caller and
//! returns the JSON-RPC object. This module is the dispatch. Three
//! shapes stay a match, because they are three different runtimes:
//! [`on_chain`] reads the store on a worker, [`run_blocking`] reads the
//! C++ core until chain sync's cutover deletes that caller, and
//! [`from_error`] / [`blocking`] cover mining, bans, and the pool.

use crate::authority::Authority;
use crate::chain_facts::FfiP2pFacts;
use crate::core::CoreRpc;
use crate::handles::ChainReadHandle;
use crate::methods::{InternalFault, RpcFault};
use crate::server::AppState;
use crate::types::JsonRpcResponse;
use shekyl_rpc_types::errors::RpcError;
use std::sync::Arc;
use tracing::warn;

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
pub(super) fn pow_hash_entitled(requested: bool, bounded: bool) -> bool {
    requested && !bounded
}

/// A JSON-RPC method this crate serves itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NativeMethod {
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
    SubmitBlock,
    BlockTemplate,
    MinerData,
    GenerateBlocks,
    SetBans,
    GetBans,
    Banned,
    FlushTxpool,
    RelayTx,
    TxpoolBacklog,
    CalcPow,
    CoinbaseTxSum,
    AlternateChains,
    CurveTreeInfo,
    CurveTreeCheckpoint,
    EmissionClaimSource,
    ShardCoverage,
}

/// The names each native method answers to — every alias the C++ dispatch
/// table carried, since dropping one 404s a name the daemon has always
/// answered.
///
/// The single source: [`native_method`] dispatches on what this returns, so a
/// name missing here is not served, and the test that checks the alias set
/// exercises the same function the request path does.
pub(super) fn native_method_for(method: &str) -> Option<NativeMethod> {
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
        "submit_block" | "submitblock" => NativeMethod::SubmitBlock,
        "get_block_template" | "getblocktemplate" => NativeMethod::BlockTemplate,
        "get_miner_data" => NativeMethod::MinerData,
        "generateblocks" => NativeMethod::GenerateBlocks,
        "set_bans" => NativeMethod::SetBans,
        "get_bans" => NativeMethod::GetBans,
        "banned" => NativeMethod::Banned,
        "flush_txpool" => NativeMethod::FlushTxpool,
        "relay_tx" => NativeMethod::RelayTx,
        "get_txpool_backlog" => NativeMethod::TxpoolBacklog,
        // Store reads (DX-Q3). One spelling each; the C++ table carried no alias.
        "calc_pow" => NativeMethod::CalcPow,
        "get_coinbase_tx_sum" => NativeMethod::CoinbaseTxSum,
        "get_alternate_chains" => NativeMethod::AlternateChains,
        "get_curve_tree_info" => NativeMethod::CurveTreeInfo,
        "get_curve_tree_checkpoint" => NativeMethod::CurveTreeCheckpoint,
        "get_archival_emission_claim_source" => NativeMethod::EmissionClaimSource,
        "get_archival_shard_coverage" => NativeMethod::ShardCoverage,
        _ => return None,
    })
}

/// A native method's failure: a chain read's [`RpcFault`], or a method
/// that answers with the RW-Q3 [`RpcError`].
#[derive(Debug, PartialEq, Eq)]
pub(super) enum NativeFail {
    Fault(RpcFault),
    Error(RpcError),
}

/// Dispatch `method` natively if Rust owns it; `None` hands it to the C++
/// table. Each arm is one handler call framed as a JSON value.
///
/// Chain rows read the node's store handle, and chain sync's view is the
/// node's. The board's connection rows are still read through the C++
/// node server (slice 4).
pub(super) async fn native_method(
    state: &Arc<AppState>,
    authority: Authority,
    method: &str,
    params: &serde_json::Value,
) -> Option<Result<serde_json::Value, NativeFail>> {
    match native_method_for(method)? {
        NativeMethod::Version => Some(frame_native(
            on_chain(state, |chain| crate::methods::get_version(chain.as_ref())).await,
        )),
        NativeMethod::BlockCount => Some(frame_native(
            on_chain(state, |chain| {
                crate::methods::get_block_count(chain.as_ref())
            })
            .await,
        )),
        NativeMethod::BlockHash => {
            // The params parse is pure and its refusal needs no store, so it
            // happens before a worker is taken.
            let height = match crate::methods::get_block_hash_height(params) {
                Ok(height) => height,
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
            };
            Some(frame_native(
                on_chain(state, move |chain| {
                    crate::methods::get_block_hash(chain.as_ref(), height)
                })
                .await,
            ))
        }
        NativeMethod::Block => {
            let request = match crate::methods::block_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
            };
            let fill_pow_hash = pow_hash_entitled(request.fill_pow_hash, authority.bounded());
            Some(frame_native(
                on_chain(state, move |chain| {
                    crate::methods::get_block(chain.as_ref(), &request, fill_pow_hash)
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
                on_chain(state, move |chain| {
                    crate::info::get_info(chain.as_ref(), disclosure, rpc_connections)
                })
                .await,
            ))
        }
        NativeMethod::SyncInfo => {
            // The chain's tip and chain sync's view are the node's; each
            // session's address is the board's. They are not one snapshot:
            // see `methods::sync_info`.
            let chain = Arc::clone(&state.handles.chain);
            Some(frame_native(
                run_blocking(state, move |core| {
                    crate::methods::sync_info(
                        chain.as_chain_facts(),
                        chain.as_sync_view(),
                        &FfiP2pFacts::new(core),
                    )
                })
                .await,
            ))
        }
        NativeMethod::Connections => {
            let chain = Arc::clone(&state.handles.chain);
            Some(frame_native(
                run_blocking(state, move |core| {
                    crate::methods::get_connections(&FfiP2pFacts::new(core), chain.as_sync_view())
                })
                .await,
            ))
        }
        NativeMethod::LastBlockHeader => {
            let request = match crate::methods::last_block_header_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
            };
            let bounded = authority.bounded();
            Some(frame_native(
                on_chain(state, move |chain| {
                    crate::methods::get_last_block_header(
                        chain.as_ref(),
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
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
            };
            let bounded = authority.bounded();
            Some(frame_native(
                on_chain(state, move |chain| {
                    crate::methods::get_block_header_by_hash(chain.as_ref(), &request, bounded)
                })
                .await,
            ))
        }
        NativeMethod::BlockHeadersRange => {
            let request = match crate::methods::block_headers_range_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
            };
            let bounded = authority.bounded();
            Some(frame_native(
                on_chain(state, move |chain| {
                    crate::methods::get_block_headers_range(chain.as_ref(), &request, bounded)
                })
                .await,
            ))
        }
        NativeMethod::FeeEstimate => {
            let request = match crate::methods::fee_estimate_request(params) {
                Ok(request) => request,
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
            };
            Some(frame_native(
                on_chain(state, move |chain| {
                    crate::methods::get_fee_estimate(chain.as_ref(), &request)
                })
                .await,
            ))
        }
        NativeMethod::OptionSet => {
            let pairs = match crate::options::option_set_request(params) {
                Ok(pairs) => pairs,
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
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
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
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
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
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
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
            };
            let fill_pow_hash = pow_hash_entitled(request.fill_pow_hash, authority.bounded());
            Some(frame_native(
                on_chain(state, move |chain| {
                    crate::methods::get_block_header_by_height(
                        chain.as_ref(),
                        request.height,
                        fill_pow_hash,
                    )
                })
                .await,
            ))
        }
        NativeMethod::CalcPow => {
            let request = match crate::methods::object_params(
                params,
                "Wrong parameters, expected an object with block_blob, height and seed_hash",
            ) {
                Ok(request) => request,
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
            };
            Some(frame_native(
                on_chain(state, move |chain| {
                    crate::read_methods::calc_pow(chain.as_ref(), &request)
                })
                .await,
            ))
        }
        NativeMethod::CoinbaseTxSum => {
            let request = match crate::methods::object_params(
                params,
                "Wrong parameters, expected an object with height and count",
            ) {
                Ok(request) => request,
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
            };
            Some(frame_native(
                on_chain(state, move |chain| {
                    crate::read_methods::get_coinbase_tx_sum(chain.as_ref(), &request)
                })
                .await,
            ))
        }
        NativeMethod::AlternateChains => Some(frame_native(
            on_chain(state, |chain| {
                crate::read_methods::get_alternate_chains(chain.as_ref())
            })
            .await,
        )),
        NativeMethod::CurveTreeInfo => Some(frame_native(
            on_chain(state, |chain| {
                crate::read_methods::get_curve_tree_info(chain.as_ref())
            })
            .await,
        )),
        NativeMethod::CurveTreeCheckpoint => {
            let request = match crate::methods::object_params(
                params,
                "Wrong parameters, expected an object with block_height",
            ) {
                Ok(request) => request,
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
            };
            Some(frame_native(
                on_chain(state, move |chain| {
                    crate::read_methods::get_curve_tree_checkpoint(chain.as_ref(), &request)
                })
                .await,
            ))
        }
        NativeMethod::EmissionClaimSource => {
            let request = match crate::methods::object_params(
                params,
                "Wrong parameters, expected an object with p_id",
            ) {
                Ok(request) => request,
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
            };
            Some(frame_native(
                on_chain(state, move |chain| {
                    crate::read_methods::get_archival_emission_claim_source(
                        chain.as_ref(),
                        &request,
                    )
                })
                .await,
            ))
        }
        NativeMethod::ShardCoverage => Some(frame_native(
            on_chain(state, |chain| {
                crate::read_methods::get_archival_shard_coverage(chain.as_ref())
            })
            .await,
        )),
        NativeMethod::SubmitBlock => {
            let request = match crate::methods::required_object_params(
                params,
                "Wrong parameters, expected an object with body",
            ) {
                Ok(request) => request,
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
            };
            let door = Arc::clone(&state.handles.door);
            Some(from_error(
                crate::mining_methods::submit_block(door.as_ref(), request).await,
            ))
        }
        NativeMethod::BlockTemplate => {
            if let Err(fault) = crate::methods::object_params::<
                shekyl_rpc_types::mining::GetBlockTemplateRequest,
            >(params, "Wrong parameters, expected no parameters")
            {
                return Some(Err(NativeFail::Fault(fault)));
            }
            let mining = Arc::clone(&state.handles.mining);
            Some(from_error(
                blocking(move || crate::mining_methods::get_block_template(mining.as_ref())).await,
            ))
        }
        NativeMethod::MinerData => {
            if let Err(fault) = crate::methods::object_params::<
                shekyl_rpc_types::mining::GetBlockTemplateRequest,
            >(params, "Wrong parameters, expected no parameters")
            {
                return Some(Err(NativeFail::Fault(fault)));
            }
            let mining = Arc::clone(&state.handles.mining);
            Some(from_error(
                blocking(move || crate::mining_methods::get_miner_data(mining.as_ref())).await,
            ))
        }
        NativeMethod::GenerateBlocks => {
            let request = match crate::methods::required_object_params(
                params,
                "Wrong parameters, expected an object with count",
            ) {
                Ok(request) => request,
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
            };
            let Some(row) = shekyl_rpc_types::methods::json_rpc("generateblocks") else {
                return Some(Err(NativeFail::Fault(RpcFault::Internal(
                    InternalFault::Serialize,
                ))));
            };
            let armed = match shekyl_rpc_types::methods::admit_armed(row, authority.armed_switch())
            {
                Ok(armed) => armed,
                Err(error) => return Some(Err(NativeFail::Error(error))),
            };
            let mining = Arc::clone(&state.handles.mining);
            let door = Arc::clone(&state.handles.door);
            let chain = Arc::clone(&state.handles.chain);
            Some(from_error(
                crate::mining_methods::generateblocks(
                    &mining,
                    door.as_ref(),
                    chain.as_ref(),
                    armed,
                    request,
                )
                .await,
            ))
        }
        NativeMethod::SetBans => {
            let request = match crate::methods::object_params(
                params,
                "Wrong parameters, expected an object with bans",
            ) {
                Ok(request) => request,
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
            };
            let bans = Arc::clone(&state.handles.bans);
            Some(from_error(
                blocking(move || crate::ban_methods::set_bans(bans.as_ref(), &request)).await,
            ))
        }
        NativeMethod::GetBans => {
            let bans = Arc::clone(&state.handles.bans);
            Some(from_error(
                blocking(move || crate::ban_methods::get_bans(bans.as_ref())).await,
            ))
        }
        NativeMethod::Banned => {
            let request = match crate::methods::required_object_params(
                params,
                "Wrong parameters, expected an object with address",
            ) {
                Ok(request) => request,
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
            };
            let bans = Arc::clone(&state.handles.bans);
            Some(from_error(
                blocking(move || crate::ban_methods::banned(bans.as_ref(), &request)).await,
            ))
        }
        NativeMethod::FlushTxpool => {
            let request = match crate::methods::object_params(
                params,
                "Wrong parameters, expected an object with txids",
            ) {
                Ok(request) => request,
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
            };
            let pool = Arc::clone(&state.handles.pool);
            Some(from_error(
                crate::pool_methods::flush_txpool(pool.as_ref(), &request).await,
            ))
        }
        NativeMethod::RelayTx => {
            let request = match crate::methods::object_params(
                params,
                "Wrong parameters, expected an object with txids",
            ) {
                Ok(request) => request,
                Err(fault) => return Some(Err(NativeFail::Fault(fault))),
            };
            let pool = Arc::clone(&state.handles.pool);
            Some(from_error(
                blocking(move || crate::pool_methods::relay_tx(pool.as_ref(), &request)).await,
            ))
        }
        NativeMethod::TxpoolBacklog => {
            let host = authority.host();
            let pool = Arc::clone(&state.handles.pool);
            Some(from_error(
                blocking(move || {
                    crate::pool_methods::get_txpool_backlog(
                        pool.as_ref(),
                        crate::pool_methods::scope_for(host),
                    )
                })
                .await,
            ))
        }
    }
}

/// Run a chain read on a worker. The handle is the node's store; the HTTP
/// task must not block on it. A join failure is an [`InternalFault`].
pub(super) async fn on_chain<T, F>(state: &Arc<AppState>, f: F) -> Result<T, RpcFault>
where
    T: Send + 'static,
    F: FnOnce(&ChainReadHandle) -> Result<T, RpcFault> + Send + 'static,
{
    let chain = Arc::clone(&state.handles.chain);
    join_fault(tokio::task::spawn_blocking(move || f(&chain)).await)?
}

/// Run a native method on a worker thread holding the live core.
///
/// What remains here reads the C++ handler (sync spans, connections). A
/// join failure is an [`InternalFault`], never a fact about the chain.
pub(super) async fn run_blocking<T, F>(state: &Arc<AppState>, f: F) -> Result<T, RpcFault>
where
    T: Send + 'static,
    F: FnOnce(Arc<CoreRpc>) -> Result<T, RpcFault> + Send + 'static,
{
    let core = state.core.clone();
    join_fault(tokio::task::spawn_blocking(move || f(core)).await)?
}

/// What a JSON-RPC caller is told when a native method does not answer.
pub(super) fn native_fault(
    id: serde_json::Value,
    method: &str,
    fault: RpcFault,
) -> JsonRpcResponse {
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

pub(super) fn join_fault<T>(out: Result<T, tokio::task::JoinError>) -> Result<T, RpcFault> {
    out.map_err(|_| RpcFault::Internal(InternalFault::Join))
}

/// Frame a native method's outcome as a JSON value. A facts fault stays a
/// facts fault; a reply the transport could not encode is an
/// [`InternalFault`] — never attributed to the core.
pub(super) fn frame_native<T: serde::Serialize>(
    reply: Result<T, RpcFault>,
) -> Result<serde_json::Value, NativeFail> {
    match reply {
        Ok(value) => serde_json::to_value(value)
            .map_err(|_| NativeFail::Fault(RpcFault::Internal(InternalFault::Serialize))),
        Err(fault) => Err(NativeFail::Fault(fault)),
    }
}

/// Frame a method whose failure is an [`RpcError`].
pub(super) fn from_error<T: serde::Serialize>(
    reply: Result<T, RpcError>,
) -> Result<serde_json::Value, NativeFail> {
    match reply {
        Ok(value) => serde_json::to_value(value)
            .map_err(|_| NativeFail::Fault(RpcFault::Internal(InternalFault::Serialize))),
        Err(error) => Err(NativeFail::Error(error)),
    }
}

/// Run a short lock-holding read off the HTTP task. A join failure is an
/// internal [`RpcError`], the same class a defect in the node is.
pub(super) async fn blocking<T, F>(f: F) -> Result<T, RpcError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, RpcError> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        Err(_) => Err(RpcError::from(crate::chain_facts::FactsFault::Internal)),
    }
}
