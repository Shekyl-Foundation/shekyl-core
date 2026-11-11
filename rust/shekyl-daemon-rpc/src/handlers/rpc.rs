// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `/json_rpc`, the daemon's one route (`RPC_WIRE.md` RW-Q1, RW-Q2).
//!
//! One request per message, strict JSON-RPC 2.0: `"jsonrpc": "2.0"`, a
//! non-null `id`, a method, and `params` a named object or left out. The
//! method's name is looked up in the method table ([`wire::Id`]); a name with
//! no row is method-not-found. The row is admitted against the connection's
//! authority, its request is read as its own type, and [`dispatch`] matches
//! the method with no wildcard arm, so a row nothing serves does not compile
//! (RW-Q7). HTTP status describes the transport only: every answer here is
//! HTTP 200 with a `result` or an `error`.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Extension;
use axum::Json;
use serde_json::{Map, Value};
use shekyl_rpc_types::errors::{Diagnostic, ErrorClass, RpcError, METHOD_NOT_FOUND};
use shekyl_rpc_types::method::{admit_armed, RpcMethod};
use shekyl_rpc_types::wire::{self, Id};

use crate::authority::{note_admitted, refusal, Authority};
use crate::handles::ChainReadHandle;
use crate::methods::{InternalFault, RpcFault};
use crate::options::OptionsFault;
use crate::server::AppState;
use crate::types::JsonRpcResponse;

/// The envelope's diagnostic codes.
pub mod codes {
    /// The message is not one JSON-RPC 2.0 request.
    pub const ENVELOPE: &str = "rpc.envelope";
    /// The params are not this method's request.
    pub const PARAMS: &str = "rpc.params";
    /// No method has this name.
    pub const METHOD: &str = "rpc.method";
}

/// Why a call did not answer.
enum Failure {
    /// A refusal: its class and its diagnostic.
    Error(RpcError),
    /// A configuration refusal, whose `data` is its list (RT-O25).
    Options(OptionsFault),
}

impl From<RpcError> for Failure {
    fn from(error: RpcError) -> Self {
        Self::Error(error)
    }
}

impl From<RpcFault> for Failure {
    fn from(fault: RpcFault) -> Self {
        Self::Error(fault.into_error())
    }
}

impl From<OptionsFault> for Failure {
    fn from(fault: OptionsFault) -> Self {
        Self::Options(fault)
    }
}

fn envelope_refusal(message: &str) -> RpcError {
    RpcError::new(
        ErrorClass::BadParams,
        Diagnostic::new(codes::ENVELOPE, message),
    )
}

/// The handler for `POST /json_rpc`.
pub async fn handle(
    State(state): State<Arc<AppState>>,
    Extension(authority): Extension<Authority>,
    body: Bytes,
) -> (StatusCode, Json<JsonRpcResponse>) {
    (StatusCode::OK, Json(answer(&state, authority, &body).await))
}

/// One call, from the body to its answer.
async fn answer(state: &Arc<AppState>, authority: Authority, body: &[u8]) -> JsonRpcResponse {
    let refused = |id: Value, error: RpcError| refusal(id, &error);
    let envelope = match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(envelope)) => envelope,
        Ok(Value::Array(_)) => {
            return refused(
                Value::Null,
                envelope_refusal("one request per message; a batch is refused"),
            )
        }
        Ok(_) => {
            return refused(
                Value::Null,
                envelope_refusal("the request is not a JSON object"),
            )
        }
        Err(e) => {
            return refused(
                Value::Null,
                envelope_refusal(&format!("the request is not JSON: {e}")),
            )
        }
    };
    let (id, method, params) = match read_envelope(envelope) {
        Ok(parts) => parts,
        Err((id, error)) => return refused(id, error),
    };
    let Some(called) = Id::of(&method) else {
        let diagnostic = Diagnostic::new(codes::METHOD, format!("no method is named {method}"))
            .param("method", method.clone());
        return JsonRpcResponse::error_with_data(
            id,
            METHOD_NOT_FOUND,
            diagnostic.message.clone(),
            serde_json::to_value(&diagnostic).ok(),
        );
    };
    let row = called.row();
    if let Err(error) = authority.admit(row) {
        return refused(id, error);
    }
    note_admitted(authority, row);
    match dispatch(state, authority, called, params).await {
        Ok(result) => JsonRpcResponse::success(id, result),
        Err(Failure::Error(error)) => {
            if matches!(error.class, ErrorClass::Internal | ErrorClass::StoreFault) {
                tracing::warn!(method = called.name(), refusal = %error.report(), "RPC method failed");
            }
            refused(id, error)
        }
        Err(Failure::Options(fault)) => {
            let (class, message, data) = fault.into_parts();
            JsonRpcResponse::error_with_data(id, class.code(), message, Some(data))
        }
    }
}

/// The envelope's three parts, strictly (RW-Q2), or the refusal with the
/// `id` to answer it under.
fn read_envelope(
    mut envelope: Map<String, Value>,
) -> Result<(Value, String, Value), (Value, RpcError)> {
    let id = envelope.remove("id").unwrap_or(Value::Null);
    let fail = |id: &Value, message: &str| Err((id.clone(), envelope_refusal(message)));
    if id.is_null() {
        return fail(
            &id,
            "a request carries a non-null id: a notification is a call nobody answers",
        );
    }
    if !matches!(id, Value::String(_) | Value::Number(_)) {
        return fail(&id, "the id is a string or a number");
    }
    if envelope.remove("jsonrpc") != Some(Value::String("2.0".to_owned())) {
        return fail(&id, "\"jsonrpc\": \"2.0\" is required");
    }
    let Some(Value::String(method)) = envelope.remove("method") else {
        return fail(&id, "the method is a string");
    };
    let params = match envelope.remove("params") {
        None => Value::Object(Map::new()),
        Some(Value::Object(params)) => Value::Object(params),
        Some(_) => return fail(&id, "params is a named object, or left out"),
    };
    if let Some(key) = envelope.keys().next() {
        return fail(
            &id,
            &format!("`{key}` is not a member of a JSON-RPC request"),
        );
    }
    Ok((id, method, params))
}

/// A method's params as its own request type.
fn request<M: RpcMethod>(params: Value) -> Result<M::Request, Failure> {
    serde_json::from_value(params).map_err(|e| {
        Failure::Error(RpcError::new(
            ErrorClass::BadParams,
            Diagnostic::new(codes::PARAMS, format!("{}: {e}", M::NAME)).param("method", M::NAME),
        ))
    })
}

fn framed<T: serde::Serialize>(reply: T) -> Result<Value, Failure> {
    serde_json::to_value(reply).map_err(|_| RpcFault::Internal(InternalFault::Serialize).into())
}

/// Run a chain read on a blocking thread: the store's reads must not block
/// the HTTP task.
async fn on_chain<T, F>(state: &Arc<AppState>, f: F) -> Result<T, RpcFault>
where
    T: Send + 'static,
    F: FnOnce(&ChainReadHandle) -> Result<T, RpcFault> + Send + 'static,
{
    let chain = Arc::clone(&state.handles.chain);
    tokio::task::spawn_blocking(move || f(&chain))
        .await
        .map_err(|_| RpcFault::Internal(InternalFault::Join))?
}

/// Run a short lock-holding read off the HTTP task.
async fn blocking<T, E, F>(f: F) -> Result<T, Failure>
where
    T: Send + 'static,
    E: Into<Failure> + Send + 'static,
    F: FnOnce() -> Result<T, E> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result.map_err(Into::into),
        Err(_) => Err(RpcFault::Internal(InternalFault::Join).into()),
    }
}

/// The method's answer. Exhaustive over [`Id`] with no wildcard arm.
#[allow(clippy::too_many_lines)]
async fn dispatch(
    state: &Arc<AppState>,
    authority: Authority,
    called: Id,
    params: Value,
) -> Result<Value, Failure> {
    let bounded = authority.bounded();
    let host = authority.host();
    match called {
        Id::Version => {
            framed(on_chain(state, |c| crate::reads::version(c.as_chain_facts())).await?)
        }
        Id::ChainHeight => {
            framed(on_chain(state, |c| crate::reads::chain_height(c.as_chain_facts())).await?)
        }
        Id::BlockHeaderShow => {
            let req = request::<wire::BlockHeaderShow>(params)?;
            framed(
                on_chain(state, move |c| {
                    crate::reads::block_header_show(c.as_chain_facts(), &req)
                })
                .await?,
            )
        }
        Id::BlockHeaderList => {
            let req = request::<wire::BlockHeaderList>(params)?;
            framed(
                on_chain(state, move |c| {
                    crate::reads::block_header_list(c.as_chain_facts(), &req, bounded)
                })
                .await?,
            )
        }
        Id::BlockShow => {
            let req = request::<wire::BlockShow>(params)?;
            framed(
                on_chain(state, move |c| {
                    crate::reads::block_show(c.as_chain_facts(), c.as_read_facts(), &req)
                })
                .await?,
            )
        }
        Id::BlockList => {
            let req = request::<wire::BlockList>(params)?;
            framed(
                on_chain(state, move |c| {
                    crate::reads::block_list(c.as_chain_facts(), c.as_read_facts(), &req, bounded)
                })
                .await?,
            )
        }
        Id::TxShow => {
            let req = request::<wire::TxShow>(params)?;
            framed(
                on_chain(state, move |c| {
                    crate::reads::tx_show(c.as_read_facts(), &req, host)
                })
                .await?,
            )
        }
        Id::TxList => {
            let req = request::<wire::TxList>(params)?;
            framed(
                on_chain(state, move |c| {
                    crate::reads::tx_list(c.as_read_facts(), &req, host)
                })
                .await?,
            )
        }
        Id::ChainSpent => {
            let req = request::<wire::ChainSpent>(params)?;
            framed(
                on_chain(state, move |c| {
                    crate::reads::chain_spent(c.as_read_facts(), &req, host)
                })
                .await?,
            )
        }
        Id::Fee => {
            request::<wire::Fee>(params)?;
            framed(on_chain(state, |c| crate::reads::fee(c.as_chain_facts())).await?)
        }
        Id::ChainCoinbaseSum => {
            let req = request::<wire::ChainCoinbaseSum>(params)?;
            // A bounded caller takes the one coinbase-read permit, then the
            // blocking pool: a cold read waits on disk (§6.3). The permit is
            // held inside the scan, so a cancelled request does not free it
            // while the read is still on disk.
            let permit = if bounded {
                Some(
                    Arc::clone(&state.coinbase_reads)
                        .acquire_owned()
                        .await
                        .map_err(|_| RpcFault::Internal(InternalFault::Join))?,
                )
            } else {
                None
            };
            framed(
                on_chain(state, move |c| {
                    let _permit = permit;
                    crate::reads::chain_coinbase_sum(c.as_read_facts(), &req)
                })
                .await?,
            )
        }
        Id::ChainAlt => {
            request::<wire::ChainAlt>(params)?;
            framed(on_chain(state, |c| crate::reads::chain_alt(c.as_read_facts())).await?)
        }
        Id::CurveShow => {
            let req = request::<wire::CurveShow>(params)?;
            framed(
                on_chain(state, move |c| {
                    crate::reads::curve_show(c.as_read_facts(), &req)
                })
                .await?,
            )
        }
        Id::ArchivalClaimShow => {
            let req = request::<wire::ArchivalClaimShow>(params)?;
            framed(
                on_chain(state, move |c| {
                    crate::reads::archival_claim_show(c.as_read_facts(), &req)
                })
                .await?,
            )
        }
        Id::ShardCoverage => {
            request::<wire::ShardCoverage>(params)?;
            framed(on_chain(state, |c| crate::reads::shard_coverage(c.as_read_facts())).await?)
        }
        Id::ShardFetch => {
            let req = request::<wire::ShardFetch>(params)?;
            // Async by contract: a fetch over the network when a desk is
            // composed. No worker is taken.
            framed(crate::shard_view::shard_fetch(state.shard_view.as_ref(), req).await?)
        }
        Id::DaemonStatus => {
            request::<wire::DaemonStatus>(params)?;
            let disclosure = authority.disclosure();
            let rpc_connections = state.conn_tracker.active_total();
            framed(
                on_chain(state, move |c| {
                    crate::info::daemon_status(
                        c.as_info_facts(),
                        c.as_chain_facts(),
                        disclosure,
                        rpc_connections,
                    )
                })
                .await?,
            )
        }
        Id::SyncStatus => {
            request::<wire::SyncStatus>(params)?;
            let chain = Arc::clone(&state.handles.chain);
            let p2p = Arc::clone(&state.handles.p2p);
            framed(
                blocking(move || {
                    crate::methods::sync_status(
                        chain.as_chain_facts(),
                        chain.as_sync_view(),
                        p2p.as_ref(),
                    )
                })
                .await?,
            )
        }
        Id::PeerConnections => {
            request::<wire::PeerConnections>(params)?;
            let chain = Arc::clone(&state.handles.chain);
            let p2p = Arc::clone(&state.handles.p2p);
            framed(
                blocking(move || {
                    crate::methods::peer_connections(p2p.as_ref(), chain.as_sync_view())
                })
                .await?,
            )
        }
        Id::PeerList => {
            let req = request::<wire::PeerList>(params)?;
            let p2p = Arc::clone(&state.handles.p2p);
            framed(blocking(move || crate::methods::peer_list(p2p.as_ref(), &req)).await?)
        }
        Id::P2pStats => {
            request::<wire::P2pStats>(params)?;
            let p2p = Arc::clone(&state.handles.p2p);
            framed(blocking(move || crate::methods::p2p_stats(p2p.as_ref())).await?)
        }
        Id::RelayStats => {
            request::<wire::RelayStats>(params)?;
            let p2p = Arc::clone(&state.handles.p2p);
            framed(blocking(move || crate::methods::relay_stats(p2p.as_ref())).await?)
        }
        Id::OptionSet => {
            let req = request::<wire::OptionSet>(params)?;
            // The handle's set runs under its own lock; no worker is taken.
            framed(crate::options::option_set(state.options.as_ref(), &req)?)
        }
        Id::OptionShow => {
            let req = request::<wire::OptionShow>(params)?;
            framed(crate::options::option_show(
                state.options.as_ref(),
                &req,
                authority.disclosure(),
            )?)
        }
        Id::DaemonStop => {
            request::<wire::DaemonStop>(params)?;
            let stop = Arc::clone(&state.handles.stop);
            framed(blocking(move || crate::node_methods::daemon_stop(stop.as_ref())).await?)
        }
        Id::TxpoolList => {
            request::<wire::TxpoolList>(params)?;
            let pool = Arc::clone(&state.handles.pool);
            framed(
                blocking(move || {
                    crate::pool_methods::txpool_list(pool.as_ref(), crate::reads::scope_for(host))
                })
                .await?,
            )
        }
        Id::TxpoolStats => {
            request::<wire::TxpoolStats>(params)?;
            let pool = Arc::clone(&state.handles.pool);
            framed(
                blocking(move || {
                    crate::pool_methods::txpool_stats(pool.as_ref(), crate::reads::scope_for(host))
                })
                .await?,
            )
        }
        Id::TxpoolFlush => {
            let req = request::<wire::TxpoolFlush>(params)?;
            framed(
                crate::pool_methods::txpool_flush(
                    state.handles.pool.as_ref(),
                    &req,
                    crate::reads::scope_for(host),
                )
                .await?,
            )
        }
        Id::TxRelay => {
            let req = request::<wire::TxRelay>(params)?;
            let pool = Arc::clone(&state.handles.pool);
            framed(
                blocking(move || {
                    crate::pool_methods::tx_relay(
                        pool.as_ref(),
                        &req,
                        crate::reads::scope_for(host),
                    )
                })
                .await?,
            )
        }
        Id::TxSubmit => {
            let req = request::<wire::TxSubmit>(params)?;
            framed(crate::submit::tx_submit(state, host, req.body.into_vec()).await?)
        }
        Id::BlockTemplate => {
            request::<wire::BlockTemplate>(params)?;
            let mining = Arc::clone(&state.handles.mining);
            framed(blocking(move || crate::mining_methods::block_template(mining.as_ref())).await?)
        }
        Id::BlockSubmit => {
            let req = request::<wire::BlockSubmit>(params)?;
            framed(crate::mining_methods::block_submit(state.handles.door.as_ref(), req).await?)
        }
        Id::Pow => {
            let req = request::<wire::Pow>(params)?;
            let budget = Arc::clone(&state.hash_budget);
            framed(
                on_chain(state, move |c| {
                    crate::reads::pow(c.as_read_facts(), &req, bounded, budget.as_ref())
                })
                .await?,
            )
        }
        Id::MineStart => {
            let req = request::<wire::MineStart>(params)?;
            framed(crate::mining_methods::mine_start(&state.handles.mining, req).await?)
        }
        Id::MineStop => {
            request::<wire::MineStop>(params)?;
            framed(crate::mining_methods::mine_stop(&state.handles.mining).await?)
        }
        Id::MineStatus => {
            request::<wire::MineStatus>(params)?;
            let mining = Arc::clone(&state.handles.mining);
            framed(blocking(move || crate::mining_methods::mine_status(mining.as_ref())).await?)
        }
        Id::BanAdd => {
            let req = request::<wire::BanAdd>(params)?;
            let bans = Arc::clone(&state.handles.bans);
            framed(blocking(move || crate::ban_methods::ban_add(bans.as_ref(), &req)).await?)
        }
        Id::BanRemove => {
            let req = request::<wire::BanRemove>(params)?;
            let bans = Arc::clone(&state.handles.bans);
            framed(blocking(move || crate::ban_methods::ban_remove(bans.as_ref(), &req)).await?)
        }
        Id::BanList => {
            request::<wire::BanList>(params)?;
            let bans = Arc::clone(&state.handles.bans);
            framed(blocking(move || crate::ban_methods::ban_list(bans.as_ref())).await?)
        }
        Id::BanShow => {
            let req = request::<wire::BanShow>(params)?;
            let bans = Arc::clone(&state.handles.bans);
            framed(blocking(move || crate::ban_methods::ban_show(bans.as_ref(), &req)).await?)
        }
        Id::DevBlockGenerate => {
            let req = request::<wire::DevBlockGenerate>(params)?;
            let armed = admit_armed(called.row(), authority.armed_switch())?;
            framed(
                crate::mining_methods::dev_block_generate(
                    &state.handles.mining,
                    state.handles.door.as_ref(),
                    state.handles.chain.as_chain_facts(),
                    armed,
                    req,
                )
                .await?,
            )
        }
        Id::DevChainPop => {
            let req = request::<wire::DevChainPop>(params)?;
            let armed = admit_armed(called.row(), authority.armed_switch())?;
            framed(
                crate::mining_methods::dev_chain_pop(state.handles.door.as_ref(), armed, req)
                    .await?,
            )
        }
    }
}
