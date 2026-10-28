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

//! Handlers for JSON REST endpoints (MAP_URI_AUTO_JON2 family).
//!
//! Each handler is a thin async wrapper that offloads the blocking C++ FFI call
//! to a Tokio blocking thread.

use crate::authority::Authority;
use crate::server::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Extension;
use std::sync::Arc;

/// Offload one blocking C++ JSON dispatch; `None` on FFI failure.
async fn dispatch_json_raw(
    state: &Arc<AppState>,
    authority: Authority,
    uri: &'static str,
    body: String,
) -> Option<String> {
    let core = state.core.clone();
    let host = authority.host();
    tokio::task::spawn_blocking(move || core.json_endpoint(uri, &body, host))
        .await
        .ok()
        .flatten()
}

fn json_ok(body: String) -> (StatusCode, [(&'static str, &'static str); 1], String) {
    (StatusCode::OK, [("content-type", "application/json")], body)
}

fn json_dispatch_error() -> (StatusCode, [(&'static str, &'static str); 1], String) {
    json_error("FFI dispatch failed")
}

/// The REST error envelope with a reason that names what actually failed —
/// a natively-served method never fails for "FFI dispatch" reasons.
fn json_error(reason: &str) -> (StatusCode, [(&'static str, &'static str); 1], String) {
    let envelope = shekyl_rpc_types::RestErrorEnvelope {
        status: shekyl_rpc_types::RpcStatus("ERROR".to_owned()),
        error: reason.to_owned(),
    };
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [("content-type", "application/json")],
        serde_json::to_string(&envelope).expect("plain data serializes"),
    )
}

async fn dispatch_json(
    state: Arc<AppState>,
    authority: Authority,
    uri: &'static str,
    body: String,
) -> impl IntoResponse {
    match dispatch_json_raw(&state, authority, uri, body).await {
        Some(json) => json_ok(json),
        None => json_dispatch_error(),
    }
}

macro_rules! json_handler {
    ($fn_name:ident, $uri:expr) => {
        pub async fn $fn_name(
            State(state): State<Arc<AppState>>,
            Extension(authority): Extension<Authority>,
            body: String,
        ) -> impl IntoResponse {
            dispatch_json(state, authority, $uri, body).await
        }
    };
}

/// A method failure, on every surface, is the JSON-RPC error object
/// (RW-Q3). Success is the method's own JSON.
fn rest_value<T: serde::Serialize>(
    value: Result<T, shekyl_rpc_types::errors::RpcError>,
) -> axum::response::Response {
    match value {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(json) => json_ok(json).into_response(),
            Err(e) => {
                tracing::warn!(?e, "reply could not be encoded");
                json_error("reply could not be encoded").into_response()
            }
        },
        Err(error) => (
            StatusCode::OK,
            [("content-type", "application/json")],
            serde_json::to_string(&crate::authority::refusal(serde_json::Value::Null, &error))
                .expect("an error serializes"),
        )
            .into_response(),
    }
}

fn rest_params<T: serde::de::DeserializeOwned>(
    body: &str,
) -> Result<T, shekyl_rpc_types::errors::RpcError> {
    use shekyl_rpc_types::errors::{Diagnostic, ErrorClass, RpcError};
    let value = if body.trim().is_empty() {
        serde_json::Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_str(body).map_err(|e| {
            RpcError::new(
                ErrorClass::BadParams,
                Diagnostic::new("rpc.bad_params", format!("the request is not JSON: {e}")),
            )
        })?
    };
    serde_json::from_value(value).map_err(|e| {
        RpcError::new(
            ErrorClass::BadParams,
            Diagnostic::new(
                "rpc.bad_params",
                format!("the request was not accepted: {e}"),
            ),
        )
    })
}

async fn rest_blocking<T, F>(f: F) -> axum::response::Response
where
    T: serde::Serialize + Send + 'static,
    F: FnOnce() -> Result<T, shekyl_rpc_types::errors::RpcError> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => rest_value(result).into_response(),
        Err(e) => {
            tracing::warn!(?e, "handler task did not complete");
            json_error("handler task did not complete").into_response()
        }
    }
}

/// `/get_height` (alias `/getheight`) — served natively (RK-1,
/// `docs/completed/DAEMON_RPC_KV_CUTOVER.md`): the body is ignored, as the C++
/// handler ignored its empty request struct. A facts fault answers with the
/// same envelope a failed FFI dispatch does.
pub async fn get_height(State(state): State<Arc<AppState>>, _body: String) -> impl IntoResponse {
    let chain = Arc::clone(&state.handles.chain);
    let result =
        tokio::task::spawn_blocking(move || crate::methods::get_height(chain.as_ref())).await;
    match result {
        Ok(Ok(reply)) => match serde_json::to_string(&reply) {
            Ok(json) => json_ok(json),
            Err(e) => {
                tracing::warn!(?e, "get_height: reply could not be encoded");
                json_error("reply could not be encoded")
            }
        },
        Ok(Err(fault)) => {
            tracing::warn!(?fault, "get_height: facts unavailable");
            json_error("chain facts unavailable")
        }
        Err(e) => {
            tracing::warn!(?e, "get_height: handler task did not complete");
            json_error("handler did not complete")
        }
    }
}
/// `GET|POST /get_transactions` (alias `/gettransactions`) over the store
/// and the pool. `decode_as_json` is refused: epee's rendering is gone.
pub async fn get_transactions(
    State(state): State<Arc<AppState>>,
    Extension(authority): Extension<Authority>,
    body: String,
) -> axum::response::Response {
    let request = match rest_params(body.as_str()) {
        Ok(request) => request,
        Err(error) => return rest_value::<shekyl_rpc_types::GetTransactionsResponse>(Err(error)),
    };
    let chain = Arc::clone(&state.handles.chain);
    let host = authority.host();
    rest_blocking(move || crate::read_methods::get_transactions(chain.as_ref(), &request, host))
        .await
}

/// `GET|POST /is_key_image_spent` over the store and the pool.
pub async fn is_key_image_spent(
    State(state): State<Arc<AppState>>,
    Extension(authority): Extension<Authority>,
    body: String,
) -> impl IntoResponse {
    let request = match rest_params::<shekyl_rpc_types::IsKeyImageSpentRequest>(body.as_str()) {
        Ok(request) => request,
        Err(error) => return rest_value::<shekyl_rpc_types::IsKeyImageSpentResponse>(Err(error)),
    };
    let chain = Arc::clone(&state.handles.chain);
    let host = authority.host();
    let result = tokio::task::spawn_blocking(move || {
        crate::read_methods::is_key_image_spent(chain.as_ref(), &request, host)
    })
    .await;
    render("is_key_image_spent", "key image facts unavailable", result).into_response()
}

pub async fn get_alt_blocks_hashes(
    State(state): State<Arc<AppState>>,
    _body: String,
) -> impl IntoResponse {
    let chain = Arc::clone(&state.handles.chain);
    let result = tokio::task::spawn_blocking(move || {
        crate::read_methods::get_alt_blocks_hashes(chain.as_ref())
    })
    .await;
    render("get_alt_blocks_hashes", "chain facts unavailable", result)
}

pub async fn get_transaction_pool(
    State(state): State<Arc<AppState>>,
    Extension(authority): Extension<Authority>,
    _body: String,
) -> impl IntoResponse {
    let pool = Arc::clone(&state.handles.pool);
    let host = authority.host();
    rest_blocking(move || {
        crate::pool_methods::get_transaction_pool(
            pool.as_ref(),
            crate::pool_methods::scope_for(host),
        )
    })
    .await
}

pub async fn get_transaction_pool_hashes(
    State(state): State<Arc<AppState>>,
    Extension(authority): Extension<Authority>,
    _body: String,
) -> impl IntoResponse {
    let pool = Arc::clone(&state.handles.pool);
    let host = authority.host();
    rest_blocking(move || {
        crate::pool_methods::get_transaction_pool_hashes(
            pool.as_ref(),
            crate::pool_methods::scope_for(host),
        )
    })
    .await
}

pub async fn get_transaction_pool_stats(
    State(state): State<Arc<AppState>>,
    Extension(authority): Extension<Authority>,
    _body: String,
) -> impl IntoResponse {
    let pool = Arc::clone(&state.handles.pool);
    let host = authority.host();
    rest_blocking(move || {
        crate::pool_methods::get_transaction_pool_stats(
            pool.as_ref(),
            crate::pool_methods::scope_for(host),
        )
    })
    .await
}

/// `/get_info` (alias `/getinfo`) — served natively (RK-5c,
/// `docs/design/DAEMON_RPC_KV_GET_INFO.md`). The body is ignored, as the C++
/// handler ignored its empty request struct.
///
/// The listener's posture becomes a [`crate::info::Disclosure`], and the
/// method reads only the parts that disclosure shows (RK-D24). This server's
/// own connection count is the transport's to supply; it is a Status field.
pub async fn get_info(
    State(state): State<Arc<AppState>>,
    Extension(authority): Extension<Authority>,
    _body: String,
) -> impl IntoResponse {
    let chain = Arc::clone(&state.handles.chain);
    let disclosure = authority.disclosure();
    let rpc_connections = state.conn_tracker.active_total();
    let result = tokio::task::spawn_blocking(move || {
        crate::info::get_info(chain.as_ref(), disclosure, rpc_connections)
    })
    .await;
    render("get_info", "node facts unavailable", result)
}

#[cfg(test)]
mod tests {

    /// The two ways to omit every field must ask the same question. They did
    /// not on the C++ bridge, and that split had a live consumer.
    #[test]
    fn bodyless_and_empty_object_are_the_same_peer_list_request() {
        let from_empty_object: shekyl_rpc_types::GetPeerListRequest =
            serde_json::from_str("{}").expect("an empty object is a valid request");
        let bodyless = shekyl_rpc_types::GetPeerListRequest::default();
        assert_eq!(
            from_empty_object, bodyless,
            "however a caller omits the fields, it is asking one question"
        );
        assert!(
            bodyless.public_only,
            "and that question is the declared OPT default, not the \
             value-initialized zero the old bridge fell back to"
        );
        assert!(!bodyless.include_blocked);
    }
    use super::json_error;

    /// A native method's failure names its own cause in the envelope —
    /// never "FFI dispatch failed", which it cannot be.
    #[test]
    fn a_store_fault_is_rendered_in_its_own_words() {
        use super::render;
        use crate::methods::{RpcFault, StoreFault};
        use shekyl_types::ChainCount;
        use shekyl_units::AtomicUnits;

        let store = StoreFault::SupplyInvariant {
            coins_generated: AtomicUnits::from_raw(1_000),
            total_burned: AtomicUnits::from_raw(1_001),
            chain_height: ChainCount::from_raw(77),
        };
        let (status, _, body) = render::<shekyl_rpc_types::GetInfoResponse>(
            "get_info",
            "node facts unavailable",
            Ok(Err(RpcFault::Store(store))),
        );
        assert_eq!(status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["status"], "ERROR");
        assert_eq!(v["error"], store.to_string());

        // A facts code beside it is still the method's generic line.
        let (_, _, body) = render::<shekyl_rpc_types::GetInfoResponse>(
            "get_info",
            "node facts unavailable",
            Ok(Err(RpcFault::Facts(
                crate::chain_facts::FactsFault::Inconsistent,
            ))),
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"], "node facts unavailable");
    }

    #[test]
    fn native_error_envelope_names_the_cause() {
        let (status, _, body) = json_error("chain facts unavailable");
        assert_eq!(status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["status"], "ERROR");
        assert_eq!(v["error"], "chain facts unavailable");
    }
}

/// `/start_mining { threads }`: the built-in miner, on the node's address
/// (N2). A request that names an address is not this method's.
pub async fn start_mining(
    State(state): State<Arc<AppState>>,
    _authority: Extension<Authority>,
    body: String,
) -> impl IntoResponse {
    let request = match rest_params(body.as_str()) {
        Ok(request) => request,
        Err(error) => {
            return rest_value::<shekyl_rpc_types::mining::StatusOnlyResponse>(Err(error))
                .into_response()
        }
    };
    let mining = Arc::clone(&state.handles.mining);
    rest_value(crate::mining_methods::start_mining(&mining, request).await).into_response()
}

pub async fn stop_mining(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mining = Arc::clone(&state.handles.mining);
    rest_value(crate::mining_methods::stop_mining(&mining).await).into_response()
}

pub async fn mining_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mining = Arc::clone(&state.handles.mining);
    rest_blocking(move || crate::mining_methods::mining_status(mining.as_ref())).await
}

json_handler!(save_bc, "/save_bc");
json_handler!(set_log_hash_rate, "/set_log_hash_rate");

/// `/stop_daemon`: ask the node to stop. The reply is sent before it goes.
pub async fn stop_daemon(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stop = Arc::clone(&state.handles.stop);
    rest_blocking(move || crate::node_methods::stop_daemon(stop.as_ref())).await
}

/// `/pop_blocks { nblocks }`, behind the armed gate the request layer already
/// applied. The token is read again here so the door cannot be called without it.
pub async fn pop_blocks(
    State(state): State<Arc<AppState>>,
    Extension(authority): Extension<Authority>,
    body: String,
) -> impl IntoResponse {
    let request = match rest_params(body.as_str()) {
        Ok(request) => request,
        Err(error) => {
            return rest_value::<shekyl_rpc_types::mining::PopBlocksResponse>(Err(error))
                .into_response()
        }
    };
    let Some(row) = shekyl_rpc_types::methods::rest_path("/pop_blocks") else {
        return json_error("pop_blocks has no row").into_response();
    };
    let armed = match shekyl_rpc_types::methods::admit_armed(row, authority.armed_switch()) {
        Ok(armed) => armed,
        Err(error) => {
            return rest_value::<shekyl_rpc_types::mining::PopBlocksResponse>(Err(error))
                .into_response()
        }
    };
    let door = Arc::clone(&state.handles.door);
    rest_value(crate::mining_methods::pop_blocks(door.as_ref(), armed, request).await)
        .into_response()
}

/// `/get_net_stats` — process start plus the global throttle counters
/// (RK-5a). Admin-only; the route table is what enforces that.
pub async fn get_net_stats(State(state): State<Arc<AppState>>, _body: String) -> impl IntoResponse {
    let core = state.core.clone();
    let result = tokio::task::spawn_blocking(move || {
        let facts = crate::chain_facts::FfiP2pFacts::new(core);
        crate::methods::get_net_stats(&facts)
    })
    .await;
    render("get_net_stats", "p2p facts unavailable", result)
}

/// `/get_peer_list` — the white and gray peerlists (RK-5a). Admin-only.
///
/// The request body is optional and its two members are optional within it,
/// so an empty body means the daemon's own defaults — `public_only` **true**,
/// `include_blocked` false.
///
/// **An absent body and an absent field mean the same thing here, and did not
/// in C++.** `dispatch_json` deserialized only when the body was non-empty
/// (`if (body_json && body_json[0])`), so a bodyless request kept the
/// value-initialized `public_only = false` — the whole peerlist — while `{}`
/// ran the KV map, applied `OPT(public_only, true)`, and answered the public
/// subset. One route, two questions, decided by body length rather than by
/// anything the caller said. Resolving both to the declared default is the
/// correction; `bodyless_and_empty_object_are_the_same_peer_list_request`
/// pins it, and the design doc's §7 records the one caller that had to start
/// asking for the whole list outright.
pub async fn get_peer_list(State(state): State<Arc<AppState>>, body: String) -> impl IntoResponse {
    let request: shekyl_rpc_types::GetPeerListRequest = if body.trim().is_empty() {
        shekyl_rpc_types::GetPeerListRequest::default()
    } else {
        match serde_json::from_str(&body) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(?e, "get_peer_list: malformed request");
                return json_error("request could not be decoded");
            }
        }
    };
    let core = state.core.clone();
    let result = tokio::task::spawn_blocking(move || {
        let facts = crate::chain_facts::FfiP2pFacts::new(core);
        crate::methods::get_peer_list(&request, &facts)
    })
    .await;
    render("get_peer_list", "p2p facts unavailable", result)
}

/// The three-way match every native REST handler above ends in, written once.
fn render<T: serde::Serialize>(
    method: &'static str,
    unavailable: &'static str,
    result: Result<Result<T, crate::methods::RpcFault>, tokio::task::JoinError>,
) -> (StatusCode, [(&'static str, &'static str); 1], String) {
    match result {
        Ok(Ok(reply)) => match serde_json::to_string(&reply) {
            Ok(json) => json_ok(json),
            Err(e) => {
                tracing::warn!(?e, method, "reply could not be encoded");
                json_error("reply could not be encoded")
            }
        },
        // A store that contradicts itself is reported in its own words:
        // which invariant, and with what numbers. The handler logged it.
        Ok(Err(crate::methods::RpcFault::Store(store))) => json_error(&store.to_string()),
        Ok(Err(fault)) => {
            tracing::warn!(?fault, method, "facts unavailable");
            json_error(unavailable)
        }
        Err(e) => {
            tracing::warn!(?e, method, "handler task did not complete");
            json_error("handler task did not complete")
        }
    }
}

/// `/get_stem_tallies` — per-successor relay outcome counts (§55).
///
/// **Host-only data (`RPC_CHANNEL.md` §6.1, RT-O9.3), and the reason
/// belongs here rather than in the method table.** This endpoint *is* the
/// anonymity graph: which peers this node stems to, and how each has
/// behaved. Sharma Appendix B spends 50–100 probes per node to reconstruct
/// exactly that, so serving it to anyone but the host's administrator hands
/// over — for free and with better fidelity — what an attacker otherwise
/// pays for. **It is not "just counters": the peer set is the sensitive
/// part, and the counts merely make it legible.** If anyone later proposes
/// moving it into a grant, that is the argument to answer first.
///
/// Raw counts, matching the relay layer's own refusal to pre-compute a rate:
/// the consumer of this endpoint is a human tuning `n_min`, `cut` and
/// `cooldown`, and a rate would pick the accumulator's memory policy for
/// them.
///
/// # The gate is the method table's policy
///
/// The row's policy is `HostOnly`, and the request layer
/// (`crate::authority::stamp`) refuses this path to every connection that is
/// not the host's administrator before the handler runs. The gate is asserted
/// on the assembled router, against a specification written out
/// independently of the table, so a row moved into a grant fails rather than
/// silently changing the oracle. A daemon fixture is not owed: naming this
/// handler from a test would pull `core_rpc_ffi_*` into the lib test binary.
pub async fn get_stem_tallies(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let core = state.core.clone();
    match tokio::task::spawn_blocking(move || core.stem_tallies())
        .await
        .ok()
        .flatten()
    {
        Some(body) => json_ok(body),
        None => json_dispatch_error(),
    }
}
