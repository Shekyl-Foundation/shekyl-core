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

use crate::server::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use std::sync::Arc;

/// Offload one blocking C++ JSON dispatch; `None` on FFI failure.
async fn dispatch_json_raw(
    state: &Arc<AppState>,
    uri: &'static str,
    body: String,
) -> Option<String> {
    let core = state.core.clone();
    tokio::task::spawn_blocking(move || core.json_endpoint(uri, &body))
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

async fn dispatch_json(state: Arc<AppState>, uri: &'static str, body: String) -> impl IntoResponse {
    match dispatch_json_raw(&state, uri, body).await {
        Some(json) => json_ok(json),
        None => json_dispatch_error(),
    }
}

/// Overwrite `rpc_connections_count` in a `get_info` body with the live count
/// from the connection tracker — Rust owns the count; the C++ handler reports 0
/// (see `core_rpc_server::get_connections_count`). Restricted RPC discloses 0,
/// matching the C++ policy for the peer/connection fields, so the tracker value
/// is only injected on the unrestricted listener. Any parse failure returns the
/// body unchanged rather than dropping the response.
fn fill_rpc_connections_count(json: String, restricted: bool, count: u64) -> String {
    if restricted {
        return json;
    }
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&json) else {
        return json;
    };
    let Some(obj) = value.as_object_mut() else {
        return json;
    };
    obj.insert("rpc_connections_count".to_owned(), count.into());
    serde_json::to_string(&value).unwrap_or(json)
}

macro_rules! json_handler {
    ($fn_name:ident, $uri:expr) => {
        pub async fn $fn_name(
            State(state): State<Arc<AppState>>,
            body: String,
        ) -> impl IntoResponse {
            dispatch_json(state, $uri, body).await
        }
    };
}

// Unrestricted endpoints

/// `/get_height` (alias `/getheight`) — served natively (RK-1,
/// `docs/design/DAEMON_RPC_KV_CUTOVER.md`): the body is ignored, as the C++
/// handler ignored its empty request struct. A facts fault answers with the
/// same envelope a failed FFI dispatch does.
pub async fn get_height(State(state): State<Arc<AppState>>, _body: String) -> impl IntoResponse {
    let core = state.core.clone();
    let result = tokio::task::spawn_blocking(move || {
        let facts = crate::chain_facts::FfiChainFacts::new(core);
        crate::methods::get_height(&facts)
    })
    .await;
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
/// What can go wrong inside `get_transactions`' blocking section: the facts
/// shim refused, or the daemon could not render a body it had just read out of
/// its own store. Distinct because they are distinct answers to the caller.
enum TxFault {
    Facts(i32),
    Render(crate::methods::RenderFailed),
}

/// `GET|POST /get_transactions` (alias `/gettransactions`) — served natively
/// (RK-4c). The gather is one FFI call answering per request slot; the
/// `(split, prune, decode_as_json)` matrix and both refusals are Rust's.
///
/// `state.restricted` decides two things the C++ could not, because the bridge
/// passed a null `ctx` until #570: the request cap, and whether the pool read
/// may disclose a transaction the node has not broadcast.
pub async fn get_transactions(
    State(state): State<Arc<AppState>>,
    body: String,
) -> impl IntoResponse {
    let request: shekyl_rpc_types::GetTransactionsRequest = if body.trim().is_empty() {
        shekyl_rpc_types::GetTransactionsRequest::default()
    } else {
        match serde_json::from_str(&body) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(?e, "get_transactions: malformed request");
                return json_error("request could not be decoded");
            }
        }
    };
    let restricted = state.restricted;
    if restricted && request.txs_hashes.len() > crate::methods::RESTRICTED_TRANSACTIONS_COUNT {
        return json_ok(status_only(
            "Too many transactions requested in restricted mode",
        ));
    }
    let ids = match crate::methods::parse_request_hashes(
        &request.txs_hashes,
        crate::methods::TX_PARSE_FAILED,
    ) {
        Ok(ids) => ids,
        Err(status) => return json_ok(status_only(&status)),
    };
    let core = state.core.clone();
    let result = tokio::task::spawn_blocking(move || {
        // `!restricted` is the pool's sensitivity flag: false withholds a
        // transaction that is not `relay_category::broadcasted` (§2.2).
        let (slots, chain_height) = core
            .transactions(&ids, !restricted)
            .map_err(TxFault::Facts)?;
        // A rendering the daemon cannot produce fails the request rather than
        // answering OK with an empty `as_json`, which is what the C++ did and
        // is the only answer a caller can act on.
        crate::methods::project_transactions(
            &request,
            &ids,
            &slots,
            chain_height,
            |blob, pruned| core.tx_to_json(blob, pruned),
        )
        .map_err(TxFault::Render)
    })
    .await;
    match result {
        Ok(Ok(reply)) => match serde_json::to_string(&reply) {
            Ok(json) => json_ok(json),
            Err(e) => {
                tracing::warn!(?e, "get_transactions: reply could not be encoded");
                json_error("reply could not be encoded")
            }
        },
        Ok(Err(TxFault::Facts(rc))) => {
            tracing::warn!(rc, "get_transactions: facts unavailable");
            json_error("transaction facts unavailable")
        }
        Ok(Err(TxFault::Render(f))) => {
            tracing::warn!(txid = %f.txid, code = f.code, "get_transactions: tx could not be rendered");
            json_error("transaction could not be decoded to json")
        }
        Err(e) => {
            tracing::warn!(?e, "get_transactions: handler task did not complete");
            json_error("handler did not complete")
        }
    }
}

/// `GET|POST /is_key_image_spent` — served natively (RK-4c).
pub async fn is_key_image_spent(
    State(state): State<Arc<AppState>>,
    body: String,
) -> impl IntoResponse {
    let request: shekyl_rpc_types::IsKeyImageSpentRequest = if body.trim().is_empty() {
        shekyl_rpc_types::IsKeyImageSpentRequest::default()
    } else {
        match serde_json::from_str(&body) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(?e, "is_key_image_spent: malformed request");
                return json_error("request could not be decoded");
            }
        }
    };
    if state.restricted
        && request.key_images.len() > crate::methods::RESTRICTED_SPENT_KEY_IMAGES_COUNT
    {
        return json_ok(status_only(
            "Too many key images queried in restricted mode",
        ));
    }
    let ids = match crate::methods::parse_request_hashes(
        &request.key_images,
        crate::methods::KI_PARSE_FAILED,
    ) {
        Ok(ids) => ids,
        Err(status) => return json_ok(status_only(&status)),
    };
    let core = state.core.clone();
    let result = tokio::task::spawn_blocking(move || core.key_images_spent(&ids)).await;
    match result {
        Ok(Ok(status)) => {
            let mut spent_status = Vec::with_capacity(status.len());
            for s in status {
                match shekyl_rpc_types::KeyImageStatus::try_from(s) {
                    Ok(v) => spent_status.push(v),
                    Err(e) => {
                        tracing::warn!(%e, "is_key_image_spent: shim returned an unknown status");
                        return json_error("key image facts unavailable");
                    }
                }
            }
            let reply = shekyl_rpc_types::IsKeyImageSpentResponse {
                status: shekyl_rpc_types::RpcStatus::ok(),
                spent_status,
            };
            match serde_json::to_string(&reply) {
                Ok(json) => json_ok(json),
                Err(e) => {
                    tracing::warn!(?e, "is_key_image_spent: reply could not be encoded");
                    json_error("reply could not be encoded")
                }
            }
        }
        Ok(Err(rc)) => {
            tracing::warn!(rc, "is_key_image_spent: facts unavailable");
            json_error("key image facts unavailable")
        }
        Err(e) => {
            tracing::warn!(?e, "is_key_image_spent: handler task did not complete");
            json_error("handler did not complete")
        }
    }
}

/// A refusal body: HTTP 200 carrying a non-OK `status` and nothing else, which
/// is the shape the C++ answered these two routes' refusals with and the shape
/// the `refusal` oracle vector pins.
fn status_only(message: &str) -> String {
    serde_json::json!({ "status": message }).to_string()
}

json_handler!(get_alt_blocks_hashes, "/get_alt_blocks_hashes");
json_handler!(get_transaction_pool, "/get_transaction_pool");
json_handler!(get_transaction_pool_hashes, "/get_transaction_pool_hashes");
json_handler!(get_transaction_pool_stats, "/get_transaction_pool_stats");
json_handler!(get_limit, "/get_limit");

/// `get_info` is not a thin passthrough: it injects the live
/// `rpc_connections_count` from the Rust connection tracker (both the
/// `/get_info` and `/getinfo` routes dispatch here).
pub async fn get_info(State(state): State<Arc<AppState>>, body: String) -> impl IntoResponse {
    match dispatch_json_raw(&state, "/get_info", body).await {
        Some(json) => json_ok(fill_rpc_connections_count(
            json,
            state.restricted,
            state.conn_tracker.active_total(),
        )),
        None => json_dispatch_error(),
    }
}

#[cfg(test)]
mod tests {
    use super::{fill_rpc_connections_count, json_error};

    /// A native method's failure names its own cause in the envelope —
    /// never "FFI dispatch failed", which it cannot be.
    #[test]
    fn native_error_envelope_names_the_cause() {
        let (status, _, body) = json_error("chain facts unavailable");
        assert_eq!(status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["status"], "ERROR");
        assert_eq!(v["error"], "chain facts unavailable");
    }

    #[test]
    fn fills_live_count_when_unrestricted() {
        let out = fill_rpc_connections_count(
            r#"{"status":"OK","rpc_connections_count":0}"#.to_string(),
            false,
            7,
        );
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["rpc_connections_count"], 7);
        assert_eq!(v["status"], "OK");
    }

    #[test]
    fn adds_the_field_when_absent() {
        let out = fill_rpc_connections_count(r#"{"status":"OK"}"#.to_string(), false, 3);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["rpc_connections_count"], 3);
    }

    #[test]
    fn restricted_leaves_the_body_verbatim() {
        let body = r#"{"rpc_connections_count":0}"#.to_string();
        assert_eq!(fill_rpc_connections_count(body.clone(), true, 9), body);
    }

    #[test]
    fn non_object_or_unparseable_bodies_pass_through() {
        assert_eq!(
            fill_rpc_connections_count("not json".to_string(), false, 5),
            "not json"
        );
        assert_eq!(
            fill_rpc_connections_count("[1,2,3]".to_string(), false, 5),
            "[1,2,3]"
        );
    }
}

// Restricted-only endpoints (restriction enforced at route registration)
json_handler!(start_mining, "/start_mining");
json_handler!(stop_mining, "/stop_mining");
json_handler!(mining_status, "/mining_status");
json_handler!(save_bc, "/save_bc");
json_handler!(set_log_hash_rate, "/set_log_hash_rate");
json_handler!(set_log_level, "/set_log_level");
json_handler!(set_log_categories, "/set_log_categories");
json_handler!(stop_daemon, "/stop_daemon");
json_handler!(set_limit, "/set_limit");
json_handler!(out_peers, "/out_peers");
json_handler!(in_peers, "/in_peers");
json_handler!(pop_blocks, "/pop_blocks");

/// `/get_net_stats` — process start plus the global throttle counters
/// (RK-5a). Admin-only; the route table is what enforces that.
pub async fn get_net_stats(State(state): State<Arc<AppState>>, _body: String) -> impl IntoResponse {
    let core = state.core.clone();
    let result = tokio::task::spawn_blocking(move || {
        let facts = crate::chain_facts::FfiP2pFacts::new(core);
        crate::methods::get_net_stats(&facts)
    })
    .await;
    render("get_net_stats", result)
}

/// `/get_peer_list` — the white and gray peerlists (RK-5a). Admin-only.
///
/// The request body is optional and its two members are optional within it,
/// so an empty body means the daemon's own defaults — `public_only` **true**,
/// `include_blocked` false.
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
    render("get_peer_list", result)
}

/// The three-way match every native REST handler above ends in, written once.
fn render<T: serde::Serialize>(
    method: &'static str,
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
        Ok(Err(fault)) => {
            tracing::warn!(?fault, method, "facts unavailable");
            json_error("p2p facts unavailable")
        }
        Err(e) => {
            tracing::warn!(?e, method, "handler task did not complete");
            json_error("handler task did not complete")
        }
    }
}

/// `/get_stem_tallies` — per-successor relay outcome counts (§55).
///
/// **Admin-only (unrestricted listener), and the reason belongs here rather
/// than in the route table.** In daemon RPC terms: `restricted` is the
/// *public* limited listener; this route is selected only when
/// `!restricted` via `server::served_paths`. This endpoint *is* the
/// anonymity graph: which peers this node stems to, and how each has
/// behaved. Sharma Appendix B spends 50–100 probes per node to reconstruct
/// exactly that, so serving it on the public listener hands over — for free
/// and with better fidelity — what an attacker otherwise pays for. **It is
/// not "just counters": the peer set is the sensitive part, and the counts
/// merely make it legible.** If anyone later proposes moving this onto the
/// restricted (public) set, that is the argument to answer first.
///
/// Raw counts, matching the relay layer's own refusal to pre-compute a rate:
/// the consumer of this endpoint is a human tuning `n_min`, `cut` and
/// `cooldown`, and a rate would pick the accumulator's memory policy for
/// them.
///
/// # The gate lives in the route table (§69, §70)
///
/// This route's `Visibility::AdminOnly` row in `server::ROUTES` is the privacy
/// fact; `server::served_routes` applies `restricted`; `server::assemble`
/// registers exactly that, and [`crate::server::build_router`] is
/// `assemble` plus layers. The gate is asserted **on the assembled router**:
/// a dummy-handler build of the real table answers 200 for this path when
/// unrestricted and 404 when restricted, and the specification the assertions
/// run against is written out independently of the route table, so a path
/// *moved* between listeners fails rather than silently changing the oracle.
/// A daemon fixture is not owed: the property is route-table selection, and
/// naming this handler from a test would pull `core_rpc_ffi_*` into the lib
/// test binary.
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
