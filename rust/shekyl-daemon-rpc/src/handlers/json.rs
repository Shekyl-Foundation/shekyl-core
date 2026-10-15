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
/// shim refused, or the daemon could not project a body it had just read out
/// of its own store — render it, or measure its archival length. Distinct
/// because they are distinct answers to the caller.
enum TxFault {
    Facts(i32),
    Projection(crate::methods::ProjectionFailed),
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
        .map_err(TxFault::Projection)
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
        Ok(Err(TxFault::Projection(crate::methods::ProjectionFailed::Render(f)))) => {
            tracing::warn!(txid = %f.txid, code = f.code, "get_transactions: tx could not be rendered");
            json_error("transaction could not be decoded to json")
        }
        Ok(Err(TxFault::Projection(crate::methods::ProjectionFailed::Length(f)))) => {
            tracing::warn!(txid = %f.txid, "get_transactions: archival length could not be measured");
            json_error("transaction archival length could not be measured")
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

/// `/get_info` (alias `/getinfo`) — served natively (RK-5c,
/// `docs/design/DAEMON_RPC_KV_GET_INFO.md`). The body is ignored, as the C++
/// handler ignored its empty request struct.
///
/// The listener's posture becomes a [`crate::info::Disclosure`], and the
/// method reads only the parts that disclosure shows (RK-D24). This server's
/// own connection count is the transport's to supply; it is a Status field.
pub async fn get_info(State(state): State<Arc<AppState>>, _body: String) -> impl IntoResponse {
    let core = state.core.clone();
    let disclosure = crate::info::Disclosure::from_listener(state.restricted);
    let rpc_connections = state.conn_tracker.active_total();
    let result = tokio::task::spawn_blocking(move || {
        let facts = crate::info_facts::FfiInfoFacts::new(core);
        crate::info::get_info(&facts, disclosure, rpc_connections)
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

// Restricted-only endpoints (restriction enforced at route registration)

/// `/start_mining`: the one request that still reaches C++ carrying values
/// the option table built (`DAEMON_CONFIG_CUTOVER.md` §2.7, IG-12).
/// `miner_address` goes through the `mine-address` row's constructor and
/// `threads_count` through `mine-threads`'s, so a refusal is the grammar's
/// (IG-11), in the REST envelope with the diagnostic's text; only a request
/// both rows accept is dispatched. The network check on the address stays
/// the miner's, as at startup.
pub async fn start_mining(State(state): State<Arc<AppState>>, body: String) -> impl IntoResponse {
    match validate_start_mining(&body) {
        Ok(()) => dispatch_json(state, "/start_mining", body)
            .await
            .into_response(),
        Err(reason) => json_refused(&reason).into_response(),
    }
}

/// The REST error envelope for a request the table refuses: a bad request,
/// not a dispatch failure.
fn json_refused(reason: &str) -> (StatusCode, [(&'static str, &'static str); 1], String) {
    let envelope = shekyl_rpc_types::RestErrorEnvelope {
        status: shekyl_rpc_types::RpcStatus("ERROR".to_owned()),
        error: reason.to_owned(),
    };
    (
        StatusCode::BAD_REQUEST,
        [("content-type", "application/json")],
        serde_json::to_string(&envelope).expect("plain data serializes"),
    )
}

/// Builds the request's two values through their rows. The C++ request
/// struct reads `miner_address` as a string and `threads_count` as an
/// integer, so each is checked in that form.
fn validate_start_mining(body: &str) -> Result<(), String> {
    use shekyl_daemon_config::TABLE;
    use shekyl_options::Source;
    let request: serde_json::Value = if body.trim().is_empty() {
        serde_json::Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_str(body).map_err(|e| format!("the request is not JSON: {e}"))?
    };
    let address = request
        .get("miner_address")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "`miner_address` is required, as a string".to_owned())?;
    let row = TABLE
        .row("mine-address")
        .expect("the table has mine-address");
    row.kind
        .parse_text(address)
        .map_err(|f| f.at("mine-address", Source::Runtime).render())?;
    let threads = request
        .get("threads_count")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "`threads_count` is required, as a non-negative integer".to_owned())?;
    let row = TABLE
        .row("mine-threads")
        .expect("the table has mine-threads");
    // The C++ reads 0 as "the machine's count", the grammar's `auto`.
    let text = if threads == 0 {
        "auto".to_owned()
    } else {
        threads.to_string()
    };
    row.kind
        .parse_text(&text)
        .map_err(|f| f.at("mine-threads", Source::Runtime).render())?;
    Ok(())
}

#[cfg(test)]
mod start_mining_tests {
    use super::validate_start_mining;

    #[test]
    fn the_two_values_are_built_through_their_rows() {
        assert_eq!(
            validate_start_mining(r#"{"miner_address":"Sabc","threads_count":2}"#),
            Ok(())
        );
        assert_eq!(
            validate_start_mining(r#"{"miner_address":"Sabc","threads_count":0}"#),
            Ok(())
        );
        let e = validate_start_mining(r#"{"miner_address":"","threads_count":2}"#).unwrap_err();
        assert!(e.contains("mine-address"), "{e}");
        let e = validate_start_mining(r#"{"miner_address":"S a","threads_count":2}"#).unwrap_err();
        assert!(e.contains("mine-address"), "{e}");
        let e = validate_start_mining(r#"{"miner_address":"Sabc"}"#).unwrap_err();
        assert!(e.contains("threads_count"), "{e}");
        let e =
            validate_start_mining(r#"{"miner_address":"Sabc","threads_count":-1}"#).unwrap_err();
        assert!(e.contains("threads_count"), "{e}");
        let e = validate_start_mining("not json").unwrap_err();
        assert!(e.contains("not JSON"), "{e}");
    }
}
json_handler!(stop_mining, "/stop_mining");
json_handler!(mining_status, "/mining_status");
json_handler!(save_bc, "/save_bc");
json_handler!(set_log_hash_rate, "/set_log_hash_rate");
json_handler!(stop_daemon, "/stop_daemon");
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
