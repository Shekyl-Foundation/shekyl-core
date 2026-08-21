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
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [("content-type", "application/json")],
        r#"{"status":"ERROR","error":"FFI dispatch failed"}"#.to_string(),
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
json_handler!(get_height, "/get_height");
json_handler!(get_transactions, "/get_transactions");
json_handler!(get_alt_blocks_hashes, "/get_alt_blocks_hashes");
json_handler!(is_key_image_spent, "/is_key_image_spent");
json_handler!(get_transaction_pool, "/get_transaction_pool");
json_handler!(
    get_transaction_pool_hashes_bin,
    "/get_transaction_pool_hashes.bin"
);
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
    use super::fill_rpc_connections_count;

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
json_handler!(get_peer_list, "/get_peer_list");
json_handler!(set_log_hash_rate, "/set_log_hash_rate");
json_handler!(set_log_level, "/set_log_level");
json_handler!(set_log_categories, "/set_log_categories");
json_handler!(stop_daemon, "/stop_daemon");
json_handler!(get_net_stats, "/get_net_stats");
json_handler!(set_limit, "/set_limit");
json_handler!(out_peers, "/out_peers");
json_handler!(in_peers, "/in_peers");
json_handler!(pop_blocks, "/pop_blocks");

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
