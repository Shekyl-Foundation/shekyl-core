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

//! Axum HTTP server replacing epee's http_server_impl_base for daemon RPC.

use crate::conn_limit::{ConnLimits, ConnTracker, LimitedListener};
use crate::core::CoreRpc;
use crate::handlers::{binary, json, json_rpc, submit};
use crate::middleware::DEFAULT_BODY_LIMIT;
use crate::submit::{DaemonSubmitEngine, DaemonTxVerifier, FfiSubmitShim, SubmitEngine};

use axum::http::{HeaderValue, Method};
use axum::routing::{get, post, MethodRouter};
use axum::Router;
use std::sync::Arc;
use tokio::sync::Notify;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::info;

pub struct AppState {
    pub core: Arc<CoreRpc>,
    /// The Rust admission engine behind `POST /submit_transaction`
    /// (`docs/design/DAEMON_SUBMIT_VERDICT.md` §3).
    pub submit_engine: Arc<DaemonSubmitEngine>,
    pub restricted: bool,
    pub shutdown: Arc<Notify>,
    /// Live connection accounting; shared with the [`LimitedListener`] and read
    /// by `get_info` to report `rpc_connections_count`.
    pub conn_tracker: Arc<ConnTracker>,
}

pub struct ServerConfig {
    pub bind_address: String,
    pub restricted: bool,
    pub body_limit: usize,
    /// Allow-list from `--rpc-access-control-origins`. Empty = CORS default-deny.
    pub cors_origins: Vec<String>,
    /// Concurrent-connection caps enforced by the [`LimitedListener`].
    pub conn_limits: ConnLimits,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:21029".into(),
            restricted: false,
            body_limit: DEFAULT_BODY_LIMIT,
            cors_origins: Vec::new(),
            conn_limits: ConnLimits::default(),
        }
    }
}

fn cors_layer(origins: &[String]) -> CorsLayer {
    // Default-deny: empty allow-list means no ACAO reflection (CorsLayer::new()).
    // When origins are configured, honor them exactly — never `*`.
    if origins.is_empty() {
        return CorsLayer::new();
    }
    let mut allowed: Vec<HeaderValue> = Vec::with_capacity(origins.len());
    for o in origins {
        match HeaderValue::from_str(o) {
            Ok(v) => allowed.push(v),
            // Don't drop a malformed origin silently — a typo/stray space that
            // fails header parsing would otherwise vanish with no diagnostic.
            Err(_) => tracing::warn!(
                origin = %o,
                "ignoring invalid --rpc-access-control-origins entry (not a valid HTTP header value)"
            ),
        }
    }
    if allowed.is_empty() {
        // Every configured origin failed to parse: CORS collapses to deny-all,
        // which looks identical to default-deny. Warn so the operator can tell
        // a broken allow-list from an unset one.
        tracing::warn!(
            "all configured --rpc-access-control-origins were invalid; CORS is \
             default-deny (all cross-origin requests rejected)"
        );
    }
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(tower_http::cors::Any)
}

// ---------------------------------------------------------------------------
// Route table (§55 / §69)
//
// Two handler-free path lists encode *which listener* serves a path. One pure
// function ([`served_paths`]) applies the restricted gate. One total match
// ([`handler_for`]) binds *what runs*. [`build_router`] only iterates
// `served_paths` — so gate tests call the same function the router uses, and
// moving a path between listeners is a list edit, not a handler-table edit.
//
// Handlers stay out of the lists (and out of anything a unit test calls)
// because naming a handler pulls `core_rpc_ffi_*` into the link set; lib tests
// build no daemon image. Residue: a path listed with no `handler_for` arm
// panics at daemon start. Not unit-tested — such a test must name a handler.
// ---------------------------------------------------------------------------

/// Paths registered on **both** listeners — JSON and binary alike.
///
/// Handler-free so tests can read it without linking `core_rpc_ffi_*`.
/// Combined with [`UNRESTRICTED_ONLY_JSON_PATHS`] via [`served_paths`];
/// [`build_router`] iterates that, not this list alone.
pub const ALWAYS_REGISTERED_PATHS: &[&str] = &[
    "/json_rpc",
    // JSON REST (with aliases) -- GET + POST to match epee behaviour
    "/get_height",
    "/getheight",
    "/get_transactions",
    "/gettransactions",
    "/get_alt_blocks_hashes",
    "/is_key_image_spent",
    // The typed submit route (DAEMON_SUBMIT_VERDICT.md §2.4) is the only
    // submit surface; the legacy /send_raw_transaction proxy was deleted
    // per §9.3. POST only.
    "/submit_transaction",
    "/get_public_nodes",
    "/get_transaction_pool",
    "/get_transaction_pool_hashes.bin",
    "/get_transaction_pool_hashes",
    "/get_transaction_pool_stats",
    "/get_info",
    "/getinfo",
    "/get_limit",
    // Binary endpoints.
    "/get_blocks.bin",
    "/getblocks.bin",
    "/get_blocks_by_height.bin",
    "/getblocks_by_height.bin",
    "/get_hashes.bin",
    "/gethashes.bin",
    "/get_o_indexes.bin",
];

/// JSON REST paths registered **only** on the unrestricted (admin) listener —
/// never on the restricted (public) one.
///
/// Handler-free by necessity: naming a handler pulls `core_rpc_ffi_*` into
/// whatever links it, and `cargo test -p shekyl-daemon-rpc` builds no daemon
/// image. [`served_paths`] is the single place the `restricted` gate is
/// applied; tests call it, [`build_router`] iterates it.
pub const UNRESTRICTED_ONLY_JSON_PATHS: &[&str] = &[
    // §55: anonymity graph — peer set is the sensitive part.
    "/get_stem_tallies",
    "/start_mining",
    "/stop_mining",
    "/mining_status",
    "/save_bc",
    "/get_peer_list",
    "/set_log_hash_rate",
    "/set_log_level",
    "/set_log_categories",
    "/set_bootstrap_daemon",
    "/stop_daemon",
    "/get_net_stats",
    "/set_limit",
    "/out_peers",
    "/in_peers",
    "/pop_blocks",
];

/// Paths this listener serves.
///
/// **Single source of the restricted gate.** [`build_router`] iterates this;
/// gate tests call this. Do not re-encode the gate as set algebra over the
/// two consts — deleting the gate here must fail the tests that call here.
pub fn served_paths(restricted: bool) -> impl Iterator<Item = &'static str> {
    let admin: &[&str] = if restricted {
        &[]
    } else {
        UNRESTRICTED_ONLY_JSON_PATHS
    };
    ALWAYS_REGISTERED_PATHS
        .iter()
        .copied()
        .chain(admin.iter().copied())
}

/// Handler bound to a served path. Total over the union of
/// [`ALWAYS_REGISTERED_PATHS`] and [`UNRESTRICTED_ONLY_JSON_PATHS`].
///
/// One match for both listeners: moving a path between lists is a list edit
/// only. Deliberately not called from unit tests — naming a handler pulls
/// `core_rpc_ffi_*` into the test binary (`#[ignore]` skips execution, not
/// linking).
///
/// # Panics
///
/// If a path is listed with no arm — loud at daemon start rather than a route
/// that silently vanishes.
fn handler_for(path: &str) -> MethodRouter<Arc<AppState>> {
    match path {
        "/json_rpc" => post(json_rpc::handle),
        "/get_height" | "/getheight" => get(json::get_height).post(json::get_height),
        "/get_transactions" | "/gettransactions" => {
            get(json::get_transactions).post(json::get_transactions)
        }
        "/get_alt_blocks_hashes" => {
            get(json::get_alt_blocks_hashes).post(json::get_alt_blocks_hashes)
        }
        "/is_key_image_spent" => get(json::is_key_image_spent).post(json::is_key_image_spent),
        "/submit_transaction" => post(submit::submit_transaction),
        "/get_public_nodes" => get(json::get_public_nodes).post(json::get_public_nodes),
        "/get_transaction_pool" => get(json::get_transaction_pool).post(json::get_transaction_pool),
        "/get_transaction_pool_hashes.bin" => {
            get(json::get_transaction_pool_hashes_bin).post(json::get_transaction_pool_hashes_bin)
        }
        "/get_transaction_pool_hashes" => {
            get(json::get_transaction_pool_hashes).post(json::get_transaction_pool_hashes)
        }
        "/get_transaction_pool_stats" => {
            get(json::get_transaction_pool_stats).post(json::get_transaction_pool_stats)
        }
        "/get_info" | "/getinfo" => get(json::get_info).post(json::get_info),
        "/get_limit" => get(json::get_limit).post(json::get_limit),
        "/get_blocks.bin" | "/getblocks.bin" => post(binary::get_blocks),
        "/get_blocks_by_height.bin" | "/getblocks_by_height.bin" => {
            post(binary::get_blocks_by_height)
        }
        "/get_hashes.bin" | "/gethashes.bin" => post(binary::get_hashes),
        "/get_o_indexes.bin" => post(binary::get_o_indexes),
        // Admin-only (listener selection is [`served_paths`], not this match).
        // §55: anonymity graph — peer set is the sensitive part.
        "/get_stem_tallies" => get(json::get_stem_tallies).post(json::get_stem_tallies),
        "/start_mining" => get(json::start_mining).post(json::start_mining),
        "/stop_mining" => get(json::stop_mining).post(json::stop_mining),
        "/mining_status" => get(json::mining_status).post(json::mining_status),
        "/save_bc" => get(json::save_bc).post(json::save_bc),
        "/get_peer_list" => get(json::get_peer_list).post(json::get_peer_list),
        "/set_log_hash_rate" => get(json::set_log_hash_rate).post(json::set_log_hash_rate),
        "/set_log_level" => get(json::set_log_level).post(json::set_log_level),
        "/set_log_categories" => get(json::set_log_categories).post(json::set_log_categories),
        "/set_bootstrap_daemon" => get(json::set_bootstrap_daemon).post(json::set_bootstrap_daemon),
        "/stop_daemon" => get(json::stop_daemon).post(json::stop_daemon),
        "/get_net_stats" => get(json::get_net_stats).post(json::get_net_stats),
        "/set_limit" => get(json::set_limit).post(json::set_limit),
        "/out_peers" => get(json::out_peers).post(json::out_peers),
        "/in_peers" => get(json::in_peers).post(json::in_peers),
        "/pop_blocks" => get(json::pop_blocks).post(json::pop_blocks),
        other => panic!("served path {other} has no handler"),
    }
}

/// Build the Axum router. `cors_origins` empty ⇒ default-deny CORS.
///
/// Routes come only from [`served_paths`]; handlers only from [`handler_for`].
pub fn build_router(state: Arc<AppState>, cors_origins: &[String]) -> Router {
    let mut router = Router::new();
    for path in served_paths(state.restricted) {
        router = router.route(path, handler_for(path));
    }

    router
        .layer(RequestBodyLimitLayer::new(state.body_limit()))
        .layer(cors_layer(cors_origins))
        .with_state(state)
}

impl AppState {
    fn body_limit(&self) -> usize {
        DEFAULT_BODY_LIMIT
    }
}

/// Bind the daemon RPC TCP listener.
///
/// Separated from serving so a caller (the FFI start path) can validate the
/// bind synchronously and fail loudly — surfacing EADDRINUSE before any handle
/// is handed back — rather than discovering the failure asynchronously inside a
/// spawned serve task.
pub async fn bind_listener(bind_address: &str) -> std::io::Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(bind_address).await
}

/// Serve the daemon RPC on an already-bound listener. Blocks until the shutdown
/// signal fires.
pub async fn serve_with_listener(
    core: Arc<CoreRpc>,
    config: ServerConfig,
    listener: tokio::net::TcpListener,
    shutdown: Arc<Notify>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let submit_engine = Arc::new(SubmitEngine::new(
        FfiSubmitShim::new(core.clone()),
        DaemonTxVerifier,
    ));
    // One tracker per listener, shared between admission (the LimitedListener)
    // and reporting (`get_info`'s rpc_connections_count).
    let conn_tracker = ConnTracker::new(config.conn_limits);
    let state = Arc::new(AppState {
        core,
        submit_engine,
        restricted: config.restricted,
        shutdown: shutdown.clone(),
        conn_tracker: conn_tracker.clone(),
    });

    let app = build_router(state, &config.cors_origins);
    info!(
        "shekyl-daemon-rpc ({}) listening on {}",
        if config.restricted {
            "restricted"
        } else {
            "unrestricted"
        },
        config.bind_address
    );
    // Surface the CORS posture at startup. Default-deny is intentional (a
    // browser cannot reach an unconfigured daemon cross-origin), but it changed
    // from the old permissive reflection, so make it observable rather than a
    // silent "my web UI stopped working after upgrade".
    if config.cors_origins.is_empty() {
        info!(
            "RPC CORS: default-deny (no --rpc-access-control-origins set; browser \
             clients cannot make cross-origin requests to this daemon)"
        );
    } else {
        info!(
            "RPC CORS: allow-list of {} configured origin(s)",
            config.cors_origins.len()
        );
    }

    if config.conn_limits != ConnLimits::default() {
        info!(
            "RPC connection caps: total={}, per-public-ip={}, per-private-ip={} (0 = unlimited)",
            config.conn_limits.max_total,
            config.conn_limits.max_per_public_ip,
            config.conn_limits.max_per_private_ip
        );
    }

    // Wrap the bound listener so every accepted connection is admitted through
    // (and accounted in) the shared tracker. The graceful-shutdown path is
    // unchanged — only the listener is adapted.
    let listener = LimitedListener::new(listener, conn_tracker);
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.notified().await })
        .await?;

    Ok(())
}

/// Start the Axum daemon RPC server (bind + serve). Blocks until the shutdown
/// signal fires.
pub async fn run_server(
    core: Arc<CoreRpc>,
    config: ServerConfig,
    shutdown: Arc<Notify>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = bind_listener(&config.bind_address).await?;
    serve_with_listener(core, config, listener, shutdown).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use http::Request;
    use tower::ServiceExt;

    /// Deleted decoy surface must not reappear on *either* listener.
    ///
    /// Assert against [`served_paths`] (the full served surface), not only
    /// `ALWAYS_REGISTERED_PATHS` — absence from the always-list alone would
    /// still pass if the route landed on the admin list.
    #[test]
    fn output_distribution_bin_not_registered() {
        assert!(
            served_paths(false).all(|p| p != "/get_output_distribution.bin"),
            "decoy distribution binary route must stay deleted on every listener"
        );
        assert!(
            served_paths(true).any(|p| p == "/get_blocks.bin"),
            "control: live binary surface still served on the restricted listener"
        );
        assert!(
            served_paths(true).any(|p| p == "/get_o_indexes.bin"),
            "control: live binary surface still served on the restricted listener"
        );
    }

    /// Dual-arm gate via the same function [`build_router`] iterates.
    ///
    /// *restricted ⇒ absent* alone passes for a route that never existed.
    /// *unrestricted ⇒ present* proves the path is spelled right and selected,
    /// which is what makes the absence mean **gated** rather than **missing**.
    /// Both arms call [`served_paths`] — re-encoding the gate as set algebra
    /// over the consts would miss a deleted `if !restricted` inside that
    /// function.
    #[test]
    fn stem_tallies_is_gated_by_restricted() {
        assert!(
            served_paths(false).any(|p| p == "/get_stem_tallies"),
            "unrestricted arm: the anonymity-graph readout must be selected, \
             or the restricted arm proves nothing"
        );
        assert!(
            served_paths(true).all(|p| p != "/get_stem_tallies"),
            "restricted arm: the anonymity graph must never reach the public \
             listener (§55)"
        );
        assert!(
            served_paths(true).any(|p| p == "/get_info"),
            "control: the restricted surface is non-empty, so the absence above is real"
        );
    }

    /// Every admin-only path is selected only when unrestricted.
    ///
    /// Generalisation of the stem-tallies arms: also catches a path listed in
    /// both consts (would be served publicly *and* look gated).
    #[test]
    fn admin_paths_are_absent_from_the_restricted_listener() {
        for path in UNRESTRICTED_ONLY_JSON_PATHS {
            assert!(
                served_paths(false).any(|p| p == *path),
                "{path} is listed admin-only but is not selected when unrestricted"
            );
            assert!(
                served_paths(true).all(|p| p != *path),
                "{path} is admin-only but is selected on the restricted listener"
            );
            assert!(
                !ALWAYS_REGISTERED_PATHS.contains(path),
                "{path} is admin-only but is also in ALWAYS_REGISTERED_PATHS"
            );
        }
    }

    #[tokio::test]
    async fn cors_default_deny_omits_allow_origin() {
        // Exercise `cors_layer` without `AppState` / C++ FFI (lib tests cannot
        // link `core_rpc_ffi_*`).
        let app = Router::new()
            .route("/get_info", get(|| async { "ok" }))
            .layer(cors_layer(&[]));
        let res = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/get_info")
                    .header("Origin", "https://evil.example")
                    .header("Access-Control-Request-Method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(res.headers().get("access-control-allow-origin").is_none());
    }

    #[tokio::test]
    async fn cors_allow_list_honors_configured_origin() {
        let origins = vec!["https://wallet.example".to_string()];
        let app = Router::new()
            .route("/get_info", get(|| async { "ok" }))
            .layer(cors_layer(&origins));
        let res = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/get_info")
                    .header("Origin", "https://wallet.example")
                    .header("Access-Control-Request-Method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("https://wallet.example")
        );
    }

    /// Optional live-daemon smoke (Axum-only shekyld). Not run in CI by default.
    #[tokio::test]
    #[ignore = "requires a running Axum-only shekyld; optional e2e smoke"]
    async fn e2e_axum_only_get_info_smoke() {
        // Operators: point a client at a local shekyld RPC and exercise
        // /get_info + /getblocks.bin. In-lane coverage is the oneshot/CORS
        // tests above plus RpcArgsDaemonSurface.
    }
}
