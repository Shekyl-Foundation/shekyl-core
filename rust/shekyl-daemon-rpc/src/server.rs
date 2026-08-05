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

/// Build the Axum router. `cors_origins` empty ⇒ default-deny CORS.
/// Paths registered on **both** listeners — JSON and binary alike.
///
/// Handler-free for the same reason as [`UNRESTRICTED_ONLY_JSON_PATHS`], and
/// iterated by [`build_router`] rather than mirroring it. Together the two
/// lists are the complete served surface, which is what lets a test assert
/// that an admin path is absent from the restricted listener rather than
/// merely absent from a copy.
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

/// The handler bound to each always-registered path. Total over
/// [`ALWAYS_REGISTERED_PATHS`].
///
/// # Panics
///
/// If a path is listed with no arm here — loud at daemon start, rather than a
/// route that silently vanishes.
fn always_handler(path: &str) -> MethodRouter<Arc<AppState>> {
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
        other => panic!("ALWAYS_REGISTERED_PATHS lists {other} with no handler"),
    }
}

/// The handler bound to each admin-only path.
///
/// **Total over [`UNRESTRICTED_ONLY_JSON_PATHS`], and deliberately separate
/// from it.** The list says *which listener serves a path* — the privacy fact,
/// and the one a test must be able to read. This says *what runs* — which
/// necessarily names handlers, and naming a handler pulls `core_rpc_ffi_*`
/// into whatever links it. Keeping them apart is what lets
/// `cargo test -p shekyl-daemon-rpc` assert the gate without a daemon image;
/// it is the same constraint that produced the old hand-maintained const, now
/// with the list *driving* registration instead of mirroring it.
///
/// # Panics
///
/// If a path is added to the list with no arm here. That is a loud failure at
/// **daemon start** — `build_router` iterates every listed path, so the first
/// start after the mistake dies with the path named. It is the only residue of
/// the split, and it is deliberately not covered by a unit test: such a test
/// would have to name a handler, and naming one relinks `core_rpc_ffi_*` into
/// the test binary, which is the constraint this whole split exists to satisfy.
/// (`#[ignore]` does not help — it skips execution, not linking.)
fn unrestricted_only_handler(path: &str) -> MethodRouter<Arc<AppState>> {
    match path {
        // §55: the anonymity graph — which peers this node stems to and how
        // each behaved. Sharma Appendix B spends 50-100 probes per node to
        // reconstruct exactly this.
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
        other => panic!("UNRESTRICTED_ONLY_JSON_PATHS lists {other} with no handler"),
    }
}

pub fn build_router(state: Arc<AppState>, cors_origins: &[String]) -> Router {
    let restricted = state.restricted;

    // Both surfaces are iterated from their path lists, so a route cannot be
    // registered without appearing in the list a test can read.
    let mut router = Router::new();
    for path in ALWAYS_REGISTERED_PATHS {
        router = router.route(path, always_handler(path));
    }

    if !restricted {
        // Iterated, not chained: `UNRESTRICTED_ONLY_JSON_PATHS` is the single
        // source of *which* paths are admin-only, so membership in that list
        // IS registration. A route cannot be moved between listeners without
        // moving its string, which is what the gate test asserts on.
        for path in UNRESTRICTED_ONLY_JSON_PATHS {
            router = router.route(path, unrestricted_only_handler(path));
        }
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

/// JSON REST paths that must be registered **only** on the unrestricted
/// (admin) listener — never on the restricted (public) one.
///
/// Handler-free by necessity: naming a handler pulls `core_rpc_ffi_*` into
/// whatever links it, and `cargo test -p shekyl-daemon-rpc` builds no daemon
/// image. Splitting *which listener* (here) from *what runs*
/// ([`unrestricted_only_handler`]) is what lets the gate be asserted at all.
///
/// **This list is no longer a mirror — [`build_router`] iterates it**, so
/// membership *is* registration and the two cannot drift. That is what
/// retires the owed dual-arm *integration* test: the property it was going to
/// establish (restricted ⇒ 404, unrestricted ⇒ not-404) is a property of this
/// list, and a daemon fixture would have tested the server around it.
pub const UNRESTRICTED_ONLY_JSON_PATHS: &[&str] = &[
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use http::Request;
    use tower::ServiceExt;

    #[test]
    fn output_distribution_bin_not_registered() {
        assert!(
            !ALWAYS_REGISTERED_PATHS.contains(&"/get_output_distribution.bin"),
            "decoy distribution binary route must stay deleted"
        );
        assert!(ALWAYS_REGISTERED_PATHS.contains(&"/get_blocks.bin"));
        assert!(ALWAYS_REGISTERED_PATHS.contains(&"/get_o_indexes.bin"));
    }

    /// The dual-arm gate, and **each arm is the other's control**.
    ///
    /// *restricted ⇒ absent* alone passes for a route that never existed, a
    /// typo, or a deleted handler. *unrestricted ⇒ present* proves the path is
    /// spelled right and actually registered, which is what makes the absence
    /// mean **gated** rather than **missing**. Only the pair is
    /// self-witnessing (§50.3: unchanged is the default state of everything
    /// that did not happen).
    ///
    /// This can fire on the defect it exists for — a route moved out of the
    /// gated set — because [`build_router`] *iterates* this list rather than
    /// mirroring it. The check it replaces asserted that a hand-maintained
    /// copy contained a string, which no amount of router editing could
    /// falsify.
    #[test]
    fn stem_tallies_is_served_only_on_the_unrestricted_listener() {
        assert!(
            UNRESTRICTED_ONLY_JSON_PATHS.contains(&"/get_stem_tallies"),
            "unrestricted arm: the anonymity-graph readout must be registered, \
             or the restricted arm proves nothing"
        );
        assert!(
            !ALWAYS_REGISTERED_PATHS.contains(&"/get_stem_tallies"),
            "restricted arm: the anonymity graph must never reach the public \
             listener (§55)"
        );
        assert!(
            ALWAYS_REGISTERED_PATHS.contains(&"/get_info"),
            "control: the always-list is populated, so the absence above is real"
        );
    }

    /// No admin-only path is also registered unconditionally.
    ///
    /// The generalisation of the arm above: a path in both lists would be
    /// served publicly *and* look gated.
    #[test]
    fn no_admin_path_is_also_registered_unconditionally() {
        for path in UNRESTRICTED_ONLY_JSON_PATHS {
            assert!(
                !ALWAYS_REGISTERED_PATHS.contains(path),
                "{path} is admin-only but is also registered unconditionally"
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
