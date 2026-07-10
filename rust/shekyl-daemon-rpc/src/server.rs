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

use crate::core::CoreRpc;
use crate::handlers::{binary, json, json_rpc, submit};
use crate::middleware::DEFAULT_BODY_LIMIT;
use crate::submit::{DaemonSubmitEngine, DaemonTxVerifier, FfiSubmitShim, SubmitEngine};

use axum::http::{HeaderValue, Method};
use axum::routing::{get, post};
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
}

pub struct ServerConfig {
    pub bind_address: String,
    pub restricted: bool,
    pub body_limit: usize,
    /// Allow-list from `--rpc-access-control-origins`. Empty = CORS default-deny.
    pub cors_origins: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:21029".into(),
            restricted: false,
            body_limit: DEFAULT_BODY_LIMIT,
            cors_origins: Vec::new(),
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
pub fn build_router(state: Arc<AppState>, cors_origins: &[String]) -> Router {
    let restricted = state.restricted;

    // JSON-RPC 2.0 and unrestricted JSON REST routes
    let mut router = Router::new()
        .route("/json_rpc", post(json_rpc::handle))
        // Unrestricted JSON REST (with aliases) -- GET + POST to match epee behavior
        .route("/get_height", get(json::get_height).post(json::get_height))
        .route("/getheight", get(json::get_height).post(json::get_height))
        .route(
            "/get_transactions",
            get(json::get_transactions).post(json::get_transactions),
        )
        .route(
            "/gettransactions",
            get(json::get_transactions).post(json::get_transactions),
        )
        .route(
            "/get_alt_blocks_hashes",
            get(json::get_alt_blocks_hashes).post(json::get_alt_blocks_hashes),
        )
        .route(
            "/is_key_image_spent",
            get(json::is_key_image_spent).post(json::is_key_image_spent),
        )
        // The typed submit route (DAEMON_SUBMIT_VERDICT.md §2.4) is the
        // only submit surface; the legacy /send_raw_transaction proxy was
        // deleted per §9.3. POST only.
        .route("/submit_transaction", post(submit::submit_transaction))
        .route(
            "/get_public_nodes",
            get(json::get_public_nodes).post(json::get_public_nodes),
        )
        .route(
            "/get_transaction_pool",
            get(json::get_transaction_pool).post(json::get_transaction_pool),
        )
        .route(
            "/get_transaction_pool_hashes.bin",
            get(json::get_transaction_pool_hashes_bin).post(json::get_transaction_pool_hashes_bin),
        )
        .route(
            "/get_transaction_pool_hashes",
            get(json::get_transaction_pool_hashes).post(json::get_transaction_pool_hashes),
        )
        .route(
            "/get_transaction_pool_stats",
            get(json::get_transaction_pool_stats).post(json::get_transaction_pool_stats),
        )
        .route("/get_info", get(json::get_info).post(json::get_info))
        .route("/getinfo", get(json::get_info).post(json::get_info))
        .route("/get_limit", get(json::get_limit).post(json::get_limit));

    // Binary endpoints (always available) — registered from the shared
    // `binary_routes()` table so `binary_uri_paths()` (and the guard test that
    // uses it) stays authoritative and cannot drift from the live router.
    for (path, handler) in binary_routes() {
        router = router.route(path, handler);
    }

    if !restricted {
        router = router
            .route(
                "/start_mining",
                get(json::start_mining).post(json::start_mining),
            )
            .route(
                "/stop_mining",
                get(json::stop_mining).post(json::stop_mining),
            )
            .route(
                "/mining_status",
                get(json::mining_status).post(json::mining_status),
            )
            .route("/save_bc", get(json::save_bc).post(json::save_bc))
            .route(
                "/get_peer_list",
                get(json::get_peer_list).post(json::get_peer_list),
            )
            .route(
                "/set_log_hash_rate",
                get(json::set_log_hash_rate).post(json::set_log_hash_rate),
            )
            .route(
                "/set_log_level",
                get(json::set_log_level).post(json::set_log_level),
            )
            .route(
                "/set_log_categories",
                get(json::set_log_categories).post(json::set_log_categories),
            )
            .route(
                "/set_bootstrap_daemon",
                get(json::set_bootstrap_daemon).post(json::set_bootstrap_daemon),
            )
            .route(
                "/stop_daemon",
                get(json::stop_daemon).post(json::stop_daemon),
            )
            .route(
                "/get_net_stats",
                get(json::get_net_stats).post(json::get_net_stats),
            )
            .route("/set_limit", get(json::set_limit).post(json::set_limit))
            .route("/out_peers", get(json::out_peers).post(json::out_peers))
            .route("/in_peers", get(json::in_peers).post(json::in_peers))
            .route("/update", get(json::update).post(json::update))
            .route("/pop_blocks", get(json::pop_blocks).post(json::pop_blocks));
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
    let state = Arc::new(AppState {
        core,
        submit_engine,
        restricted: config.restricted,
        shutdown: shutdown.clone(),
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

/// Binary (`.bin`) routes as `(path, handler)` pairs. [`build_router`]
/// registers directly from this table and [`binary_uri_paths`] derives its
/// path list from it, so the two cannot drift: adding or removing a real
/// binary route here updates both the router and the guard test at once.
fn binary_routes() -> [(&'static str, axum::routing::MethodRouter<Arc<AppState>>); 7] {
    [
        ("/get_blocks.bin", post(binary::get_blocks)),
        ("/getblocks.bin", post(binary::get_blocks)),
        (
            "/get_blocks_by_height.bin",
            post(binary::get_blocks_by_height),
        ),
        (
            "/getblocks_by_height.bin",
            post(binary::get_blocks_by_height),
        ),
        ("/get_hashes.bin", post(binary::get_hashes)),
        ("/gethashes.bin", post(binary::get_hashes)),
        ("/get_o_indexes.bin", post(binary::get_o_indexes)),
    ]
}

/// Binary URI paths registered by [`build_router`], derived from the same
/// [`binary_routes`] table the router is built from. Lets in-lane tests assert
/// deleted decoy surfaces stay gone without linking the C++ `core_rpc_ffi`
/// symbols (`cargo test -p shekyl-daemon-rpc` has no daemon image).
pub fn binary_uri_paths() -> Vec<&'static str> {
    binary_routes().into_iter().map(|(path, _)| path).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use http::Request;
    use tower::ServiceExt;

    #[test]
    fn output_distribution_bin_not_registered() {
        // Derived from the same `binary_routes()` table `build_router` registers
        // from, so this tracks the live routes rather than a hand-kept copy.
        let paths = binary_uri_paths();
        assert!(
            !paths.contains(&"/get_output_distribution.bin"),
            "decoy distribution binary route must stay deleted"
        );
        assert!(paths.contains(&"/get_blocks.bin"));
        assert!(paths.contains(&"/get_o_indexes.bin"));
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
