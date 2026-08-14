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
// Route table (§55 / §69 / §70)
//
// ONE table. Each row names an endpoint, the path(s) it answers on, and which
// listener serves it. [`served_paths`] applies the restricted gate; a total
// match ([`handler_for`]) binds what runs; [`assemble`] registers the first
// with the second, and [`build_router`] is `assemble` plus layers — so the
// gate tests build the shipping router with a dummy handler and assert
// selection by *serving requests*, not by re-reading a const.
//
// Two properties are structural rather than tested, because the table is keyed
// by an enum:
//
//   * A route with no handler does not compile. `handler_for` matches
//     [`Endpoint`] exhaustively with no wildcard, so adding a row without
//     binding it is a compile error, not a `panic!` at daemon start (§70.1).
//   * A path cannot be admin-only *and* public. Visibility is a field of the
//     row, not membership in one of two lists that could both contain it.
//
// Handlers stay out of the table (and out of anything a unit test calls)
// because naming a handler pulls `core_rpc_ffi_*` into the link set; lib tests
// build no daemon image. `assemble`'s generic handler parameter is what keeps
// that true while still letting a test route the real table.
//
// The tests assert against a specification written out separately (§70): an
// oracle that iterates this table cannot fail when the table changes.
// ---------------------------------------------------------------------------

/// Which listener serves a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Visibility {
    /// Both listeners — the wallet-facing and sync surface.
    Always,
    /// The unrestricted (admin) listener only; never the restricted (public)
    /// one. §55: `/get_stem_tallies` is the anonymity graph, the rest are node
    /// administration.
    AdminOnly,
}

/// An endpoint the daemon RPC serves.
///
/// The key that makes route-to-handler totality a compile-time property.
/// Deliberately *not* the path string: aliases (`/get_height` //
/// `/getheight`) are one endpoint answering on two paths, and keeping them
/// one variant is what stops an alias pair from drifting apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Endpoint {
    JsonRpc,
    GetHeight,
    GetTransactions,
    GetAltBlocksHashes,
    IsKeyImageSpent,
    SubmitTransaction,
    GetPublicNodes,
    GetTransactionPool,
    GetTransactionPoolHashesBin,
    GetTransactionPoolHashes,
    GetTransactionPoolStats,
    GetInfo,
    GetLimit,
    GetBlocksBin,
    GetBlocksByHeightBin,
    GetHashesBin,
    GetOIndexesBin,
    GetStemTallies,
    StartMining,
    StopMining,
    MiningStatus,
    SaveBc,
    GetPeerList,
    SetLogHashRate,
    SetLogLevel,
    SetLogCategories,
    SetBootstrapDaemon,
    StopDaemon,
    GetNetStats,
    SetLimit,
    OutPeers,
    InPeers,
    PopBlocks,
}

/// One row of the route table.
pub(crate) struct Route {
    pub(crate) endpoint: Endpoint,
    /// Paths this endpoint answers on. More than one = epee-compatibility
    /// aliases, which share a handler by construction.
    pub(crate) paths: &'static [&'static str],
    pub(crate) visibility: Visibility,
}

/// The daemon RPC route table — the single source of *what is served where*.
///
/// Handler-free so tests can read it without linking `core_rpc_ffi_*`.
/// [`served_paths`] applies the gate; [`build_router`] registers the result.
pub(crate) const ROUTES: &[Route] = &[
    Route {
        endpoint: Endpoint::JsonRpc,
        paths: &["/json_rpc"],
        visibility: Visibility::Always,
    },
    // JSON REST (with aliases) -- GET + POST to match epee behaviour.
    Route {
        endpoint: Endpoint::GetHeight,
        paths: &["/get_height", "/getheight"],
        visibility: Visibility::Always,
    },
    Route {
        endpoint: Endpoint::GetTransactions,
        paths: &["/get_transactions", "/gettransactions"],
        visibility: Visibility::Always,
    },
    Route {
        endpoint: Endpoint::GetAltBlocksHashes,
        paths: &["/get_alt_blocks_hashes"],
        visibility: Visibility::Always,
    },
    Route {
        endpoint: Endpoint::IsKeyImageSpent,
        paths: &["/is_key_image_spent"],
        visibility: Visibility::Always,
    },
    // The typed submit route (DAEMON_SUBMIT_VERDICT.md §2.4) is the only
    // submit surface; the legacy /send_raw_transaction proxy was deleted
    // per §9.3. POST only.
    Route {
        endpoint: Endpoint::SubmitTransaction,
        paths: &["/submit_transaction"],
        visibility: Visibility::Always,
    },
    Route {
        endpoint: Endpoint::GetPublicNodes,
        paths: &["/get_public_nodes"],
        visibility: Visibility::Always,
    },
    Route {
        endpoint: Endpoint::GetTransactionPool,
        paths: &["/get_transaction_pool"],
        visibility: Visibility::Always,
    },
    Route {
        endpoint: Endpoint::GetTransactionPoolHashesBin,
        paths: &["/get_transaction_pool_hashes.bin"],
        visibility: Visibility::Always,
    },
    Route {
        endpoint: Endpoint::GetTransactionPoolHashes,
        paths: &["/get_transaction_pool_hashes"],
        visibility: Visibility::Always,
    },
    Route {
        endpoint: Endpoint::GetTransactionPoolStats,
        paths: &["/get_transaction_pool_stats"],
        visibility: Visibility::Always,
    },
    Route {
        endpoint: Endpoint::GetInfo,
        paths: &["/get_info", "/getinfo"],
        visibility: Visibility::Always,
    },
    Route {
        endpoint: Endpoint::GetLimit,
        paths: &["/get_limit"],
        visibility: Visibility::Always,
    },
    // Binary endpoints.
    Route {
        endpoint: Endpoint::GetBlocksBin,
        paths: &["/get_blocks.bin", "/getblocks.bin"],
        visibility: Visibility::Always,
    },
    Route {
        endpoint: Endpoint::GetBlocksByHeightBin,
        paths: &["/get_blocks_by_height.bin", "/getblocks_by_height.bin"],
        visibility: Visibility::Always,
    },
    Route {
        endpoint: Endpoint::GetHashesBin,
        paths: &["/get_hashes.bin", "/gethashes.bin"],
        visibility: Visibility::Always,
    },
    Route {
        endpoint: Endpoint::GetOIndexesBin,
        paths: &["/get_o_indexes.bin"],
        visibility: Visibility::Always,
    },
    // §55: anonymity graph — the peer set is the sensitive part.
    Route {
        endpoint: Endpoint::GetStemTallies,
        paths: &["/get_stem_tallies"],
        visibility: Visibility::AdminOnly,
    },
    Route {
        endpoint: Endpoint::StartMining,
        paths: &["/start_mining"],
        visibility: Visibility::AdminOnly,
    },
    Route {
        endpoint: Endpoint::StopMining,
        paths: &["/stop_mining"],
        visibility: Visibility::AdminOnly,
    },
    Route {
        endpoint: Endpoint::MiningStatus,
        paths: &["/mining_status"],
        visibility: Visibility::AdminOnly,
    },
    Route {
        endpoint: Endpoint::SaveBc,
        paths: &["/save_bc"],
        visibility: Visibility::AdminOnly,
    },
    Route {
        endpoint: Endpoint::GetPeerList,
        paths: &["/get_peer_list"],
        visibility: Visibility::AdminOnly,
    },
    Route {
        endpoint: Endpoint::SetLogHashRate,
        paths: &["/set_log_hash_rate"],
        visibility: Visibility::AdminOnly,
    },
    Route {
        endpoint: Endpoint::SetLogLevel,
        paths: &["/set_log_level"],
        visibility: Visibility::AdminOnly,
    },
    Route {
        endpoint: Endpoint::SetLogCategories,
        paths: &["/set_log_categories"],
        visibility: Visibility::AdminOnly,
    },
    Route {
        endpoint: Endpoint::SetBootstrapDaemon,
        paths: &["/set_bootstrap_daemon"],
        visibility: Visibility::AdminOnly,
    },
    Route {
        endpoint: Endpoint::StopDaemon,
        paths: &["/stop_daemon"],
        visibility: Visibility::AdminOnly,
    },
    Route {
        endpoint: Endpoint::GetNetStats,
        paths: &["/get_net_stats"],
        visibility: Visibility::AdminOnly,
    },
    Route {
        endpoint: Endpoint::SetLimit,
        paths: &["/set_limit"],
        visibility: Visibility::AdminOnly,
    },
    Route {
        endpoint: Endpoint::OutPeers,
        paths: &["/out_peers"],
        visibility: Visibility::AdminOnly,
    },
    Route {
        endpoint: Endpoint::InPeers,
        paths: &["/in_peers"],
        visibility: Visibility::AdminOnly,
    },
    Route {
        endpoint: Endpoint::PopBlocks,
        paths: &["/pop_blocks"],
        visibility: Visibility::AdminOnly,
    },
];

/// Rows this listener serves.
///
/// **Single source of the restricted gate.** [`build_router`] registers what
/// this yields; the gate tests read it. Do not re-encode the gate as a filter
/// at a call site — deleting the gate here must fail the tests that call here.
pub(crate) fn served_routes(restricted: bool) -> impl Iterator<Item = &'static Route> {
    ROUTES
        .iter()
        .filter(move |route| !(restricted && route.visibility == Visibility::AdminOnly))
}

/// Paths this listener serves — [`served_routes`] flattened over aliases.
///
/// Test-only *view*, not a second gate: it delegates to [`served_routes`], so
/// deleting the `restricted` check there still fails every assertion written
/// against this. The router registers rows (it needs the [`Endpoint`] to bind
/// a handler); the specification is written in paths, because paths are what a
/// remote caller can reach.
#[cfg(test)]
pub(crate) fn served_paths(restricted: bool) -> impl Iterator<Item = &'static str> {
    served_routes(restricted).flat_map(|route| route.paths.iter().copied())
}

/// Handler bound to an endpoint.
///
/// **Total by construction**: the match is exhaustive over [`Endpoint`] with
/// no wildcard arm, so a route added to [`ROUTES`] without a handler fails to
/// compile. It used to key on `&str` and fall through to `panic!`, which made
/// the same mistake a startup abort — green CI, then a daemon that does not
/// come up (§70.1).
///
/// Deliberately not called from unit tests — naming a handler pulls
/// `core_rpc_ffi_*` into the test binary (`#[ignore]` skips execution, not
/// linking), which is why [`assemble`] takes the binding as a parameter.
fn handler_for(endpoint: Endpoint) -> MethodRouter<Arc<AppState>> {
    match endpoint {
        Endpoint::JsonRpc => post(json_rpc::handle),
        Endpoint::GetHeight => get(json::get_height).post(json::get_height),
        Endpoint::GetTransactions => get(json::get_transactions).post(json::get_transactions),
        Endpoint::GetAltBlocksHashes => {
            get(json::get_alt_blocks_hashes).post(json::get_alt_blocks_hashes)
        }
        Endpoint::IsKeyImageSpent => get(json::is_key_image_spent).post(json::is_key_image_spent),
        Endpoint::SubmitTransaction => post(submit::submit_transaction),
        Endpoint::GetPublicNodes => get(json::get_public_nodes).post(json::get_public_nodes),
        Endpoint::GetTransactionPool => {
            get(json::get_transaction_pool).post(json::get_transaction_pool)
        }
        Endpoint::GetTransactionPoolHashesBin => {
            get(json::get_transaction_pool_hashes_bin).post(json::get_transaction_pool_hashes_bin)
        }
        Endpoint::GetTransactionPoolHashes => {
            get(json::get_transaction_pool_hashes).post(json::get_transaction_pool_hashes)
        }
        Endpoint::GetTransactionPoolStats => {
            get(json::get_transaction_pool_stats).post(json::get_transaction_pool_stats)
        }
        Endpoint::GetInfo => get(json::get_info).post(json::get_info),
        Endpoint::GetLimit => get(json::get_limit).post(json::get_limit),
        Endpoint::GetBlocksBin => post(binary::get_blocks),
        Endpoint::GetBlocksByHeightBin => post(binary::get_blocks_by_height),
        Endpoint::GetHashesBin => post(binary::get_hashes),
        Endpoint::GetOIndexesBin => post(binary::get_o_indexes),
        // Admin-only (listener selection is the row's `visibility`, not this
        // match). §55: anonymity graph — the peer set is the sensitive part.
        Endpoint::GetStemTallies => get(json::get_stem_tallies).post(json::get_stem_tallies),
        Endpoint::StartMining => get(json::start_mining).post(json::start_mining),
        Endpoint::StopMining => get(json::stop_mining).post(json::stop_mining),
        Endpoint::MiningStatus => get(json::mining_status).post(json::mining_status),
        Endpoint::SaveBc => get(json::save_bc).post(json::save_bc),
        Endpoint::GetPeerList => get(json::get_peer_list).post(json::get_peer_list),
        Endpoint::SetLogHashRate => get(json::set_log_hash_rate).post(json::set_log_hash_rate),
        Endpoint::SetLogLevel => get(json::set_log_level).post(json::set_log_level),
        Endpoint::SetLogCategories => get(json::set_log_categories).post(json::set_log_categories),
        Endpoint::SetBootstrapDaemon => {
            get(json::set_bootstrap_daemon).post(json::set_bootstrap_daemon)
        }
        Endpoint::StopDaemon => get(json::stop_daemon).post(json::stop_daemon),
        Endpoint::GetNetStats => get(json::get_net_stats).post(json::get_net_stats),
        Endpoint::SetLimit => get(json::set_limit).post(json::set_limit),
        Endpoint::OutPeers => get(json::out_peers).post(json::out_peers),
        Endpoint::InPeers => get(json::in_peers).post(json::in_peers),
        Endpoint::PopBlocks => get(json::pop_blocks).post(json::pop_blocks),
    }
}

/// The routed-but-unlayered router for one listener.
///
/// Generic over the handler binding **so tests can build the real router**.
/// [`build_router`] passes [`handler_for`]; the gate tests pass a dummy
/// handler, which keeps `core_rpc_ffi_*` out of the test link set while still
/// exercising the thing that ships: `Router::route` over [`served_paths`].
/// Route selection is then asserted by *serving requests* rather than by
/// re-reading a const — and axum's duplicate-path panic fires here as a test
/// failure instead of at daemon start.
fn assemble<S, F>(restricted: bool, handler: F) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    F: Fn(Endpoint) -> MethodRouter<S>,
{
    let mut router = Router::new();
    for route in served_routes(restricted) {
        for path in route.paths {
            router = router.route(path, handler(route.endpoint));
        }
    }
    router
}

/// Build the Axum router. `cors_origins` empty ⇒ default-deny CORS.
///
/// Routes come only from [`served_paths`] (via [`assemble`]); handlers only
/// from [`handler_for`].
///
/// **Residue, deliberately named:** `state.restricted` is the one expression
/// no lib test reaches — building an [`AppState`] needs a [`CoreRpc`], which
/// links the FFI. Everything downstream of that boolean is covered by
/// [`assemble`]'s tests; the boolean itself is covered only by review.
pub fn build_router(state: Arc<AppState>, cors_origins: &[String]) -> Router {
    assemble(state.restricted, handler_for)
        .layer(RequestBodyLimitLayer::new(DEFAULT_BODY_LIMIT))
        .layer(cors_layer(cors_origins))
        .with_state(state)
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
    use http::{Request, StatusCode};
    use std::collections::BTreeSet;
    use tower::ServiceExt;

    // -----------------------------------------------------------------------
    // The specification, restated independently of the code that builds it.
    //
    // **The duplication below is deliberate and must not be "de-duplicated".**
    // An oracle derived from `ROUTES` re-states whatever that table happens to
    // say, so it cannot fail when the table changes — which is precisely how
    // the const-membership check §69 deleted managed to pass under the edit it
    // existed to catch, and how a loop over the admin rows still misses a path
    // *moved out* of them. These two arrays are the contract: which paths the
    // daemon serves, and which of them never reach the public listener.
    // Changing the route table must therefore change this table too, in a diff
    // a reviewer reads and a maintainer must justify.
    // -----------------------------------------------------------------------

    /// Paths that must be served on **both** listeners.
    const SPECIFIED_ALWAYS_PATHS: &[&str] = &[
        "/json_rpc",
        "/get_height",
        "/getheight",
        "/get_transactions",
        "/gettransactions",
        "/get_alt_blocks_hashes",
        "/is_key_image_spent",
        "/submit_transaction",
        "/get_public_nodes",
        "/get_transaction_pool",
        "/get_transaction_pool_hashes.bin",
        "/get_transaction_pool_hashes",
        "/get_transaction_pool_stats",
        "/get_info",
        "/getinfo",
        "/get_limit",
        "/get_blocks.bin",
        "/getblocks.bin",
        "/get_blocks_by_height.bin",
        "/getblocks_by_height.bin",
        "/get_hashes.bin",
        "/gethashes.bin",
        "/get_o_indexes.bin",
    ];

    /// Paths that must **never** be served on the restricted (public)
    /// listener. §55: `/get_stem_tallies` is the anonymity graph; the rest are
    /// node administration (mine, ban, shut down, roll back).
    const SPECIFIED_ADMIN_ONLY_PATHS: &[&str] = &[
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

    /// The served surface equals the specification, path for path.
    ///
    /// One assertion covers four drift directions the per-path arms cannot:
    /// a path **dropped** from a list (registered nowhere, 404 at runtime with
    /// a clean startup log), a path **added** without review, a path
    /// **migrated** between listeners, and a **duplicate** — which axum turns
    /// into a panic before the daemon binds.
    #[test]
    fn route_table_matches_the_specification() {
        let served: Vec<&str> = served_paths(false).collect();
        let unique: BTreeSet<&str> = served.iter().copied().collect();
        assert_eq!(
            unique.len(),
            served.len(),
            "duplicate path in the route table: axum panics on a repeated \
             route, so this aborts the daemon at startup"
        );

        let specified: BTreeSet<&str> = SPECIFIED_ALWAYS_PATHS
            .iter()
            .chain(SPECIFIED_ADMIN_ONLY_PATHS)
            .copied()
            .collect();
        assert_eq!(
            unique, specified,
            "served surface diverged from the specification above; if the \
             change is intended, change the specification in the same commit"
        );

        let public: BTreeSet<&str> = served_paths(true).collect();
        let specified_public: BTreeSet<&str> = SPECIFIED_ALWAYS_PATHS.iter().copied().collect();
        assert_eq!(
            public, specified_public,
            "restricted (public) listener diverged from the specification"
        );
    }

    /// Deleted decoy surface must not reappear on *either* listener.
    ///
    /// Assert against [`served_paths`] (the full served surface), not only the
    /// `Visibility::Always` rows — absence from those alone would still pass
    /// if the route landed on an admin row.
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
    /// Driven by [`SPECIFIED_ADMIN_ONLY_PATHS`], **not** by the
    /// `Visibility::AdminOnly` rows of [`ROUTES`]: a loop over the production
    /// table stops visiting a path the moment that row's visibility flips, so
    /// it would stay silent through exactly the edit that exposes
    /// `/stop_daemon` to unauthenticated remote callers.
    #[test]
    fn admin_paths_are_absent_from_the_restricted_listener() {
        for path in SPECIFIED_ADMIN_ONLY_PATHS {
            assert!(
                served_paths(false).any(|p| p == *path),
                "{path} is specified admin-only but is not selected when unrestricted"
            );
            assert!(
                served_paths(true).all(|p| p != *path),
                "{path} is admin-only but is selected on the restricted listener"
            );
        }
    }

    /// A router with the real route table and dummy handlers.
    ///
    /// This is [`build_router`]'s own assembly — the same [`assemble`] call
    /// over the same [`served_paths`] — with only the handler binding swapped,
    /// because naming a real handler pulls `core_rpc_ffi_*` into the test link
    /// set. Both methods are bound so an unrouted path answers 404 rather than
    /// 405; a 405 read as "absent" would be a vacuous pass.
    fn probe_router(restricted: bool) -> Router {
        assemble(restricted, |_| {
            get(|| async { "ok" }).post(|| async { "ok" })
        })
    }

    async fn probe(restricted: bool, path: &str) -> StatusCode {
        probe_router(restricted)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    /// The gate, asserted on the router that ships rather than on the list it
    /// is built from.
    ///
    /// [`served_paths`] returning the right strings is necessary but not
    /// sufficient: this exercises `Router::route` over those strings, so a
    /// registration that silently fails to bind is caught too. Dual-armed —
    /// the unrestricted 200 is what makes the restricted 404 mean **gated**
    /// rather than **misspelled**.
    #[tokio::test]
    async fn assembled_router_gates_the_anonymity_graph() {
        assert_eq!(
            probe(false, "/get_stem_tallies").await,
            StatusCode::OK,
            "unrestricted arm: the anonymity-graph readout must be routed, \
             or the restricted arm proves nothing"
        );
        assert_eq!(
            probe(true, "/get_stem_tallies").await,
            StatusCode::NOT_FOUND,
            "restricted arm: the anonymity graph must never reach the public \
             listener (§55)"
        );
        // Control: the restricted router is a real, populated router.
        assert_eq!(probe(true, "/get_info").await, StatusCode::OK);
        assert_eq!(probe(false, "/get_info").await, StatusCode::OK);
    }

    /// Every specified path is reachable on the listener that owns it, and
    /// every admin path 404s on the public one — checked by serving requests.
    #[tokio::test]
    async fn assembled_router_serves_exactly_the_specified_surface() {
        for path in SPECIFIED_ALWAYS_PATHS {
            assert_eq!(
                probe(true, path).await,
                StatusCode::OK,
                "{path} is specified for both listeners but is not routed on \
                 the restricted one"
            );
            assert_eq!(probe(false, path).await, StatusCode::OK, "{path}");
        }
        for path in SPECIFIED_ADMIN_ONLY_PATHS {
            assert_eq!(
                probe(false, path).await,
                StatusCode::OK,
                "{path} is specified admin-only but is not routed on the \
                 unrestricted listener"
            );
            assert_eq!(
                probe(true, path).await,
                StatusCode::NOT_FOUND,
                "{path} is admin-only but the public listener routes it"
            );
        }
        assert_eq!(
            probe(false, "/get_output_distribution.bin").await,
            StatusCode::NOT_FOUND,
            "control: an unspecified path must 404, or the OK assertions above \
             are vacuous"
        );
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
