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

use crate::bind::BoundListener;
use crate::conn_limit::{ConnLimits, ConnTracker, LimitedListener};
use crate::core::CoreRpc;
use crate::handlers::{binary, json, json_rpc, submit};
use crate::handles::Handles;
use crate::middleware::DEFAULT_BODY_LIMIT;
use crate::options::{OptionsAbsent, OptionsFacts};
use crate::shard_view::{ShardViewFacts, SkeletonAbsent};
use crate::submit::{DaemonSubmitEngine, DaemonTxVerifier, FfiSubmitShim, SubmitEngine};

use axum::http::{HeaderValue, Method};
use axum::routing::{get, post, MethodRouter};
use axum::Router;
use std::future::IntoFuture as _;
use std::sync::Arc;
use tokio::sync::watch;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::info;

pub struct AppState {
    pub core: Arc<CoreRpc>,
    /// The Rust admission engine behind `POST /submit_transaction`
    /// (`docs/design/DAEMON_SUBMIT_VERDICT.md` §3).
    pub submit_engine: Arc<DaemonSubmitEngine>,
    pub restricted: bool,
    /// Live connection accounting; shared with the [`LimitedListener`] and read
    /// by `get_info` to report `rpc_connections_count`.
    pub conn_tracker: Arc<ConnTracker>,
    /// What `request_archival_shard` reads (`shard_view::ShardViewFacts`).
    pub shard_view: Arc<dyn ShardViewFacts>,
    /// What `option_set` and `option_show` read and write
    /// (`options::OptionsFacts`, RT-O26); the composition root supplies it.
    pub options: Arc<dyn OptionsFacts>,
    /// The node's handles (N1). Present, and not yet what the live routes
    /// read: those keep the C++ `core` until the store flip.
    pub handles: Handles,
}

pub struct ServerConfig {
    pub body_limit: usize,
    /// Allow-list from `--rpc-access-control-origins`. Empty = CORS default-deny.
    pub cors_origins: Vec<String>,
    /// Concurrent-connection caps enforced by the [`LimitedListener`].
    pub conn_limits: ConnLimits,
    /// The shard view's facts source. The composition root that can compose
    /// a `ViewDesk` (the daemon image, `SV-D9`) supplies it; the default is
    /// [`SkeletonAbsent`], a daemon that serves no shard view.
    pub shard_view: Arc<dyn ShardViewFacts>,
    /// The options handle (RT-O26); the default serves no options.
    pub options: Arc<dyn OptionsFacts>,
    /// The node's handles. The default is absent: every call is not ready.
    pub handles: Handles,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            body_limit: DEFAULT_BODY_LIMIT,
            cors_origins: Vec::new(),
            conn_limits: ConnLimits::default(),
            shard_view: Arc::new(SkeletonAbsent),
            options: Arc::new(OptionsAbsent),
            handles: Handles::absent(),
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
//   * A path cannot be admin-only *and* public. Visibility is the grant of
//     the path's one row in the method table (`shekyl_rpc_types::methods`,
//     RW-Q7), not membership in one of two lists that could both contain it.
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
    GetTransactionPool,
    GetTransactionPoolHashes,
    GetTransactionPoolStats,
    GetInfo,
    GetBlocksByHeightBin,
    GetOIndexesBin,
    GetStemTallies,
    StartMining,
    StopMining,
    MiningStatus,
    SaveBc,
    GetPeerList,
    SetLogHashRate,
    StopDaemon,
    GetNetStats,
    PopBlocks,
}

/// One row of the route table.
pub(crate) struct Route {
    pub(crate) endpoint: Endpoint,
    /// Paths this endpoint answers on. More than one = epee-compatibility
    /// aliases, which share a handler by construction.
    pub(crate) paths: &'static [&'static str],
}

impl Route {
    /// Which listener serves this route: the grant of its row in the method
    /// table. A path with no row is a defect the table gate names; it is
    /// treated as the host's, so a missing row never widens what the view
    /// listener serves.
    pub(crate) fn visibility(&self) -> Visibility {
        let grant = self
            .paths
            .first()
            .and_then(|path| shekyl_rpc_types::methods::rest_path(path))
            .map(|row| row.grant);
        match grant {
            Some(shekyl_rpc_types::methods::Grant::Any) => Visibility::Always,
            Some(shekyl_rpc_types::methods::Grant::HostOnly) | None => Visibility::AdminOnly,
        }
    }
}

/// The daemon RPC route table — the single source of *what is served where*.
///
/// Handler-free so tests can read it without linking `core_rpc_ffi_*`.
/// [`served_paths`] applies the gate; [`build_router`] registers the result.
pub(crate) const ROUTES: &[Route] = &[
    Route {
        endpoint: Endpoint::JsonRpc,
        paths: &["/json_rpc"],
    },
    // JSON REST (with aliases) -- GET + POST to match epee behaviour.
    Route {
        endpoint: Endpoint::GetHeight,
        paths: &["/get_height", "/getheight"],
    },
    Route {
        endpoint: Endpoint::GetTransactions,
        paths: &["/get_transactions", "/gettransactions"],
    },
    Route {
        endpoint: Endpoint::GetAltBlocksHashes,
        paths: &["/get_alt_blocks_hashes"],
    },
    Route {
        endpoint: Endpoint::IsKeyImageSpent,
        paths: &["/is_key_image_spent"],
    },
    // The typed submit route (DAEMON_SUBMIT_VERDICT.md §2.4) is the only
    // submit surface; the legacy /send_raw_transaction proxy was deleted
    // per §9.3. POST only.
    Route {
        endpoint: Endpoint::SubmitTransaction,
        paths: &["/submit_transaction"],
    },
    Route {
        endpoint: Endpoint::GetTransactionPool,
        paths: &["/get_transaction_pool"],
    },
    Route {
        endpoint: Endpoint::GetTransactionPoolHashes,
        paths: &["/get_transaction_pool_hashes"],
    },
    Route {
        endpoint: Endpoint::GetTransactionPoolStats,
        paths: &["/get_transaction_pool_stats"],
    },
    Route {
        endpoint: Endpoint::GetInfo,
        paths: &["/get_info", "/getinfo"],
    },
    // Binary endpoints.
    Route {
        endpoint: Endpoint::GetBlocksByHeightBin,
        paths: &["/get_blocks_by_height.bin", "/getblocks_by_height.bin"],
    },
    Route {
        endpoint: Endpoint::GetOIndexesBin,
        paths: &["/get_o_indexes.bin"],
    },
    // §55: anonymity graph — the peer set is the sensitive part.
    Route {
        endpoint: Endpoint::GetStemTallies,
        paths: &["/get_stem_tallies"],
    },
    Route {
        endpoint: Endpoint::StartMining,
        paths: &["/start_mining"],
    },
    Route {
        endpoint: Endpoint::StopMining,
        paths: &["/stop_mining"],
    },
    Route {
        endpoint: Endpoint::MiningStatus,
        paths: &["/mining_status"],
    },
    Route {
        endpoint: Endpoint::SaveBc,
        paths: &["/save_bc"],
    },
    Route {
        endpoint: Endpoint::GetPeerList,
        paths: &["/get_peer_list"],
    },
    Route {
        endpoint: Endpoint::SetLogHashRate,
        paths: &["/set_log_hash_rate"],
    },
    Route {
        endpoint: Endpoint::StopDaemon,
        paths: &["/stop_daemon"],
    },
    Route {
        endpoint: Endpoint::GetNetStats,
        paths: &["/get_net_stats"],
    },
    Route {
        endpoint: Endpoint::PopBlocks,
        paths: &["/pop_blocks"],
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
        .filter(move |route| !(restricted && route.visibility() == Visibility::AdminOnly))
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
        Endpoint::GetTransactionPool => {
            get(json::get_transaction_pool).post(json::get_transaction_pool)
        }
        Endpoint::GetTransactionPoolHashes => {
            get(json::get_transaction_pool_hashes).post(json::get_transaction_pool_hashes)
        }
        Endpoint::GetTransactionPoolStats => {
            get(json::get_transaction_pool_stats).post(json::get_transaction_pool_stats)
        }
        Endpoint::GetInfo => get(json::get_info).post(json::get_info),
        Endpoint::GetBlocksByHeightBin => post(binary::get_blocks_by_height),
        Endpoint::GetOIndexesBin => post(binary::get_o_indexes),
        // Admin-only (listener selection is the method table's grant, not this
        // match). §55: anonymity graph — the peer set is the sensitive part.
        Endpoint::GetStemTallies => get(json::get_stem_tallies).post(json::get_stem_tallies),
        Endpoint::StartMining => get(json::start_mining).post(json::start_mining),
        Endpoint::StopMining => get(json::stop_mining).post(json::stop_mining),
        Endpoint::MiningStatus => get(json::mining_status).post(json::mining_status),
        Endpoint::SaveBc => get(json::save_bc).post(json::save_bc),
        Endpoint::GetPeerList => get(json::get_peer_list).post(json::get_peer_list),
        Endpoint::SetLogHashRate => get(json::set_log_hash_rate).post(json::set_log_hash_rate),
        Endpoint::StopDaemon => get(json::stop_daemon).post(json::stop_daemon),
        Endpoint::GetNetStats => get(json::get_net_stats).post(json::get_net_stats),
        Endpoint::PopBlocks => get(json::pop_blocks).post(json::pop_blocks),
    }
}

/// The routed-but-unlayered router for one server (every socket of a start).
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

/// Serves the RPC section's two listener sets on one core: `admin` at the
/// admin preset (every route) and `view` at the view preset (the routes
/// `served_routes(true)` admits), with one submit engine and ONE connection
/// tracker between them: the cap is per daemon, as the section says, and
/// `get_info` must count every socket. A tracker per listener made a cap of
/// N admit 2N — the same mistake `submit/gate.rs` records for the F39
/// verification cap ("one cap per daemon, not per listener"), re-made here
/// once already. An empty set serves nothing; both empty is a daemon with no
/// RPC, which returns once the stop arrives.
pub async fn serve_presets(
    core: Arc<CoreRpc>,
    config: ServerConfig,
    admin: Vec<BoundListener>,
    view: Vec<BoundListener>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let submit_engine = Arc::new(SubmitEngine::new(
        FfiSubmitShim::new(core.clone()),
        DaemonTxVerifier,
    ));
    let conn_tracker = ConnTracker::new(config.conn_limits);
    let router_at = |restricted: bool| {
        let state = Arc::new(AppState {
            core: core.clone(),
            submit_engine: submit_engine.clone(),
            restricted,
            conn_tracker: conn_tracker.clone(),
            shard_view: config.shard_view.clone(),
            options: config.options.clone(),
            handles: config.handles.clone(),
        });
        build_router(state, &config.cors_origins)
    };
    // Surface the CORS posture at startup. Default-deny is intentional (a
    // browser cannot reach an unconfigured daemon cross-origin), but it changed
    // from the old permissive reflection, so make it observable rather than a
    // silent "my web UI stopped working after upgrade".
    if config.cors_origins.is_empty() {
        info!(
            "RPC CORS: default-deny (no rpc-cors-origin set; browser clients \
             cannot make cross-origin requests to this daemon)"
        );
    } else {
        info!(
            "RPC CORS: allow-list of {} configured origin(s)",
            config.cors_origins.len()
        );
    }
    if config.conn_limits != ConnLimits::default() {
        info!(
            "RPC connection cap: {} (0 = unlimited)",
            config.conn_limits.max_total()
        );
    }

    serve_bound(
        vec![
            (Preset::Admin, router_at(false), admin),
            (Preset::View, router_at(true), view),
        ],
        conn_tracker,
        shutdown,
    )
    .await
}

/// The preset a listener set serves, named in its startup line.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Preset {
    Admin,
    View,
}

impl Preset {
    fn name(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::View => "view",
        }
    }
}

/// The lifecycle half of [`serve_presets`], independent of the core so it
/// can be tested as one: one `axum::serve` per bound socket, every accepted
/// connection admitted through the shared tracker, and every acceptor
/// stopped by the same level-triggered signal — including one that has not
/// been polled when the signal arrives, which is the ordering that used to
/// hang `shekyl_daemon_rpc_stop`. An acceptor that fails must not leave the
/// others serving a half-server until the operator's stop: the first
/// failure raises an internal stop the healthy acceptors drain on, and is
/// returned once every acceptor has finished
/// ([`first_error_stops_the_rest`]).
pub(crate) async fn serve_bound(
    sets: Vec<(Preset, Router, Vec<BoundListener>)>,
    conn_tracker: Arc<ConnTracker>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (fail_tx, fail_rx) = watch::channel(false);
    let mut serves = tokio::task::JoinSet::new();
    for (preset, app, bound) in sets.into_iter().flat_map(|(preset, app, listeners)| {
        listeners
            .into_iter()
            .map(move |bound| (preset, app.clone(), bound))
    }) {
        // The operator's startup line, in the category the daemon shows at
        // default verbosity (`global=info`, where the C++ `MGINFO` this
        // replaced lived); this crate's own target is filtered to errors
        // there, and a bound socket must not need --log-level 1 to be seen.
        info!(
            target: "global",
            "shekyl-daemon-rpc listening on {} ({} preset)",
            bound.local_addr(),
            preset.name()
        );
        let (_, listener) = bound.into_parts();
        // Every accepted connection is admitted through (and accounted in)
        // the one shared tracker.
        let listener = LimitedListener::new(listener, conn_tracker.clone());
        let mut stop = shutdown.clone();
        let mut fail = fail_rx.clone();
        serves.spawn(
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    // Either signal is a stop, and either outcome of each is
                    // too (the value turned true, or its sender is gone).
                    // `wait_for` is level-triggered: a send that happened
                    // before this future was first polled is still observed.
                    tokio::select! {
                        _signal = stop.wait_for(|&stop| stop) => {}
                        _signal = fail.wait_for(|&fail| fail) => {}
                    }
                })
                .into_future(),
        );
    }
    first_error_stops_the_rest(&mut serves, &fail_tx).await
}

/// Drain a set of acceptors. The first failure — an error, or a task that
/// panicked or was aborted — raises `stop_rest`, so the healthy acceptors
/// drain and exit rather than serving a half-server forever; that failure
/// is returned once every acceptor has finished. No failure: `Ok` once every
/// acceptor has stopped on the operator's signal.
pub(crate) async fn first_error_stops_the_rest<E>(
    serves: &mut tokio::task::JoinSet<Result<(), E>>,
    stop_rest: &watch::Sender<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    let mut first_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    while let Some(joined) = serves.join_next().await {
        let failure: Option<Box<dyn std::error::Error + Send + Sync>> = match joined {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(Box::new(e)),
            Err(join) => Some(Box::new(join)),
        };
        if let Some(e) = failure {
            if first_err.is_none() {
                stop_rest.send_replace(true);
                first_err = Some(e);
            }
        }
    }
    first_err.map_or(Ok(()), Err)
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
        "/get_transaction_pool",
        "/get_transaction_pool_hashes",
        "/get_transaction_pool_stats",
        "/get_info",
        "/getinfo",
        "/get_blocks_by_height.bin",
        "/getblocks_by_height.bin",
        "/get_o_indexes.bin",
    ];

    /// Paths that must **never** be served on the restricted (view-only)
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
        "/stop_daemon",
        "/get_net_stats",
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
        // wallet2's batch sync, retired in RK-4x with the pool departure
        // history behind it. Re-registering either route turns this red.
        for path in [
            "/get_blocks.bin",
            "/getblocks.bin",
            "/get_hashes.bin",
            "/gethashes.bin",
        ] {
            assert!(
                !served_paths(false).any(|p| p == path),
                "{path} was retired and must not be served"
            );
            assert!(
                !served_paths(true).any(|p| p == path),
                "{path} was retired and must not be served on the restricted listener"
            );
        }
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
        // /get_info + /get_o_indexes.bin. In-lane coverage is the oneshot/CORS
        // tests above plus RpcArgsDaemonSurface.
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::{first_error_stops_the_rest, serve_bound, Preset};
    use crate::bind::bind_listener;
    use crate::conn_limit::{ConnLimits, ConnTracker};
    use std::time::Duration;

    async fn two_loopback_listeners() -> Vec<crate::bind::BoundListener> {
        let mut out = Vec::new();
        for addr in ["127.0.0.1:0", "[::1]:0"] {
            out.push(
                bind_listener(addr.parse().unwrap())
                    .await
                    .unwrap_or_else(|e| panic!("{addr} must bind: {e}")),
            );
        }
        out
    }

    fn router() -> axum::Router {
        axum::Router::new().route("/", axum::routing::get(|| async { "ok" }))
    }

    /// One request over a bound socket; the status line's code.
    async fn status_of(addr: std::net::SocketAddr, path: &str) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        reply
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .expect("a status line")
    }

    /// Each listener set serves its own router and no other's: a path the
    /// admin router carries answers on the admin socket and is absent on the
    /// view socket, through one `serve_bound` over both sets (the shape the
    /// one RPC start builds from its section, §2.3).
    #[tokio::test]
    async fn each_preset_serves_its_own_router_on_its_own_sockets() {
        let admin_listener = bind_listener("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let view_listener = bind_listener("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let admin_addr = admin_listener.local_addr();
        let view_addr = view_listener.local_addr();
        let admin = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .route("/admin_only", axum::routing::get(|| async { "secret" }));
        let (tx, rx) = tokio::sync::watch::channel(false);
        let serving = tokio::spawn(serve_bound(
            vec![
                (Preset::Admin, admin, vec![admin_listener]),
                (Preset::View, router(), vec![view_listener]),
            ],
            ConnTracker::new(ConnLimits::default()),
            rx,
        ));
        assert_eq!(status_of(admin_addr, "/admin_only").await, 200);
        assert_eq!(status_of(view_addr, "/admin_only").await, 404);
        assert_eq!(status_of(view_addr, "/").await, 200);
        tx.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .expect("stops")
            .expect("joins")
            .expect("a clean stop is Ok");
    }

    /// The stop is level-triggered: a waiter that did not exist when the
    /// stop was sent still stops — the ordering that once hung
    /// `shekyl_daemon_rpc_stop`, when a `Notify` stored no permit for a
    /// waiter registered after the signal. Modelled exactly: the acceptors'
    /// receiver is subscribed *after* the send. The edit that turns this red
    /// is waiting with `changed()` (edge-triggered, waits for a *next*
    /// change) instead of `wait_for` (level-triggered, reads the value that
    /// is already there): the late receiver never sees an edge and the
    /// timeout fires.
    #[tokio::test]
    async fn a_stop_sent_before_the_acceptors_poll_still_stops_them() {
        let listeners = two_loopback_listeners().await;
        let (tx, _rx0) = tokio::sync::watch::channel(false);
        tx.send_replace(true);
        let rx = tx.subscribe();
        tokio::time::timeout(
            Duration::from_secs(5),
            serve_bound(
                vec![(Preset::Admin, router(), listeners)],
                ConnTracker::new(ConnLimits::default()),
                rx,
            ),
        )
        .await
        .expect("every acceptor must stop on a signal that preceded it")
        .expect("a clean stop is Ok");
    }

    /// One acceptor failing must not leave the rest serving a half-server:
    /// the first failure raises the internal stop, the waiting acceptor
    /// exits on it, and the failure is returned once both have finished.
    /// The edit that turns this red is not raising `stop_rest` on the first
    /// failure — the healthy task then waits forever and the bound fires.
    #[tokio::test]
    async fn a_failing_acceptor_stops_the_rest_and_is_reported() {
        let (fail_tx, fail_rx) = tokio::sync::watch::channel(false);
        let mut set: tokio::task::JoinSet<Result<(), std::io::Error>> = tokio::task::JoinSet::new();
        set.spawn(async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Err(std::io::Error::other("acceptor died"))
        });
        let mut waits = fail_rx.clone();
        set.spawn(async move {
            // The healthy acceptor: ends only when told to.
            let _signal = waits.wait_for(|&stop| stop).await;
            Ok(())
        });
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            first_error_stops_the_rest(&mut set, &fail_tx),
        )
        .await
        .expect("the healthy acceptor must be stopped by the failure")
        .expect_err("the first failure is reported");
        assert!(err.to_string().contains("acceptor died"), "{err}");
        assert!(*fail_rx.borrow(), "the internal stop was raised");
    }

    /// The ordinary order, and the other stop: a signal after the acceptors
    /// are running stops both, and so does dropping the sender.
    #[tokio::test]
    async fn a_stop_sent_later_and_a_dropped_sender_both_stop_every_acceptor() {
        for drop_instead in [false, true] {
            let listeners = two_loopback_listeners().await;
            let (tx, rx) = tokio::sync::watch::channel(false);
            let serving = tokio::spawn(serve_bound(
                vec![(Preset::Admin, router(), listeners)],
                ConnTracker::new(ConnLimits::default()),
                rx,
            ));
            tokio::time::sleep(Duration::from_millis(50)).await;
            if drop_instead {
                drop(tx);
            } else {
                tx.send_replace(true);
            }
            tokio::time::timeout(Duration::from_secs(5), serving)
                .await
                .expect("every acceptor must stop")
                .expect("the serve task must not panic")
                .expect("a clean stop is Ok");
        }
    }

    /// RW-Q7's gate for REST: every route's paths are one row's names in the
    /// method table, and every REST row is a route. A path served without a
    /// row, or a row nothing serves, fails here.
    #[test]
    fn every_route_is_one_method_row_and_every_rest_row_is_routed() {
        use shekyl_rpc_types::methods::{rest_path, Surface, METHODS};
        for route in crate::server::ROUTES {
            let row = rest_path(route.paths[0])
                .unwrap_or_else(|| panic!("{} has no row in the method table", route.paths[0]));
            let mut routed: Vec<&str> = route.paths.to_vec();
            let mut named: Vec<&str> = row.names().collect();
            routed.sort_unstable();
            named.sort_unstable();
            assert_eq!(
                routed, named,
                "{}: the route's paths are its row's names",
                row.name
            );
        }
        for row in METHODS.iter().filter(|row| row.surface == Surface::Rest) {
            assert!(
                crate::server::ROUTES
                    .iter()
                    .any(|route| route.paths.contains(&row.name)),
                "{} is a REST row that no route serves",
                row.name
            );
        }
    }
}
