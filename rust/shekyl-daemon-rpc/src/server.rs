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
use crate::handlers::rpc;
use crate::handles::Handles;
use crate::middleware::DEFAULT_BODY_LIMIT;
use crate::options::{OptionsAbsent, OptionsFacts};
use crate::shard_view::{ShardViewFacts, SkeletonAbsent};
use crate::submit::DaemonSubmitEngine;

use crate::authority::Authority;
use crate::hash_budget::HashBudget;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::routing::{post, MethodRouter};
use axum::{Json, Router};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{watch, Semaphore};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::info;

pub struct AppState {
    /// The Rust admission engine behind `POST /submit_transaction`
    /// (`docs/design/DAEMON_SUBMIT_VERDICT.md` §3).
    pub submit_engine: Arc<DaemonSubmitEngine>,
    /// Live connection accounting; shared with the [`LimitedListener`] and read
    /// by `get_info` to report `rpc_connections_count`.
    pub conn_tracker: Arc<ConnTracker>,
    /// What `request_archival_shard` reads (`shard_view::ShardViewFacts`).
    pub shard_view: Arc<dyn ShardViewFacts>,
    /// What `option_set` and `option_show` read and write
    /// (`options::OptionsFacts`, RT-O26); the composition root supplies it.
    pub options: Arc<dyn OptionsFacts>,
    /// The node's handles (N1): every route reads through them, the p2p
    /// facts included.
    pub handles: Handles,
    /// One hash budget for every bounded caller (§6.3).
    pub hash_budget: Arc<HashBudget>,
    /// Bounded `get_coinbase_tx_sum` reads, one at a time. Cold reads wait
    /// on disk; the permit is taken before the blocking-pool task.
    pub coinbase_reads: Arc<Semaphore>,
}

pub struct ServerConfig {
    pub body_limit: usize,
    /// Allow-list from `--rpc-access-control-origins`. Empty = CORS default-deny.
    pub cors_origins: Vec<String>,
    /// Concurrent-connection caps enforced by the [`LimitedListener`].
    pub conn_limits: ConnLimits,
    /// The shard view's facts source. The composition root that can compose
    /// a `ViewDesk` (the `shekyld` binary crate, `SV-D9`) supplies it; the default is
    /// [`SkeletonAbsent`], a daemon that serves no shard view.
    pub shard_view: Arc<dyn ShardViewFacts>,
    /// The options handle (RT-O26); the default serves no options.
    pub options: Arc<dyn OptionsFacts>,
    /// The node's handles. The default is absent: every call is not ready.
    pub handles: Handles,
    /// The node's armed-lever switch (`dev-rpc`, `RPC_CHANNEL.md` §6.1): the
    /// admin listener serves the armed test levers only while it is on.
    pub armed: bool,
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
            armed: false,
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
// The one route (RW-Q1, RW-Q2)
//
// Every method is JSON-RPC on `/json_rpc`, dispatched by the method table
// (`handlers::rpc`), where a table row with no handler does not compile. A
// path that is not `/json_rpc` is not a method: it is the shared 404 body.
// `assemble` takes the handler as a parameter so a test can route the real
// shape without an `AppState`.
// ---------------------------------------------------------------------------

/// The routed-but-unlayered router: `/json_rpc` and the 404 fallback.
fn assemble<S>(json_rpc: MethodRouter<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(shekyl_rpc_types::endpoint::JSON_RPC_PATH, json_rpc)
        // A path no row serves gets the shared answer, which names
        // `/json_rpc`, instead of an empty 404 (the wallet RPC mounts the same).
        .fallback(unrouted)
}

/// The answer to a path no route serves: HTTP 404 with the shared
/// JSON-RPC error body (`shekyl_rpc_types::endpoint`).
async fn unrouted(uri: axum::http::Uri) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(shekyl_rpc_types::endpoint::unrouted_path(uri.path())),
    )
}

/// Build the Axum router for one listener. `cors_origins` empty ⇒
/// default-deny CORS.
///
/// The route comes only from [`assemble`], its handler from [`rpc::handle`].
/// Every request is stamped with `authority`, which every gate reads
/// (`crate::authority`, RT-O32).
pub fn build_router(state: Arc<AppState>, cors_origins: &[String], authority: Authority) -> Router {
    gate(assemble(post(rpc::handle)), authority)
        .layer(RequestBodyLimitLayer::new(DEFAULT_BODY_LIMIT))
        .layer(cors_layer(cors_origins))
        .with_state(state)
}

/// `router` with the request layer that stamps `authority` and admits each
/// path. One function, so the gate tests apply exactly what ships.
fn gate<S>(router: Router<S>, authority: Authority) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(axum::middleware::from_fn(move |request, next| {
        crate::authority::stamp(authority, request, next)
    }))
}

/// Serves the RPC section's two listener sets on one node: `admin` at the
/// admin listener's authority (every grant, and the host's) and `view` at the
/// view listener's (`crate::authority::Authority::VIEW_LISTENER`), with one
/// submit engine and ONE connection
/// tracker between them: the cap is per daemon, as the section says, and
/// `get_info` must count every socket. A tracker per listener made a cap of
/// N admit 2N — the same mistake `submit/gate.rs` records for the F39
/// verification cap ("one cap per daemon, not per listener"), re-made here
/// once already. An empty set serves nothing; both empty is a daemon with no
/// RPC, which returns once the stop arrives.
pub async fn serve_listeners(
    config: ServerConfig,
    submit_engine: Arc<DaemonSubmitEngine>,
    admin: Vec<BoundListener>,
    view: Vec<BoundListener>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn_tracker = ConnTracker::new(config.conn_limits);
    let hash_budget = Arc::new(HashBudget::new(Instant::now()));
    let coinbase_reads = Arc::new(Semaphore::new(1));
    let router_at = |authority: Authority| {
        let state = Arc::new(AppState {
            submit_engine: submit_engine.clone(),
            conn_tracker: conn_tracker.clone(),
            shard_view: config.shard_view.clone(),
            options: config.options.clone(),
            handles: config.handles.clone(),
            hash_budget: Arc::clone(&hash_budget),
            coinbase_reads: Arc::clone(&coinbase_reads),
        });
        build_router(state, &config.cors_origins, authority)
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
    // The armed test levers' switch, logged at every start whichever way it
    // is set (`RPC_CHANNEL.md` §6.1): only `dev-rpc` enables them, and the
    // operator reads which it is.
    if config.armed {
        tracing::warn!(
            "RPC armed test levers: ON (dev-rpc): generateblocks and \
             /pop_blocks are served to the host's administrator"
        );
    } else {
        info!("RPC armed test levers: off (dev-rpc not set)");
    }
    if config.conn_limits != ConnLimits::default() {
        info!(
            "RPC connection cap: {} (0 = unlimited)",
            config.conn_limits.max_total()
        );
    }

    serve_bound(
        vec![
            (
                Listener::Admin,
                router_at(Authority::admin_listener(config.armed)),
                admin,
            ),
            (Listener::View, router_at(Authority::VIEW_LISTENER), view),
        ],
        conn_tracker,
        shutdown,
    )
    .await
}

/// Which listener a bound socket is. An enrolment preset
/// (`shekyl_rpc_grants::Preset`) is a different thing: the view listener
/// also serves submit and mining work until RT-W12, which the enrolment
/// preset `View` does not.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Listener {
    Admin,
    View,
}

impl Listener {
    fn name(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::View => "view",
        }
    }
}

/// The lifecycle half of [`serve_listeners`], independent of the core so it
/// can be tested as one: one plaintext HTTP/1 serve per bound socket, every
/// accepted connection admitted through the shared tracker, and every acceptor
/// stopped by the same level-triggered signal — including one that has not
/// been polled when the signal arrives, which is the ordering that used to
/// hang `shekyl_daemon_rpc_stop`. An acceptor that fails must not leave the
/// others serving a half-server until the operator's stop: the first
/// failure raises an internal stop the healthy acceptors drain on, and is
/// returned once every acceptor has finished
/// ([`first_error_stops_the_rest`]).
pub(crate) async fn serve_bound(
    sets: Vec<(Listener, Router, Vec<BoundListener>)>,
    conn_tracker: Arc<ConnTracker>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (fail_tx, fail_rx) = watch::channel(false);
    let mut serves = tokio::task::JoinSet::new();
    for (role, app, bound) in sets.into_iter().flat_map(|(role, app, listeners)| {
        listeners
            .into_iter()
            .map(move |bound| (role, app.clone(), bound))
    }) {
        // The operator's startup line, in the category the daemon shows at
        // default verbosity (`global=info`, where the C++ `MGINFO` this
        // replaced lived); this crate's own target is filtered to errors
        // there, and a bound socket must not need --log-level 1 to be seen.
        info!(
            target: "global",
            "shekyl-daemon-rpc listening on {} ({} listener)",
            bound.local_addr(),
            role.name()
        );
        let (_, listener) = bound.into_parts();
        // Every accepted connection is admitted through (and accounted in)
        // the one shared tracker.
        let listener = LimitedListener::new(listener, conn_tracker.clone());
        let mut stop = shutdown.clone();
        let mut fail = fail_rx.clone();
        serves.spawn(crate::listener_http::serve_plaintext(
            listener,
            app,
            async move {
                // Either signal is a stop, and either outcome of each is
                // too (the value turned true, or its sender is gone).
                // `wait_for` is level-triggered: a send that happened
                // before this future was first polled is still observed.
                tokio::select! {
                    _signal = stop.wait_for(|&stop| stop) => {}
                    _signal = fail.wait_for(|&fail| fail) => {}
                }
            },
        ));
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
    use http::{Request, StatusCode};
    use shekyl_rpc_types::endpoint::{unrouted_path, JSON_RPC_PATH};
    use tower::ServiceExt;

    /// Every path the 3.x daemon served as a route of its own, and the
    /// binary sync paths retired before it (RK-4x), written out here rather
    /// than derived: the 4.0 router serves `/json_rpc` alone (RW-Q1), and
    /// each of these is now the shared 404 that names it. Changing what the
    /// router serves must change this list in a diff a reviewer reads.
    const RETIRED_PATHS: &[&str] = &[
        "/get_height",
        "/getheight",
        "/get_transactions",
        "/gettransactions",
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
        "/get_alt_blocks_hashes",
        "/get_stem_tallies",
        "/start_mining",
        "/stop_mining",
        "/mining_status",
        "/get_peer_list",
        "/stop_daemon",
        "/get_net_stats",
        "/pop_blocks",
        "/get_output_distribution.bin",
        "/get_blocks.bin",
        "/getblocks.bin",
        "/get_hashes.bin",
        "/gethashes.bin",
    ];

    /// A router with the real route, the real fallback and the real gate:
    /// [`build_router`]'s own [`assemble`] and [`gate`] calls, with only the
    /// `/json_rpc` handler swapped for one that answers `ok`, because the
    /// real one needs an `AppState`. What the handler admits is
    /// `handlers::rpc`'s tests' subject.
    fn probe_router(authority: Authority) -> Router {
        gate(assemble(post(|| async { "ok" })), authority)
    }

    /// The status and body a request for `path` gets.
    async fn probe(authority: Authority, method: &str, path: &str) -> (StatusCode, Vec<u8>) {
        let response = probe_router(authority)
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, body.to_vec())
    }

    /// The router serves `/json_rpc` on both listeners and nothing else:
    /// every 3.x route, the anonymity-graph readout and the armed levers
    /// among them, is the shared 404 on both, whichever HTTP method asks.
    /// Gating moved from the path to the method row, so what the view
    /// listener may call is asserted at dispatch (`handlers::rpc` tests).
    /// Port of the 3.x `route_table_matches_the_specification`,
    /// `output_distribution_bin_not_registered`,
    /// `assembled_router_serves_exactly_the_specified_surface`,
    /// `assembled_router_gates_the_anonymity_graph` and
    /// `pop_blocks_needs_the_armed_switch`. Red check run: routing
    /// `/get_info` beside `/json_rpc` in [`assemble`] turns this red.
    #[tokio::test]
    async fn only_json_rpc_is_routed() {
        for authority in [
            Authority::admin_listener(true),
            Authority::admin_listener(false),
            Authority::VIEW_LISTENER,
        ] {
            assert_eq!(
                probe(authority, "POST", JSON_RPC_PATH).await,
                (StatusCode::OK, b"ok".to_vec()),
                "control: the one route is served"
            );
            for path in RETIRED_PATHS {
                for method in ["GET", "POST"] {
                    let (status, body) = probe(authority, method, path).await;
                    assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
                    let value: serde_json::Value =
                        serde_json::from_slice(&body).expect("the shared JSON body");
                    assert_eq!(value, unrouted_path(path), "{method} {path}");
                }
            }
        }
    }

    /// A path no row serves is told where JSON-RPC is: HTTP 404 with the
    /// shared body, never an empty one. Both listeners, both methods, and a
    /// path the wallet RPC used to serve (`/`) among them.
    #[tokio::test]
    async fn an_unrouted_path_is_told_where_json_rpc_is() {
        for authority in [Authority::admin_listener(false), Authority::VIEW_LISTENER] {
            for (method, path) in [
                ("POST", "/"),
                ("GET", "/no_such_endpoint"),
                ("POST", "/json_rpc/"),
            ] {
                let (status, body) = probe(authority, method, path).await;
                assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
                let value: serde_json::Value =
                    serde_json::from_slice(&body).expect("a JSON body, not an empty 404");
                assert_eq!(value, unrouted_path(path), "{method} {path}");
            }
        }
    }

    /// A preflight to the one route from an origin nobody configured gets
    /// no allow-origin header.
    #[tokio::test]
    async fn cors_default_deny_omits_allow_origin() {
        // Exercise `cors_layer` without an `AppState`.
        let app = assemble(post(|| async { "ok" })).layer(cors_layer(&[]));
        let res = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri(JSON_RPC_PATH)
                    .header("Origin", "https://evil.example")
                    .header("Access-Control-Request-Method", "POST")
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
        let app = assemble(post(|| async { "ok" })).layer(cors_layer(&origins));
        let res = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri(JSON_RPC_PATH)
                    .header("Origin", "https://wallet.example")
                    .header("Access-Control-Request-Method", "POST")
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
    async fn e2e_axum_only_daemon_status_smoke() {
        // Operators: point a client at a local shekyld RPC and call
        // `daemon_status` and `tx_list` on /json_rpc. In-lane coverage is the
        // oneshot/CORS tests above and the dispatch tests in `handlers::rpc`.
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::{first_error_stops_the_rest, serve_bound, Listener};
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
    async fn each_listener_serves_its_own_router_on_its_own_sockets() {
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
                (Listener::Admin, admin, vec![admin_listener]),
                (Listener::View, router(), vec![view_listener]),
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
                vec![(Listener::Admin, router(), listeners)],
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
                vec![(Listener::Admin, router(), listeners)],
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
}
