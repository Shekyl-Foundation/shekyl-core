// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Axum JSON-RPC server: `POST /` over TCP, a Unix domain socket, or — for
//! the in-process host on Windows — an owner-only named pipe.
//!
//! Also exposes [`spawn_in_process`] so Shape B (`shekyl-cli`) can host an
//! in-process server without shelling out (`WALLET_REWRITE_PLAN.md` Phase 3).
//!
//! The platform seam is [`BoundListener`]: **one** `cfg` split, at listener
//! construction, shared by [`ArmedServer::serve`] and [`spawn_in_process_with`] so the
//! two cannot drift (`WINDOWS_WALLET_SUPPORT.md` §8.1). Everything
//! Windows-specific below it lives in `shekyl-win-sec`, the crate built to
//! hold the `unsafe` this one denies (WP-D2).

use std::net::SocketAddr;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_core::Network;
use shekyl_process::stop::{FirstStop, Inherited, Stops};
use shekyl_rpc_transport::network_posture::{DaemonDisclosures, ProxyResolution};
use shekyl_rpc_types::endpoint::{unrouted_path, JSON_RPC_PATH};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

use crate::auth::{require_basic_auth, AuthConfig};
use crate::handlers;
use crate::tenant::{DaemonTarget, TenantState};
use crate::types::{JsonRpcRequest, JsonRpcResponse};

#[cfg(unix)]
#[path = "private_socket.rs"]
mod private_socket;

#[cfg(unix)]
pub use private_socket::{DIR_PREFIX, LOCK_FILE, SOCKET_FILE};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// Default max JSON-RPC body size (1 MiB). Wallet RPC payloads are small;
/// this is a DoS bound, not a semantic limit.
pub const DEFAULT_BODY_LIMIT: usize = 1024 * 1024;

/// Where the server listens.
#[derive(Debug, Clone)]
pub enum ListenAddr {
    /// TCP bind address (e.g. `127.0.0.1:29500`).
    Tcp(SocketAddr),
    /// Unix domain socket path (recommended default for local clients).
    #[cfg(unix)]
    Uds(PathBuf),
    /// The in-process host's named pipe (Windows).
    ///
    /// Not a form of `rpc-listen` or `rpc-socket-file`, and
    /// [`SelfHostedPipe`] has no public constructor, so no option and no
    /// embedder can stand up a pipe server by hand. Windows ships **no**
    /// external local form (`WINDOWS_WALLET_SUPPORT.md` §8.1 ruling); the
    /// absence is structural rather than a parse-time refusal.
    #[cfg(windows)]
    SelfHostedPipe(SelfHostedPipe),
}

/// The self-hosted pipe's name, constructible only by [`spawn_in_process`].
#[cfg(windows)]
#[derive(Clone)]
pub struct SelfHostedPipe {
    name: String,
}

/// Redacted: the name embeds the user's SID (WP-D1), and a SID is an account
/// identifier that should not reach logs by accident — the same discipline
/// `shekyl_win_sec::SidString` applies to itself.
#[cfg(windows)]
impl std::fmt::Debug for SelfHostedPipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SelfHostedPipe(<redacted>)")
    }
}

/// The option naming the Tor binary a serving wallet runs, on both wallet
/// binaries (`INPUT_GRAMMAR.md` §12.1, §12.4). Unset is discovery; a path
/// that is relative or names no file refuses the start
/// ([`shekyl_engine_core::TorFile`]).
pub const TOR_FILE_OPTION: &str = "tor-file";

/// The resolved `tor-file` option a host passes in ([`ServerConfig::tor_file`],
/// [`spawn_in_process`]), and its refusal, re-exported so a host reaches them
/// through this crate.
pub use shekyl_engine_core::{TorFile, TorFileRefused};

/// Server configuration.
#[derive(Clone)]
pub struct ServerConfig {
    /// Bind address (TCP, UDS, or the in-process pipe).
    pub listen: ListenAddr,
    /// Directory for wallet files.
    pub wallet_dir: PathBuf,
    /// Network every create/open binds to.
    pub network: Network,
    /// The daemon every wallet connects to: "this computer" with no
    /// `daemon-endpoint`, otherwise that endpoint and its `daemon-socks`.
    pub daemon: DaemonTarget,
    /// HTTP basic auth (disabled for UDS-by-default deployments).
    pub auth: AuthConfig,
    /// Argon2id cost for `create_wallet` / password rotation.
    /// Production uses [`KdfParams::default`]; tests may clamp.
    pub kdf: KdfParams,
    /// The `tor-file` option, resolved: the Tor binary a serving wallet
    /// runs. Machine-scoped, so an option of the process, never stored with
    /// a wallet.
    pub tor_file: shekyl_engine_core::TorFile,
}

/// Manual (not derived): the daemon address may carry digest credentials in
/// its authority, and [`DaemonTarget`]'s `Debug` renders it redacted
/// (`AuthConfig` redacts its own password; the remaining fields are inert).
impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("listen", &self.listen)
            .field("wallet_dir", &self.wallet_dir)
            .field("network", &self.network)
            .field("daemon", &self.daemon)
            .field("auth", &self.auth)
            .field("kdf", &self.kdf)
            .field("tor_file", &self.tor_file)
            .finish()
    }
}

/// Shared application state.
pub struct AppState {
    /// Tenant / wallet-dir state.
    pub tenants: tokio::sync::Mutex<TenantState>,
    /// Auth config: the one owned copy — [`AppState::new`] takes the
    /// `ServerConfig` by value and moves the credential out, so the config's
    /// copy does not outlive construction — shared by refcount with the
    /// middlewares that read it.
    pub auth: Arc<AuthConfig>,
    /// Argon2id cost for create / rotate.
    pub kdf: KdfParams,
    /// Signalled to request graceful shutdown.
    pub shutdown: Arc<Notify>,
    /// Notified once the server has stopped and closed the open wallet
    /// ([`serve_then_close`]); a stop-signal watcher that must end the
    /// process waits for it.
    pub closed: Arc<Notify>,
}

// `AppState` fields are public so integration tests can construct a
// state without going through `ServerConfig` bind.

impl AppState {
    /// Consumes the config: the credential moves in, and nothing else holds
    /// it afterwards. Callers bind the listener before calling this — the
    /// one thing that needs the config after validation.
    fn new(config: ServerConfig) -> Arc<Self> {
        Arc::new(Self {
            tenants: tokio::sync::Mutex::new(TenantState::new(
                config.wallet_dir,
                config.network,
                config.daemon,
                config.tor_file,
            )),
            auth: Arc::new(config.auth),
            kdf: config.kdf,
            shutdown: Arc::new(Notify::new()),
            closed: Arc::new(Notify::new()),
        })
    }
}

/// The one body media type the JSON-RPC endpoint accepts.
///
/// This is half of the browser boundary, and it is structural rather than a
/// matter of authentication. A web page can make a browser send a
/// cross-origin POST to `127.0.0.1` without any preflight *as long as* the
/// request is "simple" — `text/plain` or a form type — and default-deny CORS
/// only hides the **response** from the page; the request still executes. So
/// on the loopback listener, where RT-2 permits `AuthConfig::Disabled`, a
/// page could otherwise drive spends through a `no-cors` `text/plain` POST
/// carrying JSON-RPC. `application/json` is not a simple type: a browser
/// must preflight it, and the default-deny `CorsLayer` refuses every
/// preflight, so the request is never sent. Anything else is refused with
/// 415 before the credential check, the body limit, or the body is looked
/// at. Non-browser clients send `application/json` anyway
/// (`docs/api/wallet_rpc.yaml`). The other half is [`host_is_unrebindable`].
const JSON_MEDIA_TYPE: &str = "application/json";

/// The other half of the browser boundary: **DNS rebinding**. A page served
/// from `evil.example` can have that name re-pointed at `127.0.0.1` after it
/// loads; the browser then treats an `application/json` fetch to
/// `evil.example:29500` as same-origin, sends no preflight, and the JSON
/// gate alone does not stop it. Rebinding needs a DNS *name*, so the request
/// carries one in its `Host` — and a wallet bound to a numeric address has
/// no legitimate reason to be addressed by a name other than `localhost`.
/// Accepted: an IP literal (`127.0.0.1:29500`, `[::1]:29500`) or `localhost`,
/// port optional, case folded — parsed as an authority, strictly: a
/// bracketed IPv6 literal may be followed by nothing or `:<port>`, and so
/// may an IPv4 literal or `localhost`, with the port numeric. Anything else
/// — a name DNS could re-point, or non-authority syntax such as
/// `[::1]evil` — is a request that was routed here by a name this server
/// never answered to.
///
/// Applied only where authentication is disabled — the loopback exception,
/// where the browser boundary is the only gate. On an authenticated leg the
/// credential is the gate and an operator's `wallet.lan:29500` keeps working.
fn host_is_unrebindable(host: &str) -> bool {
    /// Nothing, or `:<u16>` — the only suffix an authority's host may carry.
    fn port_suffix_ok(suffix: &str) -> bool {
        suffix.is_empty()
            || suffix
                .strip_prefix(':')
                .is_some_and(|port| port.parse::<u16>().is_ok())
    }
    let host = host.trim();
    if let Some(rest) = host.strip_prefix('[') {
        // `[v6]` or `[v6]:port`; the brackets are the v6 literal's syntax.
        return rest.split_once(']').is_some_and(|(inner, after)| {
            inner.parse::<std::net::Ipv6Addr>().is_ok() && port_suffix_ok(after)
        });
    }
    let (name, suffix) = host.split_at(host.find(':').unwrap_or(host.len()));
    (name.eq_ignore_ascii_case("localhost") || name.parse::<std::net::Ipv4Addr>().is_ok())
        && port_suffix_ok(suffix)
}

/// `Content-Type` media type, parameters (`; charset=utf-8`) ignored, case
/// folded (RFC 9110 §8.3.1).
fn is_json_media_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|media| media.trim().eq_ignore_ascii_case(JSON_MEDIA_TYPE))
}

/// Axum middleware: the browser boundary. Refuse any body-carrying request
/// (POST, PUT, PATCH) that is not `application/json` (415) — a request with
/// no body has no media type to judge, and the router's own 405 is the
/// accurate answer to a `GET /` — and, where authentication is disabled,
/// any request addressed by a rebindable name (421 Misdirected Request),
/// method-independent: a rebound page could read as well as spend. Both run
/// before the credential check, the body limit, or the body.
async fn browser_boundary(
    axum::extract::State(auth): axum::extract::State<Arc<AuthConfig>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::header;
    use axum::response::IntoResponse as _;
    // Both verdicts are taken before the await: a borrow of the request kept
    // alive across `next.run` would make this future `!Send` (`Body` is not
    // `Sync`), and axum's middleware requires `Send`.
    let headers = request.headers();
    let carries_body = matches!(
        *request.method(),
        axum::http::Method::POST | axum::http::Method::PUT | axum::http::Method::PATCH
    );
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_json_media_type);
    let host_ok = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .is_some_and(host_is_unrebindable);
    if carries_body && !is_json {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "this endpoint accepts only Content-Type: application/json",
        )
            .into_response();
    }
    if matches!(*auth, AuthConfig::Disabled) && !host_ok {
        return (
            StatusCode::MISDIRECTED_REQUEST,
            "this endpoint answers only to its IP address or `localhost` when authentication \
             is disabled (a hostname can be rebound to this machine by a web page)",
        )
            .into_response();
    }
    next.run(request).await
}

/// Build the axum router (shared by TCP, UDS, the pipe, and in-process tests).
///
/// Layer order, outermost first: CORS (default-deny, so every preflight
/// fails), the browser boundary (`application/json` only; an unrebindable
/// `Host` where auth is disabled), then authentication. The body limit is
/// axum's `DefaultBodyLimit`, enforced where the body is read (the handler's
/// `Bytes` extractor) rather than by a layer that rewraps the body type —
/// so it constrains no middleware order, and a declared oversize length is
/// judged only after every gate. A browser-driven request is refused by the
/// boundary before a credential is compared; a non-JSON request never
/// reaches the handler.
///
/// JSON-RPC is served at [`JSON_RPC_PATH`] only, the path the daemon uses;
/// there is no alias at `/` (rule 83). Any other path gets the shared
/// [`unrouted_path`] answer, behind the same layers: an unauthenticated
/// request is refused before it learns which path is served.
pub fn build_router(state: Arc<AppState>) -> Router {
    let auth = Arc::clone(&state.auth);
    Router::new()
        .route(JSON_RPC_PATH, post(json_rpc_handler))
        .fallback(unrouted)
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&auth),
            require_basic_auth,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(DEFAULT_BODY_LIMIT))
        .layer(axum::middleware::from_fn_with_state(auth, browser_boundary))
        // Default-deny CORS. This process will host spend operations; a
        // permissive ACAO on loopback TCP would let a malicious web page
        // read responses, and — with the JSON gate above — the preflight it
        // forces is what keeps the page from sending the request at all.
        // Reopen only for an explicit web-client deployment (rule 21).
        .layer(CorsLayer::new())
        .with_state(state)
}

/// The answer to a path no route serves: HTTP 404 with the shared
/// JSON-RPC error body, which names [`JSON_RPC_PATH`].
async fn unrouted(uri: axum::http::Uri) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::NOT_FOUND, Json(unrouted_path(uri.path())))
}

async fn json_rpc_handler(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> (StatusCode, Json<JsonRpcResponse>) {
    // HTTP status is 200 for every JSON-RPC exchange (spec). Distinguish
    // invalid JSON syntax (-32700) from structurally invalid requests
    // (-32600) per JSON-RPC 2.0 §5 / OpenAPI WalletRpcErrorCode.
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return (StatusCode::OK, Json(JsonRpcResponse::parse_error()));
        }
    };

    let req = match JsonRpcRequest::try_from_value(value) {
        Ok(req) => req,
        Err((id, err)) => {
            return (StatusCode::OK, Json(JsonRpcResponse::from_error(id, &err)));
        }
    };

    let id = req.id.clone();
    match handlers::dispatch(&state.tenants, &req.method, &req.params, state.kdf).await {
        Ok(result) => (StatusCode::OK, Json(JsonRpcResponse::success(id, result))),
        Err(err) => (StatusCode::OK, Json(JsonRpcResponse::from_error(id, &err))),
    }
}

/// Removes a UDS path on drop so serve errors cannot leave a stale socket.
/// A removal that fails for any reason but the path being gone is logged:
/// it leaves a socket behind, and nothing else would say so (rule 82).
#[cfg(unix)]
struct UdsCleanup(PathBuf);

#[cfg(unix)]
impl Drop for UdsCleanup {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.0) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(
                path = %self.0.display(),
                error = %e,
                "the wallet RPC socket could not be removed"
            ),
        }
    }
}

/// Refuse a malformed `daemon-endpoint` / `daemon-socks` at startup (offline
/// shape check only — an unreachable daemon stays fine for offline
/// commands). Deferred to first use, a bad flag would surface on
/// `open_wallet` as "daemon unreachable": the wrong remedy pointer
/// (rule 82 — the failure must name the flag, at the moment it can be
/// fixed).
fn validate_daemon_endpoint(config: &ServerConfig) -> Result<(), BoxErr> {
    let DaemonTarget::Address { url, proxy } = &config.daemon else {
        // "This computer" has no address to check: its rendezvous is read at
        // each call.
        return Ok(());
    };
    shekyl_rpc_transport::validate_endpoint(url, proxy.as_deref()).map_err(|e| {
        // Both flags are named here; the inner cause identifies the half
        // ("daemon URL ..." / "proxy ..." / "TLS connector ...").
        // Attributing one flag per failure would need either a second
        // validation pass (mislabeling a TLS-root failure as
        // daemon-endpoint) or matching on error text — both worse than
        // naming the pair.
        format!("invalid daemon endpoint configuration (daemon-endpoint / daemon-socks): {e}")
            .into()
    })
}

/// What `daemon-endpoint` discloses at startup: the network-path warning
/// and, for a daemon that is not loopback, the §1 operator statement
/// (`RPC_TRANSPORT_POSTURE.md`, RT-W7) — discouragement at the point of
/// configuration, which for this binary is the moment it starts. Pure; the
/// caller logs each statement. The daemon transport resolves hostnames at the
/// proxy regardless of scheme, so the local-DNS-leak warning never applies
/// here ([`ProxyResolution::AlwaysRemote`]).
///
/// Runs after [`validate_daemon_endpoint`]: an address that is refused is
/// not an endpoint this server uses, so there is nothing to disclose about
/// it. Empty for "this computer", which is no network path.
fn daemon_disclosures(config: &ServerConfig) -> DaemonDisclosures {
    match &config.daemon {
        DaemonTarget::ThisComputer { .. } => DaemonDisclosures::default(),
        DaemonTarget::Address { url, proxy } => {
            shekyl_rpc_transport::network_posture::daemon_disclosures(
                "daemon-endpoint",
                url,
                proxy.as_deref(),
                ProxyResolution::AlwaysRemote,
            )
        }
    }
}

/// The local alternative the listen refusals point at, per platform: a
/// socket file exists on Unix only, so the hint must not name it
/// elsewhere. One definition, defined on every target.
const LOCAL_ENDPOINT_HINT: &str = if cfg!(unix) {
    " (or rpc-socket-file)"
} else {
    ""
};

/// Refuse a listen configuration that would expose the wallet RPC beyond what
/// the operator can see or authenticate (`RPC_TRANSPORT_POSTURE.md`
/// RT-1, RT-2). One function, called on every path that binds, so the two
/// sites cannot disagree.
///
/// - **RT-1:** a wildcard address (`0.0.0.0`, `::`, and their IPv4-mapped
///   forms, folded by `to_canonical`) is refused outright. A wildcard bind is
///   a bind to interfaces that do not exist yet — the VPN that comes up
///   tomorrow, the hotspot, the container bridge — so it is consent on behalf
///   of the operator's future self, which no one-time confirmation can cover.
/// - **RT-2:** `AuthConfig::Disabled` on a non-loopback address is refused.
///   There is no defensible deployment of an unauthenticated wallet RPC that
///   the network can reach; every request, spends included, would be honoured.
///
/// The socket and the pipe carry their authorization in the transport and
/// pass through; the arms are explicit so a new variant has to decide.
///
/// A bind that passes both rules on a non-loopback address is the one
/// posture RT-3 tolerates only until RT-W4: Basic over cleartext, the
/// credential in every request. That is logged as a warning at the same
/// seam, so the operator who chose it is told what it costs.
fn validate_listen(config: &ServerConfig) -> Result<(), BoxErr> {
    let addr = match &config.listen {
        ListenAddr::Tcp(addr) => addr,
        #[cfg(unix)]
        ListenAddr::Uds(_) => return Ok(()),
        #[cfg(windows)]
        ListenAddr::SelfHostedPipe(_) => return Ok(()),
    };
    // One classifier for every Shekyl listener (`shekyl_rpc_transport::listen`),
    // so the wallet and the daemon cannot disagree on what a spelling names.
    use shekyl_rpc_transport::listen::{ListenClass, WILDCARD_REASON};
    match shekyl_rpc_transport::listen::classify_listen(*addr) {
        // The reason is the one copy every listener shares; the remedy is
        // this listener's.
        ListenClass::Wildcard => Err(format!(
            "refusing to bind the wallet RPC to the wildcard address {addr}: {WILDCARD_REASON}. \
             Bind a specific IP address instead: 127.0.0.1 or [::1] for this machine \
             only{LOCAL_ENDPOINT_HINT}, or the address of the one interface your clients are \
             on (which also requires rpc-username and rpc-password in the configuration file)."
        )
        .into()),
        ListenClass::Loopback => Ok(()),
        ListenClass::Addressed => {
            // RT-2. `Basic` always carries a real credential: `BasicCredential` has no
            // public fields and its constructor refuses a blank half, so the seam
            // does not re-inspect it — the guarantee is the type's. The only way
            // to reach this arm is to have asked for no authentication.
            if matches!(config.auth, AuthConfig::Disabled) {
                return Err(format!(
                    "refusing to serve the wallet RPC on {addr} without authentication: the \
                     address is reachable from the network and every request, spends included, \
                     would be honoured. Bind 127.0.0.1 or [::1]{LOCAL_ENDPOINT_HINT}, or set \
                     rpc-username and rpc-password in the configuration file."
                )
                .into());
            }
            // RT-3. Permitted, and said out loud: until the pinned-TLS leg (RT-W4)
            // lands, a network-reachable bind carries the credential in the clear.
            warn!(
                %addr,
                "serving the wallet RPC off loopback with HTTP Basic over cleartext: the \
                 credential travels in every request and any network path between a client \
                 and this host can read it (RPC_TRANSPORT_POSTURE.md RT-3). Keep that path one \
                 you control; the encrypted remote leg is RT-W4."
            );
            Ok(())
        }
    }
}

/// The program's name in the line its start says about its stops.
const PROGRAM: &str = "shekyl-wallet-rpc";

/// A checked configuration whose stops are armed, before anything that
/// needs a clean stop to be released exists: a stop from here on, the bind
/// included, is a clean stop that removes the socket.
pub struct ArmedServer {
    config: ServerConfig,
    stops: Stops,
    notice: Option<String>,
}

/// The checks a start makes before it binds, with nothing bound or created:
/// the daemon endpoint and the listen posture. `config-verify` runs exactly
/// these (`INPUT_GRAMMAR.md` IG-Q63).
///
/// # Errors
/// The configuration is refused.
pub fn check_server_config(config: &ServerConfig) -> Result<(), BoxErr> {
    validate_daemon_endpoint(config)?;
    validate_listen(config)
}

/// Check `config` and arm the stops: the first of the server's two start
/// steps, then [`ArmedServer::serve`].
///
/// The stops are `shekyl_process::stop`'s: `SIGTERM`, `SIGINT` and
/// `SIGHUP` on Unix, every console event on Windows. The first stops the
/// listener, lets in-flight requests finish, and closes the wallet through
/// the `close_wallet` choreography with the shutdown save; a second exits
/// at once with status 130 and no cleanup. An inherited ignore is kept,
/// and the line the start owes for it is [`ArmedServer::notice`], for the
/// binary to say on standard error (IG-14; Rick, 2026-11-20).
///
/// # Errors
/// The configuration is refused, or the stops could not be armed.
pub fn arm_server(config: ServerConfig) -> Result<ArmedServer, BoxErr> {
    let inherited = Inherited::at_start();
    check_server_config(&config)?;
    // The binary's own `daemon-endpoint`, said once at startup. The
    // in-process server (`spawn_in_process_with`) does not repeat it: its
    // host, shekyl-cli, discloses the same address on its own stderr first.
    for warning in daemon_disclosures(&config) {
        warn!("{warning}");
    }
    let notice = inherited.line(PROGRAM);
    let stops = Stops::arm(inherited)
        .map_err(|e| format!("the stop signals could not be registered: {e}"))?;
    Ok(ArmedServer {
        config,
        stops,
        notice,
    })
}

impl ArmedServer {
    /// The IG-14 line this start owes about its stops, naming the program:
    /// on Unix when `SIGINT` was ignored, on Windows on every start.
    #[must_use]
    pub fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }

    /// Bind, serve until the first stop, then close the open wallet.
    ///
    /// # Errors
    /// The listener could not be bound or served.
    pub async fn serve(self) -> Result<(), BoxErr> {
        let Self { config, stops, .. } = self;
        let bound = BoundListener::bind(&config.listen).await?;
        let state = AppState::new(config);
        let app = build_router(state.clone());
        watch_stops(stops, Arc::clone(&state), AfterClose::Return);
        let ready = bound.ready_line("shekyl-wallet-rpc listening")?;
        shekyl_logging::announce(&ready, &ready);
        serve_then_close(bound, app, state).await?;
        Ok(())
    }
}

/// The status a host that ends on its stop exits with once the wallet is
/// closed: 128 plus `SIGINT`, the status a shell gives a program its
/// interrupt ended.
const EXIT_STOPPED: i32 = 130;

/// What the watcher does once the wallet is closed.
#[derive(Clone, Copy)]
enum AfterClose {
    /// Nothing: the host's own serve call returns.
    Return,
    /// End the process with [`EXIT_STOPPED`]. For a host whose main thread
    /// is not waiting on the server (`shekyl-cli`).
    Exit,
}

/// The first stop asks `state`'s server to stop; the serve task closes
/// the open wallet. A second stop is `shekyl_process::stop`'s: it exits at
/// once.
fn watch_stops(mut stops: Stops, state: Arc<AppState>, after: AfterClose) {
    tokio::spawn(async move {
        let FirstStop::Stop(first) = stops.first().await else {
            // A later arm replaced this one. That start has its own watcher.
            return;
        };
        let line = format!(
            "stop requested by {first}: closing the open wallet; a second stop exits at once"
        );
        match after {
            // A server's stop the operator asked for is announced (IG-14).
            AfterClose::Return => shekyl_logging::announce(&format!("{PROGRAM}: {line}"), &line),
            // A hosted server's is its host's to say.
            AfterClose::Exit => info!("{line}"),
        }
        state.shutdown.notify_one();
        if let AfterClose::Exit = after {
            state.closed.notified().await;
            std::process::exit(EXIT_STOPPED);
        }
    });
}

/// Serve until shutdown is requested, then close the open wallet — the one
/// stopping path both hosts share ([`ArmedServer::serve`], and the in-process
/// server behind [`InProcessHandle::shutdown`]). The wallet is closed even
/// when the serve loop failed, and [`AppState::closed`] is notified last.
async fn serve_then_close(
    bound: BoundListener,
    app: Router,
    state: Arc<AppState>,
) -> std::io::Result<()> {
    let served = bound.serve(app, Arc::clone(&state.shutdown)).await;
    crate::lifecycle::close_for_shutdown(&state.tenants).await;
    state.closed.notify_one();
    served
}

/// A listener bound to its address, per platform — **the** `cfg` seam.
///
/// [`ArmedServer::serve`] and [`spawn_in_process_with`] both go through
/// [`Self::bind`] and [`Self::serve`], so there is one place the platform
/// decision is made and one place the serve loop is written. Five `cfg`
/// splits at five call sites would scatter the boundary across a file whose
/// job is the serve loop (`WINDOWS_WALLET_SUPPORT.md` §8.1).
enum BoundListener {
    Tcp(TcpListener),
    /// The socket and the guard that unlinks its path. Owned here so a
    /// failure between `bind` and serve still unlinks the bound socket,
    /// rather than leaving a path that blocks the next bind.
    #[cfg(unix)]
    Uds(UnixListener, UdsCleanup),
    #[cfg(windows)]
    Pipe(PipeListener),
}

impl BoundListener {
    async fn bind(listen: &ListenAddr) -> Result<Self, BoxErr> {
        match listen {
            ListenAddr::Tcp(addr) => Ok(Self::Tcp(TcpListener::bind(addr).await?)),
            #[cfg(unix)]
            ListenAddr::Uds(path) => {
                let bound = bind_uds(path)?;
                // Own the socket path for cleanup BEFORE the runtime takes
                // it, so a refusal there still unlinks the bound socket.
                let cleanup = UdsCleanup(path.clone());
                Ok(Self::Uds(bound.into_tokio()?, cleanup))
            }
            #[cfg(windows)]
            ListenAddr::SelfHostedPipe(pipe) => {
                // The descriptor (owner-only, logon-SID DACL, Medium label)
                // is applied at creation, and `first_pipe_instance(true)`
                // refuses a name someone else already holds — both inside
                // `shekyl-win-sec`. There is no narrowing to order before a
                // listen, as the Unix bind does, and no directory to mirror
                // the Unix private socket directory: the containment that
                // directory gave the Unix socket is rebuilt as the loud
                // create here plus the peer check at the client's dial (§8.1).
                let listener = shekyl_win_sec::OwnerOnlyPipeListener::bind(pipe.name.clone())?;
                Ok(Self::Pipe(PipeListener(listener)))
            }
        }
    }

    /// Where this listener can be reached.
    fn endpoint(&self) -> std::io::Result<InProcessListen> {
        match self {
            Self::Tcp(listener) => Ok(InProcessListen::Tcp(listener.local_addr()?)),
            #[cfg(unix)]
            Self::Uds(_, cleanup) => Ok(InProcessListen::Uds(cleanup.0.clone())),
            #[cfg(windows)]
            Self::Pipe(listener) => Ok(InProcessListen::NamedPipe(listener.0.name().to_owned())),
        }
    }

    /// The line that says where this listener is. The pipe's name is
    /// deliberately left out: it carries the user's SID (see
    /// `SelfHostedPipe`).
    fn ready_line(&self, what: &str) -> std::io::Result<String> {
        Ok(match self {
            Self::Tcp(listener) => format!("{what} (TCP) on {}", listener.local_addr()?),
            #[cfg(unix)]
            Self::Uds(_, cleanup) => format!("{what} (UDS) at {}", cleanup.0.display()),
            #[cfg(windows)]
            Self::Pipe(_) => format!("{what} (named pipe)"),
        })
    }

    /// The hosted server's line, an `info!` event: its host is the program
    /// the operator ran.
    fn log_ready(&self, what: &str) -> std::io::Result<()> {
        info!("{}", self.ready_line(what)?);
        Ok(())
    }

    /// Serve `app` until `shutdown` fires.
    async fn serve(self, app: Router, shutdown: Arc<Notify>) -> std::io::Result<()> {
        let graceful = async move {
            shutdown.notified().await;
        };
        match self {
            Self::Tcp(listener) => {
                axum::serve(listener, app)
                    .with_graceful_shutdown(graceful)
                    .await
            }
            #[cfg(unix)]
            Self::Uds(listener, cleanup) => {
                // Owned by the serve future so the socket is unlinked on any
                // exit path, success or error.
                let _cleanup = cleanup;
                axum::serve(listener, app)
                    .with_graceful_shutdown(graceful)
                    .await
            }
            #[cfg(windows)]
            Self::Pipe(listener) => {
                axum::serve(listener, app)
                    .with_graceful_shutdown(graceful)
                    .await
            }
        }
    }
}

/// The self-hosted pipe as an axum [`Listener`](axum::serve::Listener).
///
/// A named pipe has no accept queue; each connection consumes an instance and
/// the server creates the next one itself. That loop lives in
/// `shekyl_win_sec::OwnerOnlyPipeListener::accept` (it is where the `unsafe`
/// create call is); this wrapper only adapts its fallible accept to axum's
/// infallible one, with exactly the retry shape axum gives its own TCP and
/// UDS listeners: log at `error!`, sleep one second, try again — never tear
/// the server down on an accept error.
#[cfg(windows)]
struct PipeListener(shekyl_win_sec::OwnerOnlyPipeListener);

#[cfg(windows)]
impl axum::serve::Listener for PipeListener {
    type Io = shekyl_win_sec::ConnectedPipe;
    type Addr = ();

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.0.accept().await {
                Ok(io) => return (io, ()),
                Err(e) => {
                    // axum's `handle_accept_error`, verbatim in shape: `error!`
                    // and a one-second sleep (its hyper-inherited EMFILE
                    // reasoning). A fault that persists stays visible once a
                    // second rather than being rate-limited into silence, and
                    // every CLI call in the meantime fails in the open with
                    // `NotFound` or a refusal — including the case where the
                    // listener is trying to reclaim a squatted name.
                    tracing::error!(error = %e, "named pipe accept error; retrying in 1s");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(())
    }
}

/// Bind the wallet RPC's socket at `path` through the listeners' shared
/// bind (`shekyl_rpc_transport::listen::bind_owner_only_socket`): its
/// directory this account's alone, a socket a stopped server left replaced,
/// then the socket bound, 0600, and only then listening. The UDS deployments
/// run with HTTP auth disabled ("auth rides the transport",
/// `wallet_rpc.yaml`), which is sound only because nothing but this account
/// can ever connect to it.
///
/// A missing directory is made owner-only, and a umask that strips the
/// owner's bits refuses (`shekyl_os_account::create_account_dir_all`); an existing one is held
/// to the shared rule, and the refusal names what the directory is.
///
/// Unix only, with no Windows counterpart: `CreateNamedPipe` takes the
/// descriptor at creation (`WINDOWS_WALLET_SUPPORT.md` §8.1).
#[cfg(unix)]
fn bind_uds(path: &Path) -> Result<shekyl_rpc_transport::listen::OwnerOnlyListener, BoxErr> {
    use shekyl_rpc_transport::listen::{bind_owner_only_socket, ListenerLine};
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if let Err(e) = std::fs::symlink_metadata(dir) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(format!("{}: {e}", dir.display()).into());
        }
        shekyl_os_account::create_account_dir_all(dir)?;
    }
    // A socket a server still answers on is not taken over; one a stopped
    // or killed server left was removed. Anything else at the path is not
    // this server's to remove.
    match bind_owner_only_socket(path) {
        Ok(bound) => Ok(bound),
        Err(refusal) => Err(refusal
            .line(
                path,
                dir,
                &ListenerLine {
                    listener: "the wallet RPC's socket",
                    holder: "a server",
                    answers: &format!("another server answers on {}", path.display()),
                    no_directory: &format!(
                        "{} names no directory to hold the socket",
                        path.display()
                    ),
                },
            )
            .into()),
    }
}

/// Per-process spawn counter, so multiple in-process servers in one process
/// (test binaries; future multi-session hosts) never share an endpoint name.
/// Feeds the UDS directory name on Unix and the pipe name on Windows.
fn next_spawn() -> u64 {
    static SPAWN_COUNTER: AtomicU64 = AtomicU64::new(0);
    SPAWN_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Where an in-process server listens.
#[derive(Clone)]
pub enum InProcessListen {
    /// Loopback TCP (explicit opt-in via [`spawn_in_process_with`]).
    Tcp(SocketAddr),
    /// Unix domain socket (the secure default of [`spawn_in_process`]).
    #[cfg(unix)]
    Uds(PathBuf),
    /// The owner-only named pipe (the secure default of
    /// [`spawn_in_process`] on Windows). The in-process client dials this
    /// name through `shekyl_win_sec::open_verified`, which refuses it before
    /// any byte is written unless the owner and integrity are ours.
    #[cfg(windows)]
    NamedPipe(String),
}

/// Manual: the pipe name embeds the user's SID and is redacted, as in
/// `SelfHostedPipe`; the other arms render as derived.
impl std::fmt::Debug for InProcessListen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(addr) => f.debug_tuple("Tcp").field(addr).finish(),
            #[cfg(unix)]
            Self::Uds(path) => f.debug_tuple("Uds").field(path).finish(),
            #[cfg(windows)]
            Self::NamedPipe(_) => f.write_str("NamedPipe(<redacted>)"),
        }
    }
}

/// Handle returned by [`spawn_in_process`] / [`spawn_in_process_with`].
pub struct InProcessHandle {
    /// Shared state (call `shutdown.notify_one()` via [`Self::shutdown`]).
    state: Arc<AppState>,
    /// Background serve task.
    join: JoinHandle<Result<(), std::io::Error>>,
    /// Where the server listens.
    pub listen: InProcessListen,
    /// Private directory and the lock held for its life
    /// ([`spawn_in_process`] only).
    #[cfg(unix)]
    socket: Option<private_socket::PrivateDir>,
}

impl InProcessHandle {
    /// Make the process's stops (`shekyl_process::stop`: SIGTERM, SIGINT,
    /// SIGHUP; on Windows every console event) stop this server, close the
    /// open wallet, and then end the process with status 130; a second
    /// stop ends it at once. For a host whose main thread is not waiting
    /// on the server (`shekyl-cli`), which read `inherited` before
    /// anything installed a handler. Call from inside the host's runtime.
    ///
    /// # Errors
    ///
    /// The stops could not be armed.
    pub fn exit_on_stop_signal(&self, inherited: Inherited) -> std::io::Result<()> {
        let stops = Stops::arm(inherited)?;
        watch_stops(stops, Arc::clone(&self.state), AfterClose::Exit);
        Ok(())
    }

    /// Request graceful shutdown and wait for the serve task to finish; the
    /// serve task closes the open wallet before it ends. Then the private
    /// socket directory [`spawn_in_process`] made is removed, whatever the
    /// serve task's end; a pipe leaves nothing behind.
    ///
    /// # Errors
    ///
    /// The serve task's failure, the directory's removal failing, or both.
    /// A removal failure names its path, including when the serve task
    /// failed as well, so a directory left behind is said.
    pub async fn shutdown(self) -> Result<(), BoxErr> {
        self.state.shutdown.notify_one();
        let served = self.join.await;
        let removed = {
            #[cfg(unix)]
            {
                self.socket.map(|socket| socket.remove().map(|_| ()))
            }
            #[cfg(not(unix))]
            {
                None
            }
        };
        combine_shutdown(served, removed)
    }

    /// UDS socket path (`None` when listening on TCP).
    #[cfg(unix)]
    pub fn socket_path(&self) -> Option<&Path> {
        match &self.listen {
            InProcessListen::Uds(path) => Some(path),
            InProcessListen::Tcp(_) => None,
        }
    }

    /// Named-pipe name (`None` when listening on TCP).
    #[cfg(windows)]
    pub fn pipe_name(&self) -> Option<&str> {
        match &self.listen {
            InProcessListen::NamedPipe(name) => Some(name),
            InProcessListen::Tcp(_) => None,
        }
    }
}

/// Spawn an in-process server on a private local endpoint.
///
/// Shape B entry point: `shekyl-cli` one-shot / REPL hosts a server without
/// a subprocess. Never binds TCP: an auth-less loopback port would let any
/// local process drive the open wallet. The daemon is not dialed until
/// refresh/send, so an unreachable daemon is fine for offline commands.
///
/// **Unix:** the socket lives in a fresh 0700 directory (under
/// `$XDG_RUNTIME_DIR`, temp-dir fallback), published under its final name
/// only while this process holds that directory's lock, and is itself 0600,
/// so only the owning user can connect — that filesystem gate is why
/// [`AuthConfig::Disabled`] is sound here.
///
/// **Windows:** an owner-only named pipe, `\\.\pipe\shekyl-wallet-<sid>-<pid>-<n>`,
/// created with its descriptor and with `first_pipe_instance(true)`, so a
/// name already held fails loud rather than being joined. The 0700
/// directory's containment — nobody else at the name we dial — has no pipe
/// analogue, so `AuthConfig::Disabled` is sound here only together with the
/// client's peer check at the dial (`shekyl_win_sec::open_verified`), which
/// is why that check is load-bearing on this path
/// (`WINDOWS_WALLET_SUPPORT.md` §8.1).
pub async fn spawn_in_process(
    wallet_dir: PathBuf,
    network: Network,
    daemon: DaemonTarget,
    tor_file: shekyl_engine_core::TorFile,
) -> Result<InProcessHandle, BoxErr> {
    #[cfg(unix)]
    {
        let socket = private_socket::create(next_spawn())?;
        let listen = ListenAddr::Uds(socket.path().join(SOCKET_FILE));
        match spawn_in_process_with(private_config(
            listen, wallet_dir, network, daemon, tor_file,
        ))
        .await
        {
            Ok(mut handle) => {
                handle.socket = Some(socket);
                Ok(handle)
            }
            Err(error) => {
                // Nothing is listening. The directory was published; remove it
                // now. Drop only releases the lock, and the next start's sweep
                // is the backstop when this removal fails.
                match socket.remove() {
                    Ok(_) => Err(error),
                    Err(removed) => Err(format!("{error}; {removed}").into()),
                }
            }
        }
    }
    #[cfg(windows)]
    {
        let owner = shekyl_win_sec::current_user_sid()?;
        let name = shekyl_win_sec::self_hosted_pipe_name(&owner, next_spawn());
        let listen = ListenAddr::SelfHostedPipe(SelfHostedPipe { name });
        spawn_in_process_with(private_config(
            listen, wallet_dir, network, daemon, tor_file,
        ))
        .await
    }
}

/// The auth-less configuration [`spawn_in_process`] uses on every platform;
/// only `listen` differs, and it is the caller's.
fn private_config(
    listen: ListenAddr,
    wallet_dir: PathBuf,
    network: Network,
    daemon: DaemonTarget,
    tor_file: shekyl_engine_core::TorFile,
) -> ServerConfig {
    ServerConfig {
        listen,
        wallet_dir,
        network,
        daemon,
        auth: AuthConfig::Disabled,
        kdf: KdfParams::default(),
        tor_file,
    }
}

/// Spawn an in-process server with a full [`ServerConfig`] (tests / CLI).
///
/// Honors `config.listen`: UDS sockets are chmodded 0600 after bind; TCP
/// is served as configured, within [`validate_listen`]'s refusals — auth-less
/// TCP is accepted on loopback only, and never on a wildcard address (prefer
/// [`spawn_in_process`]).
pub async fn spawn_in_process_with(config: ServerConfig) -> Result<InProcessHandle, BoxErr> {
    validate_daemon_endpoint(&config)?;
    validate_listen(&config)?;
    let bound = BoundListener::bind(&config.listen).await?;
    let state = AppState::new(config);
    let app = build_router(state.clone());

    let listen = bound.endpoint()?;
    bound.log_ready("shekyl-wallet-rpc in-process server started")?;
    let join = tokio::spawn(serve_then_close(bound, app, Arc::clone(&state)));
    Ok(InProcessHandle {
        state,
        join,
        listen,
        #[cfg(unix)]
        socket: None,
    })
}

/// The serve task's end and the directory removal, as one error when both fail.
///
/// The removal's error already names its path. Dropping it because the serve
/// task also failed is how a directory left behind went unsaid.
fn combine_shutdown(
    served: Result<Result<(), std::io::Error>, tokio::task::JoinError>,
    removed: Option<std::io::Result<()>>,
) -> Result<(), BoxErr> {
    let served = match served {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(BoxErr::from(error)),
        Err(error) => Err(BoxErr::from(error)),
    };
    let removed = match removed {
        None | Some(Ok(())) => Ok(()),
        Some(Err(error)) => Err(error),
    };
    combine_ends(served, removed)
}

fn combine_ends(
    served: Result<(), BoxErr>,
    removed: Result<(), std::io::Error>,
) -> Result<(), BoxErr> {
    match (served, removed) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(served), Ok(())) => Err(served),
        (Ok(()), Err(removed)) => Err(removed.into()),
        (Err(served), Err(removed)) => Err(format!("{served}; {removed}").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both failures are one error, and the removal's path survives the
    /// serve task's failure. Red edit: return `served` and drop `removed`.
    #[test]
    fn a_removal_failure_is_kept_when_the_serve_task_also_fails() {
        let removal = || {
            Err(std::io::Error::other(
                "/tmp/shekyl-rpc-9-1: directory not empty",
            ))
        };
        assert!(combine_ends(Ok(()), Ok(())).is_ok());
        let served = combine_ends(Err("the serve task ended".into()), Ok(())).unwrap_err();
        assert!(served.to_string().contains("the serve task ended"));
        let removed = combine_ends(Ok(()), removal()).unwrap_err();
        assert!(removed.to_string().contains("shekyl-rpc-9-1"), "{removed}");
        let both = combine_ends(Err("the serve task ended".into()), removal()).unwrap_err();
        let text = both.to_string();
        assert!(text.contains("the serve task ended"), "{text}");
        assert!(text.contains("shekyl-rpc-9-1"), "{text}");
    }

    use tracing::instrument::WithSubscriber as _;

    /// The credential-redaction pin: no `Debug` of server configuration —
    /// the shapes that reach logs and panic output — renders the digest
    /// credentials a daemon address may carry, a proxy userinfo, or the
    /// `rpc-password` value (rules 30/35).
    #[test]
    fn debug_of_server_state_never_renders_credentials() {
        let endpoint = DaemonTarget::Address {
            url: "http://user:hunter2@127.0.0.1:28581/prefix".into(),
            proxy: Some("socks5h://puser:swordfish@127.0.0.1:9050".into()),
        };
        let config = ServerConfig {
            listen: ListenAddr::Tcp(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
            wallet_dir: std::path::PathBuf::from("."),
            network: Network::Stagenet,
            daemon: endpoint.clone(),
            auth: AuthConfig::Basic(
                crate::auth::BasicCredential::new("rpcuser", "opensesame").expect("a credential"),
            ),
            kdf: KdfParams::default(),
            tor_file: TorFile::discover(),
        };

        for rendered in [
            format!("{endpoint:?}"),
            format!("{config:?}"),
            format!("{:?}", config.auth),
        ] {
            for secret in ["hunter2", "swordfish", "opensesame"] {
                assert!(
                    !rendered.contains(secret),
                    "a Debug render leaked {secret:?}: {rendered}"
                );
            }
        }
        // The redaction is visible (not silently dropping the field), and
        // the non-secret parts survive for diagnostics.
        assert!(format!("{endpoint:?}").contains("<redacted>"));
        assert!(format!("{endpoint:?}").contains("127.0.0.1:28581"));
        assert!(format!("{:?}", config.auth).contains("rpcuser"));
    }

    /// A config with the given listen address and auth; everything else is
    /// inert for the listen refusals.
    fn listen_config(listen: &str, auth: AuthConfig) -> ServerConfig {
        ServerConfig {
            listen: ListenAddr::Tcp(listen.parse().expect("listen parses")),
            wallet_dir: std::path::PathBuf::from("."),
            network: Network::Stagenet,
            daemon: DaemonTarget::address("http://127.0.0.1:1"),
            auth,
            kdf: KdfParams::default(),
            tor_file: TorFile::discover(),
        }
    }

    fn basic() -> AuthConfig {
        AuthConfig::Basic(crate::auth::BasicCredential::new("user", "pass").expect("a credential"))
    }

    /// RT-1: every wildcard spelling is refused, with auth *enabled* so the
    /// refusal is provably the wildcard rule and not RT-2.
    #[test]
    fn wildcard_binds_are_refused_even_with_auth() {
        for addr in ["0.0.0.0:29500", "[::]:29500", "[::ffff:0.0.0.0]:29500"] {
            let err = validate_listen(&listen_config(addr, basic()))
                .expect_err("wildcard bind must be refused")
                .to_string();
            assert!(err.contains("wildcard"), "{addr}: {err}");
            assert!(
                err.contains("127.0.0.1"),
                "{addr}: must say what to do: {err}"
            );
        }
    }

    /// RT-2: an unauthenticated, network-reachable bind is refused — the
    /// IPv6 and IPv4-mapped spellings included, so the rule cannot be
    /// sidestepped by notation.
    #[test]
    fn unauthenticated_non_loopback_bind_is_refused() {
        for addr in [
            "192.0.2.1:29500",
            "[2001:db8::1]:29500",
            "[::ffff:192.0.2.1]:29500",
        ] {
            let err = validate_listen(&listen_config(addr, AuthConfig::Disabled))
                .expect_err("auth-less non-loopback bind must be refused")
                .to_string();
            assert!(err.contains("without authentication"), "{addr}: {err}");
            assert!(
                err.contains("rpc-username"),
                "{addr}: must say what to do: {err}"
            );
        }
    }

    /// The complements, so the refusals are seen to be narrow: loopback with
    /// auth disabled passes (the in-process default's posture), and an
    /// addressed bind with auth passes validation (binding is not attempted
    /// here — the address is TEST-NET).
    #[test]
    fn loopback_and_authenticated_binds_pass_validation() {
        for addr in ["127.0.0.1:0", "[::1]:0", "[::ffff:127.0.0.1]:0"] {
            validate_listen(&listen_config(addr, AuthConfig::Disabled))
                .unwrap_or_else(|e| panic!("{addr} with auth disabled must pass: {e}"));
        }
        validate_listen(&listen_config("192.0.2.1:29500", basic()))
            .expect("an addressed bind with auth passes validation");
        #[cfg(unix)]
        {
            let mut socket = listen_config("127.0.0.1:0", AuthConfig::Disabled);
            socket.listen = ListenAddr::Uds("/tmp/x.sock".into());
            validate_listen(&socket).expect("the socket carries its own authorization");
        }
    }

    /// The wiring, not the predicate: both bind paths must consult
    /// `validate_listen`. The edit that turns each half red is deleting the
    /// call at that site. The oracle is the wildcard message itself, not a
    /// bare `is_err()`: `validate_daemon_endpoint` runs first on both paths,
    /// and any refusal of the fixture's daemon address would otherwise
    /// satisfy the test with the listen check gone. `arm_server` refuses
    /// before anything binds.
    #[tokio::test]
    async fn both_bind_paths_refuse_a_wildcard_before_binding() {
        let config = listen_config("0.0.0.0:0", basic());
        let Err(err) = spawn_in_process_with(config.clone()).await else {
            panic!("spawn_in_process_with must refuse a wildcard bind");
        };
        let err = err.to_string();
        assert!(err.contains("wildcard"), "spawn_in_process_with: {err}");
        let Err(err) = arm_server(config) else {
            panic!("arm_server must refuse a wildcard bind");
        };
        let err = err.to_string();
        assert!(err.contains("wildcard"), "arm_server: {err}");
    }

    /// RT-W7's binary-specific facts — the predicate itself is pinned in the
    /// transport module: the label names the flag, the loopback default is
    /// silent, and the daemon transport resolves at the proxy regardless of
    /// scheme, so a `socks5://` proxy is not a DNS leak here and must not be
    /// reported as one.
    #[test]
    fn daemon_disclosures_name_the_flag_and_never_a_dns_leak() {
        let mut config = listen_config("127.0.0.1:0", AuthConfig::Disabled);
        assert!(
            daemon_disclosures(&config).is_empty(),
            "the loopback default is silent"
        );
        config.daemon = DaemonTarget::ThisComputer {
            network: Network::Stagenet,
        };
        assert!(
            daemon_disclosures(&config).is_empty(),
            "this computer is no network path"
        );

        config.daemon = DaemonTarget::address("http://node.example.com:11029");
        let direct = daemon_disclosures(&config);
        let path = direct.path.as_deref().expect("path warning");
        assert!(path.contains("daemon-endpoint"), "{path}");
        assert!(direct.operator.is_some(), "{direct:?}");

        config.daemon = DaemonTarget::Address {
            url: "http://node.example.com:11029".into(),
            proxy: Some("socks5://127.0.0.1:9050".into()),
        };
        let proxied = daemon_disclosures(&config);
        assert!(
            proxied.path.is_none(),
            "the scan transport resolves at the proxy: {proxied:?}"
        );
        assert!(proxied.operator.is_some(), "{proxied:?}");
    }

    /// The wiring: the binary's start (`arm_server`, then `serve`) logs the
    /// disclosure before it binds. The edit that turns this red is deleting
    /// the `daemon_disclosures` loop in `arm_server`. This test holds the
    /// listen port first, so `serve` returns (address in use) right after the
    /// disclosure — no timer to
    /// wait out, and "said before bound" is pinned with it.
    ///
    /// The subscriber rides the future (`with_subscriber`) rather than the
    /// thread (`subscriber::set_default`): it is the default on whatever
    /// polls it. Both work here — an awaited future is polled by `block_on`
    /// on this thread, under either runtime flavor — but that is an ambient
    /// fact about the runtime, and no assertion in this test checks it. A
    /// capture that cannot be broken by where the future runs needs one
    /// fewer thing held true elsewhere.
    #[tokio::test]
    async fn the_start_logs_the_operator_statement_before_binding() {
        #[derive(Clone)]
        struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("sink").extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let sink = Sink(Arc::new(std::sync::Mutex::new(Vec::new())));
        let writer = sink.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();

        let held = std::net::TcpListener::bind("127.0.0.1:0").expect("hold a port");
        let port = held.local_addr().expect("local addr").port();
        let mut config = listen_config(&format!("127.0.0.1:{port}"), AuthConfig::Disabled);
        config.daemon = DaemonTarget::address("http://203.0.113.7:11029");
        let err = async { arm_server(config)?.serve().await }
            .with_subscriber(subscriber)
            .await
            .expect_err("the held port refuses the bind");
        drop(held);

        let logged = String::from_utf8(sink.0.lock().expect("sink").clone()).expect("utf-8");
        assert!(
            logged.contains("operates that daemon"),
            "the statement precedes the bind that failed with {err}: {logged}"
        );
    }

    /// The browser boundary's predicate: the JSON media type with or without
    /// parameters, any case, and nothing a browser can send without a
    /// preflight. The integration test in `tests/http_get_version.rs`
    /// proves the wiring (a `text/plain` POST is 415).
    #[test]
    fn only_the_json_media_type_passes_the_gate() {
        for ok in [
            "application/json",
            "application/json; charset=utf-8",
            "Application/JSON",
            " application/json ;charset=utf-8",
        ] {
            assert!(is_json_media_type(ok), "{ok:?}");
        }
        for bad in [
            "text/plain",
            "text/plain;charset=UTF-8",
            "application/x-www-form-urlencoded",
            "multipart/form-data; boundary=x",
            "application/jsonx",
            "application/json-rpc",
            "",
        ] {
            assert!(!is_json_media_type(bad), "{bad:?}");
        }
    }

    /// The rebinding half's predicate: IP literals and `localhost`, with or
    /// without a port, any case; never a name that DNS could re-point.
    #[test]
    fn only_ip_literals_and_localhost_are_unrebindable() {
        for ok in [
            "127.0.0.1",
            "127.0.0.1:29500",
            "[::1]",
            "[::1]:29500",
            "localhost",
            "LOCALHOST:29500",
            "192.168.1.20:29500",
        ] {
            assert!(host_is_unrebindable(ok), "{ok:?}");
        }
        for bad in [
            "",
            "evil.example",
            "evil.example:29500",
            "localhost.evil.example",
            "127.0.0.1.evil.example",
            "[evil.example]:29500",
            "::1",
            // Non-authority syntax: the boundary must not be parsable around.
            "[::1]evil",
            "[::1]:notaport",
            "[::1]:",
            "127.0.0.1:notaport",
            "localhost:",
            "localhost:29500:evil",
        ] {
            assert!(!host_is_unrebindable(bad), "{bad:?}");
        }
    }
}
