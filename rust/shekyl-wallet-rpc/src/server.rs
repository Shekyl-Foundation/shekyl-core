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
//! construction, shared by [`run_server`] and [`spawn_in_process_with`] so the
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
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

use crate::auth::{require_basic_auth, AuthConfig};
use crate::handlers;
use crate::tenant::{DaemonEndpoint, TenantState};
use crate::types::{JsonRpcRequest, JsonRpcResponse};

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
    /// Not a `--rpc-bind` form: [`ListenAddr::parse`] never produces it, and
    /// [`SelfHostedPipe`] has no public constructor, so no string and no
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

impl ListenAddr {
    /// Parse a listen string: `uds:///path` (Unix) or a numeric `IP:PORT`
    /// (`127.0.0.1:29500`, `[::1]:29500`). Hostnames are not resolved —
    /// a listen address names an interface, and resolving one at bind time
    /// would make the bind depend on a resolver answer — so the refusal
    /// says so rather than leaving `localhost:29500` to a syntax error.
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some(path) = s.strip_prefix("uds://") {
            return Self::uds(path);
        }
        shekyl_rpc_transport::listen::parse_listen_addr(s)
            .map(Self::Tcp)
            .map_err(|e| e.to_string())
    }

    /// The `uds://` form on Unix: a non-empty path.
    #[cfg(unix)]
    fn uds(path: &str) -> Result<Self, String> {
        if path.is_empty() {
            return Err("uds:// path must not be empty".into());
        }
        Ok(Self::Uds(PathBuf::from(path)))
    }

    /// The `uds://` form on Windows: refused, naming the platform.
    ///
    /// Same parse-surface class as the CLI's `--rpc-url`: a string match that
    /// compiles everywhere and offers a transport the platform lacks. With no
    /// `Uds` variant here, this arm cannot return one. The standalone server
    /// on Windows listens on TCP (the external `http://` form, unchanged).
    #[cfg(windows)]
    fn uds(_path: &str) -> Result<Self, String> {
        Err(
            "uds:// listen addresses are not available on Windows: a Unix domain socket has \
             no Windows form. The Windows wallet is self-hosted (run shekyl-cli without \
             --rpc-url); a standalone shekyl-wallet-rpc listens on IP:PORT with --rpc-login."
                .into(),
        )
    }
}

/// Server configuration.
#[derive(Clone)]
pub struct ServerConfig {
    /// Bind address (TCP, UDS, or the in-process pipe).
    pub listen: ListenAddr,
    /// Directory for wallet files.
    pub wallet_dir: PathBuf,
    /// Network every create/open binds to.
    pub network: Network,
    /// Daemon JSON-RPC base URL (e.g. `http://127.0.0.1:28581`).
    pub daemon_address: String,
    /// SOCKS5h proxy for the daemon transport (CLI `--proxy`); `None` = direct.
    pub proxy: Option<String>,
    /// HTTP basic auth (disabled for UDS-by-default deployments).
    pub auth: AuthConfig,
    /// Argon2id cost for `create_wallet` / password rotation.
    /// Production uses [`KdfParams::default`]; tests may clamp.
    pub kdf: KdfParams,
}

/// Manual (not derived): `daemon_address` may carry digest credentials in
/// its authority, so it renders through the transport's `redacted_endpoint`
/// (`AuthConfig` redacts its own password; the remaining fields are inert).
impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("listen", &self.listen)
            .field("wallet_dir", &self.wallet_dir)
            .field("network", &self.network)
            .field(
                "daemon_address",
                &shekyl_rpc_transport::redacted_endpoint(&self.daemon_address),
            )
            .field(
                "proxy",
                &self
                    .proxy
                    .as_deref()
                    .map(shekyl_rpc_transport::redacted_endpoint),
            )
            .field("auth", &self.auth)
            .field("kdf", &self.kdf)
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
                DaemonEndpoint {
                    address: config.daemon_address,
                    proxy: config.proxy,
                },
            )),
            auth: Arc::new(config.auth),
            kdf: config.kdf,
            shutdown: Arc::new(Notify::new()),
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
pub fn build_router(state: Arc<AppState>) -> Router {
    let auth = Arc::clone(&state.auth);
    Router::new()
        .route("/", post(json_rpc_handler))
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
#[cfg(unix)]
struct UdsCleanup(PathBuf);

#[cfg(unix)]
impl Drop for UdsCleanup {
    fn drop(&mut self) {
        drop(std::fs::remove_file(&self.0));
    }
}

/// Refuse a malformed `--daemon-address` / `--proxy` at startup (offline
/// shape check only — an unreachable daemon stays fine for offline
/// commands). Deferred to first use, a bad flag would surface on
/// `open_wallet` as "daemon unreachable": the wrong remedy pointer
/// (rule 82 — the failure must name the flag, at the moment it can be
/// fixed).
fn validate_daemon_endpoint(config: &ServerConfig) -> Result<(), BoxErr> {
    shekyl_rpc_transport::validate_endpoint(&config.daemon_address, config.proxy.as_deref())
        .map_err(|e| {
            // Both flags are named here; the inner cause identifies the half
            // ("daemon URL ..." / "--proxy ..." / "TLS connector ...").
            // Attributing one flag per failure would need either a second
            // validation pass (mislabeling a TLS-root failure as
            // --daemon-address) or matching on error text — both worse than
            // naming the pair.
            format!("invalid daemon endpoint configuration (--daemon-address / --proxy): {e}")
                .into()
        })
}

/// The local alternative the listen refusals point at, per platform: a
/// `uds://` socket exists on Unix only, so the hint must not name it
/// elsewhere. One definition, defined on every target.
const LOCAL_ENDPOINT_HINT: &str = if cfg!(unix) {
    " (or a uds:///path socket)"
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
    use shekyl_rpc_transport::listen::ListenClass;
    match shekyl_rpc_transport::listen::classify_listen(*addr) {
        ListenClass::Wildcard => Err(format!(
            "refusing to bind the wallet RPC to the wildcard address {addr}: 0.0.0.0 and :: \
             bind every interface, including ones that do not exist yet (a VPN that comes up \
             later, a hotspot, a container bridge). Bind a specific IP address instead: \
             127.0.0.1 or [::1] for this machine only{LOCAL_ENDPOINT_HINT}, or the address \
             of the one interface your clients are on (which also requires --rpc-login \
             NAME:PASSWORD)."
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
                    "refusing to serve the wallet RPC on {addr} without authentication (--rpc-login \
                     not set, or --disable-rpc-login given): the address is reachable from the \
                     network and every request, spends included, would be honoured. Bind 127.0.0.1 \
                     or [::1]{LOCAL_ENDPOINT_HINT}, or set --rpc-login NAME:PASSWORD."
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

/// Run the server until shutdown (SIGINT / SIGTERM via the Notify, or
/// process exit). Blocks the calling task.
pub async fn run_server(config: ServerConfig) -> Result<(), BoxErr> {
    validate_daemon_endpoint(&config)?;
    validate_listen(&config)?;
    let bound = BoundListener::bind(&config.listen).await?;
    let state = AppState::new(config);
    let app = build_router(state.clone());
    let shutdown = state.shutdown.clone();

    bound.log_ready("shekyl-wallet-rpc listening")?;
    bound.serve(app, shutdown).await?;
    Ok(())
}

/// A listener bound to its address, per platform — **the** `cfg` seam.
///
/// [`run_server`] and [`spawn_in_process_with`] both go through
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
                prepare_uds_path(path)?;
                let listener = UnixListener::bind(path)?;
                // Own the socket path for cleanup BEFORE restrict_socket_perms
                // so a chmod failure still unlinks the bound socket.
                let cleanup = UdsCleanup(path.clone());
                restrict_socket_perms(path)?;
                Ok(Self::Uds(listener, cleanup))
            }
            #[cfg(windows)]
            ListenAddr::SelfHostedPipe(pipe) => {
                // The descriptor (owner-only, logon-SID DACL, Medium label)
                // is applied at creation, and `first_pipe_instance(true)`
                // refuses a name someone else already holds — both inside
                // `shekyl-win-sec`. There is no post-bind step to mirror
                // `restrict_socket_perms`, and no directory to mirror
                // `private_socket_dir`: the containment those gave the Unix
                // socket is rebuilt as the loud create here plus the peer
                // check at the client's dial (§8.1).
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

    /// One `info!` line per transport. The pipe's name is deliberately not
    /// logged: it carries the user's SID (see [`SelfHostedPipe`]).
    fn log_ready(&self, what: &str) -> std::io::Result<()> {
        match self {
            Self::Tcp(listener) => {
                let local = listener.local_addr()?;
                info!(%local, "{what} (TCP)");
            }
            #[cfg(unix)]
            Self::Uds(_, cleanup) => {
                info!(path = %cleanup.0.display(), "{what} (UDS)");
            }
            #[cfg(windows)]
            Self::Pipe(_) => {
                info!("{what} (named pipe)");
            }
        }
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

#[cfg(unix)]
fn prepare_uds_path(path: &Path) -> Result<(), BoxErr> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Restrict a freshly bound UDS socket to owner-only (0600).
///
/// The wallet RPC's UDS deployments run with HTTP auth disabled ("auth
/// rides the transport", `wallet_rpc.yaml`), which is only sound if the
/// socket itself is permission-gated. Applied after `bind`; the in-process
/// default additionally parents the socket in a 0700 directory so the
/// pre-chmod window is unreachable.
///
/// Unix only, with no Windows counterpart: `CreateNamedPipe` takes the
/// descriptor at creation, so there is no post-bind step to port
/// (`WINDOWS_WALLET_SUPPORT.md` §8.1).
#[cfg(unix)]
fn restrict_socket_perms(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// Per-process spawn counter, so multiple in-process servers in one process
/// (test binaries; future multi-session hosts) never share an endpoint name.
/// Feeds the UDS directory name on Unix and the pipe name on Windows.
fn next_spawn() -> u64 {
    static SPAWN_COUNTER: AtomicU64 = AtomicU64::new(0);
    SPAWN_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Create the private, per-spawn runtime directory that holds the
/// in-process UDS socket.
///
/// Prefers `$XDG_RUNTIME_DIR` (user-private tmpfs per the XDG base-dir
/// spec; `WALLET_REWRITE_PLAN.md` Phase 3 deliverables), falling back to
/// the system temp dir. Created 0700. The name is pid- **and**
/// spawn-counter-scoped ([`next_spawn`]). A pre-existing entry at the path
/// is removed if we own it; if removal fails (e.g. an attacker-planted entry
/// under a sticky-bit temp dir) creation fails loud rather than reusing it.
///
/// Unix only. Its four jobs on Windows: access control → the pipe's DACL;
/// collision avoidance → the per-spawn pipe name; stale-directory cleanup →
/// no analogue (a pipe is a kernel object); **containment** — nobody else
/// can place an object at the name we are about to dial — → the loud
/// first-instance create plus the client's peer check
/// (`WINDOWS_WALLET_SUPPORT.md` §8.1, corrected 2026-08-20).
#[cfg(unix)]
fn private_socket_dir() -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;

    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!(
        "shekyl-rpc-{}-{}",
        std::process::id(),
        next_spawn()
    ));
    // Stale leftover from a crashed run with a recycled pid: remove if ours.
    drop(std::fs::remove_dir_all(&dir));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
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
/// [`SelfHostedPipe`]; the other arms render as derived.
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
    /// Private socket dir removed on shutdown ([`spawn_in_process`] only).
    #[cfg(unix)]
    socket_dir: Option<PathBuf>,
}

impl InProcessHandle {
    /// Request graceful shutdown and wait for the serve task to finish.
    pub async fn shutdown(self) -> Result<(), BoxErr> {
        self.state.shutdown.notify_one();
        self.join.await??;
        // The serve task's UdsCleanup already unlinked the socket; remove
        // the private dir that held it. A pipe leaves nothing behind.
        #[cfg(unix)]
        if let Some(dir) = &self.socket_dir {
            drop(std::fs::remove_dir(dir));
        }
        Ok(())
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
/// refresh/send, so an unreachable `daemon_address` is fine for offline
/// commands.
///
/// **Unix:** the socket lives in a fresh 0700, pid-scoped directory (under
/// `$XDG_RUNTIME_DIR`, temp-dir fallback) and is itself 0600, so only the
/// owning user can connect — that filesystem gate is why
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
    daemon_address: String,
    proxy: Option<String>,
) -> Result<InProcessHandle, BoxErr> {
    #[cfg(unix)]
    {
        let socket_dir = private_socket_dir()?;
        let listen = ListenAddr::Uds(socket_dir.join("wallet-rpc.sock"));
        let mut handle = spawn_in_process_with(private_config(
            listen,
            wallet_dir,
            network,
            daemon_address,
            proxy,
        ))
        .await?;
        handle.socket_dir = Some(socket_dir);
        Ok(handle)
    }
    #[cfg(windows)]
    {
        let owner = shekyl_win_sec::current_user_sid()?;
        let name = shekyl_win_sec::self_hosted_pipe_name(&owner, next_spawn());
        let listen = ListenAddr::SelfHostedPipe(SelfHostedPipe { name });
        spawn_in_process_with(private_config(
            listen,
            wallet_dir,
            network,
            daemon_address,
            proxy,
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
    daemon_address: String,
    proxy: Option<String>,
) -> ServerConfig {
    ServerConfig {
        listen,
        wallet_dir,
        network,
        daemon_address,
        proxy,
        auth: AuthConfig::Disabled,
        kdf: KdfParams::default(),
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
    let shutdown = state.shutdown.clone();

    let listen = bound.endpoint()?;
    bound.log_ready("shekyl-wallet-rpc in-process server started")?;
    let join = tokio::spawn(bound.serve(app, shutdown));
    Ok(InProcessHandle {
        state,
        join,
        listen,
        #[cfg(unix)]
        socket_dir: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant::DaemonEndpoint;

    /// The credential-redaction pin: no `Debug` of server configuration —
    /// the shapes that reach logs and panic output — renders the digest
    /// credentials a daemon address may carry, a proxy userinfo, or the
    /// `--rpc-login` password (rules 30/35).
    #[test]
    fn debug_of_server_state_never_renders_credentials() {
        let endpoint = DaemonEndpoint {
            address: "http://user:hunter2@127.0.0.1:28581/prefix".into(),
            proxy: Some("socks5h://puser:swordfish@127.0.0.1:9050".into()),
        };
        let config = ServerConfig {
            listen: ListenAddr::Tcp(std::net::SocketAddr::from(([127, 0, 0, 1], 0))),
            wallet_dir: std::path::PathBuf::from("."),
            network: Network::Stagenet,
            daemon_address: endpoint.address.clone(),
            proxy: endpoint.proxy.clone(),
            auth: AuthConfig::from_rpc_login("rpcuser:opensesame").expect("login parses"),
            kdf: KdfParams::default(),
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
            listen: ListenAddr::parse(listen).expect("listen parses"),
            wallet_dir: std::path::PathBuf::from("."),
            network: Network::Stagenet,
            daemon_address: "http://127.0.0.1:1".into(),
            proxy: None,
            auth,
            kdf: KdfParams::default(),
        }
    }

    fn basic() -> AuthConfig {
        AuthConfig::from_rpc_login("user:pass").expect("login parses")
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
                err.contains("--rpc-login"),
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
        validate_listen(&listen_config("uds:///tmp/x.sock", AuthConfig::Disabled))
            .expect("the socket carries its own authorization");
    }

    /// The wiring, not the predicate: both bind paths must consult
    /// `validate_listen`. The edit that turns each half red is deleting the
    /// call at that site. The oracle is the wildcard message itself, not a
    /// bare `is_err()`: `validate_daemon_endpoint` runs first on both paths,
    /// and any refusal of the fixture's daemon address would otherwise
    /// satisfy the test with the listen check gone. `run_server` would
    /// block forever if the refusal did not fire, hence the timeout — a
    /// hang here is a failure, not a pass.
    #[tokio::test]
    async fn both_bind_paths_refuse_a_wildcard_before_binding() {
        let config = listen_config("0.0.0.0:0", basic());
        let Err(err) = spawn_in_process_with(config.clone()).await else {
            panic!("spawn_in_process_with must refuse a wildcard bind");
        };
        let err = err.to_string();
        assert!(err.contains("wildcard"), "spawn_in_process_with: {err}");
        let err = tokio::time::timeout(std::time::Duration::from_secs(5), run_server(config))
            .await
            .expect("run_server must return (refuse) rather than bind and block")
            .expect_err("run_server must refuse a wildcard bind")
            .to_string();
        assert!(err.contains("wildcard"), "run_server: {err}");
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

    /// `localhost:29500` is the spelling the retired server's docs taught;
    /// the refusal must say what to use instead, not just "syntax".
    #[test]
    fn hostname_listen_is_refused_with_the_remedy() {
        let err = ListenAddr::parse("localhost:29500").expect_err("hostnames do not parse");
        assert!(err.contains("hostnames are not resolved"), "{err}");
        assert!(err.contains("127.0.0.1:29500"), "{err}");
    }

    /// `uds://` is a Unix form. On Windows it must be refused at parse, naming
    /// the platform — not accepted and failed later at bind
    /// (`WINDOWS_WALLET_SUPPORT.md` §8.1, the parse surface).
    #[test]
    fn uds_listen_form_is_unix_only() {
        #[cfg(unix)]
        assert!(matches!(
            ListenAddr::parse("uds:///tmp/x.sock"),
            Ok(ListenAddr::Uds(_))
        ));
        #[cfg(windows)]
        {
            let err = ListenAddr::parse("uds:///tmp/x.sock")
                .err()
                .expect("uds:// must be refused on Windows");
            assert!(err.contains("Windows"), "{err}");
        }
        // Empty path is refused everywhere; the TCP form parses everywhere.
        assert!(ListenAddr::parse("uds://").is_err());
        assert!(matches!(
            ListenAddr::parse("127.0.0.1:29500"),
            Ok(ListenAddr::Tcp(_))
        ));
    }
}
