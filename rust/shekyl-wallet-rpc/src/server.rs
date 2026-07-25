// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Axum JSON-RPC server: `POST /` over TCP or Unix domain socket.
//!
//! Also exposes [`spawn_in_process`] so Shape B (`shekyl-cli`) can host an
//! in-process server without shelling out (`WALLET_REWRITE_PLAN.md` Phase 3).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_core::Network;
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::info;

use crate::auth::{require_basic_auth, AuthConfig};
use crate::handlers;
use crate::tenant::{DaemonEndpoint, TenantState};
use crate::types::{JsonRpcRequest, JsonRpcResponse};

/// Default max JSON-RPC body size (1 MiB). Wallet RPC payloads are small;
/// this is a DoS bound, not a semantic limit.
pub const DEFAULT_BODY_LIMIT: usize = 1024 * 1024;

/// Where the server listens.
#[derive(Debug, Clone)]
pub enum ListenAddr {
    /// TCP bind address (e.g. `127.0.0.1:29500`).
    Tcp(SocketAddr),
    /// Unix domain socket path (recommended default for local clients).
    Uds(PathBuf),
}

impl ListenAddr {
    /// Parse a listen string: `uds:///path` or `host:port` / `ip:port`.
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some(path) = s.strip_prefix("uds://") {
            if path.is_empty() {
                return Err("uds:// path must not be empty".into());
            }
            return Ok(Self::Uds(PathBuf::from(path)));
        }
        s.parse::<SocketAddr>()
            .map(Self::Tcp)
            .map_err(|e| format!("invalid listen address '{s}': {e}"))
    }
}

/// Server configuration.
#[derive(Clone)]
pub struct ServerConfig {
    /// Bind address (TCP or UDS).
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
    /// Auth config (also injected as middleware state).
    pub auth: AuthConfig,
    /// Argon2id cost for create / rotate.
    pub kdf: KdfParams,
    /// Signalled to request graceful shutdown.
    pub shutdown: Arc<Notify>,
}

// `AppState` fields are public so integration tests can construct a
// state without going through `ServerConfig` bind.

impl AppState {
    fn new(config: &ServerConfig) -> Arc<Self> {
        Arc::new(Self {
            tenants: tokio::sync::Mutex::new(TenantState::new(
                config.wallet_dir.clone(),
                config.network,
                DaemonEndpoint {
                    address: config.daemon_address.clone(),
                    proxy: config.proxy.clone(),
                },
            )),
            auth: config.auth.clone(),
            kdf: config.kdf,
            shutdown: Arc::new(Notify::new()),
        })
    }
}

/// Build the axum router (shared by TCP, UDS, and in-process tests).
pub fn build_router(state: Arc<AppState>) -> Router {
    let auth = state.auth.clone();
    Router::new()
        .route("/", post(json_rpc_handler))
        .layer(axum::middleware::from_fn_with_state(
            auth,
            require_basic_auth,
        ))
        .layer(RequestBodyLimitLayer::new(DEFAULT_BODY_LIMIT))
        // Default-deny CORS. This process will host spend operations; a
        // permissive ACAO on loopback TCP would let a malicious web page
        // drive-by the wallet. Reopen only for an explicit web-client
        // deployment (rule 21).
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
struct UdsCleanup(PathBuf);

impl Drop for UdsCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Refuse a malformed `--daemon-address` / `--proxy` at startup (offline
/// shape check only — an unreachable daemon stays fine for offline
/// commands). Deferred to first use, a bad flag would surface on
/// `open_wallet` as "daemon unreachable": the wrong remedy pointer
/// (rule 82 — the failure must name the flag, at the moment it can be
/// fixed).
fn validate_daemon_endpoint(
    config: &ServerConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

/// Run the server until shutdown (SIGINT / SIGTERM via the Notify, or
/// process exit). Blocks the calling task.
pub async fn run_server(
    config: ServerConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    validate_daemon_endpoint(&config)?;
    let state = AppState::new(&config);
    let app = build_router(state.clone());
    let shutdown = state.shutdown.clone();

    match &config.listen {
        ListenAddr::Tcp(addr) => {
            let listener = TcpListener::bind(addr).await?;
            let local = listener.local_addr()?;
            info!(%local, "shekyl-wallet-rpc listening (TCP)");
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    shutdown.notified().await;
                })
                .await?;
        }
        ListenAddr::Uds(path) => {
            prepare_uds_path(path)?;
            let listener = UnixListener::bind(path)?;
            // Own the socket path for cleanup BEFORE any fallible step: a
            // failure in restrict_socket_perms below must still unlink the
            // bound socket, or the leftover path blocks the next bind.
            let _cleanup = UdsCleanup(path.clone());
            restrict_socket_perms(path)?;
            info!(path = %path.display(), "shekyl-wallet-rpc listening (UDS)");
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    shutdown.notified().await;
                })
                .await?;
        }
    }
    Ok(())
}

fn prepare_uds_path(path: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
fn restrict_socket_perms(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// Create the private, per-spawn runtime directory that holds the
/// in-process UDS socket.
///
/// Prefers `$XDG_RUNTIME_DIR` (user-private tmpfs per the XDG base-dir
/// spec; `WALLET_REWRITE_PLAN.md` Phase 3 deliverables), falling back to
/// the system temp dir. Created 0700. The name is pid- **and**
/// spawn-counter-scoped so multiple in-process servers in one process
/// (test binaries; future multi-session hosts) never collide. A
/// pre-existing entry at the path is removed if we own it; if removal
/// fails (e.g. an attacker-planted entry under a sticky-bit temp dir)
/// creation fails loud rather than reusing it.
fn private_socket_dir() -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SPAWN_COUNTER: AtomicU64 = AtomicU64::new(0);

    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let n = SPAWN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = base.join(format!("shekyl-rpc-{}-{n}", std::process::id()));
    // Stale leftover from a crashed run with a recycled pid: remove if ours.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
}

/// Where an in-process server listens.
#[derive(Debug, Clone)]
pub enum InProcessListen {
    /// Loopback TCP (explicit opt-in via [`spawn_in_process_with`]).
    Tcp(SocketAddr),
    /// Unix domain socket (the secure default of [`spawn_in_process`]).
    Uds(PathBuf),
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
    socket_dir: Option<PathBuf>,
}

impl InProcessHandle {
    /// Request graceful shutdown and wait for the serve task to finish.
    pub async fn shutdown(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.state.shutdown.notify_one();
        self.join.await??;
        // The serve task's UdsCleanup already unlinked the socket; remove
        // the private dir that held it.
        if let Some(dir) = &self.socket_dir {
            let _ = std::fs::remove_dir(dir);
        }
        Ok(())
    }

    /// UDS socket path (`None` when listening on TCP).
    pub fn socket_path(&self) -> Option<&Path> {
        match &self.listen {
            InProcessListen::Uds(path) => Some(path),
            InProcessListen::Tcp(_) => None,
        }
    }
}

/// Spawn an in-process server on a private Unix domain socket.
///
/// Shape B entry point: `shekyl-cli` one-shot / REPL hosts a server without
/// a subprocess. The socket lives in a fresh 0700, pid-scoped directory
/// (under `$XDG_RUNTIME_DIR`, temp-dir fallback) and is itself 0600, so
/// only the owning user can connect — that filesystem gate is why
/// [`AuthConfig::Disabled`] is sound here. Never binds TCP: an auth-less
/// loopback port would let any local process drive the open wallet.
///
/// The daemon is not dialed until refresh/send, so an unreachable
/// `daemon_address` is fine for offline commands.
pub async fn spawn_in_process(
    wallet_dir: PathBuf,
    network: Network,
    daemon_address: String,
    proxy: Option<String>,
) -> Result<InProcessHandle, Box<dyn std::error::Error + Send + Sync>> {
    let socket_dir = private_socket_dir()?;
    let mut handle = spawn_in_process_with(ServerConfig {
        listen: ListenAddr::Uds(socket_dir.join("wallet-rpc.sock")),
        wallet_dir,
        network,
        daemon_address,
        proxy,
        auth: AuthConfig::Disabled,
        kdf: KdfParams::default(),
    })
    .await?;
    handle.socket_dir = Some(socket_dir);
    Ok(handle)
}

/// Spawn an in-process server with a full [`ServerConfig`] (tests / CLI).
///
/// Honors `config.listen`: UDS sockets are chmodded 0600 after bind; TCP
/// is served as configured (callers binding auth-less TCP own that risk —
/// prefer [`spawn_in_process`]).
pub async fn spawn_in_process_with(
    config: ServerConfig,
) -> Result<InProcessHandle, Box<dyn std::error::Error + Send + Sync>> {
    validate_daemon_endpoint(&config)?;
    let state = AppState::new(&config);
    let app = build_router(state.clone());
    let shutdown = state.shutdown.clone();
    match &config.listen {
        ListenAddr::Tcp(addr) => {
            let listener = TcpListener::bind(addr).await?;
            let local_addr = listener.local_addr()?;
            let join = tokio::spawn(async move {
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        shutdown.notified().await;
                    })
                    .await
            });
            info!(%local_addr, "shekyl-wallet-rpc in-process server started (TCP)");
            Ok(InProcessHandle {
                state,
                join,
                listen: InProcessListen::Tcp(local_addr),
                socket_dir: None,
            })
        }
        ListenAddr::Uds(path) => {
            prepare_uds_path(path)?;
            let listener = UnixListener::bind(path)?;
            // Own the socket path for cleanup BEFORE restrict_socket_perms so a
            // chmod failure still unlinks the bound socket rather than leaking
            // it. Ownership then moves into the serve task below.
            let cleanup = UdsCleanup(path.clone());
            restrict_socket_perms(path)?;
            let join = tokio::spawn(async move {
                // Owned by the serve task so the socket is unlinked on any
                // exit path, success or error.
                let _cleanup = cleanup;
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        shutdown.notified().await;
                    })
                    .await
            });
            info!(path = %path.display(), "shekyl-wallet-rpc in-process server started (UDS)");
            Ok(InProcessHandle {
                state,
                join,
                listen: InProcessListen::Uds(path.clone()),
                socket_dir: None,
            })
        }
    }
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
            auth: AuthConfig::from_rpc_login(Some("rpcuser:opensesame")),
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
}
