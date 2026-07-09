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

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::info;

use crate::auth::{require_basic_auth, AuthConfig};
use crate::error::WalletRpcError;
use crate::handlers;
use crate::tenant::TenantState;
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
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Bind address (TCP or UDS).
    pub listen: ListenAddr,
    /// Directory for wallet files.
    pub wallet_dir: PathBuf,
    /// HTTP basic auth (disabled for UDS-by-default deployments).
    pub auth: AuthConfig,
}

/// Shared application state.
pub struct AppState {
    /// Tenant / wallet-dir state.
    pub tenants: tokio::sync::Mutex<TenantState>,
    /// Auth config (also injected as middleware state).
    pub auth: AuthConfig,
    /// Signalled to request graceful shutdown.
    pub shutdown: Arc<Notify>,
}

// `AppState` fields are public so integration tests can construct a
// state without going through `ServerConfig` bind.

impl AppState {
    fn new(config: &ServerConfig) -> Arc<Self> {
        Arc::new(Self {
            tenants: tokio::sync::Mutex::new(TenantState::new(config.wallet_dir.clone())),
            auth: config.auth.clone(),
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
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn json_rpc_handler(
    State(_state): State<Arc<AppState>>,
    body: Result<Json<JsonRpcRequest>, axum::extract::rejection::JsonRejection>,
) -> (StatusCode, Json<JsonRpcResponse>) {
    // HTTP status is 200 for every well-formed JSON-RPC exchange (spec).
    // Malformed JSON still returns 200 with a JSON-RPC parse error so
    // clients can use a single response path.
    let req = match body {
        Ok(Json(req)) => req,
        Err(_) => {
            return (StatusCode::OK, Json(JsonRpcResponse::parse_error()));
        }
    };

    let id = req.id.clone();
    if req.jsonrpc != "2.0" {
        let err = WalletRpcError::InvalidRequest(format!(
            "jsonrpc must be \"2.0\", got {:?}",
            req.jsonrpc
        ));
        return (StatusCode::OK, Json(JsonRpcResponse::from_error(id, &err)));
    }

    if req.method.is_empty() {
        let err = WalletRpcError::InvalidRequest("method must be non-empty".into());
        return (StatusCode::OK, Json(JsonRpcResponse::from_error(id, &err)));
    }

    match handlers::dispatch(&req.method, &req.params) {
        Ok(result) => (StatusCode::OK, Json(JsonRpcResponse::success(id, result))),
        Err(err) => (StatusCode::OK, Json(JsonRpcResponse::from_error(id, &err))),
    }
}

/// Run the server until shutdown (SIGINT / SIGTERM via the Notify, or
/// process exit). Blocks the calling task.
pub async fn run_server(
    config: ServerConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
            info!(path = %path.display(), "shekyl-wallet-rpc listening (UDS)");
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    shutdown.notified().await;
                })
                .await?;
            let _ = std::fs::remove_file(path);
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

/// Handle returned by [`spawn_in_process`].
pub struct InProcessHandle {
    /// Shared state (call `shutdown.notify_one()` via [`Self::shutdown`]).
    state: Arc<AppState>,
    /// Background serve task.
    join: JoinHandle<Result<(), std::io::Error>>,
    /// Bound TCP address (always TCP for in-process; UDS is for the binary).
    pub local_addr: SocketAddr,
}

impl InProcessHandle {
    /// Request graceful shutdown and wait for the serve task to finish.
    pub async fn shutdown(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.state.shutdown.notify_one();
        self.join.await??;
        Ok(())
    }

    /// Base URL for HTTP clients (`http://127.0.0.1:port`).
    pub fn base_url(&self) -> String {
        format!("http://{}", self.local_addr)
    }
}

/// Spawn an in-process server on an ephemeral localhost TCP port.
///
/// Shape B entry point: `shekyl-cli` one-shot / REPL hosts a server without
/// a subprocess. Auth is disabled for the loopback in-process case (the
/// caller is the same process); pass credentials via [`ServerConfig`] if a
/// future caller needs them.
pub async fn spawn_in_process(
    wallet_dir: PathBuf,
) -> Result<InProcessHandle, Box<dyn std::error::Error + Send + Sync>> {
    let config = ServerConfig {
        listen: ListenAddr::Tcp(SocketAddr::from(([127, 0, 0, 1], 0))),
        wallet_dir,
        auth: AuthConfig::Disabled,
    };
    let state = AppState::new(&config);
    let app = build_router(state.clone());
    let listener = TcpListener::bind(config.listen_tcp_ephemeral()).await?;
    let local_addr = listener.local_addr()?;
    let shutdown = state.shutdown.clone();
    let join = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown.notified().await;
            })
            .await
    });
    info!(%local_addr, "shekyl-wallet-rpc in-process server started");
    Ok(InProcessHandle {
        state,
        join,
        local_addr,
    })
}

impl ServerConfig {
    fn listen_tcp_ephemeral(&self) -> SocketAddr {
        match self.listen {
            ListenAddr::Tcp(addr) => addr,
            ListenAddr::Uds(_) => SocketAddr::from(([127, 0, 0, 1], 0)),
        }
    }
}
