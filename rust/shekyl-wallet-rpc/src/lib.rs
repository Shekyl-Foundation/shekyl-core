// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl-native wallet JSON-RPC server (Phase 4).
//!
//! Implements the contract in [`docs/api/wallet_rpc.yaml`](../../docs/api/wallet_rpc.yaml).
//! This crate is Engine-backed and Shekyl-native — it is **not** the transitional
//! `shekyl-engine-rpc` wallet2 FFI bridge (deleted at Phase 5).
//!
//! # Phase 4a scope
//!
//! Scaffold only: axum JSON-RPC on `POST /`, `WalletRpcError` code table,
//! single-tenant session state, HTTP basic auth + UDS listener, in-process
//! spawn for Shape B (`shekyl-cli`), and the `get_version` method. Lifecycle
//! and send methods land in subsequent 4b sub-PRs.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod error;
pub mod handlers;
pub mod server;
pub mod tenant;
pub mod types;

pub use auth::AuthConfig;
pub use error::{WalletRpcError, WalletRpcErrorCode};
pub use server::{
    build_router, run_server, spawn_in_process, AppState, InProcessHandle, ListenAddr, ServerConfig,
};
pub use tenant::{Tenant, TenantState};
pub use types::{GetVersionResult, JsonRpcRequest, JsonRpcResponse, API_VERSION};

/// Crate / binary semver (`CARGO_PKG_VERSION`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
