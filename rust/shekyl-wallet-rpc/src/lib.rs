// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl-native wallet JSON-RPC server (Phase 4).
//!
//! Implements the contract in [`docs/api/wallet_rpc.yaml`](../../docs/api/wallet_rpc.yaml).
//! This crate is Engine-backed and Shekyl-native. The transitional
//! `shekyl-engine-rpc` wallet2 FFI bridge it used to be confused with is
//! deleted (roadmap B1); this crate is the only Rust wallet RPC server.
//!
//! # Phase 4b / 4c
//!
//! Lifecycle, read queries, refresh, send lifecycle, WI-RPC-1/2a/3, and
//! Phase 4c `rescan_blockchain` (Engine `start_rescan`).

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod error;
pub mod fees;
pub mod handlers;
pub mod lifecycle;
pub mod notes;
pub mod params;
pub mod project;
pub mod proofs;
pub mod queries;
pub mod receiving;
pub mod send;
pub mod server;
pub mod staking;
pub mod sync;
pub mod tenant;
pub mod types;

pub use auth::AuthConfig;
pub use error::{WalletRpcError, WalletRpcErrorCode};
pub use server::{
    build_router, run_server, spawn_in_process, spawn_in_process_with, AppState, InProcessHandle,
    InProcessListen, ListenAddr, ServerConfig,
};
// Re-exported so in-process hosts (shekyl-cli) can name the network a
// spawned server binds to without a direct shekyl-engine-core dependency.
pub use shekyl_engine_core::Network;
pub use tenant::{DaemonEndpoint, SharedEngine, Tenant, TenantState};
pub use types::{GetVersionResult, JsonRpcRequest, JsonRpcResponse, WalletHandle, API_VERSION};

/// Crate / binary semver (`CARGO_PKG_VERSION`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
