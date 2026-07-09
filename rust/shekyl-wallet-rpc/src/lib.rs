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
//! # Phase 4b
//!
//! Lifecycle + read queries (`get_balance`, `get_primary_address`,
//! `get_transfers`, `get_transfer_by_id`, `get_height`), plus the Phase 4a
//! scaffold. Refresh / send / `rescan_blockchain` land in later commits.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod error;
pub mod handlers;
pub mod lifecycle;
pub mod project;
pub mod queries;
pub mod server;
pub mod tenant;
pub mod types;

pub use auth::AuthConfig;
pub use error::{WalletRpcError, WalletRpcErrorCode};
pub use server::{
    build_router, run_server, spawn_in_process, spawn_in_process_with, AppState, InProcessHandle,
    ListenAddr, ServerConfig,
};
pub use tenant::{Tenant, TenantState};
pub use types::{GetVersionResult, JsonRpcRequest, JsonRpcResponse, WalletHandle, API_VERSION};

/// Crate / binary semver (`CARGO_PKG_VERSION`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
