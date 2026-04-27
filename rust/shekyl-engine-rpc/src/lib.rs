// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl wallet RPC server library.
//!
//! Provides a Rust JSON-RPC server that wraps the C++ wallet2 library via FFI.
//! Can be used as:
//! - A standalone binary (drop-in replacement for `shekyl-engine-rpc`)
//! - An embedded library in the Tauri GUI wallet
//!
//! With the `rust-scanner` feature enabled, scanner-backed read-only methods
//! are handled natively in Rust via `shekyl-scanner`.

pub mod ffi;
pub mod handlers;
pub mod server;
pub mod types;
pub mod engine;

#[cfg(feature = "rust-scanner")]
pub mod scanner_state;

#[cfg(feature = "multisig")]
pub mod multisig_handlers;

pub use server::{run_server, ServerConfig};
pub use engine::{EngineError, EngineResult, ProgressEvent, Wallet2};

#[cfg(feature = "rust-scanner")]
pub use scanner_state::ScannerState;
