// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Genesis build/verify tool (`geblock`) — library surface.
//!
//! Deterministic Rust replacement for the retired C++ `genesis_builder`
//! (formerly `shekyl-dev/tools/genesis_builder`, deleted alongside
//! `cryptonote::build_genesis_coinbase_from_destinations`). The tool:
//!
//! - derives the genesis transaction key **deterministically** from the
//!   network's name and its recipients file ([`txkey`]), so every network's
//!   genesis in the table (`shekyl_network`) is byte-reproducible from
//!   `config/genesis_recipients.<name>.json` — anyone can rebuild and check it;
//! - assembles the genesis coinbase tx and the genesis block, nonce 0 on
//!   every network ([`builder`]), on top of `shekyl-wire`;
//! - runs the fresh-entropy genesis wallet ceremony ([`wallets`]);
//! - writes and checks the table's genesis pins ([`table`]), regtest's
//!   committed test recipients included.
//!
//! Logic lives here (not in `main.rs`) so the integration tests under
//! `tests/` can drive it directly — the same split
//! `shekyl-randomx-differential` uses.

#![deny(unsafe_code)]

pub mod builder;
pub mod recipients;
pub mod table;
pub mod txkey;
pub mod wallets;

/// Tool-level error: operator-facing messages, one flat surface.
///
/// Crypto/address/wire failures are folded into [`GenesisToolError::Invalid`]
/// as formatted strings — this is an operator tool, and every such failure is
/// terminal for the run; no caller matches on the inner error.
#[derive(Debug, thiserror::Error)]
pub enum GenesisToolError {
    /// Filesystem or wire-serialization I/O failure.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    /// Recipients-file JSON parse failure.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// Validation, address, or crypto failure (message is the full story).
    #[error("{0}")]
    Invalid(String),
}

/// Shorthand constructor for [`GenesisToolError::Invalid`].
pub(crate) fn invalid(msg: impl Into<String>) -> GenesisToolError {
    GenesisToolError::Invalid(msg.into())
}
