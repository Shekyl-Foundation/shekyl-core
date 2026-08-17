// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-domain error enums for the `Engine` orchestrator.
//!
//! Cross-cutting lock 2 in the rewrite plan locks the error shape:
//!
//! > Domain layer (`shekyl-engine-core`) ships per-domain error enums
//! > (`SendError`, `RefreshError`, `KeyError`, `IoError`, etc.) with
//! > `thiserror` + `#[from]` conversions for ergonomic `?` propagation.
//! > The RPC layer (`shekyl-engine-rpc`) defines a single
//! > `WalletRpcError` enum that every domain error converts into.
//!
//! The quoted lock is verbatim; the crate it names has moved. The RPC layer
//! is now `shekyl-wallet-rpc` — the transitional `shekyl-engine-rpc`
//! wallet2-FFI bridge is deleted (roadmap B1). The shape of the lock is
//! unchanged: one RPC-layer error enum, every domain error converting in.
//!
//! Each enum is *closed* — no `Other(String)` catch-all — so a reviewer
//! can read the variants and know every distinguishable failure mode.
//! The RPC-layer translation is the single audited site for mapping
//! these to JSON-RPC error codes; the wallet-core API never returns a
//! stringly-typed error.
//!
//! # `#[from]` conversions
//!
//! This commit defines the variants but does not yet wire `#[from]`
//! impls for upstream errors (`shekyl_engine_file::WalletFileError`,
//! `shekyl_crypto_pq::CryptoError`, `shekyl_engine_state::WalletLedgerError`,
//! `shekyl_engine_prefs::PrefsError`, daemon-RPC errors, scanner
//! errors, tx-builder errors). Each `#[from]` lands in the same commit
//! that introduces the lifecycle / refresh / send method whose `?`
//! operator needs the conversion. This keeps each commit's dependency
//! graph minimal; an `#[from]` impl without a caller is dead code by
//! construction.
//!
//! # Variant names locked in by the plan
//!
//! - [`OpenError::NetworkMismatch`] — wallet file says network N, daemon
//!   client says network M.
//! - [`RefreshError::ConcurrentMutation`] — `apply_scan_result`'s
//!   `start_height` does not match the wallet's current `synced_height`
//!   (a second refresh raced ahead, or the caller mutated the wallet
//!   between snapshot and merge); caller retries.
//! - [`PendingTxError::TooOld`] — the tx was built outside the current
//!   reorg window.
//! - [`PendingTxError::ChainStateChanged`] — the wallet's recorded block
//!   hash at `built_at_height` no longer matches `built_at_tip_hash`.
//! - [`FeeEstimatorError::DaemonFeeUnreasonable`] — the daemon's fee
//!   snapshot failed well-formedness (non-monotonic tier band, or a
//!   named tier whose effective weight-1 charge exceeds the derived
//!   era-maximum cap, `absolute_fee_rate_cap()` = 14,000,000
//!   atomic-units/weight).

// Split by workflow per ENGINE_COMPOSITION_DECOMPOSITION.md §2 (the
// transfer/ carve precedent): same code, new ownership. Every item is
// re-exported here so historical `engine::error::X` import paths keep
// working unchanged.
mod economics;
mod io;
mod key;
mod lifecycle;
mod refresh;
mod send;
mod submit;

pub(crate) use economics::EconomicsError;
pub use io::IoError;
pub(crate) use key::KeyEngineError;
pub use key::KeyError;
#[cfg(feature = "conformance")]
pub use lifecycle::StakeSelfCertFailure;
pub use lifecycle::{ChangePasswordError, OpenError, PersistenceError};
pub(crate) use refresh::LedgerError;
pub use refresh::RefreshError;
pub use send::{PendingTxError, SendError, TxError};
pub use submit::{
    AmbiguousErrorKind, OutputSelectorError, RetryableRejectCause, SignerError, SubmitError,
    TerminalErrorKind,
};

pub use super::fee_policy::{CeilingViolation, CustomFeeBand, FeeEstimatorError};
