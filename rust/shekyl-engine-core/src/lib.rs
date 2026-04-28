// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! Shekyl engine core: orchestrator and transaction builders for staking operations.
//!
//! Provides Rust-native builders for:
//! - Claim transactions (reward withdrawal)
//! - Stake transactions (creating staked outputs)
//! - Unstake transactions (spending matured staked outputs)
//! - Combined claim-and-unstake workflow

pub mod claim_builder;
pub mod engine;
pub mod error;
#[cfg(feature = "multisig")]
pub mod multisig;
pub mod scan;
pub mod workflow;

pub use claim_builder::{ClaimTxBuilder, ClaimTxPlan};
pub use engine::{
    Capability, CapabilityInput, Credentials, DaemonClient, Engine, EngineCreateParams,
    EngineSignerKind, FeePriority, IoError, KeyError, Network, OpenError, OpenedEngine, PendingTx,
    PendingTxError, RefreshError, RefreshHandle, RefreshOptions, RefreshPhase, RefreshProgress,
    RefreshReorgEvent, RefreshSummary, ReservationId, SendError, SoloSigner, TxError, TxHash,
    TxRecipient, TxRecipientSummary, TxRequest,
};
pub use error::EngineCoreError;
pub use scan::{DetectedTransfer, KeyImageObserved, ReorgRewind, ScanResult, StakeEvent};
pub use workflow::ClaimAndUnstakePlan;

#[cfg(test)]
mod tests;

/// **Not part of the public API.** Re-exports otherwise-`pub(crate)`
/// types so external Criterion benchmarks (`benches/*.rs`) can measure
/// internal data structures without weakening their crate-local
/// visibility for production callers. Gated behind the
/// `bench-internals` feature; consumers must not depend on it.
#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub mod __bench_internals {
    pub use crate::engine::refresh::LedgerSnapshot;
}
