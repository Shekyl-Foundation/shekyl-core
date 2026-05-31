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
    Capability, CapabilityInput, ChangePasswordError, Credentials, DaemonClient, DaemonOp,
    DiagnosticSink, Engine, EngineCreateParams, EngineSignerKind, FeePriority, IoError, KeyError,
    LocalRefresh, MalformedKind, Network, NoopDiagnosticSink, OpenError, OpenedEngine, PendingTx,
    PendingTxError, PersistenceError, ProtocolErrorKind, RefreshDiagnostic, RefreshError,
    RefreshHandle, RefreshOptions, RefreshPhase, RefreshProgress, RefreshReorgEvent,
    RefreshSummary, ReservationId, SendError, SoloSigner, StateWrapKey, SuppressedClass,
    TracingDiagnosticSink, TxError, TxHash, TxRecipient, TxRecipientSummary, TxRequest,
    ViewMaterial,
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
    pub use crate::engine::local_keys::LocalKeys;
    pub use crate::engine::local_ledger::LocalLedger;
    pub use crate::engine::refresh::LedgerSnapshot;
    pub use crate::engine::{
        engine_account_public_address_for_bench, engine_balance_for_bench,
        engine_economics_base_emission_at_for_bench,
        engine_economics_parameters_snapshot_for_bench, engine_local_ledger_for_bench,
    };
}
