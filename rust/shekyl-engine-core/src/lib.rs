// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! Shekyl engine core: the wallet orchestrator ([`engine::Engine`]) and its supporting
//! transaction/scan builders for the wallet stack.

pub mod attribution;
pub mod consensus_constants;
pub mod engine;
pub mod error;
#[cfg(feature = "multisig")]
pub mod multisig;
pub mod outbound_label;
pub mod scan;

pub use consensus_constants::ARCHIVAL_BOND_FLOOR_ATOMIC;
pub use engine::payment_requests::{NewPaymentRequest, PaymentRequestFilter};
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
pub use outbound_label::label_plaintext_for_payment_uri;
pub use scan::{DetectedTransfer, KeyImageObserved, ReorgRewind, ScanResult, StakeEvent};

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
    // §5.3 B9 dispatch-overhead + merge-path bench support.
    pub use crate::engine::key_dispatch_bench::{
        build_key_baseline_fixture, build_merge_projection_fixture, drop_key_baseline_fixture,
        drop_merge_projection_fixture, KeyBaselineBenchFixture, KeyDispatchBenchHarness,
        MergeProjectionBenchFixture, MERGE_BENCH_OUTPUT_COUNT,
    };
}
