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
pub mod outbound_label;
pub mod scan;

pub use consensus_constants::ARCHIVAL_BOND_FLOOR_ATOMIC;
pub use engine::payment_requests::{NewPaymentRequest, PaymentRequestFilter};
/// The MS-5 multisig signer marker — only present under `--features multisig`.
#[cfg(feature = "multisig")]
pub use engine::MultisigSignerV2;
pub use engine::{
    Capability, CapabilityInput, ChangePasswordError, Credentials, DaemonClient, DaemonOp,
    DiagnosticSink, Engine, EngineCreateParams, EngineSignerKind, FeePriority, FirstStakeError,
    FirstStakeOutcome, IoError, KeyError, LocalRefresh, MalformedKind, Network, NoopDiagnosticSink,
    OpenError, OpenedEngine, PScanHandle, PScanStartError, PendingTx, PendingTxError,
    PersistenceError, ProtocolErrorKind, RefreshDiagnostic, RefreshError, RefreshHandle,
    RefreshOptions, RefreshPhase, RefreshProgress, RefreshReorgEvent, RefreshSummary,
    ReservationId, ScannableBlock, SendError, SoloSigner, StateWrapKey, SuppressedClass,
    TracingDiagnosticSink, TxError, TxHash, TxRecipient, TxRecipientSummary, TxRequest,
    ViewMaterial,
};
pub use outbound_label::label_plaintext_for_payment_uri;
pub use scan::{DetectedTransfer, KeyImageObserved, ReorgRewind, ScanResult};

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

/// **Not part of the public API.** The external half of the `test-helpers`
/// feature (`Cargo.toml` `[features]` note): a narrow, feature-gated surface a
/// downstream crate's tests can use to construct engine states that its own
/// production API cannot yet reach.
///
/// First (and currently sole) consumer: **`shekyl-wallet-rpc`**, whose WI-1
/// P-scan lifecycle test needs a *staker* wallet to prove the embedder wires
/// [`Engine::start_pscan_if_staker`] into open/close. No RPC staking entry
/// exists yet (it is a separate, still-unbuilt work item), so the only way to
/// reach `staking_enabled` from the RPC crate's tests is
/// [`Engine::persist_bond_record`] — exposed here behind the feature rather than
/// widened to `pub`, so no production-visible surface changes. This is the
/// "public-re-export half lands with its first downstream consumer" step the
/// `test-helpers` feature doc reserved (rule 21): a named consumer, not
/// speculative pre-provisioning.
#[cfg(any(test, feature = "test-helpers"))]
#[doc(hidden)]
pub mod __test_helpers {
    use crate::engine::{Engine, SoloSigner};
    use shekyl_types::PSlot;

    /// SP-R0 arm #1 DQ-F fire lane (see `engine/pscan/arm1_fire.rs`).
    /// `not(test)`: the harness only exists in compilations where
    /// `#[cfg(test)]` constructors do not (Guard 1, structural).
    #[cfg(not(test))]
    pub use crate::engine::pscan::arm1_fire::{
        run_arm1_fire, run_arm3_fire, Arm1FireReport, Arm3FireReport,
    };

    /// Turn an open [`Engine`] into a staker: persist a bond record for `slot`,
    /// which sets `staking_enabled` durably, so a subsequent reopen spawns the
    /// [`StakeEngine`](crate::engine::stake_engine::StakeEngine) and the
    /// embedder's P-scan auto-start has a persona to scan as. The bond ticket is
    /// discarded (the test only needs the staking-enabled side effect); errors
    /// are flattened to a `String` so no `pub(crate)` error type leaks.
    ///
    /// Test-only (feature-gated); never compiled into a default production build.
    pub fn make_staker_for_test(engine: &Engine<SoloSigner>, slot: u32) -> Result<(), String> {
        engine
            .persist_bond_record(PSlot::from_raw(slot))
            .map(|_ticket| ())
            .map_err(|e| e.to_string())
    }
}
