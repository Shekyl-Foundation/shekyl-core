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
pub use engine::local_ledger_ops::{AbandonTxError, AbandonTxOutcome, SetTxNoteError};
pub use engine::payment_requests::{NewPaymentRequest, PaymentRequestFilter};
/// The MS-5 multisig signer marker — only present under `--features multisig`.
#[cfg(feature = "multisig")]
pub use engine::MultisigSignerV2;
pub use engine::{
    Capability, CapabilityInput, ChangePasswordError, Credentials, DaemonClient, DaemonOp,
    DiagnosticSink, DrainBalanceReadError, Engine, EngineCreateParams, EngineSignerKind,
    FeePriority, FeeTierQuote, FirstStakeError, FirstStakeOutcome, InputCount, IoError, KeyError,
    LocalRefresh, MalformedKind, Network, NoopDiagnosticSink, OpenError, OpenedEngine, OutputCount,
    PScanHandle, PScanStartError, PendingTx, PendingTxError, PersistenceError, ProtocolErrorKind,
    RefreshDiagnostic, RefreshError, RefreshHandle, RefreshOptions, RefreshPhase, RefreshProgress,
    RefreshReorgEvent, RefreshSummary, ReservationId, ScannableBlock, SendError, SoloSigner,
    StakePosture, StakedBalance, StakedOutput, StakingReadError, StakingReadView, StateWrapKey,
    SubmitOutcome, SuppressedClass, TracingDiagnosticSink, TxError, TxHash, TxRecipient,
    TxRecipientSummary, TxRequest, TxShapeEstimate, ViewMaterial,
};
pub use outbound_label::label_plaintext_for_payment_uri;
// Re-exported so the wallet-RPC layer's `make_uri` / `parse_uri` projections
// can consume the one payment-URI codec without a direct `shekyl-address`
// dependency — mirroring the `ShekylAddress` re-export in [`engine`].
// Canonical definition stays in `shekyl-address`; do not wrap or redefine.
/// SH-2b-2's embedder surface: the serving lifecycle handle and its start
/// failures, re-exported beside `PScanHandle` for the same reason — the
/// embedder parks the handle for the wallet's open lifetime and shuts it down
/// on close. Re-exported here rather than through `engine`'s own list because
/// that module sits at its decomposition ceiling.
pub use engine::stake_engine::serving::{ServingHandle, ServingStartError, TorConfigError};
pub use scan::{DetectedTransfer, KeyImageObserved, ReorgRewind, ScanResult};
pub use shekyl_address::{format_payment_uri, parse_payment_uri, PaymentUri, PaymentUriError};
/// The tor-posture producer, re-exported so an embedder can spawn the
/// translator from this root rather than taking a second direct dependency.
///
/// The example compiles the path rather than asserting it in prose: a
/// re-export list that silently omits a name the docs point at is invisible to
/// every lint, because `unused_imports` does not fire on a `pub use` at a
/// public root.
///
/// ```
/// use shekyl_engine_core::tor_posture::spawn_tor_posture_translator;
/// use shekyl_engine_core::{AlarmCondition, OperatorAlarms};
///
/// let alarms = OperatorAlarms::new();
/// assert!(alarms.board().condition(AlarmCondition::TransportLiveness).is_none());
/// let _reachable_from_this_root = spawn_tor_posture_translator;
/// ```
pub use shekyl_operator_alarm::tor_posture;
/// The OA-1 operator alarm channel: the surface a human reads when a guarantee
/// the wallet cannot restore by itself has been lost.
///
/// Re-exported rather than re-declared, and it lives in its own leaf crate
/// because it names no engine type — an embedder can match on
/// [`OperatorAlarm`] and render a board without linking the orchestrator,
/// which is what rule 82 wants of a failure-mode surface. It is deliberately
/// **not** part of `engine::diagnostics`: that trait's contract is droppable,
/// silently-lossy and restart-amnesiac by design, all of which are wrong for a
/// condition whose evidence disappears before its consequence does.
///
/// The tor supervisor reports through it today; the serving conditions join in
/// SH-2b-2. The producer module is re-exported [just below](tor_posture).
pub use shekyl_operator_alarm::{
    AlarmBoard, AlarmCondition, AlarmLifetime, Arming, ConditionState, DegradedCause,
    DisarmedReason, IncidentId, OperatorAlarm, OperatorAlarms, RaisedAlarm,
};

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
