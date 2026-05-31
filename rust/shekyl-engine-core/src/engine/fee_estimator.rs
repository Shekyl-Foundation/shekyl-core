// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fee-estimation trait surface for the C5 `PendingTxEngine`
//! impl.
//!
//! Phase 0j binding form per
//! `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §3.1 (R16 segment-2c
//! closure + segment-2d V3.0-lift evaluation).
//!
//! # Surface
//!
//! - [`FeeEstimator`] — the trait V3.x alternative
//!   estimators plug into ([`DaemonFeeEstimator`] is the V3.0
//!   default; V3.x adds `ExplicitFeeEstimator` and the
//!   `LedgerEngine`-historical `WalletSideEstimator` per
//!   segment-2d R16 (c)'s V3.x scope).
//! - [`FeePriority`] — the caller-supplied fee preference
//!   enum; migrated from `engine::pending` (the prior home;
//!   `engine::pending` keeps a backward-compatibility
//!   re-export for crate-internal callers per the
//!   "trait-surface is the canonical citation" pin).
//! - [`FeeEstimationContext`] — the structural context the
//!   estimator reasons against (recipient count, input
//!   count, ledger snapshot for V3.x wallet-side analysis).
//! - [`DaemonFeeEstimator`] — V3.0 default impl; Phase 1
//!   stub returns
//!   [`STUB_FEE_ATOMIC_UNITS`](super::pending::STUB_FEE_ATOMIC_UNITS).
//!
//! # Trait-vs-implementation split (R16)
//!
//! The trait surface is **narrow** — single method, no
//! algorithm-internal knobs in the trait signature. Estimation
//! strategy details (daemon-recommendation queries, explicit
//! caller-supplied feerates, wallet-side historical analysis,
//! …) are the impl's responsibility, not the trait surface's.
//! R16's design pin: adding a new estimator to V3.x is a new
//! [`FeeEstimator`] impl; the trait surface does not
//! re-open.
//!
//! # FeePriority migration
//!
//! [`FeePriority`] was historically defined in
//! `engine::pending`. PR 5 C4γ migrates the definition to
//! this module (the trait surface that consumes it) per the
//! `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §7.X "trait-surface is
//! the canonical citation" pin. `engine::pending` re-exports
//! [`FeePriority`] for backward source-text compatibility
//! within the crate; the `engine::mod` re-export surface is
//! unchanged.

use std::num::NonZeroU64;

use super::error::FeeEstimatorError;
use super::refresh::LedgerSnapshot;

/// Caller-supplied fee preference for the
/// `PendingTxEngine::build` pipeline.
///
/// Phase 1 ignores the variant and uses
/// [`STUB_FEE_ATOMIC_UNITS`](super::pending::STUB_FEE_ATOMIC_UNITS);
/// Phase 2a resolves each variant against the daemon's
/// `get_fee_estimates` (for [`DaemonFeeEstimator`]) or
/// against the implementor's strategy (for the V3.x
/// `ExplicitFeeEstimator` / `WalletSideEstimator`).
///
/// # Migration note (PR 5 C4γ)
///
/// This type was previously defined in `engine::pending`;
/// the canonical home is now this module per the §7.X
/// "trait-surface is the canonical citation" pin.
/// `engine::pending` re-exports for backward source-text
/// compatibility within the crate. No external API breakage:
/// `engine::mod` re-exports [`FeePriority`] from the
/// `engine::pending` re-export, so consumer code referencing
/// `shekyl_engine_core::engine::FeePriority` is unaffected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeePriority {
    /// Slowest tier; cheapest. Targets confirmation within a
    /// few blocks rather than the next block.
    Economy,
    /// Default tier; balanced cost vs. confirmation time.
    Standard,
    /// Fastest tier short of fee-spiking; targets next-block
    /// inclusion under normal mempool conditions.
    Priority,
    /// Caller-pinned feerate in atomic-units-per-byte. The
    /// daemon's estimate is bypassed entirely (and so are
    /// `TxError::DaemonFeeUnreasonable` sanity checks).
    Custom(NonZeroU64),
}

/// Structural context the estimator reasons against.
///
/// Carries the structurally-minimal fields the estimator
/// needs without coupling to the broader `PendingTxEngine`
/// pipeline:
///
/// - `ledger`: the engine's snapshot of ledger state. V3.0's
///   [`DaemonFeeEstimator`] ignores this; V3.x's
///   `WalletSideEstimator` analyzes historical block-fee
///   distribution off the snapshot per segment-2d R16 (c).
/// - `recipient_count`: the transaction's recipient count.
///   Used to size the projected transaction's outputs
///   contribution to the fee calculation.
/// - `input_count`: the transaction's input count (output
///   selector's `SelectedOutputs::indices.len()`). Used to
///   size the projected transaction's inputs contribution
///   to the fee calculation.
///
/// The estimator does not need access to the recipient
/// addresses, output amounts, or any per-recipient
/// cryptographic material — only the structural counts and
/// the ledger snapshot.
#[derive(Debug, Clone, Copy)]
pub struct FeeEstimationContext<'a> {
    /// Engine's snapshot of ledger state. V3.0
    /// [`DaemonFeeEstimator`] ignores this; V3.x
    /// `WalletSideEstimator` analyzes historical block-fee
    /// distribution off the snapshot per segment-2d R16 (c).
    pub ledger: &'a LedgerSnapshot,
    /// Number of recipients in the transaction. Used by
    /// estimators that size the fee against the projected
    /// transaction shape.
    pub recipient_count: usize,
    /// Number of inputs the output selector identified. Used
    /// by estimators that size the fee against the projected
    /// transaction shape.
    pub input_count: usize,
}

/// Trait isolating fee-estimation strategy from the
/// `LocalPendingTx::build` pipeline.
///
/// Phase 0j binding form per
/// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §3.1 (R16 segment-2c
/// closure). [`DaemonFeeEstimator`] is the V3.0 default
/// implementor; V3.x adds alternative impls per the
/// `docs/FOLLOWUPS.md` R16 entry:
///
/// - `ExplicitFeeEstimator` (V3.x): consumes a caller-pinned
///   feerate for wallet-UI / API explicit-fee workflows.
/// - `WalletSideEstimator` (V3.x; lands as a coordinated
///   `LedgerEngine` + `FeeEstimator` PR per R16 (c) /
///   segment-2d V3.0-lift evaluation): analyzes
///   [`LedgerSnapshot`] historical block-fee distribution to
///   estimate fees without daemon contact, improving wallet
///   privacy posture.
///
/// # F3-transitive sensitive-material discipline pin
///
/// Per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.5 F3 closure,
/// **[`FeeEstimator::Error`] and its `Debug` / `Display`
/// projections SHOULD NOT carry sensitive material**. The
/// `FeeEstimator` doesn't normally hold spend secrets (the
/// estimation context carries structural counts and the
/// ledger snapshot — no key material), so this is the
/// lighter-touch transitive application of the F3 discipline
/// pinned on [`Signer::Error`](super::signer::Signer::Error).
/// The trait still names the discipline uniformly so the
/// secret-locality boundary is grep-able across all engine
/// trait surfaces.
///
/// # Trait bounds
///
/// - `Send + Sync + 'static`: matches the engine-trait
///   pattern so an estimator can be held behind
///   `Arc<dyn FeeEstimator<Error = E>>` if needed.
/// - `type Error: Into<FeeEstimatorError>`: the
///   implementor's local error converts to the engine-wide
///   [`FeeEstimatorError`] discriminant set (landed C2α).
pub trait FeeEstimator: Send + Sync + 'static {
    /// Implementor-specific error type that converts into
    /// the engine-wide [`FeeEstimatorError`].
    type Error: Into<FeeEstimatorError>;

    /// Estimate the fee for a transaction with the given
    /// `priority` and structural shape (`context`).
    ///
    /// Returns the fee in atomic units. The caller
    /// (`LocalPendingTx::build`) adds this to the
    /// request's total amount to compute the
    /// [`OutputSelector::select_outputs`](super::OutputSelector::select_outputs)
    /// target.
    ///
    /// # Errors
    ///
    /// Returns the implementor's local `Error` type. The
    /// orchestrator converts via `.into()` to the engine-wide
    /// [`FeeEstimatorError`]. V3.0's [`DaemonFeeEstimator`]
    /// returns [`FeeEstimatorError::DaemonUnreachable`] on
    /// network failure and [`FeeEstimatorError::DaemonResponseInvalid`]
    /// on malformed responses; the Phase 1 stub returns `Ok`
    /// unconditionally with [`STUB_FEE_ATOMIC_UNITS`](super::pending::STUB_FEE_ATOMIC_UNITS).
    fn estimate_fee(
        &self,
        priority: FeePriority,
        context: &FeeEstimationContext<'_>,
    ) -> Result<u64, Self::Error>;
}

/// V3.0 default [`FeeEstimator`] implementor.
///
/// **Phase 1 stub.** Returns
/// [`STUB_FEE_ATOMIC_UNITS`](super::pending::STUB_FEE_ATOMIC_UNITS)
/// regardless of `priority` or `context` — matches the
/// pre-PR-5 `build_pending_tx_in_state` body's `let fee =
/// STUB_FEE_ATOMIC_UNITS;` line byte-for-byte. Phase 2a wires
/// the actual daemon `get_fee_estimates` query against the
/// priority variant.
///
/// # V3.x successors
///
/// `ExplicitFeeEstimator` and `WalletSideEstimator` are
/// V3.x successor impls landing per the
/// `docs/FOLLOWUPS.md` R16 entry. They plug in as
/// alternative [`FeeEstimator`] impls (the trait surface
/// does not re-open).
///
/// Zero-sized.
#[derive(Debug, Clone, Copy, Default)]
pub struct DaemonFeeEstimator;

impl FeeEstimator for DaemonFeeEstimator {
    type Error = FeeEstimatorError;

    fn estimate_fee(
        &self,
        _priority: FeePriority,
        _context: &FeeEstimationContext<'_>,
    ) -> Result<u64, FeeEstimatorError> {
        // Phase 1 stub: returns STUB_FEE_ATOMIC_UNITS
        // verbatim. Matches the pre-PR-5
        // `build_pending_tx_in_state` body's `let fee =
        // STUB_FEE_ATOMIC_UNITS;` line. Phase 2a wires daemon
        // `get_fee_estimates` against `_priority` and `_context`.
        Ok(super::pending::STUB_FEE_ATOMIC_UNITS)
    }
}

#[cfg(test)]
mod tests {
    //! C4γ `FeeEstimator` / `DaemonFeeEstimator` regression
    //! tests.
    //!
    //! Coverage scope (per `STAGE_1_PR_5_PENDING_TX_ENGINE.md`
    //! §7.X C4γ):
    //!
    //! - `daemon_fee_estimator_phase1_stub_returns_constant`
    //!   — regression: any priority + context yields
    //!   [`STUB_FEE_ATOMIC_UNITS`](super::super::pending::STUB_FEE_ATOMIC_UNITS).
    use super::*;
    use crate::engine::pending::STUB_FEE_ATOMIC_UNITS;
    use std::num::NonZeroU64;

    fn dummy_context() -> LedgerSnapshot {
        // The Phase 1 stub ignores all context fields; a
        // default-empty LedgerSnapshot is sufficient for the
        // regression. The `from_ledger_for_bench` constructor
        // is gated behind `bench-internals`; for the C4γ
        // stub-regression we don't need a real LedgerBlock —
        // we just need to verify the stub returns the
        // constant.
        //
        // Constructing a LedgerSnapshot from outside its
        // module requires either the bench-internals gate
        // or a pub(crate)-from-within-engine path. Here, the
        // test sits inside the engine module tree, so we
        // use the pub(crate) `from_ledger` constructor with
        // an empty LedgerBlock.
        use shekyl_engine_state::LedgerBlock;
        let block = LedgerBlock::empty();
        LedgerSnapshot::from_ledger(&block)
    }

    #[test]
    fn daemon_fee_estimator_phase1_stub_returns_constant() {
        let ledger = dummy_context();
        let context = FeeEstimationContext {
            ledger: &ledger,
            recipient_count: 1,
            input_count: 1,
        };
        // Phase 1 stub invariant: returns STUB_FEE_ATOMIC_UNITS
        // for every priority variant.
        for priority in [
            FeePriority::Economy,
            FeePriority::Standard,
            FeePriority::Priority,
            FeePriority::Custom(NonZeroU64::new(42).unwrap()),
        ] {
            let fee = DaemonFeeEstimator
                .estimate_fee(priority, &context)
                .expect("Phase 1 stub returns Ok unconditionally");
            assert_eq!(
                fee, STUB_FEE_ATOMIC_UNITS,
                "Phase 1 stub returns STUB_FEE_ATOMIC_UNITS regardless of priority"
            );
        }
    }
}
