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
//! - [`DaemonFeeEstimator`] — V3.0 default impl: resolves the
//!   priority against the build's atomic daemon fee snapshot
//!   through the single-source weight model and the two-pass
//!   convergence fixpoint (`tx_fee_model`).
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

use shekyl_units::AtomicUnits;

use super::error::FeeEstimatorError;
use super::fee_policy::ValidatedFeeEstimates;
use super::refresh::LedgerSnapshot;
use super::tx_counts::{InputCount, OutputCount};
use super::tx_fee_model::{converge_fee, fee_from_weight, fee_rate_for_priority, predict_weight};

/// Caller-supplied fee preference for the
/// `PendingTxEngine::build` pipeline.
///
/// Each variant is resolved against the daemon's
/// `get_fee_estimates` snapshot (for [`DaemonFeeEstimator`]) or
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
    /// daemon's named tiers are bypassed, but not the Custom band:
    /// the rate must sit between the snapshot's economy floor and
    /// min(100× economy, the absolute per-weight cap)
    /// ([`FeeEstimatorError::CustomFeeOutOfRange`](super::error::FeeEstimatorError)
    /// otherwise). Snapshot well-formedness (monotonicity, absolute
    /// cap on *named* tiers) is already decided before this variant
    /// is interpreted — an honest 2021-scaling Priority tier does
    /// not lock Custom.
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
/// - `output_count`: projected output count for this fee
///   variant (`N` payments or `N+1` with change intent).
/// - `fee_snapshot`: validated §3.3 snapshot fetched once
///   per build; the sync estimator reads rates from here.
/// - `tree_depth`: FCMP++ tree depth for weight prediction.
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
    /// Number of inputs the output selector identified
    /// (bounded `1..=MAX_INPUTS`). Used by estimators that size
    /// the fee against the projected transaction shape.
    pub input_count: InputCount,
    /// Projected output count for this fee variant
    /// (bounded `1..=MAX_OUTPUTS`).
    pub output_count: OutputCount,
    /// Validated single-RPC fee snapshot for the build (§3.3 / PF1).
    pub fee_snapshot: ValidatedFeeEstimates,
    /// Tree depth for structural weight prediction.
    pub tree_depth: u8,
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
    /// network failure, [`FeeEstimatorError::DaemonResponseInvalid`]
    /// on malformed responses, [`FeeEstimatorError::DaemonFeeUnreasonable`]
    /// on a non-monotonic or over-cap snapshot, and
    /// [`FeeEstimatorError::CustomFeeOutOfRange`] on a caller-band miss.
    fn estimate_fee(
        &self,
        priority: FeePriority,
        context: &FeeEstimationContext<'_>,
    ) -> Result<AtomicUnits, Self::Error>;
}

/// V3.0 default [`FeeEstimator`] implementor.
///
/// Resolves `priority` against the context's validated daemon fee
/// snapshot: the priority maps to a per-weight rate, and the fee
/// converges through the single-source weight model at the context's
/// structural shape (`tx_fee_model::converge_fee`). It deliberately
/// ignores `context.ledger` — that field is the V3.x
/// `WalletSideEstimator` hook (wallet-side history), not this
/// estimator's input. Snapshot well-formedness is the fetch
/// boundary's job (`ValidatedFeeEstimates`), not this impl's.
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
        priority: FeePriority,
        context: &FeeEstimationContext<'_>,
    ) -> Result<AtomicUnits, FeeEstimatorError> {
        let rate = fee_rate_for_priority(priority, &context.fee_snapshot)?;
        // The counts are type-bounded (`>= 1`), so no `.max(1)` floor is needed.
        let n_in = context.input_count;
        let n_out = context.output_count;
        let seed = fee_from_weight(&rate, predict_weight(n_in, n_out, context.tree_depth, 0));
        let fee = converge_fee(&rate, n_in, n_out, context.tree_depth, seed);
        Ok(AtomicUnits::from_raw(fee))
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
    //! - `daemon_fee_estimator_returns_positive_fee_from_snapshot`
    //!   — regression: structural estimator yields a positive fee
    //!   from a fixed §3.3 snapshot.
    use super::*;
    use crate::engine::fee_policy::ValidatedFeeEstimates;
    use crate::engine::traits::FeeEstimates;
    use shekyl_rpc_client::FeeRate;
    use std::num::NonZeroU64;

    fn dummy_context() -> LedgerSnapshot {
        // `DaemonFeeEstimator` deliberately ignores the ledger field
        // (that hook is the V3.x `WalletSideEstimator`'s), so a
        // default-empty LedgerSnapshot is sufficient here.
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

    fn test_fee_snapshot() -> ValidatedFeeEstimates {
        // Distinct, monotonic, under the absolute cap. Ceiling
        // refusals live in `fee_policy::tests`.
        ValidatedFeeEstimates::try_new(FeeEstimates {
            economy: FeeRate::new(5, 1).expect("economy fee rate is non-zero"),
            standard: FeeRate::new(10, 1).expect("standard fee rate is non-zero"),
            priority: FeeRate::new(40, 1).expect("priority fee rate is non-zero"),
            quantization_mask: 1,
        })
        .expect("test fixture is well-formed")
    }

    #[test]
    fn daemon_fee_estimator_returns_positive_fee_from_snapshot() {
        let ledger = dummy_context();
        let snapshot = test_fee_snapshot();
        let context = FeeEstimationContext {
            ledger: &ledger,
            recipient_count: 1,
            input_count: InputCount::clamped(1),
            output_count: OutputCount::clamped(2),
            fee_snapshot: snapshot,
            tree_depth: 1,
        };
        for priority in [
            FeePriority::Economy,
            FeePriority::Standard,
            FeePriority::Priority,
            FeePriority::Custom(NonZeroU64::new(42).unwrap()),
        ] {
            let fee = DaemonFeeEstimator
                .estimate_fee(priority, &context)
                .expect("estimator returns Ok for valid snapshot");
            assert!(
                fee > AtomicUnits::ZERO,
                "priority {priority:?} yields a positive fee"
            );
        }
    }

    /// PHASE_2A_SEND_PATH.md §8.1 — priority tiers map to distinct daemon rates.
    #[tokio::test]
    async fn daemon_fee_estimator_maps_test_daemon_priority_tiers() {
        use crate::engine::fee_snapshot::{DaemonFeeSnapshotSource, FeeSnapshotSource};
        use crate::engine::test_support::{TestDaemon, DEFAULT_TEST_SEED};

        let daemon = std::sync::Arc::new(TestDaemon::with_seed(DEFAULT_TEST_SEED));
        daemon.set_fee_estimates(FeeEstimates {
            economy: FeeRate::new(5, 1).expect("economy rate"),
            standard: FeeRate::new(10, 1).expect("standard rate"),
            priority: FeeRate::new(40, 1).expect("priority rate"),
            quantization_mask: 1,
        });

        let snapshot = DaemonFeeSnapshotSource::from_arc(std::sync::Arc::clone(&daemon))
            .fetch()
            .await
            .expect("fee snapshot fetch");
        let ledger = dummy_context();
        let base = FeeEstimationContext {
            ledger: &ledger,
            recipient_count: 1,
            input_count: InputCount::clamped(1),
            output_count: OutputCount::clamped(2),
            fee_snapshot: snapshot,
            tree_depth: 1,
        };

        let economy = DaemonFeeEstimator
            .estimate_fee(FeePriority::Economy, &base)
            .expect("economy fee");
        let standard = DaemonFeeEstimator
            .estimate_fee(FeePriority::Standard, &base)
            .expect("standard fee");
        let priority = DaemonFeeEstimator
            .estimate_fee(FeePriority::Priority, &base)
            .expect("priority fee");

        assert!(economy > AtomicUnits::ZERO);
        assert!(standard > economy);
        assert!(priority > standard);
    }
}
