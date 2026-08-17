// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `EconomicsEngine` error vocabulary (PR 7).

// --- Economics (PR 7) ------------------------------------------------------

/// Per-domain error for
/// [`EconomicsEngine`](crate::engine::traits::economics::EconomicsEngine), the
/// §2.7 trait that owns canonical economic derivation (base subsidy,
/// adaptive burn) for governance / display.
///
/// The trait declares `type Error: Into<EconomicsError>`; the V3.0
/// implementor [`LocalEconomics`](crate::engine::local_economics::LocalEconomics)
/// uses `Error = EconomicsError` directly, so the variants below are the
/// full failure surface of the trait at V3.0.
///
/// `#[non_exhaustive]` per the Stage 1 trait-error convention
/// (`LedgerError`, `KeyEngineError`): variants accrete additively as
/// V3.x consumers reveal new failure modes without re-opening the §2.7
/// trait surface.
///
/// # Two altitudes of failure (§6.3 G4)
///
/// - [`Self::Emission`] — the neutral-trajectory projection
///   (`base_emission_at`) hit an arithmetic boundary
///   (`already_generated` over supply, accumulation overflow). These
///   are structural impossibilities for a well-formed chain; the
///   variant exists so the projection cannot silently wrap.
/// - [`Self::ActivityInvariantViolation`] — an
///   [`ActivityMetric`](shekyl_economics::ActivityMetric) presented to
///   `burn_amount` carried a field combination impossible for any single
///   chain state. This is the implementor-side discriminator naming
///   *which* structural invariant the producer broke. **Coherence**
///   failures (four fields sampled from different chain views) are
///   **not** caught here — that is the producer's obligation per the
///   `ActivityMetric` rustdoc, and the V3.0 consequence is wrong
///   advisory display, not a typed error.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub(crate) enum EconomicsError {
    /// Neutral-trajectory emission projection failed at an arithmetic
    /// boundary. Wraps [`shekyl_economics::EmissionError`] (over-supply
    /// `already_generated`, or accumulation overflow).
    #[error("emission projection failure: {0}")]
    Emission(#[from] shekyl_economics::EmissionError),

    /// An [`ActivityMetric`](shekyl_economics::ActivityMetric) violated a
    /// structural invariant. Wraps
    /// [`shekyl_economics::ActivityInvariantViolation`] so the caller can
    /// tell which invariant (`circulating ≤ supply`,
    /// `staked ≤ circulating`, genesis-zero) the producer broke.
    #[error("activity metric invariant violation: {0}")]
    ActivityInvariantViolation(#[from] shekyl_economics::ActivityInvariantViolation),
}
