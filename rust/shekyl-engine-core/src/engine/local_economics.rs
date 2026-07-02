// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `LocalEconomics` — the V3.0 [`EconomicsEngine`] implementor.
//!
//! A **stateless** wrapper (§2.7 Stage 1 implementing-type note): it
//! holds the build-time-resolved [`EconomicParams`] and nothing mutable
//! (the claim-era `ChainEconomicsSource` read seam died with
//! `pool_weighted_total` — `LEGACY_CLAIM_ERA_RETIREMENT.md`). Every method
//! is a pure-function composition over `shekyl-economics` primitives plus
//! caller inputs:
//!
//! - [`base_emission_at`](EconomicsEngine::base_emission_at) — pure
//!   projection (`base_block_reward ∘ projected_already_generated`).
//! - [`burn_amount`](EconomicsEngine::burn_amount) — applies the adaptive
//!   burn percentage (`calc_burn_pct_from_activity`) to `fee`; the
//!   `stake_ratio` is formed by the single shared helper, never
//!   hand-divided here (Bug-2 class).
//! - [`parameters_snapshot`](EconomicsEngine::parameters_snapshot) — the
//!   constants rulebook, rebuilt fresh on every call (no cache).
//!
//! # CALIBRATION-PENDING
//!
//! The numeric outputs of these methods depend on
//! `config/economics_params.json` constants that are **still under
//! pre-genesis testnet recalibration** (emission speed factor, burn
//! coefficients, staker shares). The method *surfaces* are
//! stable; the *values* may churn each calibration generation
//! ([`CALIBRATION_GENERATION`](shekyl_economics::CALIBRATION_GENERATION)).
//! Value-vector tests are calibration-tagged; the generation-invariant
//! differential (C4) survives recalibration because it pins the shared 0h
//! primitive, not a specific height's emission.
//!
//! At V3.x Component 3 this type gains a `Mutex<AdaptiveBurnState>`; the
//! [`EconomicsEngine`] surface is unchanged across V3.0 → V3.x → Stage 4
//! (`EconomicsActor`).

use shekyl_economics::params::mul_scale;
use shekyl_economics::{ActivityMetric, EconomicParams, CALIBRATION_GENERATION};

use super::economics_snapshot::{
    snapshot_calibration_digest, CalibrationStamp, EconomicsParametersSnapshot,
};
use super::error::EconomicsError;
use super::traits::economics::EconomicsEngine;

/// V3.0 [`EconomicsEngine`] implementor — a pure-projection rulebook over
/// the build-time-resolved [`EconomicParams`].
// `pub` (not `pub(crate)`) to match the other default `Engine`
// implementors (`LocalLedger`, `LocalRefresh`, `LocalPendingTx`): it is
// the default `E` type argument of the `pub` `Engine`, so a more-private
// visibility trips `private_interfaces`. The `EconomicsEngine` trait
// itself stays `pub(crate)`, so R6 holds — external crates cannot name
// the trait to invoke its methods.
pub struct LocalEconomics {
    /// Build-time-resolved economic constants
    /// ([`EconomicParams::default`]). Immutable at V3.0.
    // R6: read only by the trait methods, which have zero V3.0 consumer (§5.5).
    #[allow(dead_code)]
    params: EconomicParams,
}

impl LocalEconomics {
    /// Construct with the build-time-resolved [`EconomicParams`] loader.
    pub(crate) fn new() -> Self {
        Self {
            params: EconomicParams::default(),
        }
    }

    /// Construct with an explicit `params` set. Used by the C4 fixtures,
    /// whose recorded rows are tagged with the calibration generation /
    /// `params_digest` they were generated under, so the differential must
    /// run against those exact constants.
    #[cfg(test)]
    pub(crate) fn with_params(params: EconomicParams) -> Self {
        Self { params }
    }
}

/// Convert a fixed-point [`SCALE`](shekyl_economics::EconomicParams)
/// (`1_000_000` = `1.0`) value to basis points (`÷100`), saturating into
/// `u16`. Lossy by design — the snapshot is a display rulebook, not a
/// consensus input.
// R6: used only by `parameters_snapshot`, which has zero V3.0 consumer (§5.5).
#[allow(dead_code)]
fn scale_to_bp(value: u64) -> u16 {
    u16::try_from(value / 100).unwrap_or(u16::MAX)
}

/// Convert a fixed-point SCALE value to milli-units (`÷1000`), saturating
/// into `u16`.
// R6: used only by `parameters_snapshot`, which has zero V3.0 consumer (§5.5).
#[allow(dead_code)]
fn scale_to_milli_u16(value: u64) -> u16 {
    u16::try_from(value / 1000).unwrap_or(u16::MAX)
}

/// Convert a fixed-point SCALE value to milli-units (`÷1000`), saturating
/// into `u32` (release multipliers can exceed `1.0`).
// R6: used only by `parameters_snapshot`, which has zero V3.0 consumer (§5.5).
#[allow(dead_code)]
fn scale_to_milli_u32(value: u64) -> u32 {
    u32::try_from(value / 1000).unwrap_or(u32::MAX)
}

impl EconomicsEngine for LocalEconomics {
    type Error = EconomicsError;

    fn base_emission_at(&self, height: u64) -> Result<u64, Self::Error> {
        // Pure projection — composes the shared 0h primitive; reads
        // nothing from `self.source`. `EmissionError` (`already_generated`
        // over supply, accumulation overflow) maps into `EconomicsError`
        // via `#[from]`.
        Ok(shekyl_economics::base_emission_at(height, &self.params)?)
    }

    fn burn_amount(&self, fee: u64, activity: ActivityMetric) -> Result<u64, Self::Error> {
        // `activity` was validated at `ActivityMetric::new`, so the
        // structural invariant `total_staked <= circulating_supply`
        // holds and `total_staked` fits in `u64`. The `unwrap_or` clamp
        // to `circulating_supply` is the proven upper bound and is never
        // reached in practice; it keeps the path panic-free regardless.
        let total_staked =
            u64::try_from(activity.total_staked()).unwrap_or(activity.circulating_supply());
        let burn_pct = shekyl_economics::calc_burn_pct_from_activity(
            activity.tx_volume(),
            self.params.tx_volume_baseline,
            activity.circulating_supply(),
            total_staked,
            &self.params,
        );
        // Absolute atomic units to burn: apply the SCALE-fixed-point
        // percentage to `fee` with the same `mul_scale` floor the
        // consensus burn split uses (no second rounding rule).
        Ok(mul_scale(fee, burn_pct))
    }

    fn parameters_snapshot(&self) -> EconomicsParametersSnapshot {
        // Rebuilt fresh on every call — no process-wide cache (§6.3 G5).
        // The `as_of` stamp lets a consumer detect a stale captured copy.
        let p = &self.params;
        EconomicsParametersSnapshot {
            emission_speed_factor: u8::try_from(p.emission_speed_factor_per_minute)
                .unwrap_or(u8::MAX),
            money_supply_atomic: p.money_supply,
            final_subsidy_per_minute: p.final_subsidy_per_minute,
            tx_volume_baseline: p.tx_volume_baseline,
            release_min_milli: scale_to_milli_u32(p.release_min),
            release_max_milli: scale_to_milli_u32(p.release_max),
            burn_base_rate_bp: scale_to_bp(p.burn_base_rate),
            burn_cap_bp: scale_to_bp(p.burn_cap),
            staker_fee_pool_share_bp: scale_to_bp(p.staker_pool_share),
            staker_emission_share_bp: scale_to_bp(shekyl_economics::STAKER_EMISSION_SHARE),
            staker_emission_decay_milli: scale_to_milli_u16(
                shekyl_economics::STAKER_EMISSION_DECAY,
            ),
            as_of: CalibrationStamp {
                generation: CALIBRATION_GENERATION,
                // Full-surface digest: covers `EconomicParams` *and* the
                // staker-emission consts this snapshot also exposes
                // (§6.3 G5) — not just the `EconomicParams` sub-digest
                // `shekyl_economics::params_digest` produces.
                params_digest: snapshot_calibration_digest(
                    p,
                    shekyl_economics::STAKER_EMISSION_SHARE,
                    shekyl_economics::STAKER_EMISSION_DECAY,
                ),
            },
        }
    }
}
