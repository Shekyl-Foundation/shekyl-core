// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Raw fee-correction scalar `C`.
//!
//! [`FeeCorrection`] is the multiplier the daemon serves, raw (FL-R20). No
//! quantizer stands over it: the pow2 ceiling, the hysteresis band and the
//! representable-`C` floor went with FL-R21, and the wallet's absolute cap
//! is the exact structural maximum of this expression
//! (`shekyl-engine-core` `fee_policy.rs`).

use crate::params::{EconomicParams, SCALE};
use crate::release::calc_release_multiplier;
use crate::volume::TxVolume;

/// Raw fee-correction scalar `C = (1−σ)·M_r/(1−b)` in [`SCALE`] units.
///
/// Served multiplier for every rung and the relay floor. `C < 1` on a quiet
/// chain lowers the floor; `C > 1` raises it. No snap, no band, no rounding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FeeCorrection(u64);

impl FeeCorrection {
    /// `C = 1` in SCALE units.
    pub const UNITY: Self = Self(SCALE);

    /// Wrap a SCALE-unit value. Tests, the FFI, and the wallet-cap bound
    /// (the structural maximum of `C`, a number ≥ any reachable `C`) use
    /// this.
    #[must_use]
    pub const fn from_scaled(scaled: u64) -> Self {
        Self(scaled)
    }

    #[must_use]
    pub const fn as_scaled(self) -> u64 {
        self.0
    }
}

/// `C = (1−σ)·M_r/(1−b)` from the caller's already-computed `σ` and `b`
/// (the same `shekyl_emission_share_at` / `shekyl_calc_burn_pct` values
/// the validation path uses at this state).
///
/// Total: `σ` and `b` are clamped below `SCALE`, so the divisor is at least
/// 1 and the quotient of two `u128`s built from `u64`s cannot exceed
/// `u64::MAX`.
#[must_use]
pub fn fee_correction(
    tx_volume: TxVolume,
    sigma_scaled: u64,
    burn_pct_scaled: u64,
    params: &EconomicParams,
) -> FeeCorrection {
    let m_r = calc_release_multiplier(
        tx_volume,
        params.tx_volume_baseline,
        params.release_min,
        params.release_max,
    );
    let sigma = sigma_scaled.min(SCALE - 1);
    let b = burn_pct_scaled.min(params.burn_cap).min(SCALE - 1);
    FeeCorrection(
        u64::try_from(u128::from(SCALE - sigma) * u128::from(m_r) / u128::from(SCALE - b))
            .expect("C fits u64: numerator <= SCALE * release_max, divisor >= 1"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_correction_is_continuous_and_falls_below_one() {
        let p = EconomicParams::default();

        assert_eq!(
            fee_correction(TxVolume::per_block(50), 0, 0, &p),
            FeeCorrection::UNITY
        );

        let quiet = fee_correction(TxVolume::per_block(1), SCALE * 15 / 100, 0, &p);
        assert_eq!(quiet.as_scaled(), SCALE * 68 / 100);
        assert!(
            quiet < FeeCorrection::UNITY,
            "raw C must be able to LOWER the floor"
        );

        let a = fee_correction(TxVolume::window(50 * 720 + 1, 720), 0, 0, &p);
        let b = fee_correction(TxVolume::window(50 * 720 + 2, 720), 0, 0, &p);
        assert!(b >= a, "C is monotone in volume");
        assert!(
            b.as_scaled() - a.as_scaled() < SCALE / 1000,
            "one tx must move raw C by well under 0.1%, got {} in SCALE units",
            b.as_scaled() - a.as_scaled()
        );
    }
}
