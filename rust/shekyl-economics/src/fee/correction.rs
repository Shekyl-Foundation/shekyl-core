// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Raw fee-correction scalar `C`, and the wallet-cap ceiling over it.
//!
//! [`FeeCorrection`] is the multiplier the daemon serves. [`quantize_pow2_ceil`]
//! is `C_q ≥ C`: the wallet's absolute fee-rate cap uses it as an upper
//! bound, and the daemon does not multiply by it (FL-R20). The §7
//! hysteresis band was deleted with FL-R21.

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

    /// Wrap a SCALE-unit value. Tests, FFI, and the wallet-cap bound (a
    /// number ≥ any reachable `C`) use this.
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

/// Exact-integer `2^k ≤ c/s` (no float log2 — this feeds a
/// wallet-must-match-daemon derivation).
fn pow2_le(c: u128, s: u128, k: i32) -> bool {
    if k >= 0 {
        (s << k) <= c
    } else {
        s <= (c << (-k))
    }
}

/// Ceiling pow2 snap in `SCALE` fixed point: smallest exact power of two
/// `≥ c/SCALE`. Panics only if the snapped exponent leaves the range
/// `SCALE` can represent exactly (`2^-6 … 2^43`).
#[must_use]
pub fn quantize_pow2_ceil(c_scaled: u64) -> u64 {
    assert!(c_scaled > 0, "correction factor is structurally positive");
    let c = u128::from(c_scaled);
    let s = u128::from(SCALE);
    let mut kf: i32 = -40;
    while pow2_le(c, s, kf + 1) {
        kf += 1;
    }
    let exact = if kf >= 0 {
        (s << kf) == c
    } else {
        (c << (-kf)) == s
    };
    let k = if exact { kf } else { kf + 1 };
    assert!(
        (-6..=43).contains(&k),
        "2^{k} not exactly representable in SCALE units"
    );
    if k >= 0 {
        SCALE << k
    } else {
        SCALE >> (-k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantize_snap_is_exact_integer_ceiling() {
        for c in [500_000u64, 1_000_000, 2_000_000, 4_000_000] {
            assert_eq!(quantize_pow2_ceil(c), c);
        }
        assert_eq!(quantize_pow2_ceil(680_000), 1_000_000);
        assert_eq!(quantize_pow2_ceil(1_130_000), 2_000_000);
        assert_eq!(quantize_pow2_ceil(12_917_390), 16_000_000);
    }

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
