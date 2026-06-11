//! Integer reward arithmetic for archival emission (REWARD_EMISSION_LEG.md §4).
//!
//! Substrate-free: no LMDB, no FFI. Consumed by consensus verification, KATs, and
//! `shekyl-staking-sim` (`--curve-impl=integer`).

#![deny(clippy::float_arithmetic)]

/// Fixed-point scale for work, scarcity, and curve values (milli-units).
pub const WORK_MILLI_SCALE: u64 = 1_000;

/// Provisional banded PL `Curve`: decreasing slopes → plateau.
///
/// Work breakpoints are fractions of `plateau_work_milli`; plateau credited work is
/// `plateau_value_milli`. Default shape matches the float sim (`reward.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandedCurveParams {
    pub plateau_work_milli: u64,
    pub plateau_value_milli: u64,
}

impl BandedCurveParams {
    /// Build from sim-style `cap` (plateau credited value); work to plateau is `2·cap`.
    #[must_use]
    pub const fn from_sim_cap_milli(plateau_value_milli: u64) -> Self {
        Self {
            plateau_work_milli: plateau_value_milli.saturating_mul(2),
            plateau_value_milli,
        }
    }

    #[must_use]
    pub const fn default_provisional() -> Self {
        Self::from_sim_cap_milli(8_000)
    }
}

/// `g(age) = 1 + age_weight_milli · age_milli / WORK_MILLI_SCALE` in milli-units.
#[must_use]
pub fn g_age_milli(age_milli: u64, age_weight_milli: u64) -> u64 {
    WORK_MILLI_SCALE.saturating_add(
        mul_div_floor(age_weight_milli, age_milli, WORK_MILLI_SCALE).unwrap_or(u64::MAX),
    )
}

/// Scarcity milli = floor((WORK_MILLI_SCALE / r_market) * g_age_milli / WORK_MILLI_SCALE).
#[must_use]
pub fn scarcity_milli(r_market: u64, age_milli: u64, age_weight_milli: u64) -> u64 {
    if r_market == 0 {
        return 0;
    }
    let g = g_age_milli(age_milli, age_weight_milli);
    mul_div_floor(
        WORK_MILLI_SCALE,
        g,
        r_market.saturating_mul(WORK_MILLI_SCALE),
    )
    .unwrap_or(0)
}

/// Evaluate banded piecewise-linear `Curve(work_milli)` → credited work milli.
#[must_use]
pub fn curve_milli(work_milli: u64, params: &BandedCurveParams) -> u64 {
    if work_milli == 0 || params.plateau_value_milli == 0 {
        return 0;
    }
    let pw = params.plateau_work_milli.max(1);
    let pv = params.plateau_value_milli;
    let b1 = pw / 4;
    let b2 = pw / 2;
    let b3 = pw;

    if work_milli >= b3 {
        return pv;
    }

    let mut y = 0u64;

    // segment 1: slope 1.0
    let mut x = if work_milli > b1 {
        y = y.saturating_add(b1);
        b1
    } else {
        return work_milli;
    };

    // segment 2: slope 0.5
    if work_milli > b2 {
        let seg = b2 - x;
        y = y.saturating_add(seg / 2);
        x = b2;
    } else {
        let seg = work_milli - x;
        return y.saturating_add(seg / 2);
    }

    // segment 3: slope 0.25
    let seg = work_milli - x;
    y.saturating_add(mul_div_floor(seg, 1, 4).unwrap_or(0))
}

/// `floor(a * b / d)` with `u128` intermediate; `None` on overflow of quotient to u64.
#[must_use]
pub fn mul_div_floor(a: u64, b: u64, d: u64) -> Option<u64> {
    if d == 0 {
        return None;
    }
    let q = u128::from(a).saturating_mul(u128::from(b)) / u128::from(d);
    u64::try_from(q).ok()
}

/// Per-P reward: `floor(budget * capped / sigma_work)`; dust stays unminted.
#[must_use]
pub fn reward_share_floor(budget: u64, capped_milli: u64, sigma_work_milli: u64) -> u64 {
    if sigma_work_milli == 0 || capped_milli == 0 {
        return 0;
    }
    mul_div_floor(budget, capped_milli, sigma_work_milli).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curve_reaches_plateau_at_plateau_work() {
        let p = BandedCurveParams::from_sim_cap_milli(8_000);
        assert_eq!(curve_milli(16_000, &p), 8_000);
        assert_eq!(curve_milli(32_000, &p), 8_000);
    }

    #[test]
    fn curve_monotone_below_plateau() {
        let p = BandedCurveParams::default_provisional();
        let mut prev = 0;
        for w in (1..=16_000).step_by(500) {
            let c = curve_milli(w, &p);
            assert!(c >= prev, "w={w} c={c} prev={prev}");
            prev = c;
        }
    }

    #[test]
    fn reward_share_sums_to_budget_when_single_claimer() {
        let budget = 1_000_000u64;
        let capped = 8_000u64;
        assert_eq!(reward_share_floor(budget, capped, capped), budget);
    }
}
