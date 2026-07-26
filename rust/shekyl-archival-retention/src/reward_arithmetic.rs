//! Integer reward arithmetic for archival emission (REWARD_EMISSION_LEG.md §4).
//!
//! Substrate-free: no LMDB, no FFI. Consumed by consensus verification, KATs, and
//! `shekyl-staking-sim` (`--curve-impl=integer`).

#![deny(clippy::float_arithmetic)]

/// Fixed-point scale for work, scarcity, and curve values (milli-units).
///
/// **Consensus invariant, frozen by PR 1.5** (`ARCHIVAL_SIM_ECONOMICS_VERDICT.md`).
/// This is the fixed-point scale the §5.4 zero-tolerance emission-vin compare runs
/// in; every node must agree on it bit-for-bit. **Changing this value forks the
/// chain** and invalidates the F-E8 u128 width audit (a larger scale widens the
/// `mul_div_floor` operands). It is not a tuning knob — the milli freeze is
/// validated band-interior; see `ARCHIVAL_REWARD_ARITHMETIC.md` §Economic-tolerance
/// for the raise-`N` reopen criterion.
pub const WORK_MILLI_SCALE: u64 = 1_000;

// Tripwire: the value above is consensus-load-bearing and frozen. Editing the
// const without consciously editing this guard (and reading the note) forks the
// chain. Mirrors the `const _: () = assert!(...)` discipline in consensus_state.rs.
const _: () = assert!(
    WORK_MILLI_SCALE == 1_000,
    "WORK_MILLI_SCALE is a frozen consensus invariant (PR 1.5); changing it forks the chain"
);

/// Micro-units per milli-unit — the finer intermediate precision the per-shard
/// scarcity term is accumulated at before the **single** floor back to milli
/// (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` D1, F-B). Flooring each shard's
/// `g/r` at milli (the pre-fix path) zeroed every holder of a shard past the
/// co-holder cliff (`r_market > g_milli`); carrying `10⁻⁶` and flooring once at
/// the aggregate confines the truncation to `< 1` micro/shard.
pub const WORK_MICRO_PER_MILLI: u64 = 1_000;

/// Fixed-point scale for the per-shard micro scarcity term (`= WORK_MILLI_SCALE
/// · WORK_MICRO_PER_MILLI = 10⁶`). Per-entry micro is bounded by `1000·g ≤
/// 3.5×10⁶` at the calibration-band ceiling — `u32` with ~1,200× headroom
/// (F-C); the per-bond aggregate needs `u64` (`work_micro_by_bond`). This does
/// **not** reopen the F-E8 `u128` width audit: `WORK_MILLI_SCALE` is untouched
/// and every new intermediate stays inside the existing `u64`/`u128` domains.
pub const WORK_MICRO_SCALE: u64 = WORK_MILLI_SCALE * WORK_MICRO_PER_MILLI;

const _: () = assert!(
    WORK_MICRO_SCALE == 1_000_000,
    "WORK_MICRO_SCALE = WORK_MILLI_SCALE · WORK_MICRO_PER_MILLI; the micro path is 10⁻³ of milli"
);

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

/// Per-shard scarcity in **micro-units**:
/// `floor((WORK_MICRO_SCALE / r_market) · g_age_milli / WORK_MILLI_SCALE)`
/// `= floor(WORK_MICRO_PER_MILLI · g / r_market)`.
///
/// This replaces the pre-fix per-shard `scarcity_milli`, which floored `g/r` at
/// milli and so returned `0` for every shard past the co-holder cliff
/// (`r_market > g_milli`), zeroing bulk holders of common shards
/// (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` D1). The micro term is summed
/// per bond and floored to milli **once** at the aggregate
/// ([`work_milli_from_micro`]).
///
/// **Rounding direction (§11.5):** the single `mul_div_floor` floors, so a
/// sub-micro remainder is dropped — the residual always favours the protocol,
/// never the claimant. `r_market == 0` (no market co-holder) scores `0`.
#[must_use]
pub fn scarcity_micro(r_market: u64, age_milli: u64, age_weight_milli: u64) -> u64 {
    if r_market == 0 {
        return 0;
    }
    let g = g_age_milli(age_milli, age_weight_milli);
    mul_div_floor(
        WORK_MICRO_SCALE,
        g,
        r_market.saturating_mul(WORK_MILLI_SCALE),
    )
    .unwrap_or(0)
}

/// The **single** floor-to-milli site (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`
/// F-E): collapse a per-bond micro accumulator to the milli value the curve and
/// the persisted `Σwork(E)` consume. Both epoch close and the emission verify
/// body reach milli through this one function, so their per-shard (micro) and
/// aggregate (milli) views cannot drift onto different scales.
///
/// **Rounding direction (§11.5):** integer division floors, dropping the
/// sub-milli remainder in the protocol's favour — the same direction as every
/// other step in the micro path.
#[must_use]
pub fn work_milli_from_micro(work_micro: u64) -> u64 {
    work_micro / WORK_MICRO_PER_MILLI
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
