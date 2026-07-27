//! Economic system parameters — mirrors constants from cryptonote_config.h.

use serde::{Deserialize, Serialize};

include!(concat!(env!("OUT_DIR"), "/params_generated.rs"));

pub const SCALE: u64 = GENERATED_SCALE;

/// Total coin supply ceiling in atomic units (`money_supply` from
/// `config/economics_params.json`). Exposed for structural-invariant
/// validation in [`crate::activity::ActivityMetric::new`]
/// (`circulating_supply ≤ MONEY_SUPPLY`).
pub const MONEY_SUPPLY: u64 = GENERATED_MONEY_SUPPLY;

/// Base staker emission share in fixed-point [`SCALE`] units
/// (`shekyl_staker_emission_share`; `150_000` = 15%). This is the
/// **base** share before the height-dependent decay in
/// [`crate::emission_share::calc_effective_emission_share`]; consumers
/// that need the effective share apply the decay themselves. Surfaced
/// for the `EconomicsParametersSnapshot` rulebook (PR 7 §5.3 R2).
pub const STAKER_EMISSION_SHARE: u64 = GENERATED_STAKER_EMISSION_SHARE;

/// Per-year staker emission decay factor in fixed-point [`SCALE`] units
/// (`shekyl_staker_emission_decay`; `900_000` = 0.90/year). Snapshot
/// rulebook constant (PR 7 §5.3 R2).
pub const STAKER_EMISSION_DECAY: u64 = GENERATED_STAKER_EMISSION_DECAY;

/// Blocks per year at the configured DAA target
/// (`shekyl_blocks_per_year`). Used with [`STAKER_EMISSION_DECAY`] to
/// project the effective staker emission share at a height.
pub const BLOCKS_PER_YEAR: u64 = GENERATED_BLOCKS_PER_YEAR;

/// Calibration generation index for the resolved economic parameter set
/// (**CALIBRATION-PENDING**).
///
/// The monotonic configuration-epoch tag surfaced through
/// `CalibrationStamp::generation` (PR 7 §6.3 G5). At V3.0 it is a
/// build-time constant, **not** a chain height: it increments on each
/// pre-genesis testnet recalibration of `config/economics_params.json`,
/// so a consumer holding an older snapshot can detect "estimate from
/// generation N; current is N+1" without a bit-exact digest compare.
///
/// Pre-genesis the parameter set is still under calibration, so this
/// starts at `0`. Bump it whenever the resolved `EconomicParams` change
/// in a way operators should treat as a new epoch.
///
/// **Reopening criteria (`21-reversion-clause-discipline.mdc`):** at V3.x
/// Component 3 adaptive burn may bind calibration epochs to heights
/// (`generation_active_at(height)`); that is a FOLLOWUPS item and would
/// move the generation out of this build-time constant into engine-held
/// state. Until then it stays a constant.
pub const CALIBRATION_GENERATION: u32 = 0;

/// A malformed parameter set, refused at the door.
///
/// N-1 (PR #373 review): the runtime fail-closed in
/// [`crate::escalation::staker_pool_share_at`] is the *second* layer. This is the
/// first — a bad asymptote must not be **storable**, not merely unapplied,
/// because it is the field that would silently delete the burn channel if it
/// were ever honoured.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EconomicParamsError {
    /// `escalation_asymptote_share >= SCALE` would redirect the entire burn and
    /// delete the deflation channel (§6.1 constraint 3).
    #[error(
        "escalation asymptote {asymptote} must be < SCALE ({scale}): a full-scale \
         share redirects the entire burn and deletes the deflation channel"
    )]
    AsymptoteAtOrAboveScale {
        /// The offending asymptote.
        asymptote: u64,
        /// `SCALE`, for the message.
        scale: u64,
    },
    /// `escalation_asymptote_share < staker_pool_share` would make the
    /// "escalation" descend, breaking §6.1 constraints 1 and 2.
    #[error(
        "escalation asymptote {asymptote} is below the floor {floor}: the \
         escalation would descend, and archivers would be worse off than under \
         the flat share"
    )]
    AsymptoteBelowFloor {
        /// The offending asymptote.
        asymptote: u64,
        /// The floor it fell below.
        floor: u64,
    },
}

/// Deserialization shim — every `EconomicParams` that arrives from serde is
/// routed through [`EconomicParams::validate`] first.
///
/// This is what makes the well-formedness check a **door** rather than an
/// advisory: `#[serde(try_from = ...)]` means there is no way to deserialize an
/// invalid parameter set at all, so downstream code cannot be handed one.
#[derive(Deserialize)]
#[serde(rename = "EconomicParams")]
struct EconomicParamsWire {
    release_min: u64,
    release_max: u64,
    tx_volume_baseline: u64,
    burn_base_rate: u64,
    burn_cap: u64,
    staker_pool_share: u64,
    money_supply: u64,
    emission_speed_factor_per_minute: u64,
    final_subsidy_per_minute: u64,
    daa_target_seconds: u64,
    escalation_knee_n: u64,
    escalation_asymptote_share: u64,
}

impl TryFrom<EconomicParamsWire> for EconomicParams {
    type Error = EconomicParamsError;

    fn try_from(w: EconomicParamsWire) -> Result<Self, Self::Error> {
        let p = Self {
            release_min: w.release_min,
            release_max: w.release_max,
            tx_volume_baseline: w.tx_volume_baseline,
            burn_base_rate: w.burn_base_rate,
            burn_cap: w.burn_cap,
            staker_pool_share: w.staker_pool_share,
            money_supply: w.money_supply,
            emission_speed_factor_per_minute: w.emission_speed_factor_per_minute,
            final_subsidy_per_minute: w.final_subsidy_per_minute,
            daa_target_seconds: w.daa_target_seconds,
            escalation_knee_n: w.escalation_knee_n,
            escalation_asymptote_share: w.escalation_asymptote_share,
        };
        p.validate()?;
        Ok(p)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "EconomicParamsWire")]
pub struct EconomicParams {
    pub release_min: u64,
    pub release_max: u64,
    pub tx_volume_baseline: u64,
    pub burn_base_rate: u64,
    pub burn_cap: u64,
    pub staker_pool_share: u64,
    pub money_supply: u64,
    pub emission_speed_factor_per_minute: u64,
    pub final_subsidy_per_minute: u64,
    pub daa_target_seconds: u64,
    /// `frozen_segment_count` at which the D2 escalation saturates. Shape frozen,
    /// **number provisional-until-testnet** (§11.4 ceremony).
    pub escalation_knee_n: u64,
    /// Staker share at and beyond the knee. **Number provisional**; the genesis
    /// value equals `staker_pool_share`, which makes the escalation flat and the
    /// behaviour bit-identical to today's constant until the ceremony pins it.
    pub escalation_asymptote_share: u64,
}

impl Default for EconomicParams {
    fn default() -> Self {
        Self {
            release_min: GENERATED_RELEASE_MIN,
            release_max: GENERATED_RELEASE_MAX,
            tx_volume_baseline: GENERATED_TX_VOLUME_BASELINE,
            burn_base_rate: GENERATED_BURN_BASE_RATE,
            burn_cap: GENERATED_BURN_CAP,
            staker_pool_share: GENERATED_STAKER_POOL_SHARE,
            money_supply: GENERATED_MONEY_SUPPLY,
            emission_speed_factor_per_minute: GENERATED_EMISSION_SPEED_FACTOR_PER_MINUTE,
            final_subsidy_per_minute: GENERATED_FINAL_SUBSIDY_PER_MINUTE,
            daa_target_seconds: GENERATED_DAA_TARGET_SECONDS,
            escalation_knee_n: GENERATED_ESCALATION_KNEE_N,
            escalation_asymptote_share: GENERATED_ESCALATION_ASYMPTOTE_SHARE,
        }
    }
}

impl EconomicParams {
    /// Reject a parameter set whose escalation numbers violate the **frozen
    /// shape** (§6.1 constraints 1–3).
    ///
    /// Called from the serde `try_from` shim, so it gates every deserialization,
    /// and available directly for construction paths.
    ///
    /// This validates the *shape's* invariants only — it deliberately does **not**
    /// opine on which asymptote is correct. That number is ceremony-gated and
    /// unpinned (§11.4); a validator that ranged it here would be pinning it by
    /// the back door.
    pub fn validate(&self) -> Result<(), EconomicParamsError> {
        if self.escalation_asymptote_share >= SCALE {
            return Err(EconomicParamsError::AsymptoteAtOrAboveScale {
                asymptote: self.escalation_asymptote_share,
                scale: SCALE,
            });
        }
        if self.escalation_asymptote_share < self.staker_pool_share {
            return Err(EconomicParamsError::AsymptoteBelowFloor {
                asymptote: self.escalation_asymptote_share,
                floor: self.staker_pool_share,
            });
        }
        Ok(())
    }

    /// The escalation shape parameters this set implies.
    ///
    /// `staker_pool_share` **is** the floor — the escalation's constraint-2 base
    /// is the very constant it replaces, which is what makes the change a strict
    /// improvement rather than a redistribution.
    #[must_use]
    pub fn escalation(&self) -> crate::escalation::EscalationParams {
        crate::escalation::EscalationParams {
            floor_share: self.staker_pool_share,
            knee_n: self.escalation_knee_n,
            asymptote_share: self.escalation_asymptote_share,
        }
    }
}

/// `stake_ratio = total_staked / circulating_supply` in fixed-point SCALE units.
///
/// **Observability only.** Burn no longer consumes `stake_ratio` — the
/// `× (1 + stake_ratio)` factor was deleted (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`
/// F-D). The one live consumer is the staking sim's gate-7 recorder, which
/// reports the ratio as a scenario observable; it feeds no consensus quantity.
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub fn calc_stake_ratio(total_staked: u64, circulating_supply: u64) -> u64 {
    if circulating_supply == 0 {
        return 0;
    }
    (u128::from(total_staked) * u128::from(SCALE) / u128::from(circulating_supply)) as u64
}

/// Clamp a value to [lo, hi].
#[inline]
pub fn clamp(value: u64, lo: u64, hi: u64) -> u64 {
    if value < lo {
        lo
    } else if value > hi {
        hi
    } else {
        value
    }
}

/// Multiply two u64 values and divide by SCALE, using u128 intermediary to avoid overflow.
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub fn mul_scale(a: u64, b: u64) -> u64 {
    let product = u128::from(a) * u128::from(b);
    (product / u128::from(SCALE)) as u64
}

/// Integer square root via Newton's method (floor).
pub fn isqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clamp() {
        assert_eq!(clamp(500_000, 800_000, 1_300_000), 800_000);
        assert_eq!(clamp(1_000_000, 800_000, 1_300_000), 1_000_000);
        assert_eq!(clamp(2_000_000, 800_000, 1_300_000), 1_300_000);
    }

    #[test]
    fn test_mul_scale() {
        assert_eq!(mul_scale(2_000_000, 500_000), 1_000_000); // 2.0 * 0.5 = 1.0
        assert_eq!(mul_scale(1_000_000, 1_000_000), 1_000_000); // 1.0 * 1.0 = 1.0
        assert_eq!(mul_scale(1_300_000, 1_000_000), 1_300_000); // 1.3 * 1.0 = 1.3
    }

    #[test]
    fn test_mul_scale_no_overflow() {
        let big = u64::MAX;
        let result = mul_scale(big, SCALE);
        assert_eq!(result, big);
    }

    #[test]
    fn test_isqrt() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(4), 2);
        assert_eq!(isqrt(9), 3);
        assert_eq!(isqrt(10), 3);
        assert_eq!(isqrt(1_000_000), 1000);
    }
}

#[cfg(test)]
mod escalation_param_tests {
    use super::*;

    fn valid_json(asymptote: u64, floor: u64) -> String {
        format!(
            r#"{{"release_min":1,"release_max":2,"tx_volume_baseline":3,
                "burn_base_rate":4,"burn_cap":5,"staker_pool_share":{floor},
                "money_supply":7,"emission_speed_factor_per_minute":8,
                "final_subsidy_per_minute":9,"daa_target_seconds":10,
                "escalation_knee_n":100000,"escalation_asymptote_share":{asymptote}}}"#
        )
    }

    /// **N-1: the malformed asymptote is UNSTORABLE, not merely unapplied.**
    ///
    /// `staker_pool_share_at` fails closed at apply time, but that is the second
    /// layer. This asserts the first: serde itself refuses, so a bad asymptote
    /// cannot reach consensus state at all. It is the one field that would
    /// silently delete the burn channel if honoured, so it gets a door and a
    /// belt.
    #[test]
    fn deserialization_refuses_an_asymptote_that_would_delete_the_burn_channel() {
        let err = serde_json::from_str::<EconomicParams>(&valid_json(SCALE, 250_000))
            .expect_err("a full-scale asymptote must not deserialize");
        assert!(
            err.to_string().contains("deflation channel"),
            "error must name the harm: {err}"
        );

        // Above scale is refused too, not just exactly at it.
        assert!(serde_json::from_str::<EconomicParams>(&valid_json(SCALE + 1, 250_000)).is_err());
    }

    /// A descending "escalation" is refused at the door: it would break
    /// constraints 1 and 2 and make archivers worse off than the flat share.
    #[test]
    fn deserialization_refuses_an_asymptote_below_the_floor() {
        let err = serde_json::from_str::<EconomicParams>(&valid_json(100_000, 250_000))
            .expect_err("a descending escalation must not deserialize");
        assert!(
            err.to_string().contains("below the floor"),
            "error must name the inversion: {err}"
        );
    }

    /// The neutral genesis parameterization deserializes and is exactly flat —
    /// shipping the frozen shape must not ship an unpinned number.
    #[test]
    fn the_neutral_genesis_parameterization_is_accepted_and_flat() {
        let p: EconomicParams =
            serde_json::from_str(&valid_json(250_000, 250_000)).expect("neutral params are valid");
        let esc = p.escalation();
        assert!(esc.is_well_formed());
        for n in [0u64, 1, 50_000, 100_000, u64::MAX] {
            assert_eq!(
                crate::escalation::staker_pool_share_at(n, &esc),
                250_000,
                "the pre-ceremony default must be bit-identical to the flat share"
            );
        }
    }

    /// The shipped defaults are themselves well-formed — a config that cannot
    /// pass its own validator would be caught here rather than at a node start.
    #[test]
    fn shipped_defaults_are_well_formed() {
        EconomicParams::default()
            .validate()
            .expect("config/economics_params.json must satisfy the frozen shape");
    }
}
