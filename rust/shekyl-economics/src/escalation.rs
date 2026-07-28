// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **D2 staker-share escalation — the frozen shape.**
//!
//! Replaces the flat `staker_pool_share` constant with a pure map of the burden
//! operand `n = frozen_segment_count` ([`FrozenSegmentCount`]). Shape is
//! genesis-frozen (§6.1); the asymptote **numeric** is provisional-until-testnet
//! (§11.4). See `ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`.
//!
//! # Frozen constraints (§6.1)
//!
//! 1. Monotone in `n`
//! 2. Floor at today's share (strict improvement, never a redistribution)
//! 3. Asymptote strictly below [`SCALE`](crate::params::SCALE) (deflation survives)
//! 4. Banded piecewise-linear integer fixed-point ([`shekyl_units::banded_pl`])
//! 5. Pure map of `n` — no EMA, rate-limiter, or per-block state
//!
//! # Construction
//!
//! [`EscalationParams`] is **well-formed by construction** ([`EscalationParams::try_new`]).
//! There is no apply-time fail-closed path: a malformed shape cannot be held in
//! the type. [`EconomicParams::validate`](crate::params::EconomicParams::validate)
//! and the serde door both route through the same constructor.

use shekyl_units::banded_pl::{curve_milli, mul_div_floor, BandedCurveParams};

use crate::params::SCALE;

/// D2 burden operand: `n = frozen_segment_count` at **parent-block** state.
///
/// State-shaped (chain progression owns the value). Callers read it once per
/// template/connect via the asserting C++ read-point and pass the typed count
/// through the burn split — never a bare height, never tip-after-`add_block`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct FrozenSegmentCount(u64);

impl FrozenSegmentCount {
    /// Zero frozen segments (genesis / empty tree).
    pub const ZERO: Self = Self(0);

    /// Wrap a raw count.
    #[must_use]
    pub const fn new(n: u64) -> Self {
        Self(n)
    }

    /// Raw `u64` count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for FrozenSegmentCount {
    fn from(n: u64) -> Self {
        Self::new(n)
    }
}

impl From<FrozenSegmentCount> for u64 {
    fn from(n: FrozenSegmentCount) -> Self {
        n.get()
    }
}

/// Fixed-point share over [`SCALE`] (`1_000_000` = 100 %).
///
/// Distinguishes share numerics from fee amounts / segment counts at the type
/// boundary. Does **not** enforce `< SCALE` by itself — that is an
/// [`EscalationParams`] shape rule on the asymptote (and, via the floor ≤
/// asymptote chain, on the floor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ScaledShare(u64);

impl ScaledShare {
    /// Wrap a raw fixed-point value.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Raw fixed-point value.
    #[must_use]
    pub const fn to_raw(self) -> u64 {
        self.0
    }
}

impl From<u64> for ScaledShare {
    fn from(raw: u64) -> Self {
        Self::from_raw(raw)
    }
}

impl From<ScaledShare> for u64 {
    fn from(s: ScaledShare) -> Self {
        s.to_raw()
    }
}

/// Shape-rule violation for [`EscalationParams::try_new`].
///
/// Single source of truth for §6.1 structural checks; params-load and tests both
/// go through this error rather than restating the predicates.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EscalationShapeError {
    /// `asymptote >= SCALE` would redirect the entire burn.
    #[error(
        "escalation asymptote {asymptote} must be < SCALE ({scale}): a full-scale \
         share redirects the entire burn and deletes the deflation channel"
    )]
    AsymptoteAtOrAboveScale {
        /// Offending asymptote (raw SCALE units).
        asymptote: u64,
        /// [`SCALE`].
        scale: u64,
    },
    /// `asymptote < floor` would make the map descend.
    #[error(
        "escalation asymptote {asymptote} is below the floor {floor}: the \
         escalation would descend, and archivers would be worse off than under \
         the flat share"
    )]
    AsymptoteBelowFloor {
        /// Offending asymptote.
        asymptote: u64,
        /// Floor it fell below.
        floor: u64,
    },
    /// `knee_n == 0` is a zeroed config field, not a parameterization.
    #[error(
        "escalation knee must be > 0: a zero knee gives the ramp no domain (a \
         zeroed config field, not a parameterization)"
    )]
    KneeZero,
}

/// Well-formed escalation shape parameters.
///
/// Fields are private: the only constructor is [`Self::try_new`], so every value
/// of this type satisfies the §6.1 structural rules. Numerics stay data (not
/// code constants) so the shape can freeze while the asymptote re-pin stays open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscalationParams {
    floor_share: ScaledShare,
    knee_n: u64,
    asymptote_share: ScaledShare,
}

impl EscalationParams {
    /// Build a well-formed shape, or refuse.
    ///
    /// - `asymptote < SCALE` — constraint 3 (deflation channel)
    /// - `floor <= asymptote` — constraints 1–2 (monotone, no one worse off)
    /// - `knee_n > 0` — ramp has a domain (zero is a config error, not intent)
    #[must_use = "check whether the shape was accepted"]
    pub const fn try_new(
        floor_share: ScaledShare,
        knee_n: u64,
        asymptote_share: ScaledShare,
    ) -> Result<Self, EscalationShapeError> {
        let floor = floor_share.to_raw();
        let asymptote = asymptote_share.to_raw();
        if asymptote >= SCALE {
            return Err(EscalationShapeError::AsymptoteAtOrAboveScale {
                asymptote,
                scale: SCALE,
            });
        }
        if asymptote < floor {
            return Err(EscalationShapeError::AsymptoteBelowFloor { asymptote, floor });
        }
        if knee_n == 0 {
            return Err(EscalationShapeError::KneeZero);
        }
        Ok(Self {
            floor_share,
            knee_n,
            asymptote_share,
        })
    }

    /// Share at `n = 0` (the §6.1 floor).
    #[must_use]
    pub const fn floor_share(self) -> ScaledShare {
        self.floor_share
    }

    /// `frozen_segment_count` at which the share saturates.
    #[must_use]
    pub const fn knee_n(self) -> u64 {
        self.knee_n
    }

    /// Share at and beyond the knee (`< SCALE` by construction).
    #[must_use]
    pub const fn asymptote_share(self) -> ScaledShare {
        self.asymptote_share
    }
}

/// `staker_pool_share` as a pure map of the burden operand `n`.
///
/// Rises from `floor_share` at `n = 0` along the continuous banded-PL ramp,
/// saturating at `asymptote_share` for `n >= knee_n`. Uses
/// [`BandedCurveParams::continuous`] so there is no share cliff at the knee.
///
/// **`params` is well-formed by type** — no fail-closed branch.
#[must_use]
pub fn staker_pool_share_at(n: FrozenSegmentCount, params: &EscalationParams) -> ScaledShare {
    let floor = params.floor_share.to_raw();
    let asymptote = params.asymptote_share.to_raw();
    let span = asymptote - floor;
    if span == 0 {
        return params.floor_share;
    }

    let shape = BandedCurveParams::continuous(params.knee_n);
    let full = shape.plateau_value_milli;
    if full == 0 {
        // knee_n == 1 → continuous plateau floors to 0: no ramp interior, but
        // the endpoints still exist (floor strictly below the knee, asymptote
        // at and beyond it).
        return if n.get() >= params.knee_n {
            params.asymptote_share
        } else {
            params.floor_share
        };
    }
    let raw = curve_milli(n.get(), &shape);
    // share = floor + span * raw / full. Floors so the share is never rounded
    // UP into a larger redirection of the burn than the ramp earns.
    let lift = mul_div_floor(span, raw, full).unwrap_or(0);
    ScaledShare::from_raw(floor.saturating_add(lift))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Genesis-shaped params: today's floor, mid-band knee, mid-band asymptote.
    /// **Test fixture, not the pin** — the numeric is deliberately unpinned.
    fn params() -> EscalationParams {
        EscalationParams::try_new(
            ScaledShare::from_raw(250_000),
            100_000,
            ScaledShare::from_raw(750_000),
        )
        .expect("fixture is well-formed")
    }

    fn share_at(n: u64, p: &EscalationParams) -> u64 {
        staker_pool_share_at(FrozenSegmentCount::new(n), p).to_raw()
    }

    #[test]
    fn constraint_1_monotone_in_n() {
        let p = params();
        let mut prev = 0;
        for n in (0..=250_000u64).step_by(311) {
            let s = share_at(n, &p);
            assert!(s >= prev, "share fell at n={n}: {s} < {prev}");
            prev = s;
        }
    }

    #[test]
    fn constraint_2_floor_is_todays_share() {
        let p = params();
        assert_eq!(share_at(0, &p), 250_000);
        for n in [0u64, 1, 7, 1_000, 99_999, 100_000, 10_000_000] {
            assert!(share_at(n, &p) >= p.floor_share().to_raw());
        }
    }

    #[test]
    fn no_one_is_ever_worse_off_than_the_flat_share() {
        const TODAY: u64 = 250_000;
        for knee in [1u64, 2, 1_000, 25_000, 100_000, 250_000] {
            for asymptote in [TODAY, 400_000, 750_000, 900_000, SCALE - 1] {
                let p = EscalationParams::try_new(
                    ScaledShare::from_raw(TODAY),
                    knee,
                    ScaledShare::from_raw(asymptote),
                )
                .expect("fixture must be accepted");
                for n in [0u64, 1, knee / 2, knee.saturating_sub(1), knee, knee + 1, u64::MAX] {
                    let s = share_at(n, &p);
                    assert!(
                        s >= TODAY,
                        "escalation went BELOW today's flat share: n={n} share={s}"
                    );
                    assert!(s < SCALE, "deflation channel deleted: n={n} share={s}");
                }
            }
        }
    }

    #[test]
    fn constraint_3_deflation_channel_survives() {
        let p = params();
        assert_eq!(share_at(p.knee_n(), &p), p.asymptote_share().to_raw());
        assert_eq!(share_at(u64::MAX, &p), p.asymptote_share().to_raw());
        for n in [0u64, 50_000, 100_000, u64::MAX] {
            assert!(
                share_at(n, &p) < SCALE,
                "share reached full scale at n={n} — the burn channel is deleted"
            );
        }
    }

    #[test]
    fn try_new_refuses_shape_violations() {
        assert!(matches!(
            EscalationParams::try_new(
                ScaledShare::from_raw(250_000),
                100_000,
                ScaledShare::from_raw(SCALE),
            ),
            Err(EscalationShapeError::AsymptoteAtOrAboveScale { .. })
        ));
        assert!(matches!(
            EscalationParams::try_new(
                ScaledShare::from_raw(750_000),
                100_000,
                ScaledShare::from_raw(250_000),
            ),
            Err(EscalationShapeError::AsymptoteBelowFloor { .. })
        ));
        assert!(matches!(
            EscalationParams::try_new(
                ScaledShare::from_raw(250_000),
                0,
                ScaledShare::from_raw(750_000),
            ),
            Err(EscalationShapeError::KneeZero)
        ));
        // Malformed shapes are unrepresentable — there is no fail-closed apply path.
    }

    #[test]
    fn constraint_4_ramps_rather_than_steps() {
        let p = params();
        let mid = share_at(p.knee_n() / 2, &p);
        assert!(
            mid > p.floor_share().to_raw() && mid < p.asymptote_share().to_raw(),
            "interior value {mid} is not strictly between the endpoints"
        );
    }

    #[test]
    fn constraint_5_is_a_pure_map_with_no_history() {
        let p = params();
        let ascending: Vec<u64> = (0..40).map(|i| share_at(i * 3_000, &p)).collect();
        let mut descending: Vec<u64> = (0..40).rev().map(|i| share_at(i * 3_000, &p)).collect();
        descending.reverse();
        assert_eq!(ascending, descending, "evaluation order changed the result");
    }

    #[test]
    fn no_share_cliff_at_the_knee() {
        let p = params();
        let knee_step = share_at(p.knee_n(), &p) - share_at(p.knee_n() - 1, &p);

        let mut max_interior_step = 0;
        let mut prev = share_at(0, &p);
        for n in 1..p.knee_n() {
            let cur = share_at(n, &p);
            max_interior_step = max_interior_step.max(cur - prev);
            prev = cur;
        }

        assert!(
            knee_step <= max_interior_step,
            "the knee is a cliff: step {knee_step} exceeds the ramp's largest \
             interior step {max_interior_step}"
        );
        assert!(
            max_interior_step > 0,
            "fixture must actually ramp, or this proves nothing"
        );
    }

    #[test]
    fn rounding_never_favours_the_pool() {
        let p = EscalationParams::try_new(
            ScaledShare::from_raw(250_000),
            7,
            ScaledShare::from_raw(750_001),
        )
        .unwrap();
        for n in 0..=7u64 {
            let s = share_at(n, &p);
            assert!(s >= p.floor_share().to_raw() && s <= p.asymptote_share().to_raw());
        }
    }

    #[test]
    fn flat_and_one_knee_endpoints() {
        let flat = EscalationParams::try_new(
            ScaledShare::from_raw(250_000),
            100_000,
            ScaledShare::from_raw(250_000),
        )
        .unwrap();
        assert_eq!(share_at(u64::MAX, &flat), 250_000);

        let one_knee = EscalationParams::try_new(
            ScaledShare::from_raw(250_000),
            1,
            ScaledShare::from_raw(750_000),
        )
        .unwrap();
        assert_eq!(share_at(0, &one_knee), 250_000);
        assert_eq!(share_at(1, &one_knee), 750_000);
        assert_eq!(share_at(5, &one_knee), 750_000);
    }

    #[test]
    fn frozen_segment_count_newtype_round_trip() {
        let n = FrozenSegmentCount::new(42);
        assert_eq!(n.get(), 42);
        assert_eq!(u64::from(n), 42);
        assert_eq!(FrozenSegmentCount::from(7u64).get(), 7);
        assert_eq!(FrozenSegmentCount::ZERO.get(), 0);
    }
}
