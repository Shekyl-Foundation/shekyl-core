// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The D2 shard-indexed staker-share **escalation family**
//! (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §6.1, DQ-2D).
//!
//! Stage 2 does not pick one curve — it sweeps a **family** conforming to the
//! frozen §6.1 shape constraints and reports which members clear the burden
//! (A1) without failing W9/W10. Stage 3 freezes the winner's number.
//!
//! Every candidate reuses the **consensus** [`curve_milli`] + [`mul_div_floor`]
//! (the §6.1 "curve_milli precedent") so the recommended shape is
//! bit-implementable, not a float sketch (DQ-2G). Given the floor `F` (today's
//! 25%) and an asymptote `A`, over a saturation knee `K`:
//!
//! ```text
//! raw   = curve_milli(n, { plateau_work_milli: K, plateau_value_milli: K/2 })  // ∈ [0, K/2], = K/2 at n ≥ K
//! lift  = mul_div_floor(A - F, raw, K/2)                                       // ∈ [0, A - F]
//! share = F + lift                                                             // ∈ [F, A]
//! ```
//!
//! `curve_milli` is only **continuous** when `plateau_value = plateau_work / 2`
//! (its reward-curve calibration) — using `pv = A − F` directly would put a
//! **cliff at the knee** (the exact bounded-slope violation §6.1 forbids). So we
//! run `curve_milli` in its continuous form (rising `0 → K/2` with the banded
//! slopes `1, ½, ¼`) and rescale the output to `[0, A − F]` with the consensus
//! `mul_div_floor`. This satisfies the §6.1 frozen set **by construction**:
//! 1. **Monotone in `n`** — `curve_milli` is non-decreasing.
//! 2. **Floor at 25%** — `curve_milli(0) = 0`, so `share(0) = F`.
//! 3. **Asymptote `< 100%`** — it plateaus at `A` (chosen `< SCALE`), so the
//!    deflation channel `1 − A` of burn survives forever.
//! 4. **Banded piecewise-linear, integer fixed-point** — `curve_milli` +
//!    `mul_div_floor`, no float.
//! 5. **No time-derivative / smoothing** — `share` is a pure map of `n`; there
//!    is no state, EMA, or rate-limiter. Smoothness is inherited from the
//!    operand (monotone + slow, §6.0).

use shekyl_archival_retention::{curve_milli, mul_div_floor, BandedCurveParams};

/// Fixed-point scale for shares (`SCALE = 1_000_000`; `250_000 = 25%`). Mirrors
/// `shekyl_economics::params::SCALE` — the units `staker_pool_share` is carried
/// in.
pub const SHARE_SCALE: u64 = 1_000_000;

/// The §6.1 floor: today's `staker_pool_share` (`economics_params.json` =
/// `250_000` = 25%). The escalation never dips below it.
pub const FLOOR_SHARE: u64 = 250_000;

/// Asymptote candidates (all strictly `< SHARE_SCALE`, so `actually_destroyed`
/// deflation survives): 50% / 75% / 90% of burn to the staker pool at
/// saturation.
pub const ASYMPTOTE_BAND: [u64; 3] = [500_000, 750_000, 900_000];

/// Knee candidates — the `frozen_segment_count` at which the share saturates to
/// the asymptote. Wide spread on purpose (§6.0 wide-but-slow): a larger knee is
/// a slower ratchet. `25_000` ≈ the baseline-traffic corpus at ~10y; `250_000`
/// only saturates deep in a sustained-growth chain.
pub const KNEE_BAND: [u64; 3] = [25_000, 100_000, 250_000];

/// One §6.1-conformant escalation candidate: a saturating banded-PL lift of the
/// staker share from [`FLOOR_SHARE`] to `asymptote` as `n` rises to `knee`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscalationCurve {
    /// Saturation share, fixed-point `SHARE_SCALE`. Must be `> FLOOR_SHARE` and
    /// `< SHARE_SCALE`.
    pub asymptote: u64,
    /// `frozen_segment_count` at which `share` reaches `asymptote`.
    pub knee_shards: u64,
}

impl EscalationCurve {
    /// The staker-pool share at `n` frozen shards, fixed-point `SHARE_SCALE`,
    /// in `[FLOOR_SHARE, asymptote]`. Reuses the consensus `curve_milli` (in its
    /// continuous `pv = pw/2` form) rescaled by `mul_div_floor` — see the module
    /// doc for why the naive `pv = A − F` form would cliff.
    #[must_use]
    pub fn share(&self, n: u64) -> u64 {
        let knee = self.knee_shards.max(1);
        let cap = (knee / 2).max(1); // curve_milli's continuous plateau value
        let raw = curve_milli(
            n,
            &BandedCurveParams {
                plateau_work_milli: knee,
                plateau_value_milli: cap,
            },
        );
        let span = self.asymptote.saturating_sub(FLOOR_SHARE);
        // lift = span · raw / cap ∈ [0, span]; floor keeps it integer-exact.
        let lift = mul_div_floor(span, raw, cap).unwrap_or(span).min(span);
        FLOOR_SHARE + lift
    }

    /// The share as a fraction (for reporting / the fiat conversion in A1).
    #[must_use]
    pub fn share_fraction(&self, n: u64) -> f64 {
        self.share(n) as f64 / SHARE_SCALE as f64
    }
}

/// The full swept family: every (asymptote × knee) candidate. Stage 3 picks the
/// winner from the members A1 shows clear (under 0%/yr Kryder) without failing
/// W9/W10.
#[must_use]
pub fn family() -> Vec<EscalationCurve> {
    let mut curves = Vec::with_capacity(ASYMPTOTE_BAND.len() * KNEE_BAND.len());
    for &asymptote in &ASYMPTOTE_BAND {
        for &knee_shards in &KNEE_BAND {
            curves.push(EscalationCurve {
                asymptote,
                knee_shards,
            });
        }
    }
    curves
}

/// The **status-quo** curve: the frozen 25% share, no escalation. The A1
/// baseline every candidate is measured against (does escalation clear where the
/// flat share does not?).
#[must_use]
pub fn flat_25() -> EscalationCurve {
    EscalationCurve {
        asymptote: FLOOR_SHARE,
        knee_shards: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_at_zero_plateau_at_knee() {
        for c in family() {
            // n = 0 ⇒ exactly the 25% floor.
            assert_eq!(c.share(0), FLOOR_SHARE);
            // n ≥ knee ⇒ exactly the asymptote (plateau), never above.
            assert_eq!(c.share(c.knee_shards), c.asymptote);
            assert_eq!(c.share(c.knee_shards * 10), c.asymptote);
        }
    }

    #[test]
    fn monotone_and_bounded_below_full_burn() {
        for c in family() {
            let mut prev = 0u64;
            for n in (0..=c.knee_shards).step_by((c.knee_shards / 50).max(1) as usize) {
                let s = c.share(n);
                assert!(s >= prev, "share must be monotone in n");
                assert!(s >= FLOOR_SHARE, "never below the 25% floor");
                assert!(
                    s < SHARE_SCALE,
                    "asymptote < 100% — deflation must survive: {s}"
                );
                prev = s;
            }
        }
    }

    #[test]
    fn flat_25_never_escalates() {
        let f = flat_25();
        assert_eq!(f.share(0), FLOOR_SHARE);
        assert_eq!(f.share(1_000_000), FLOOR_SHARE);
    }

    #[test]
    fn no_cliff_bounded_slope() {
        // §6.1 "no cliffs, bounded slope": over a fine grid, no single small
        // step in n captures a large fraction of the total lift. This is the
        // exact property the `pv = A - F` form violated (a jump to the asymptote
        // at the knee).
        for c in family() {
            let span = c.asymptote - FLOOR_SHARE;
            let step = (c.knee_shards / 200).max(1);
            let mut prev = c.share(0);
            let mut n = step;
            while n <= c.knee_shards {
                let s = c.share(n);
                let delta = s - prev;
                assert!(
                    delta * 10 < span,
                    "cliff in ({},{}) at n={n}: step {delta} >= span/10 ({})",
                    c.asymptote,
                    c.knee_shards,
                    span / 10
                );
                prev = s;
                n += step;
            }
        }
    }

    #[test]
    fn larger_knee_is_a_slower_ratchet() {
        // At a fixed asymptote and a mid shard count, a larger knee gives a
        // lower share (the lift is spread over more shards — §6.0 slower).
        let n = 20_000;
        let fast = EscalationCurve {
            asymptote: 750_000,
            knee_shards: 25_000,
        };
        let slow = EscalationCurve {
            asymptote: 750_000,
            knee_shards: 250_000,
        };
        assert!(fast.share(n) > slow.share(n));
    }
}
