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
//! **This module owns *which candidates to sweep*, never *how a share is
//! computed*.** Stage 3a promoted the escalation to consensus code
//! ([`shekyl_economics::escalation::staker_pool_share_at`]), and
//! [`EscalationCurve::share`] now delegates to it. The ramp arithmetic that used
//! to live here — `curve_milli` in its continuous form, rescaled by
//! `mul_div_floor` — moved with it, and is deliberately **not** restated: a
//! local copy would be free to drift from the shape the chain actually freezes,
//! which would silently turn every swept verdict into a statement about the sim
//! rather than about consensus.
//!
//! The §6.1 frozen set is likewise asserted where it is implemented (each
//! constraint carries an executable test in the consensus module), not
//! re-argued here. The sweep's job is to say which `(asymptote, knee)` members
//! clear the burden model; the *shape* they share is settled upstream.
//!
//! Floor and scale are read from the shipped config too
//! ([`floor_share`], [`SHARE_SCALE`]) rather than declared locally, for the same
//! reason: a sim that redeclares the chain's constants can model a chain that
//! does not exist.

// Stage 3a: the escalation is CONSENSUS code now, so this module deps it rather
// than restating it. Nothing here computes a ramp.
use shekyl_economics::escalation::{
    staker_pool_share_at, ClosedShardCount, EscalationParams, ScaledShare,
};
use shekyl_economics::params::{EconomicParams, SCALE};

/// Fixed-point scale for shares (`250_000 = 25 %`). **Sourced from**
/// `shekyl_economics::params::SCALE` rather than restated — it is the unit
/// `staker_pool_share` is carried in, and a sim that redeclared it could drift
/// from the chain it is modelling.
pub const SHARE_SCALE: u64 = SCALE;

/// The §6.1 floor: today's `staker_pool_share`. **Read from the shipped config**
/// via [`EconomicParams::default`], not restated, so the sim's floor is the
/// chain's floor by construction.
#[must_use]
pub fn floor_share() -> u64 {
    EconomicParams::default().staker_pool_share
}

/// Asymptote candidates (all strictly `< SHARE_SCALE`, so `actually_destroyed`
/// deflation survives): 50% / 75% / 90% of burn to the staker pool at
/// saturation.
pub const ASYMPTOTE_BAND: [u64; 3] = [500_000, 750_000, 900_000];

/// Knee candidates — the **closed-shard count** (`shard_of` of cumulative
/// archival length, `W` = 3 MB per shard; `SHT-Q2`) at which the share
/// saturates to the asymptote. Wide spread on purpose (§6.0 wide-but-slow): a
/// larger knee is a slower ratchet. **Re-derived in the byte-keyed unit by the
/// Stage-2 sweep, not converted from the J-segment band**
/// (`ARCHIVAL_SHARD_COUNT_CUTOVER.md` §F step 3): the low member is the
/// baseline-traffic trajectory's `n` at ~10 y, the high member is the
/// sustained-growth trajectory's final `n`, the middle is their geometric
/// mean. Those are the band's **definitions**; this constant is their sweep
/// of 2026-10-01 — baseline `n` at 10 y = 523,841; sustained-growth final
/// `n` = 10,279,293; geometric mean ≈ 2.32 M — rounded to one significant
/// figure and a half. The fold has moved since: under the production fill
/// rule (ESR-6) the baseline carries 22 of its 50 transactions a block for
/// eleven years, and its `n` at 10 y is 229,864. On the design's emission
/// curve the largest final `n` is 2,079,614, below the shipped knee.
/// `stage2::an_out_of_band_knee_is_held_only_while_the_escalation_is_flat`
/// evaluates the definitions on the current fold, prints the band and
/// where the shipped knee stands against it, holds the shipped knee at
/// the swept middle (`KNEE_BAND[1]`), and lets that knee stand outside the
/// live band only while the escalation is flat; re-deriving the band and
/// the knee is GF-7's, after ESR-10 (`docs/FOLLOWUPS.md`).
///
/// **A knee in shards is an archival length in disguise.** `knee · W` is the
/// quantity the sweep actually chose (how much archive is held when the share
/// saturates); the shard count is that length divided by a provisional `W`.
/// A `W` re-pin that left this constant alone would silently move the knee
/// — [`KNEE_ARCHIVAL_LEN_BYTES`] pins the product so that re-pin fails here
/// instead.
pub const KNEE_BAND: [u64; 3] = [500_000, 2_250_000, 10_000_000];

/// The middle knee as the archival length it stands for: `2,250,000 · W` at
/// `W = 3,000,000 B` — 6.75 TB of closed archive. The quantity the ceremony is
/// really choosing; `KNEE_BAND[1]` is this divided by
/// [`shekyl_types::SHARD_LENGTH`].
pub const KNEE_ARCHIVAL_LEN_BYTES: u64 = 6_750_000_000_000;

/// One §6.1-conformant escalation candidate: a saturating banded-PL lift of the
/// staker share from [`floor_share`] to `asymptote` as `n` rises to `knee`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscalationCurve {
    /// Saturation share, fixed-point `SHARE_SCALE`. Must be `> floor_share()` and
    /// `< SHARE_SCALE`.
    pub asymptote: u64,
    /// Closed-shard count at which `share` reaches `asymptote`.
    pub knee_shards: u64,
}

impl EscalationCurve {
    /// The staker-pool share at `n` closed shards, fixed-point `SHARE_SCALE`.
    ///
    /// **Delegates to the consensus function** — this module owns *which
    /// candidates to sweep*, never *how a share is computed*. A local ramp here
    /// would be a mirror of `staker_pool_share_at`, free to drift from the
    /// shape the chain actually freezes, which would make every swept verdict a
    /// statement about the sim rather than about consensus.
    #[must_use]
    pub fn share(&self, n: u64) -> u64 {
        staker_pool_share_at(ClosedShardCount::new(n), &self.params()).to_raw()
    }

    /// This candidate as consensus [`EscalationParams`] (well-formed by
    /// [`EscalationParams::try_new`] — band members are shape-legal by construction).
    #[must_use]
    pub fn params(&self) -> EscalationParams {
        EscalationParams::try_new(
            ScaledShare::from_raw(floor_share()),
            self.knee_shards,
            ScaledShare::from_raw(self.asymptote),
        )
        .expect("escalation family members are §6.1-conformant by construction")
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
        asymptote: floor_share(),
        // Any representable knee: the value is inert here because
        // `asymptote == floor` makes the ramp flat (span 0), so
        // `staker_pool_share_at` returns the floor for every `n` regardless of
        // the knee. MIN_KNEE_N keeps it shape-legal now that `try_new` rejects
        // sub-ramp knees.
        knee_shards: EscalationParams::MIN_KNEE_N,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_at_zero_plateau_at_knee() {
        for c in family() {
            // n = 0 ⇒ exactly the 25% floor.
            assert_eq!(c.share(0), floor_share());
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
                assert!(s >= floor_share(), "never below the 25% floor");
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
        assert_eq!(f.share(0), floor_share());
        assert_eq!(f.share(1_000_000), floor_share());
    }

    #[test]
    fn no_cliff_bounded_slope() {
        // §6.1 "no cliffs, bounded slope": over a fine grid, no single small
        // step in n captures a large fraction of the total lift. This is the
        // exact property the `pv = A - F` form violated (a jump to the asymptote
        // at the knee).
        for c in family() {
            let span = c.asymptote - floor_share();
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
    fn knee_is_an_archival_length_pinned_against_a_w_repin() {
        // The sweep chose an amount of held archive, not a shard count. If `W`
        // is re-pinned and KNEE_BAND is not re-derived, the knee silently
        // moves in bytes; this is where that shows. On failure: re-run the
        // Stage-2 sweep (ARCHIVAL_SHARD_COUNT_CUTOVER.md §F step 3), do not
        // divide the constant through.
        let w = shekyl_types::SHARD_LENGTH.to_raw();
        assert_eq!(
            KNEE_BAND[1] * w,
            KNEE_ARCHIVAL_LEN_BYTES,
            "knee {} shards x W {w} B != pinned {} B: W moved under the knee",
            KNEE_BAND[1],
            KNEE_ARCHIVAL_LEN_BYTES
        );
        assert_eq!(
            KNEE_ARCHIVAL_LEN_BYTES % w,
            0,
            "the knee length is whole shards"
        );
    }

    #[test]
    fn larger_knee_is_a_slower_ratchet() {
        // At a fixed asymptote and a mid shard count, a larger knee gives a
        // lower share (the lift is spread over more shards — §6.0 slower).
        let n = KNEE_BAND[0] * 4 / 5;
        let fast = EscalationCurve {
            asymptote: 750_000,
            knee_shards: KNEE_BAND[0],
        };
        let slow = EscalationCurve {
            asymptote: 750_000,
            knee_shards: KNEE_BAND[2],
        };
        assert!(fast.share(n) > slow.share(n));
    }
}
