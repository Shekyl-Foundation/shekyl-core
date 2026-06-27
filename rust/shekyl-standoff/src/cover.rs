// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The funding-seam **cover-amount** draw — the amount-axis sibling of the
//! entry-gap timing draw, float-free by construction.
//!
//! Where [`crate::draw::draw_entry_gap`] decorrelates *when* `P` funds and
//! enters, this draws *how much* the principal sends on top of the public
//! `bond_floor`: `cover ~ U[C_min, C_min + span(C)]`, where `span(C)` is the
//! genesis-frozen response curve over the live-bond count `C`
//! (`ARCHIVAL_COVER_DRAW.md` §8). Same float-free discipline as the entry-gap
//! draw: pure integer arithmetic, bit-identical across architectures, golden-
//! vector-pinnable — because two wallets computing a different cover from the
//! same `C` would draw from *different distributions*, the cross-wallet
//! uniformity break the whole mechanism exists to close.
//!
//! ## The form is single-sourced here (C4)
//!
//! [`cover_dial_span_atomic`] is the one implementation of the §8.8 curve; the
//! simulator imports it, the golden vector freezes it, and the wallet draws with
//! it — so the curve cannot drift between "what we validated" and "what ships".

use crate::draw::{bounded_uniform, GapRng};

/// `K_sat → 0` tail boundary (`ARCHIVAL_COVER_DRAW.md` §8.7): at/below this count
/// the span is `0`, so `cover == C_min` exactly — the bootstrap tail (§8.5, the
/// dissolved `C_boot`), openly conceded to the network-isolation + funder-scope
/// seams.
pub const COVER_TAIL_COUNT: u64 = 13;
/// Count at which the smoothstep ramp reaches the cap (the §8.7 knee plateau).
pub const COVER_RAMP_END_COUNT: u64 = 79;
/// Cover-span cap `C_max − C_min`: `k = 10 rungs × 0.75 SKL = 7.5 SKL` — the
/// joint-corner saturation knee (§8.7).
pub const COVER_SPAN_CAP_ATOMIC: u64 = 7_500_000_000;

/// Working-capital **runway floor** `C_min` in atomic units — the lower edge of
/// every draw (§8.3). **PROVISIONAL:** `1 rung = 0.75 SKL`, the §8.3 minimum,
/// pending the 2d-1 earnings-ramp sizing (which may raise it against pessimistic
/// slow yield). Single-sourced here so that when 2d-1 lands, this const moves and
/// the golden vector re-freezes against it — the wallet always reads the one
/// canonical value, never a baked placeholder. **The golden vector below is
/// provisional-until-`C_min`-lands.**
pub const COVER_RUNWAY_FLOOR_ATOMIC: u64 = 750_000_000;

/// `span(C) = C_max − C_min` in atomic units — the §8.8 float-free response form.
///
/// Cubic **smoothstep** `s(t) = t²(3 − 2t)` with `t = (C − tail)/(end − tail)`,
/// scaled to the cap: it decays into the low tail with **zero slope** (the value
/// *and* its rate reach `0` — a decay, not a clamp-kink) and joins the cap with
/// zero slope (no kink at the top). Pure `u64` arithmetic, so identical on every
/// architecture and golden-vector-pinnable.
///
/// `num²·(3·den − 2·num) ≤ den³`, so `span ≤ CAP` and the result is monotone in
/// `num`; and `CAP · num²·(…) ≤ CAP · den³ ≈ 2.16e15 < u64::MAX`, so the
/// intermediate never overflows.
#[must_use]
pub fn cover_dial_span_atomic(count: u64) -> u64 {
    if count <= COVER_TAIL_COUNT {
        return 0;
    }
    if count >= COVER_RAMP_END_COUNT {
        return COVER_SPAN_CAP_ATOMIC;
    }
    let num = count - COVER_TAIL_COUNT;
    let den = COVER_RAMP_END_COUNT - COVER_TAIL_COUNT;
    let s_num = num * num * (3 * den - 2 * num);
    let s_den = den * den * den;
    COVER_SPAN_CAP_ATOMIC * s_num / s_den
}

/// Draw the cover amount (atomic units): `cover = c_min + U[0, span(count)]`.
///
/// Uniform over `[c_min, c_min + span(count)]`. The uniformity holds for **every**
/// span the curve produces — [`bounded_uniform`] is exact rejection sampling for
/// any bound (it rejects the incomplete top bucket of `2^64`), so the realized
/// distribution is exactly uniform whether `span` is tiny (`count = 14 → ~5.1M
/// atomic`) or the cap (`7.5e9`); there is no `span`-dependent residual bias that
/// would drift the distribution shape with the population. At the bootstrap tail
/// (`count ≤ 13`, `span = 0`) the draw is `c_min` exactly — the continuous
/// `span → 0` limit of the uniform (`bounded_uniform(rng, 0) == 0`), so there is
/// no draw-layer discontinuity between the conceded tail and the first ramp step.
///
/// `c_min` is taken as an explicit single-sourced input (the wallet passes
/// [`COVER_RUNWAY_FLOOR_ATOMIC`]) rather than baked, so the pending 2d-1 `C_min`
/// flows from one canonical constant. Caller guarantees `c_min + COVER_SPAN_CAP_ATOMIC`
/// fits `u64` (trivially true for any realistic runway floor).
#[must_use]
pub fn draw_cover_amount<R: GapRng + ?Sized>(count: u64, c_min: u64, rng: &mut R) -> u64 {
    let span = cover_dial_span_atomic(count);
    c_min + bounded_uniform(rng, span)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SplitMix64(u64);
    impl GapRng for SplitMix64 {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    #[test]
    fn span_golden_vector() {
        // Pinned (C, span) — the simulator and any wallet must reproduce these
        // bit-for-bit (§8.8). These are arch-independent (pure integer).
        assert_eq!(cover_dial_span_atomic(0), 0);
        assert_eq!(cover_dial_span_atomic(13), 0); // tail boundary
        assert_eq!(cover_dial_span_atomic(14), 5_113_114); // smallest nonzero span
        assert_eq!(cover_dial_span_atomic(46), 3_750_000_000); // midpoint t=0.5 → cap/2
        assert_eq!(cover_dial_span_atomic(79), 7_500_000_000); // ramp end → cap
        assert_eq!(cover_dial_span_atomic(154), 7_500_000_000); // flat above
    }

    #[test]
    fn span_is_monotone_and_capped() {
        let mut prev = 0u64;
        for c in 0..=200u64 {
            let s = cover_dial_span_atomic(c);
            assert!(s >= prev, "monotone at C={c}");
            assert!(s <= COVER_SPAN_CAP_ATOMIC, "capped at C={c}");
            prev = s;
        }
    }

    #[test]
    fn span_decays_into_the_tail_no_clamp_kink() {
        // §8.4: convex into the low tail (slope rising from 0 ⇒ decay, not clamp),
        // concave into the cap (slope falling to 0 ⇒ no kink at the join).
        let d = |c: u64| {
            i128::from(cover_dial_span_atomic(c + 1)) - i128::from(cover_dial_span_atomic(c))
        };
        assert!(d(14) > d(13), "convex into the tail");
        assert!(d(76) < d(75), "concave into the cap");
    }

    #[test]
    fn smallest_nonzero_span_is_not_near_constant() {
        // Check 2(a): the first nonzero span is a genuine wide draw (~5.1M atomic
        // values), not a dust-collapsed near-constant — the integer count step
        // 13→14 jumps span 0 → 5.1M, so there is no tiny-span regime to collapse.
        assert!(cover_dial_span_atomic(14) > 1_000_000);
    }

    #[test]
    fn bootstrap_tail_draws_exactly_c_min() {
        // Check 2(b): at the conceded tail (span = 0) the draw is c_min exactly —
        // the continuous span→0 limit, consuming one rng word like every draw.
        let c_min = COVER_RUNWAY_FLOOR_ATOMIC;
        for c in [0u64, 5, 13] {
            let mut rng = SplitMix64(0xABCD_0000 ^ c);
            for _ in 0..32 {
                assert_eq!(draw_cover_amount(c, c_min, &mut rng), c_min);
            }
        }
    }

    #[test]
    fn cover_draw_golden_vector_multiple_spans() {
        // Check 1: pin the realized draw at SEVERAL spans (tail / mid / cap), since
        // uniformity-of-the-draw is now a property of the span, not a fixed window.
        // Provisional-until-C_min-lands (uses COVER_RUNWAY_FLOOR_ATOMIC).
        let c_min = COVER_RUNWAY_FLOOR_ATOMIC;
        let draw1 = |count: u64, seed: u64| {
            let mut rng = SplitMix64(seed);
            draw_cover_amount(count, c_min, &mut rng)
        };
        // tail (span 5.1M), mid (span 3.75e9), cap (span 7.5e9). Bit-identical
        // across architectures (pure-integer draw); drift = the draw changed.
        assert_eq!(draw1(14, 0xC0FFEE01), 754_676_825);
        assert_eq!(draw1(46, 0xC0FFEE02), 4_300_942_604);
        assert_eq!(draw1(79, 0xC0FFEE03), 7_112_999_756);
        // Every draw lands in [c_min, c_min + span].
        for (count, seed) in [(14u64, 1u64), (46, 2), (79, 3), (200, 4)] {
            let span = cover_dial_span_atomic(count);
            let mut rng = SplitMix64(seed);
            for _ in 0..256 {
                let cover = draw_cover_amount(count, c_min, &mut rng);
                assert!(cover >= c_min && cover <= c_min + span);
            }
        }
    }
}
