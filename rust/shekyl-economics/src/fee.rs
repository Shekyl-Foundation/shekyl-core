// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The corrected fee ladder (FL round §5.2, three tiers per FL-R17) and its
//! quantized correction factor (FL-R12′ round-8 amendment, whole-scalar
//! form).
//!
//! **What the daemon serves** (`FEE_LADDER_DERIVATION.md` §5.2, signed
//! rungs FL-R17 / operand per the adopted round-8 amendment):
//!
//! ```text
//! served = C_q · ladder(max(curve(remaining), TAIL))
//! C_q    = 2^ceil(log2( (1−σ)·M_r / (1−b) ))     — the WHOLE volume-
//!                                                   dependent scalar
//! ```
//!
//! The amendment quantizes the whole scalar rather than leaving `M_r` raw
//! in the operand: `Q(C′)·M_r ≠ Q(C′·M_r)` — identical in algebra, not in
//! quantization — and the raw-`M_r` split re-created the measured FL-C4a
//! dwell failure (4-block anonymity cohorts at baseline volume). The
//! operand is therefore the **M_r-neutral** total reward view
//! ([`crate::base_block_reward`]); `M_r` lives inside the quantized scalar.
//!
//! Tier contracts (§5.5): `fees[0]` economy — the admission rung, clamped
//! by the CALLER at the unbuffered relay floor; `fees[1]` standard — the
//! sustained-growth rung and the default; `fees[3]` priority — exact
//! marginal-cost pricing of expansion to the 2×median cap, the `Fh` main
//! arm made **unconditional** (the surge discount was FL-C2(b)'s one
//! derived defect in the inherited shape). `fees[2]` is the RK-5 wire
//! bridge: the dead `Fm` slot serves the standard value so the vector
//! shape does not change before the RPC cutover and wallet2-transliterated
//! `Elevated` callers stay inside the largest anonymity set.

use crate::params::{EconomicParams, SCALE};
use crate::release::calc_release_multiplier;

/// `CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES = 2`:
/// `round_money_up(v, 2)` — round UP to 2 significant decimal digits.
///
/// Production owner of this rule. Wallet cap and the FL instrument
/// import this function rather than carrying a third copy. The C++
/// original throws on overflow; saturation here is unreachable for any
/// fee the ladder can emit and documented as the fail-safe.
#[must_use]
pub fn round_money_up_2(v: u64) -> u64 {
    if v < 100 {
        return v;
    }
    let mut unit = 1u64;
    let mut head = v;
    while head >= 100 {
        head /= 10;
        unit *= 10;
    }
    v.div_ceil(unit).saturating_mul(unit)
}

/// Exact-integer `2^k ≤ c/s` (no float log2 — this feeds a
/// wallet-must-match-daemon derivation, so cross-platform float behavior
/// must not be load-bearing).
fn pow2_le(c: u128, s: u128, k: i32) -> bool {
    if k >= 0 {
        (s << k) <= c
    } else {
        s <= (c << (-k))
    }
}

/// Ceiling pow2 snap in `SCALE` fixed point: smallest exact power of two
/// `≥ c/SCALE`. Panics only if the snapped exponent leaves the range
/// `SCALE = 10^6` can represent exactly (`2^-6 … 2^43`), unreachable for
/// the derivation's `C` range — loud, not truncated, if a parameter change
/// ever widens it.
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

/// The quantized fee-correction scalar `C_q` (round-8 amendment,
/// whole-scalar form), with boundary hysteresis.
///
/// `sigma` and `burn_pct` are the caller's already-computed fixed-point
/// components (the same `shekyl_calc_emission_share` / `shekyl_calc_burn_pct`
/// values the validation path uses at this state — one source, no second
/// derivation). `prev_cq_scaled = 0` means no previous value (no
/// hysteresis).
///
/// Hysteresis (FL round §7 construction requirement): a state sitting
/// exactly on a pow2 boundary must not flicker between steps. The raw
/// `C_q` replaces the previous one only when `C` has moved beyond the
/// previous step's implied band by more than `HYSTERESIS_MARGIN_MILLI`
/// (3%); within the band the previous quantized value is kept.
///
/// **The daemon does not reach this branch.** `blockchain.cpp` passes
/// `prev_cq = 0`, so what is served is the plain ceiling snap. The band
/// needs a previous value, and there is no deterministic one to hand it:
/// a remembered value makes the served rate depend on the process's
/// query history, and the previous block's unseeded snap is a one-step
/// approximation that inverts the result rather than the recurrence
/// `C_q(h) = f(C(h), C_q(h−1))`, which cannot be evaluated without an
/// anchor. Serving hysteresis therefore requires `C_q` persisted as
/// chain state. The band is kept here, exercised by its own tests and by
/// the sim, because that is the open ruling's subject — FL-R3 in
/// `FEE_LADDER_DERIVATION.md` §8 carries the blocker and the two ways to
/// close it. Do not wire a caller to a nonzero `prev_cq` before it is
/// ruled.
#[must_use]
pub fn fee_correction_quantized(
    tx_volume_avg: u64,
    sigma_scaled: u64,
    burn_pct_scaled: u64,
    prev_cq_scaled: u64,
    params: &EconomicParams,
) -> u64 {
    let m_r = calc_release_multiplier(
        tx_volume_avg,
        params.tx_volume_baseline,
        params.release_min,
        params.release_max,
    );
    let sigma = sigma_scaled.min(SCALE - 1);
    let b = burn_pct_scaled.min(params.burn_cap).min(SCALE - 1);
    let c = u64::try_from(u128::from(SCALE - sigma) * u128::from(m_r) / u128::from(SCALE - b))
        .expect("C fits u64");
    // TOTALITY AT THE BOUNDARY is `hysteresis_step`'s floor: `σ` and `b`
    // are clamped just above, so what remains is a `C` of 0, which the
    // floor absorbs. The reasoning lives there, with the code that does
    // it.
    hysteresis_step(c, prev_cq_scaled)
}

/// The pow2 ceiling snap of a raw correction `C`, behind the §7
/// hysteresis band.
///
/// Split out of [`fee_correction_quantized`] so the band has ONE
/// implementation. The derivation instrument sweeps raw `C` directly and
/// so cannot enter through the whole-scalar function; it used to carry a
/// transliterated copy of this logic, which had already drifted — the
/// copy never picked up the `MIN_REPRESENTABLE_C` floor — and a
/// measurement taken on a drifted copy is a measurement of a different
/// mechanism than the one shipped.
///
/// `prev_cq_scaled = 0` means no history: the plain ceiling snap. With a
/// history the raw `C` must clear the new step's boundary by
/// `HYSTERESIS_MARGIN_MILLI` before the value moves, i.e. `C` must leave
/// `[prev/2·(1−m), prev·(1+m)]`.
///
/// `C` is floored at the smallest exactly-representable value first.
/// [`quantize_pow2_ceil`] is deliberately LOUD about a `C` outside that
/// window — the guard earns its keep on the derivation path, where a
/// parameter change that widened the range should stop the build rather
/// than truncate — but this is reached through `extern "C"`, where rule
/// 40 forbids a malformed input from panicking across the ABI. A `σ` at
/// its clamp with a dormant multiplier drives integer division to
/// `C = 0`, which no chain state produces (the reachable floor is ≈ 0.68)
/// but a caller can hand us. Flooring keeps the boundary total, and the
/// direction is the safe one: a smaller `C_q` can only under-price, which
/// the caller's relay-floor clamp then lifts (§5.2's acceptance identity).
#[must_use]
pub fn hysteresis_step(c_scaled: u64, prev_cq_scaled: u64) -> u64 {
    const MIN_REPRESENTABLE_C: u64 = SCALE >> 6;
    const HYSTERESIS_MARGIN_MILLI: u128 = 30; // 3%
    let c = c_scaled.max(MIN_REPRESENTABLE_C);
    let cq = quantize_pow2_ceil(c);
    if prev_cq_scaled == 0 || cq == prev_cq_scaled {
        return cq;
    }
    let prev = u128::from(prev_cq_scaled);
    let c = u128::from(c);
    let upper = prev * (1000 + HYSTERESIS_MARGIN_MILLI) / 1000;
    let lower = (prev / 2) * (1000 - HYSTERESIS_MARGIN_MILLI) / 1000;
    if c > upper || c < lower {
        cq
    } else {
        prev_cq_scaled
    }
}

/// The three priced rungs. The RK-5 wire shape is a derived view
/// ([`Self::as_slots`]): slot 2 mirrors `standard` so the vector length
/// does not change before the RPC cutover. Named fields mean the bridge
/// slot cannot drift from `standard` independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeLadder {
    pub economy: u64,
    pub standard: u64,
    pub priority: u64,
}

impl FeeLadder {
    /// Every rung at the `u64` rail. The saturation
    /// [`corrected_fee_ladder`] takes outside its `u128` domain, which no
    /// chain state reaches.
    pub const SATURATED: Self = Self {
        economy: u64::MAX,
        standard: u64::MAX,
        priority: u64::MAX,
    };

    /// Wire shape `[economy, standard, standard, priority]`.
    #[must_use]
    pub const fn as_slots(self) -> [u64; 4] {
        [self.economy, self.standard, self.standard, self.priority]
    }
}

/// The corrected three-tier ladder (FL-R17) plus the RK-5 bridge slot.
///
/// `base_reward` is the **M_r-neutral** total reward
/// ([`crate::base_block_reward`] — `max(curve(remaining), TAIL)`, total
/// past the asymptote); `c_q` is [`fee_correction_quantized`]'s output.
/// The rung formulas are the derived ones (`FEE_LADDER_DERIVATION.md`
/// §3.2/§5.2):
///
/// * `economy  = C_q · R·w_ref/Mfw²` — single-reference-tx self-funding
///   (the caller clamps this at the unbuffered relay floor, which is what
///   makes the estimate err only toward acceptance);
/// * `standard = C_q · 4·R·w_ref/Mfw²`;
/// * `priority = C_q · 2·R/Mfw` — the `Fh` main arm, UNCONDITIONAL: no
///   surge discount, full expansion is funded in every state.
///
/// `C_q` lives in the numerator before the median division (`(C_q·R·w)/M²`,
/// not `(R·w/M²)·C_q`). Truncating the rung first throws away a remainder
/// that `C_q > 1` would have scaled over a rounding step (10 SKL / 1.5 MB
/// / `C_q = 16` is 220 vs 210). Amount arithmetic, so the formula is the
/// integer reading of the signed expression, not a post-hoc rescale.
///
/// Each rung is then daemon-rounded to 2 significant digits.
///
/// Total: outside the arithmetic's `u128` domain — which no chain state
/// reaches, see [`checked_corrected_fee_ladder`] — every rung saturates,
/// the same fallback the division already takes. Callers that must
/// distinguish that input from a priced ladder use the checked form; the
/// FFI boundary does, and refuses it.
#[must_use]
pub fn corrected_fee_ladder(
    base_reward: u64,
    mnw: u64,
    mlw: u64,
    full_reward_zone: u64,
    ref_tx_weight: u64,
    c_q: u64,
) -> FeeLadder {
    checked_corrected_fee_ladder(base_reward, mnw, mlw, full_reward_zone, ref_tx_weight, c_q)
        .unwrap_or(FeeLadder::SATURATED)
}

/// [`corrected_fee_ladder`], or `None` when the scalars cannot form the
/// rungs' products in `u128`.
///
/// Every honest input is far inside the domain — `R` is bounded by the
/// subsidy curve at ≈2⁴¹, `w_ref` is 3 000, `C_q` ≤ 16 in `SCALE` units,
/// and `Mfw` is a block weight — so the fallible arm exists for the
/// `extern "C"` boundary alone (rule 40): the ABI takes bare `u64`s, and
/// operands near `u64::MAX` overflow `u128` BEFORE `round_scaled`'s
/// conversion fallback can see it, which is an abort in an
/// overflow-checked build and wrapped fees otherwise.
///
/// The domain is decided HERE, from the same operands the rungs
/// multiply, rather than being re-derived at the boundary. **The three
/// rungs do not share an operand list** — `priority` is `2·R·C_q` and is
/// the only rung that does not carry `w_ref` — so a boundary check
/// written against one representative product is not a check of the
/// others: `w_ref = 0` zeroes every `w_ref`-bearing product and passes,
/// then `2·R·C_q` overflows. That is not a hypothetical; it is what the
/// hand-mirrored boundary copy this replaces actually did.
#[must_use]
pub fn checked_corrected_fee_ladder(
    base_reward: u64,
    mnw: u64,
    mlw: u64,
    full_reward_zone: u64,
    ref_tx_weight: u64,
    c_q: u64,
) -> Option<FeeLadder> {
    let mfw = mnw.min(mlw).max(full_reward_zone).max(1);
    let round_scaled = |num: u128, den: u128| -> u64 {
        round_money_up_2(u64::try_from(num / den).unwrap_or(u64::MAX))
    };
    let base = u128::from(base_reward);
    let w_ref = u128::from(ref_tx_weight);
    let m = u128::from(mfw);
    let cq = u128::from(c_q);
    let s = u128::from(SCALE);
    let ms = m.checked_mul(s)?;
    let m2s = m.checked_mul(ms)?;
    let base_w_cq = base.checked_mul(w_ref)?.checked_mul(cq)?;
    let base_cq = base.checked_mul(cq)?;
    Some(FeeLadder {
        economy: round_scaled(base_w_cq, m2s),
        standard: round_scaled(base_w_cq.checked_mul(4)?, m2s),
        priority: round_scaled(base_cq.checked_mul(2)?, ms),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base_block_reward;

    /// Neutral correction (`C_q = 1`) against the `scaling_2021.cpp`
    /// heritage vectors, with the FL-R17 shape applied: three tiers, the
    /// bridge slot mirroring standard, and the `Fh` main arm
    /// unconditional (the 22 000 surge value in the second heritage case
    /// becomes the main-arm 67 000 — the FL-C2(b) fix, deliberate).
    #[test]
    fn neutral_ladder_matches_heritage_vectors_with_signed_shape() {
        let coin = 1_000_000_000u64;
        assert_eq!(
            corrected_fee_ladder(10 * coin, 300_000, 300_000, 300_000, 3_000, SCALE).as_slots(),
            [340, 1400, 1400, 67_000]
        );
        // Heritage case 2: Mnw = 15 MB surge over a 300 kB long-term
        // median. Was 22 000 under the surge discount; the unconditional
        // main arm prices full expansion here too.
        assert_eq!(
            corrected_fee_ladder(10 * coin, 15_000_000, 300_000, 300_000, 3_000, SCALE).as_slots(),
            [340, 1400, 1400, 67_000]
        );
        assert_eq!(
            corrected_fee_ladder(10 * coin, 1_500_000, 1_500_000, 300_000, 3_000, SCALE).as_slots(),
            [13, 53, 53, 14_000]
        );
    }

    /// The domain must be decided per RUNG, not against a representative
    /// product. Each case below overflows exactly one rung's operand
    /// list while leaving the others formable, so a check written against
    /// any single product lets one of them through — which is how
    /// `priority` (`2·R·C_q`, the rung with no `w_ref`) survived a
    /// boundary check written against `4·R·w_ref·C_q`.
    #[test]
    fn the_domain_covers_each_rung_separately() {
        let z = 300_000;
        // `w_ref = 0` collapses every `w_ref`-bearing product to zero;
        // only `priority`'s `2·R·C_q` can still overflow.
        assert!(checked_corrected_fee_ladder(u64::MAX, z, z, z, 0, u64::MAX).is_none());
        // …and with `C_q` small it is back in the domain, so the refusal
        // above is the arithmetic and not a blanket on `w_ref = 0`.
        assert!(checked_corrected_fee_ladder(u64::MAX, z, z, z, 0, SCALE).is_some());
        // `C_q = 1` (a scalar, not `SCALE`) keeps `priority` formable
        // while `4·R·w_ref·C_q` overflows.
        assert!(checked_corrected_fee_ladder(u64::MAX, z, z, z, u64::MAX, 1).is_none());
        // A denominator past the rail, with a numerator that fits.
        assert!(checked_corrected_fee_ladder(1, u64::MAX, u64::MAX, u64::MAX, 1, 1).is_none());
        // The honest domain is not swept up by any of it.
        assert!(checked_corrected_fee_ladder(10_000_000_000, z, z, z, 3_000, SCALE).is_some());
    }

    /// The infallible entry saturates rather than aborting, and does so
    /// at the same input the checked form refuses.
    #[test]
    fn the_infallible_entry_saturates_outside_the_domain() {
        let z = 300_000;
        assert_eq!(
            corrected_fee_ladder(u64::MAX, z, z, z, 0, u64::MAX),
            FeeLadder::SATURATED
        );
        assert_eq!(FeeLadder::SATURATED.as_slots(), [u64::MAX; 4]);
    }

    /// `C_q` in the numerator before the median division, not a rescale of
    /// an already-truncated rung. The 10 SKL / 1.5 MB / `C_q = 16` case is
    /// the measured divergence (220 vs the post-truncation 210).
    #[test]
    fn correction_lives_in_the_numerator() {
        let coin = 1_000_000_000u64;
        let ladder =
            corrected_fee_ladder(10 * coin, 1_500_000, 1_500_000, 300_000, 3_000, 16 * SCALE);
        assert_eq!(ladder.economy, 220);
        assert_eq!(ladder.as_slots()[2], ladder.standard);
    }

    /// Genesis-condition top rung with `C_q = 1` is the uncongested
    /// genesis `Fh` (14,000,000); at the genesis-congested `C_q = 2` it is
    /// the 28,000,000 FL-R9 wallet-cap bound.
    #[test]
    fn genesis_top_rung_anchors() {
        let p = EconomicParams::default();
        let base = base_block_reward(0, &p).unwrap();
        assert_eq!(
            corrected_fee_ladder(base, 300_000, 300_000, 300_000, 3_000, SCALE).priority,
            14_000_000
        );
        assert_eq!(
            corrected_fee_ladder(base, 300_000, 300_000, 300_000, 3_000, 2 * SCALE).priority,
            28_000_000
        );
    }

    #[test]
    fn quantize_snap_is_exact_integer_ceiling() {
        for c in [500_000u64, 1_000_000, 2_000_000, 4_000_000] {
            assert_eq!(quantize_pow2_ceil(c), c);
        }
        assert_eq!(quantize_pow2_ceil(680_000), 1_000_000);
        assert_eq!(quantize_pow2_ceil(1_130_000), 2_000_000);
        assert_eq!(quantize_pow2_ceil(12_917_390), 16_000_000);
    }

    /// The hysteresis band: sitting on a boundary does not flicker; a
    /// decisive move does switch.
    #[test]
    fn correction_hysteresis_holds_the_boundary() {
        let p = EconomicParams::default();
        // v = 51 at zero sigma/burn puts raw C = 1.02 — just past the
        // 2^0 boundary, inside the 3% band of a held C_q = 1.
        assert_eq!(fee_correction_quantized(51, 0, 0, SCALE, &p), SCALE);
        // Without a previous value it snaps up.
        assert_eq!(fee_correction_quantized(51, 0, 0, 0, &p), 2 * SCALE);
        // A decisive move (v = 65 → M_r = 1.3) leaves the band and steps.
        assert_eq!(fee_correction_quantized(65, 0, 0, SCALE, &p), 2 * SCALE);
        // And a held higher step survives small dips below its boundary.
        assert_eq!(fee_correction_quantized(51, 0, 0, 2 * SCALE, &p), 2 * SCALE);
    }

    #[test]
    fn round_money_up_two_places_matches_cpp() {
        assert_eq!(round_money_up_2(0), 0);
        assert_eq!(round_money_up_2(99), 99);
        assert_eq!(round_money_up_2(101), 110);
        assert_eq!(round_money_up_2(27_810), 28_000);
        assert_eq!(round_money_up_2(13_653_333), 14_000_000);
    }
}
