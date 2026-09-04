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
/// First Rust *production* owner of this rule (the wallet-side
/// `fee_policy.rs` copy and the sim instrument's copy single-source from
/// here when they next move — FL round record, review round 3 deferral).
/// The C++ original throws on overflow; saturation here is unreachable for
/// any fee the ladder can emit and documented as the fail-safe.
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
/// (3%); within the band the previous quantized value is kept. The §4.4
/// dwell scenarios are the acceptance gate.
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
    let cq = quantize_pow2_ceil(c);
    if prev_cq_scaled == 0 || cq == prev_cq_scaled {
        return cq;
    }
    // Boundary band around the PREVIOUS step: keep it unless C has left
    // [prev/2·(1+m), prev·(1+m)] — i.e. the raw C must clear the new
    // step's boundary by the margin before the served value moves.
    const HYSTERESIS_MARGIN_MILLI: u128 = 30; // 3%
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

/// The corrected four-slot ladder (three tiers + the RK-5 bridge slot).
///
/// `base_reward` is the **M_r-neutral** total reward
/// ([`crate::base_block_reward`] — `max(curve(remaining), TAIL)`, total
/// past the asymptote); `c_q` is [`fee_correction_quantized`]'s output.
/// The rung formulas are the derived ones (`FEE_LADDER_DERIVATION.md`
/// §3.2/§5.2):
///
/// * `fees[0] = C_q · R·w_ref/Mfw²` — single-reference-tx self-funding
///   (the caller clamps this at the unbuffered relay floor, which is what
///   makes the estimate err only toward acceptance);
/// * `fees[1] = C_q · 4·R·w_ref/Mfw²`;
/// * `fees[2] = fees[1]` — wire bridge (see module docs);
/// * `fees[3] = C_q · 2·R/Mfw` — the `Fh` main arm, UNCONDITIONAL: no
///   surge discount, full expansion is funded in every state.
///
/// All arithmetic in `u128` intermediates; each rung is scaled unrounded,
/// then daemon-rounded to 2 significant digits.
#[must_use]
pub fn corrected_fee_ladder(
    base_reward: u64,
    mnw: u64,
    mlw: u64,
    full_reward_zone: u64,
    ref_tx_weight: u64,
    c_q: u64,
) -> [u64; 4] {
    let mfw = mnw.min(mlw).max(full_reward_zone).max(1);
    let scale = |raw: u128| -> u64 {
        let scaled = raw * u128::from(c_q) / u128::from(SCALE);
        round_money_up_2(u64::try_from(scaled).unwrap_or(u64::MAX))
    };
    let base = u128::from(base_reward);
    let w_ref = u128::from(ref_tx_weight);
    let m = u128::from(mfw);
    let economy = scale(base * w_ref / (m * m));
    let standard = scale(4 * base * w_ref / (m * m));
    let priority = scale(2 * base / m);
    [economy, standard, standard, priority]
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
            corrected_fee_ladder(10 * coin, 300_000, 300_000, 300_000, 3_000, SCALE),
            [340, 1400, 1400, 67_000]
        );
        // Heritage case 2: Mnw = 15 MB surge over a 300 kB long-term
        // median. Was 22 000 under the surge discount; the unconditional
        // main arm prices full expansion here too.
        assert_eq!(
            corrected_fee_ladder(10 * coin, 15_000_000, 300_000, 300_000, 3_000, SCALE),
            [340, 1400, 1400, 67_000]
        );
        assert_eq!(
            corrected_fee_ladder(10 * coin, 1_500_000, 1_500_000, 300_000, 3_000, SCALE),
            [13, 53, 53, 14_000]
        );
    }

    /// Genesis-condition top rung with `C_q = 1` is the wallet cap's
    /// 14,000,000 anchor; at the genesis-congested `C_q = 2` it is the
    /// 28,000,000 FL-R9 bound.
    #[test]
    fn genesis_top_rung_anchors() {
        let p = EconomicParams::default();
        let base = base_block_reward(0, &p).unwrap();
        assert_eq!(
            corrected_fee_ladder(base, 300_000, 300_000, 300_000, 3_000, SCALE)[3],
            14_000_000
        );
        assert_eq!(
            corrected_fee_ladder(base, 300_000, 300_000, 300_000, 3_000, 2 * SCALE)[3],
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
