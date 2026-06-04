// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Confidential-claim entitlement arithmetic — Round 2 impl-spec + de-risking.
//!
//! Implements the integer core of the bounded-remainder entitlement relation
//! from [`CONFIDENTIAL_STAKING.md`](../../../docs/design/CONFIDENTIAL_STAKING.md)
//! §6.4.1 and lets the **data** pick the denominator `D`:
//!
//! ```text
//! N            = tier_num_reduced(tier) · Σ_S K_S_scaled      (public scalar)
//! D            = D_TIER · SCALE_rate = 2 · 2^k = 2^(k+1)        (power of two)
//! reward       = floor(N · amount / D)                          // toward under-claim
//! N · amount   = D · reward + ρ,            0 ≤ ρ < D            // bounded remainder
//! ```
//!
//! # Why `D` is a product of two scales (the §6.4.1 correction)
//!
//! The spec text pins "`D = SCALE`", but that is only correct if `Σ_S K_S` is a
//! plain integer. It is **not**: the per-weighted-atomic rate `ρ_e =
//! budget_e / band_sum_e ≈ 1e-8 … 1e-3` is sub-integer, so `Σ_S K_S` must carry
//! a rate-precision scale `SCALE_rate` or every reward floors to zero. The
//! tier multiplier carries its own scale. Hence `D = D_TIER · SCALE_rate`
//! **intrinsically**.
//!
//! Two levers minimize `D` (and therefore the remainder range-proof width):
//!
//! - **`D_TIER`** reduces to the LCD of the tier multipliers. The pinned tiers
//!   are `{1.0, 1.5, 2.0}` ([`crate::tiers`]), whose LCD is **2**, so
//!   `tier_num_reduced ∈ {2, 3, 4}` represents them *exactly*
//!   ([`tier_num_reduced`]). `D_TIER = 2` contributes exactly one bit.
//! - **`SCALE_rate = 2^k`** is the sole precision dial; post-fold (decision
//!   1(b)) precision is free up to the field-wrap margin, so [`precision_sweep`]
//!   locates the **floor-dominated knee** and [`SCALE_RATE_K`] pins `k = 48`
//!   there (not the obsolete "smallest k clearing 0.1%").
//!
//! Both being powers of two makes `D = 2^(k+1)` a power of two, so `[0, D)` is a
//! native power-of-two range. `D = 2^49` is the **value** bound on the honest
//! remainder; it is *not* the width of the range proof (see below).
//!
//! # The remainder range proof's width — decision 1(b)
//!
//! The inflation-critical content of the remainder bound is the **lower** bound
//! `ρ ≥ 0`, **not** a tight upper bound `ρ < D`. Over-claiming `reward+k`
//! (`k ≥ 1`) forces the integer remainder `ρ' = N·amount − D·(reward+k) < 0`;
//! a field-wrap to a non-negative `ρ' < 2^64` would require
//! `reward+k > (ℓ − 2^64)/D ≈ 2^203`, but the reward output's own range proof
//! bounds it `< 2^64` — a **139-bit margin** at the pinned `k = 48`
//! ([`wraparound_over_claim_margin_bits`]). So **any** range width
//! `w ∈ [⌈log2 D⌉, ~203]` is inflation-sound; the honest `ρ < D < 2^64` always
//! fits.
//!
//! Therefore `C_ρ` is **folded into the claim tx's existing reward-output
//! `AggregateRangeProof`** (native 64-bit, `mask·G + amount·H` matches
//! `C_ρ = ρ_blind·G + ρ·H`, `ρ < 2^49` fits `u64`) as one additional aggregated
//! commitment — cheapest (no new proof system, marginal cost ≈ one commitment in
//! an aggregate that already exists) and sound. The folded `C_ρ` is the **same
//! group element** the entitlement relation consumes, bound in one transcript
//! (§6.4.1 decision 3) — not a free-floating commitment. A *tight* `⌈log2 D⌉`-bit
//! range would only additionally forbid **under**-claim (`reward < floor`),
//! which mints *less*, is the prover's own loss, preserves `Σ reward ≤ budget`,
//! and is **not** load-bearing. See
//! [`CONFIDENTIAL_STAKING.md`](../../../docs/design/CONFIDENTIAL_STAKING.md)
//! §6.4.1 decision 1(b).
//!
//! # Floor loss is always sub-atomic
//!
//! `reward = floor(N·amount/D)` discards `< 1` atomic unit **regardless of `D`**.
//! So `D` does **not** govern payout rounding (that is always sub-atomic); it
//! governs **rate quantization** — how finely the public `ρ_e` is representable.
//! [`precision_sweep`] therefore measures the rate-quantization error, not the
//! floor loss.

use crate::tiers::tier_by_id;
use shekyl_economics::params::SCALE;

pub mod transcript;

/// Reduced tier-factor denominator: the LCD of the pinned tier multipliers
/// `{1.0, 1.5, 2.0}`. `D = D_TIER · SCALE_rate`.
///
/// **Reversion (`21-reversion-clause-discipline.mdc`):** if a future tier
/// multiplier is not exactly representable over `D_TIER` (e.g. a `1.333…×`
/// tier), [`tier_num_reduced`] returns `None` (loud reject) and `D_TIER` must
/// be re-derived from the new LCD. Pre-genesis the tier set is launch-final, so
/// this is a constant.
pub const D_TIER: u64 = 2;

/// The pinned rate-precision exponent: `SCALE_rate = 2^SCALE_RATE_K`, hence
/// `D = D_TIER · SCALE_rate = 2^(SCALE_RATE_K + 1)`.
///
/// **Chosen by the floor-dominated knee, not a precision threshold.** Decision
/// 1(b) folded `C_ρ` into the reward output's native 64-bit range proof, so the
/// remainder only has to fit `2^64` and rate precision is **free** up to the
/// field-wrap margin `wraparound_over_claim_margin_bits(k) = 187 − k`. The
/// precision sweep ([`precision_sweep`]) shows the worst-case *relative*
/// rate-quantization error falling until `k = 48` (≈ 2.1e-5) and then
/// **plateauing** (identical at `k = 48, 52, 56, 60`): past the knee the
/// irreducible reward floor `floor(N·amount/D)`, not the rate scale, sets the
/// worst-case error, so finer quantization cannot improve payout accuracy.
/// `k = 48` is the smallest `k` at that knee — rate quantization is as fine as
/// it can matter — with a **139-bit** field-wrap margin and ~130-bit `N·amount`
/// overflow headroom ([`overflow_headroom_bits`]), both far from binding.
///
/// The earlier `k = 38` was the smallest `k` clearing an *arbitrary* 0.1%
/// relative-error floor — the correct rule when precision traded against proof
/// width, obsolete the moment the fold fixed the width at 64.
///
/// **Reversion (`21-reversion-clause-discipline.mdc`):** re-pin only if (a) the
/// realistic rate range (`config/economics_params.json`) moves the knee, or
/// (b) the reward-output range width changes (it sets the margin via
/// [`OUTPUT_RANGE_PROOF_BITS`]). Safe band: any `k` with a comfortably positive
/// margin (`≥ ~64`); below the knee wastes free precision, above it erodes
/// margin for no fidelity gain. (The u128 sweep harness is faithful only to
/// `k ≈ 60`; the real upper bound is the analytic margin, not the simulation.)
pub const SCALE_RATE_K: u32 = 48;

/// The Ed25519 scalar-field order `ℓ = 2^252 + 27742317777372353535851937790883648493`.
/// The cancel relation `N·amount − D·reward − ρ = 0` must hold over the
/// integers, so `N·amount` must not wrap mod `ℓ`. Used by
/// [`max_n_times_amount_fits_scalar_field`] as the overflow ceiling.
pub const ED25519_SCALAR_ORDER: u128 = {
    // ℓ exceeds u128; we only ever compare a u128 product against a u128 floor
    // far below ℓ. Expose a conservative 2^126 headroom marker instead of the
    // true ℓ (which does not fit u128) — see `overflow_headroom_bits`.
    1u128 << 126
};

/// Reduce a tier's `yield_multiplier` (fixed-point over [`SCALE`]) to its
/// integer numerator over [`D_TIER`].
///
/// Returns `None` if the reduction is not exact (the tier is not representable
/// over `D_TIER`) — a loud reject, never a silent round.
///
/// For the pinned tiers: `1.0 → 2`, `1.5 → 3`, `2.0 → 4`.
#[must_use]
pub fn tier_num_reduced(tier_id: u8) -> Option<u64> {
    let tier = tier_by_id(tier_id)?;
    let scaled = u128::from(tier.yield_multiplier) * u128::from(D_TIER);
    if scaled % u128::from(SCALE) != 0 {
        return None;
    }
    u64::try_from(scaled / u128::from(SCALE)).ok()
}

/// `SCALE_rate = 2^k`, the rate-precision scale.
#[must_use]
pub fn scale_rate(k: u32) -> u128 {
    1u128 << k
}

/// `D = D_TIER · SCALE_rate = 2^(k+1)`.
#[must_use]
pub fn denominator(k: u32) -> u128 {
    u128::from(D_TIER) * scale_rate(k)
}

/// Bit-width of the honest remainder's **value** bound `⌈log2 D⌉ = k + 1`.
///
/// Note this is the bound on the *value* `ρ < D`, not the width of the range
/// proof actually used: `C_ρ` is folded into the native 64-bit reward-output
/// `AggregateRangeProof` (decision 1(b); [`OUTPUT_RANGE_PROOF_BITS`]).
#[must_use]
pub fn remainder_proof_bits(k: u32) -> u32 {
    k + 1
}

/// Approximate bit-length of the Ed25519 scalar-field order `ℓ ≈ 2^252`.
pub const SCALAR_FIELD_BITS: u32 = 252;

/// Width of the reward-output range proof Monero's `AggregateRangeProof` uses
/// (`COMMITMENT_BITS`). `C_ρ` is folded into this aggregate (decision 1(b)), and
/// the reward commitment is itself bounded to this width by the same proof.
pub const OUTPUT_RANGE_PROOF_BITS: u32 = 64;

/// Margin (bits) protecting the native-64-bit fold against a **field-wrap
/// over-claim**.
///
/// To mint `reward+k` (`k ≥ 1`) the integer remainder `ρ' = N·amount −
/// D·(reward+k)` is negative; the only way past a non-negative range proof is a
/// field wrap `ρ' + ℓ < 2^64`, which needs `D·(reward+k) > ℓ − 2^64`, i.e.
/// `reward+k > (ℓ − 2^64)/D ≈ 2^(SCALAR_FIELD_BITS − ⌈log2 D⌉)`. But the reward
/// output's own range proof bounds `reward+k < 2^OUTPUT_RANGE_PROOF_BITS`. The
/// gap between those exponents is the margin; positive ⇒ no reachable wrap, so
/// the 64-bit fold is inflation-sound. For the pinned `k = 48` ([`SCALE_RATE_K`],
/// `D = 2^49`) it is `252 − 49 − 64 = 139` bits.
#[must_use]
pub fn wraparound_over_claim_margin_bits(k: u32) -> i32 {
    i32::try_from(SCALAR_FIELD_BITS).expect("252 fits i32")
        - i32::try_from(remainder_proof_bits(k)).expect("k+1 fits i32")
        - i32::try_from(OUTPUT_RANGE_PROOF_BITS).expect("64 fits i32")
}

/// The consensus rate-quantization step: `ρ_e_scaled = floor(numer · 2^k / denom)`,
/// where `(numer, denom)` is the rational rate `ρ_e = budget_e / band_sum_e`.
///
/// This is the **single** integer division in the system (done once per
/// rate-epoch at consensus when `ρ_e` is set — §3, §4.1), not a per-claim
/// rounding. Returns the scaled integer rate stored on-chain.
#[must_use]
pub fn rho_e_scaled(budget_e: u128, band_sum_e: u128, k: u32) -> u128 {
    if band_sum_e == 0 {
        return 0;
    }
    budget_e.saturating_mul(scale_rate(k)) / band_sum_e
}

/// The integer entitlement: `reward = floor(N·amount/D)` and the bounded
/// remainder `ρ = N·amount − D·reward ∈ [0, D)`.
///
/// `n` is the public multiplier `N = tier_num_reduced · Σ_S K_S_scaled`;
/// `amount` is the hidden principal; `k` selects `D = 2^(k+1)`.
#[must_use]
pub fn reward_and_remainder(n: u128, amount: u128, k: u32) -> (u128, u128) {
    let d = denominator(k);
    let product = n.saturating_mul(amount);
    let reward = product / d;
    let rho = product - reward * d;
    (reward, rho)
}

/// Largest `N·amount` produced at the consensus extremes, for the overflow
/// guard. `N = tier_num_reduced_max · Σ_S K_S_scaled` over at most
/// `max_epochs · rate_epoch_blocks` blocks at the capped scaled rate
/// `rho_e_scaled_cap`; `amount ≤ money_supply`.
#[must_use]
pub fn max_n_times_amount(
    rho_e_scaled_cap: u128,
    rate_epoch_blocks: u128,
    max_epochs: u128,
    money_supply: u128,
) -> u128 {
    let tier_num_max = u128::from(D_TIER) + 2; // {2,3,4} → max 4 for tiers {1,1.5,2}
    let k_total = rho_e_scaled_cap
        .saturating_mul(rate_epoch_blocks)
        .saturating_mul(max_epochs);
    let n = tier_num_max.saturating_mul(k_total);
    n.saturating_mul(money_supply)
}

/// Spare bits between the worst-case `N·amount` and the scalar field, i.e.
/// `252 − ⌈log2(N·amount)⌉`. Positive ⇒ no wrap in the cancel relation.
#[must_use]
pub fn overflow_headroom_bits(max_n_times_amount: u128) -> i32 {
    if max_n_times_amount == 0 {
        return 252;
    }
    let bits_used = 128 - max_n_times_amount.leading_zeros();
    252 - i32::try_from(bits_used).expect("bits_used ≤ 128 fits i32")
}

/// One row of the precision sweep: at scale exponent `k`, over a realistic
/// `ρ_e` operating point, the worst relative rate-quantization error and the
/// worst absolute atomic mispay across the swept stake sizes / tiers / window.
#[derive(Debug, Clone, PartialEq)]
pub struct PrecisionRow {
    pub k: u32,
    pub d_bits: u32,
    /// Worst-case relative error of the quantized reward vs the ideal
    /// real-valued reward, across the sweep (dimensionless).
    pub max_relative_error: f64,
    /// Worst-case absolute atomic units mis-paid (under-paid) across the sweep.
    pub max_abs_atomic_error: u128,
    /// Smallest non-zero scaled rate observed (0 ⇒ a rate floored to zero — the
    /// scale is too coarse to represent the smallest operating rate at all).
    pub min_nonzero_rho_scaled: u128,
    /// True iff some operating rate floored to a zero scaled rate at this `k`.
    pub any_rate_underflowed: bool,
    /// Field-wrap over-claim margin at this `k` ([`wraparound_over_claim_margin_bits`]):
    /// `187 − k` bits. This is the **only ceiling** on `k` post-fold (decision
    /// 1(b)) — precision is otherwise free, so the sweep reports error *and*
    /// margin side by side to make the threshold choice auditable.
    pub margin_bits: i32,
}

/// A single realistic operating point for the rate `ρ_e = budget_e / band_sum_e`.
#[derive(Debug, Clone, Copy)]
pub struct RateOperatingPoint {
    pub budget_e: u128,
    pub band_sum_e: u128,
}

/// Sweep scale exponents `k` over the given realistic rate operating points,
/// stake sizes, tiers, and window length; return one [`PrecisionRow`] per `k`.
///
/// `min_meaningful_yield` filters out operating points whose **per-unit yield**
/// (`ρ_e · window_blocks`, amount-independent) is below the threshold: such
/// rates produce economically negligible yield for *any* staker, so their
/// quantization precision is irrelevant and must not drive the recommendation.
/// The relative-error metric and the underflow flag are computed over
/// meaningful points only; negligible points are still reported via
/// `max_abs_atomic_error` and `min_nonzero_rho_scaled`.
///
/// The economically-negligible relative threshold is applied by the caller
/// ([`recommend_k`]); this function just measures.
#[must_use]
pub fn precision_sweep(
    ks: &[u32],
    rates: &[RateOperatingPoint],
    stake_amounts: &[u128],
    window_blocks: u128,
    min_meaningful_yield: f64,
) -> Vec<PrecisionRow> {
    let mut rows = Vec::with_capacity(ks.len());
    for &k in ks {
        let mut max_rel = 0.0f64;
        let mut max_abs = 0u128;
        let mut min_nonzero = u128::MAX;
        let mut underflowed = false;

        for rate in rates {
            // Scaled (consensus) rate and the ideal real rate.
            let rho_scaled = rho_e_scaled(rate.budget_e, rate.band_sum_e, k);
            #[allow(clippy::cast_precision_loss)]
            let rho_real = rate.budget_e as f64 / rate.band_sum_e as f64;

            // Per-unit yield over the window (amount-independent). Rates below
            // the meaningfulness floor produce negligible yield and do not gate
            // the recommendation.
            #[allow(clippy::cast_precision_loss)]
            let per_unit_yield = rho_real * window_blocks as f64;
            let meaningful = per_unit_yield >= min_meaningful_yield;

            if meaningful {
                if rho_scaled == 0 {
                    underflowed = true;
                } else {
                    min_nonzero = min_nonzero.min(rho_scaled);
                }
            }

            // K accumulated over the window.
            let k_total_scaled = rho_scaled.saturating_mul(window_blocks);
            #[allow(clippy::cast_precision_loss)]
            let k_total_real = rho_real * window_blocks as f64;

            for tier_id in 0u8..3 {
                let tnum = tier_num_reduced(tier_id).expect("pinned tier reduces exactly");
                // Ideal real tier factor = yield_multiplier / SCALE.
                let tier = tier_by_id(tier_id).unwrap();
                #[allow(clippy::cast_precision_loss)]
                let tier_real = tier.yield_multiplier as f64 / SCALE as f64;

                let n = u128::from(tnum).saturating_mul(k_total_scaled);

                for &amount in stake_amounts {
                    let (reward_q, _rho) = reward_and_remainder(n, amount, k);
                    #[allow(clippy::cast_precision_loss)]
                    let reward_ideal = tier_real * k_total_real * amount as f64;

                    #[allow(clippy::cast_precision_loss)]
                    let reward_q_f = reward_q as f64;
                    let abs_err = (reward_ideal - reward_q_f).abs();
                    if meaningful && reward_ideal > 0.0 {
                        let rel = abs_err / reward_ideal;
                        if rel > max_rel {
                            max_rel = rel;
                        }
                    }
                    #[allow(
                        clippy::cast_possible_truncation,
                        clippy::cast_sign_loss,
                        clippy::cast_precision_loss
                    )]
                    let abs_atomic = abs_err as u128;
                    if abs_atomic > max_abs {
                        max_abs = abs_atomic;
                    }
                }
            }
        }

        rows.push(PrecisionRow {
            k,
            d_bits: remainder_proof_bits(k),
            max_relative_error: max_rel,
            max_abs_atomic_error: max_abs,
            min_nonzero_rho_scaled: if min_nonzero == u128::MAX {
                0
            } else {
                min_nonzero
            },
            any_rate_underflowed: underflowed,
            margin_bits: wraparound_over_claim_margin_bits(k),
        });
    }
    rows
}

/// The **post-fold** decision rule (decision 1(b) dissolved the precision-vs-width
/// tradeoff): the smallest `k` at the **floor-dominated knee** — where the
/// worst-case relative rate-quantization error reaches within `slack`× of its
/// asymptotic minimum across the swept range. Beyond the knee the irreducible
/// reward floor, not the rate scale, sets the error, so finer quantization
/// cannot improve accuracy; below it, free precision is left unused.
///
/// Only non-underflowed rows are eligible (an underflowed `k` cannot represent
/// the smallest operating rate at all). Returns the knee row, or `None` if no
/// row is eligible.
///
/// This **replaces** the obsolete "smallest `k` clearing an arbitrary relative
/// threshold" rule, which optimized for minimum precision because more
/// precision was assumed to cost proof width — a cost the fold removed.
#[must_use]
pub fn recommend_k_knee(rows: &[PrecisionRow], slack: f64) -> Option<&PrecisionRow> {
    let floor = rows
        .iter()
        .filter(|r| !r.any_rate_underflowed)
        .map(|r| r.max_relative_error)
        .fold(f64::INFINITY, f64::min);
    if !floor.is_finite() {
        return None;
    }
    rows.iter()
        .filter(|r| !r.any_rate_underflowed && r.max_relative_error <= floor * slack)
        .min_by_key(|r| r.k)
}

#[cfg(test)]
mod tests;
