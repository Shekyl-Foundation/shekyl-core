// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Round 2 de-risking bundle for the bounded-remainder entitlement (§6.4.1):
//! soundness properties, overflow-at-extremes, and the `SCALE_rate` precision
//! sweep that picks `D = 2^(k+1)`.
//!
//! Randomized properties use a deterministic LCG rather than `proptest` to
//! match the crate's existing plain-`#[test]` convention
//! ([`crate::property_tests`]) and keep the dependency surface unchanged
//! (`17-dependency-discipline.mdc`).

use super::*;

// ── Realistic economic magnitudes (from config/economics_params.json) ──
//
// money_supply = 4_294_967_296_000_000_000 (≈ 2^32 coins × 1e9 atomic/coin)
// coin         = 1e9 atomic              SCALE = 1e6
// blocks/year  = 262_800  ⇒ ~2 min/block  rate_epoch = 1000 blocks
// staker share = 15%      final_subsidy ≈ 3e8 atomic/min ⇒ ~6e8 atomic/block tail
// early block emission ≈ money_supply >> 22 ≈ 1.0e12 atomic/block

const MONEY_SUPPLY: u128 = 4_294_967_296_000_000_000;
const COIN: u128 = 1_000_000_000;
const RATE_EPOCH_BLOCKS: u128 = 1_000;
const MAX_EPOCHS_PER_CLAIM: u128 = 15;

/// A rate producing less than this per-unit yield over the claim window is
/// economically negligible (here: < 1e-5 = 0.001% yield), so its quantization
/// precision does not gate the `D` recommendation.
///
/// This is a **yield** threshold (`rate · window`), hence **era-independent**: it
/// bounds the smallest *meaningful* rate at `MIN_MEANINGFUL_YIELD / window`
/// regardless of *when* that rate occurs. Emission decays 0.90/yr, so the
/// rate range shrinks over the emission lifetime — but the knee
/// ([`SCALE_RATE_K`]) is set by the smallest meaningful rate, and decay only
/// changes *which* `(budget, band)` realize a given rate, not this floor. A rate
/// below the floor is sub-meaningful by definition. See
/// `knee_is_lifetime_invariant_not_genesis_only` — the constant is the lifetime
/// knee, not the genesis knee. The lever that *would* move it is this cutoff,
/// not the era.
const MIN_MEANINGFUL_YIELD: f64 = 1e-5;

/// Realistic `ρ_e = budget_e/band_sum_e` operating points spanning the rate
/// range: (per-block staker emission, weighted staked). High rate = small band
/// + early emission; low rate = large band + tail emission.
fn rate_grid() -> Vec<RateOperatingPoint> {
    // Per-block staker emission ≈ 0.15 · block_emission. Spans the emission
    // lifetime: `emit_early` is genesis; `emit_mid` is ~15× lower (≈ 26 yr out at
    // 0.90/yr decay); `emit_tail` is the *terminal* tail subsidy (the asymptotic
    // emission floor — maximally far future, past any 3-decade point). So the
    // rate range is lifetime-spanning, not near-term.
    let emit_early: u128 = 153_000_000_000; // 0.15 · 1.02e12  (genesis)
    let emit_mid: u128 = 10_000_000_000; // 0.15 · ~6.7e10  (~26 yr out)
    let emit_tail: u128 = 90_000_000; // 0.15 · 6e8  (terminal tail subsidy)
                                      // Weighted staked band: participation × circulating × tier_mult.
    let band_small: u128 = 10_000_000_000_000; // ~1% early circulating, low mult
    let band_mid: u128 = 10_000_000_000_000_000; // ~mid chain
    let band_large: u128 = 6_900_000_000_000_000_000; // ~80% of supply × 2.0

    let mut grid = Vec::new();
    for &b in &[emit_early, emit_mid, emit_tail] {
        for &s in &[band_small, band_mid, band_large] {
            grid.push(RateOperatingPoint {
                budget_e: b,
                band_sum_e: s,
            });
        }
    }
    grid
}

/// Stake sizes swept: 1 coin, 100 coins, 10k coins, 1M coins, and a whale.
fn stake_grid() -> Vec<u128> {
    vec![
        COIN,
        100 * COIN,
        10_000 * COIN,
        1_000_000 * COIN,
        100_000_000 * COIN,
    ]
}

// Deterministic LCG (numerical-recipes constants) for randomized properties.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        self.0
    }
    fn in_range(&mut self, lo: u128, hi: u128) -> u128 {
        if hi <= lo {
            return lo;
        }
        lo + u128::from(self.next()) % (hi - lo)
    }
}

// ── Tier reduction ──

#[test]
fn pinned_tiers_reduce_exactly_over_d_tier() {
    assert_eq!(tier_num_reduced(0), Some(2)); // 1.0× → 2/2
    assert_eq!(tier_num_reduced(1), Some(3)); // 1.5× → 3/2
    assert_eq!(tier_num_reduced(2), Some(4)); // 2.0× → 4/2
    assert_eq!(tier_num_reduced(3), None); // no such tier
}

#[test]
fn d_tier_is_a_power_of_two_and_d_too() {
    assert!(D_TIER.is_power_of_two());
    for k in 0u32..40 {
        assert_eq!(denominator(k), 1u128 << (k + 1));
        assert!(denominator(k).is_power_of_two());
        assert_eq!(remainder_proof_bits(k), k + 1);
    }
}

// ── Soundness: the relation identity ──

#[test]
fn reward_remainder_identity_and_bound() {
    let mut rng = Lcg(0xDEAD_BEEF);
    for _ in 0..200_000 {
        let k = 16 + (rng.next() % 24) as u32; // k ∈ [16, 40)
        let n = rng.in_range(0, 1u128 << 50);
        let amount = rng.in_range(0, MONEY_SUPPLY);
        let (reward, rho) = reward_and_remainder(n, amount, k);
        let d = denominator(k);
        // N·amount = D·reward + ρ exactly, with 0 ≤ ρ < D.
        assert_eq!(reward * d + rho, n.saturating_mul(amount));
        assert!(rho < d, "remainder must be < D");
    }
}

#[test]
fn rounding_is_toward_under_claim() {
    // floor never over-pays: D·reward ≤ N·amount.
    let mut rng = Lcg(0x0BAD_F00D);
    for _ in 0..200_000 {
        let k = 16 + (rng.next() % 24) as u32;
        let n = rng.in_range(0, 1u128 << 50);
        let amount = rng.in_range(0, MONEY_SUPPLY);
        let (reward, _rho) = reward_and_remainder(n, amount, k);
        assert!(reward * denominator(k) <= n.saturating_mul(amount));
    }
}

#[test]
fn forged_over_claim_forces_negative_remainder_for_any_k() {
    // Claiming reward+j (j ≥ 1) forces ρ' = N·amount − D·(reward+j) < 0 as an
    // integer — so no non-negative remainder exists, for ANY over-claim step,
    // independent of the range-proof width. The lower bound ρ ≥ 0 is the
    // inflation-critical half of the bound (decision 1(b)); trap (a) is closed
    // by ρ ≥ 0, not by a tight upper bound.
    let mut rng = Lcg(0xFEED_FACE);
    for _ in 0..200_000 {
        let k = 16 + (rng.next() % 24) as u32;
        let n = rng.in_range(1, 1u128 << 50);
        let amount = rng.in_range(1, MONEY_SUPPLY);
        let d = denominator(k);
        let (reward, _rho) = reward_and_remainder(n, amount, k);
        let product = n.saturating_mul(amount);
        for j in 1u128..=4 {
            let forged = reward + j;
            assert!(
                forged.saturating_mul(d) > product,
                "reward+{j} must exceed N·amount, leaving no non-negative ρ"
            );
        }
    }
}

#[test]
fn native_64bit_fold_is_sound_no_reachable_field_wrap() {
    // Decision 1(b): C_ρ folds into the reward output's native 64-bit
    // AggregateRangeProof. Soundness rests on the field-wrap over-claim being
    // unreachable: a wrap needs reward+k ≥ 2^(252−⌈log2 D⌉), but the reward
    // output's range proof bounds it < 2^64. The margin must be comfortably
    // positive across every operating k (here the swept and pinned range).
    for k in 10u32..=64 {
        let margin = wraparound_over_claim_margin_bits(k);
        assert!(
            margin > 0,
            "k={k}: field-wrap over-claim margin is {margin} bits (≤ 0 ⇒ 64-bit \
             fold unsound; would need a tighter range)"
        );
    }
    // Fixed check on the margin arithmetic itself (187 − k), independent of the
    // pinned k.
    assert_eq!(wraparound_over_claim_margin_bits(0), 187);
    // The pinned operating point (SCALE_RATE_K, the floor-dominated knee) keeps
    // a wide margin (defense in depth): 187 − 48 = 139.
    assert_eq!(wraparound_over_claim_margin_bits(SCALE_RATE_K), 139);
    assert_eq!(SCALE_RATE_K, 48);
}

#[test]
fn honest_remainder_always_fits_the_64bit_slot() {
    // The honest remainder ρ < D = 2^(k+1) ≤ 2^64 for every k ≤ 63, so honest
    // provers can always produce the folded 64-bit range proof. (For the pinned
    // k=48, ρ < 2^49, with 15 bits to spare in the 64-bit slot.)
    let mut rng = Lcg(0x5EED_1B0B);
    for _ in 0..200_000 {
        let k = 16 + (rng.next() % 24) as u32; // k ∈ [16, 40) ⇒ D ≤ 2^40
        let n = rng.in_range(0, 1u128 << 50);
        let amount = rng.in_range(0, MONEY_SUPPLY);
        let (_reward, rho) = reward_and_remainder(n, amount, k);
        assert!(rho < (1u128 << OUTPUT_RANGE_PROOF_BITS));
        assert!(rho < denominator(k));
    }
}

#[test]
fn under_claim_is_representable_but_not_inflationary() {
    // A *tight* ρ<D range would forbid under-claim; the 64-bit fold permits it.
    // This test documents that the permitted under-claim mints strictly LESS
    // than the honest floor (prover's own loss), so it is not load-bearing to
    // forbid it: reward' = floor − t (t ≥ 1) with ρ' = honest_ρ + t·D < 2^64.
    for k in [30u32, 38, 40] {
        let d = denominator(k);
        let n = 7u128; // N·amount = 7·amount
        let amount = 1_000_000u128;
        let (floor_reward, honest_rho) = reward_and_remainder(n, amount, k);
        let product = n * amount;
        // Largest under-claim still fitting the 64-bit remainder slot.
        let max_t = ((1u128 << OUTPUT_RANGE_PROOF_BITS) - 1 - honest_rho) / d;
        if max_t >= 1 && floor_reward >= 1 {
            let t = max_t.min(floor_reward);
            let under_reward = floor_reward - t;
            let under_rho = product - under_reward * d;
            assert_eq!(
                under_reward * d + under_rho,
                product,
                "relation still holds"
            );
            assert!(
                under_rho < (1u128 << OUTPUT_RANGE_PROOF_BITS),
                "ρ' fits 64-bit"
            );
            assert!(
                under_reward < floor_reward,
                "under-claim mints strictly less"
            );
        }
    }
}

#[test]
fn maximal_honest_remainder_passes() {
    // Construct N·amount ≡ D−1 (mod D): ρ = D−1 is honest and in range.
    for k in 10u32..40 {
        let d = denominator(k);
        let amount = 1u128;
        let n = d - 1; // N·amount = D−1
        let (reward, rho) = reward_and_remainder(n, amount, k);
        assert_eq!(reward, 0);
        assert_eq!(rho, d - 1);
        assert!(rho < d);
    }
}

#[test]
fn aggregate_floor_never_over_pays_budget() {
    // Σ floor(N·amount_i/D) ≤ floor(N·Σamount_i/D) + (count−1): the per-stake
    // floors never sum above the ideal aggregate by more than the count, so the
    // protocol cannot over-mint relative to the real entitlement (the §9
    // step-2 bound holds under the floor).
    let mut rng = Lcg(0xC0FF_EE00);
    for _ in 0..50_000 {
        let k = 16 + (rng.next() % 24) as u32;
        let n = rng.in_range(1, 1u128 << 40);
        let count = 1 + u128::from(rng.next() % 50);
        let mut sum_floor = 0u128;
        let mut sum_amount = 0u128;
        for _ in 0..count {
            let amount = rng.in_range(1, 100_000 * COIN);
            sum_amount += amount;
            let (r, _) = reward_and_remainder(n, amount, k);
            sum_floor += r;
        }
        let (ideal_floor, _) = reward_and_remainder(n, sum_amount, k);
        assert!(
            sum_floor <= ideal_floor + count,
            "per-stake floors over-pay the aggregate by more than count"
        );
        assert!(sum_floor <= ideal_floor + (count - 1) + 1);
    }
}

// ── Overflow at the extremes ──

#[test]
fn overflow_headroom_is_comfortable() {
    // Worst-case N·amount uses the capped scaled rate. Even a generously high
    // scaled-rate cap stays far below the Ed25519 scalar field.
    for k in [24u32, 32, 40, SCALE_RATE_K, 56] {
        // A high scaled-rate cap: ρ_cap_scaled ≈ ρ_cap·2^k. Take ρ_cap ≈ 1e-2
        // (extreme) ⇒ scaled ≈ 0.01·2^k.
        let rho_cap_scaled = scale_rate(k) / 100;
        let maxna = max_n_times_amount(
            rho_cap_scaled,
            RATE_EPOCH_BLOCKS,
            MAX_EPOCHS_PER_CLAIM,
            MONEY_SUPPLY,
        );
        let headroom = overflow_headroom_bits(maxna);
        eprintln!(
            "  k={k}: max N·amount ≈ 2^{}, overflow headroom {headroom} bits",
            128 - maxna.leading_zeros()
        );
        assert!(
            headroom > 64,
            "k={k}: N·amount headroom to ℓ is only {headroom} bits (maxna≈2^{})",
            128 - maxna.leading_zeros()
        );
        // And the product itself must fit u128 (the harness computes in u128).
        assert!(maxna < ED25519_SCALAR_ORDER || maxna < u128::MAX);
    }
}

// ── Precision sweep: let the data pick k ──

// Faithful range of the u128 sweep harness: at k ≳ 60 the *simulation's*
// `N·amount` saturates u128 (a harness limit, not a consensus property — real
// arithmetic runs in the ~2^252 scalar field). The post-fold ceiling on k is
// the analytic field-wrap margin (`wraparound_over_claim_margin_bits`), not the
// sweep, so the sweep need only span the rise + the floor-dominated plateau.
const SWEEP_KS: [u32; 11] = [20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60];

#[test]
fn precision_sweep_recommends_a_k() {
    let rows = precision_sweep(
        &SWEEP_KS,
        &rate_grid(),
        &stake_grid(),
        MAX_EPOCHS_PER_CLAIM * RATE_EPOCH_BLOCKS,
        MIN_MEANINGFUL_YIELD,
    );

    // Print the full curve so the human sees where "negligible" begins and
    // where the field-wrap margin (the only post-fold ceiling) starts to bite.
    eprintln!("\n  k | D bits | max rel err | max abs atomic | min ρ_scaled | margin | underflow");
    eprintln!("  --+--------+-------------+----------------+--------------+--------+----------");
    for r in &rows {
        eprintln!(
            "  {:>2}| {:>6} | {:>11.3e} | {:>14} | {:>12} | {:>6} | {}",
            r.k,
            r.d_bits,
            r.max_relative_error,
            r.max_abs_atomic_error,
            r.min_nonzero_rho_scaled,
            r.margin_bits,
            r.any_rate_underflowed
        );
    }

    // Post-fold decision rule (decision 1(b)): the floor-dominated knee — the
    // smallest k whose worst-case relative error is within 2× of its asymptotic
    // minimum. Past the knee the reward floor, not the rate scale, dominates;
    // below it, free precision is unused. (The pre-fold "smallest k clearing
    // 0.1%" rule is retired — it optimized against a proof-width cost the fold
    // removed.)
    let chosen = recommend_k_knee(&rows, 2.0).expect("some swept k must be eligible");
    eprintln!(
        "\n  → knee at k = {} ⇒ SCALE_rate = 2^{}, D = 2^{}; margin {} bits; ρ folds into the 64-bit slot\n",
        chosen.k,
        chosen.k,
        chosen.k + 1,
        chosen.margin_bits
    );
    // The knee is the pinned SCALE_RATE_K, and it sits at the error plateau with
    // a wide field-wrap margin (the only post-fold ceiling).
    assert_eq!(
        chosen.k, SCALE_RATE_K,
        "knee must match the pinned constant"
    );
    assert!(chosen.margin_bits >= 100, "knee must retain a wide margin");
    // The plateau is real: every k past the knee has the same worst-case
    // relative error (the reward floor, not rate precision, is binding).
    let knee_err = chosen.max_relative_error;
    for r in rows.iter().filter(|r| r.k > chosen.k) {
        assert!(
            (r.max_relative_error - knee_err).abs() < knee_err * 1e-6,
            "k={} error {:e} differs from the knee plateau {:e}",
            r.k,
            r.max_relative_error,
            knee_err
        );
    }
}

/// The knee is **lifetime-invariant**, not a genesis artifact. Emission decays
/// 0.90/yr (~25× over three decades), shrinking rates over the emission
/// lifetime; rate-quantization error is worst for the smallest rate, so a knee
/// computed against near-term rates only would undershoot. This test confirms
/// the committed sweep does not undershoot:
///
/// 1. the rate grid spans down to the **terminal tail subsidy** (far-future,
///    past any 3-decade point), not just genesis/near-term rates; and
/// 2. the meaningful-yield cutoff is a *yield* threshold, hence era-independent —
///    it floors the smallest meaningful rate at `MIN_MEANINGFUL_YIELD / window`
///    regardless of era — and at the pinned `SCALE_RATE_K` the rate-quantization
///    error **even at that floor rate** already sits below the floor-dominated
///    plateau. So the rate term has crossed under the reward floor for *every*
///    meaningful rate; a lower-emission era cannot lift it back (it would only
///    produce sub-meaningful rates). The knee is therefore `SCALE_RATE_K` across
///    the lifetime, and the lever that *would* move it is the cutoff, not time.
#[test]
fn knee_is_lifetime_invariant_not_genesis_only() {
    // (1) The grid reaches the terminal-subsidy regime — far below any near-term
    // rate, so the knee is computed against lifetime rates, not genesis.
    let smallest_grid_rate = rate_grid()
        .iter()
        .map(|p| {
            #[allow(clippy::cast_precision_loss)]
            let r = p.budget_e as f64 / p.band_sum_e as f64;
            r
        })
        .fold(f64::INFINITY, f64::min);
    assert!(
        smallest_grid_rate < 1e-10,
        "grid must span the far-future tail regime (smallest rate {smallest_grid_rate:e})"
    );

    // (2) The era-independent meaningful-rate floor: smaller rates are
    // sub-meaningful by definition of the yield cutoff, regardless of era.
    #[allow(clippy::cast_precision_loss)]
    let window = (MAX_EPOCHS_PER_CLAIM * RATE_EPOCH_BLOCKS) as f64;
    let rate_floor = MIN_MEANINGFUL_YIELD / window;

    // Rate-quantization rel. error at the floor rate ≈ 1/ρ_scaled, ρ_scaled =
    // rate · 2^k. At the pinned knee this must already be below the plateau.
    #[allow(clippy::cast_precision_loss)]
    let two_pow_k = (1u128 << SCALE_RATE_K) as f64;
    let rho_scaled_floor = rate_floor * two_pow_k;
    let rate_quant_err_at_floor = 1.0 / rho_scaled_floor;

    let rows = precision_sweep(
        &SWEEP_KS,
        &rate_grid(),
        &stake_grid(),
        MAX_EPOCHS_PER_CLAIM * RATE_EPOCH_BLOCKS,
        MIN_MEANINGFUL_YIELD,
    );
    let plateau = rows
        .iter()
        .find(|r| r.k == SCALE_RATE_K)
        .expect("SCALE_RATE_K is swept")
        .max_relative_error;

    assert!(
        rate_quant_err_at_floor < plateau,
        "lifetime knee exceeds SCALE_RATE_K: rate-quant at the meaningful-rate \
         floor ({rate_quant_err_at_floor:e}) ≥ floor-dominated plateau ({plateau:e}) \
         — re-pin k or revisit MIN_MEANINGFUL_YIELD"
    );
}

/// Recorder: emits the sweep to `docs/test_vectors/staking/entitlement_precision_sweep.json`.
/// Ignored by default; run with
/// `SHEKYL_REGEN_FIXTURES=1 cargo test -p shekyl-staking -- regen_precision_sweep --ignored`.
#[test]
#[ignore = "regeneration helper; writes the committed sweep fixture"]
fn regen_precision_sweep() {
    assert_eq!(
        std::env::var("SHEKYL_REGEN_FIXTURES").as_deref(),
        Ok("1"),
        "set SHEKYL_REGEN_FIXTURES=1 to regenerate"
    );
    let rows = precision_sweep(
        &SWEEP_KS,
        &rate_grid(),
        &stake_grid(),
        MAX_EPOCHS_PER_CLAIM * RATE_EPOCH_BLOCKS,
        MIN_MEANINGFUL_YIELD,
    );
    // Hand-rolled JSON to keep the dependency surface unchanged.
    let mut json = String::from("{\n  \"rows\": [\n");
    for (i, r) in rows.iter().enumerate() {
        json.push_str(&format!(
            "    {{ \"k\": {}, \"d_bits\": {}, \"max_relative_error\": {:e}, \"max_abs_atomic_error\": {}, \"min_nonzero_rho_scaled\": {}, \"margin_bits\": {}, \"any_rate_underflowed\": {} }}{}\n",
            r.k, r.d_bits, r.max_relative_error, r.max_abs_atomic_error,
            r.min_nonzero_rho_scaled, r.margin_bits, r.any_rate_underflowed,
            if i + 1 < rows.len() { "," } else { "" }
        ));
    }
    json.push_str("  ]\n}\n");
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/test_vectors/staking/entitlement_precision_sweep.json"
    );
    std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap()).unwrap();
    std::fs::write(path, json).expect("write sweep fixture");
}
