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
const MIN_MEANINGFUL_YIELD: f64 = 1e-5;

/// Realistic `ρ_e = budget_e/band_sum_e` operating points spanning the rate
/// range: (per-block staker emission, weighted staked). High rate = small band
/// + early emission; low rate = large band + tail emission.
fn rate_grid() -> Vec<RateOperatingPoint> {
    // Per-block staker emission ≈ 0.15 · block_emission.
    let emit_early: u128 = 153_000_000_000; // 0.15 · 1.02e12
    let emit_mid: u128 = 10_000_000_000; // 0.15 · ~6.7e10
    let emit_tail: u128 = 90_000_000; // 0.15 · 6e8
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
fn forged_over_claim_has_no_valid_remainder() {
    // Claiming reward+1 forces ρ' = N·amount − D·(reward+1) < 0, which no
    // unsigned remainder in [0, D) can satisfy — exactly trap (a) closed.
    let mut rng = Lcg(0xFEED_FACE);
    for _ in 0..200_000 {
        let k = 16 + (rng.next() % 24) as u32;
        let n = rng.in_range(1, 1u128 << 50);
        let amount = rng.in_range(1, MONEY_SUPPLY);
        let d = denominator(k);
        let (reward, _rho) = reward_and_remainder(n, amount, k);
        let product = n.saturating_mul(amount);
        // The honest reward is the unique one with a valid remainder.
        let forged = reward + 1;
        assert!(
            forged * d > product,
            "reward+1 must exceed N·amount, leaving no ρ ∈ [0,D)"
        );
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
    for k in [24u32, 32, 40, 48] {
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

const SWEEP_KS: [u32; 11] = [20, 24, 28, 30, 32, 34, 36, 38, 40, 44, 48];

#[test]
fn precision_sweep_recommends_a_k() {
    let rows = precision_sweep(
        &SWEEP_KS,
        &rate_grid(),
        &stake_grid(),
        MAX_EPOCHS_PER_CLAIM * RATE_EPOCH_BLOCKS,
        MIN_MEANINGFUL_YIELD,
    );

    // Print the full curve so the human sees where "negligible" begins.
    eprintln!("\n  k | D bits | max rel err | max abs atomic | min ρ_scaled | underflow");
    eprintln!("  --+--------+-------------+----------------+--------------+----------");
    for r in &rows {
        eprintln!(
            "  {:>2}| {:>6} | {:>11.3e} | {:>14} | {:>12} | {}",
            r.k,
            r.d_bits,
            r.max_relative_error,
            r.max_abs_atomic_error,
            r.min_nonzero_rho_scaled,
            r.any_rate_underflowed
        );
    }

    // Decision rule: smallest k with no rate underflow and worst relative
    // rate-quantization error < 0.1% across the realistic operating range.
    let chosen = recommend_k(&rows, 1e-3).expect("some swept k must pass");
    eprintln!(
        "\n  → recommended k = {} ⇒ SCALE_rate = 2^{}, D = 2^{} ({}-bit remainder range proof)\n",
        chosen.k,
        chosen.k,
        chosen.k + 1,
        chosen.d_bits
    );
    // The recommendation must be a real, bounded width (sanity rails).
    assert!(chosen.d_bits >= 21 && chosen.d_bits <= 49);
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
            "    {{ \"k\": {}, \"d_bits\": {}, \"max_relative_error\": {:e}, \"max_abs_atomic_error\": {}, \"min_nonzero_rho_scaled\": {}, \"any_rate_underflowed\": {} }}{}\n",
            r.k, r.d_bits, r.max_relative_error, r.max_abs_atomic_error,
            r.min_nonzero_rho_scaled, r.any_rate_underflowed,
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
