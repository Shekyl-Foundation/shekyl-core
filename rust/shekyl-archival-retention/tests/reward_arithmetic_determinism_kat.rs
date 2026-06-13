//! Cross-implementation / cross-arch determinism KAT for the integer reward
//! arithmetic (`REWARD_EMISSION_VIN_PLAN.md` M-1 half (b); verdict in
//! `ARCHIVAL_SIM_ECONOMICS_VERDICT.md` §"PR 1.5").
//!
//! ## Why this exists
//!
//! The emission-vin verify (`REWARD_EMISSION_VIN_PLAN.md` §5.4) compares a
//! consensus-side recompute against the wallet-built `reward_amount_plain` at
//! **zero tolerance**. That compare is only safe if every implementation, on
//! every architecture, produces **bit-identical** integer values. This file
//! pins those values to golden fixtures.
//!
//! ## Determinism contract
//!
//! `reward_arithmetic` is pure fixed-width integer arithmetic: `u64` operands,
//! `u128` intermediates in `mul_div_floor`, no `usize`/`isize`, and
//! `#![deny(clippy::float_arithmetic)]` forbids floating point. Rust defines the
//! result of every fixed-width integer operation (`+`, `*`, `/`, `saturating_*`,
//! `u64::try_from`) identically on all target architectures, so cross-arch
//! bit-identity holds **by construction**. These golden vectors are the
//! *regression guard*: any future change to operation order (e.g. the
//! u128-before-divide order in `mul_div_floor`), operand width, or an accidental
//! float/`usize` introduction changes a pinned value and fails here. Run in CI on
//! both `x86_64` and `aarch64` so an arch-divergent change is caught on the
//! second target as well as on the primary.
//!
//! This supersedes the earlier same-arch in-process double-call of `curve_milli`,
//! which exercised neither a second arch nor the Form-C division path.

use shekyl_archival_retention::reward_arithmetic::{
    curve_milli, g_age_milli, mul_div_floor, reward_share_floor, scarcity_milli, BandedCurveParams,
    WORK_MILLI_SCALE,
};

#[test]
fn scale_is_frozen_at_milli() {
    // The fixed-point scale the zero-tolerance compare runs in. Mirror of the
    // in-crate compile-time guard; here as a runtime golden so a build that
    // somehow changed it still fails the KAT.
    assert_eq!(WORK_MILLI_SCALE, 1_000);
}

#[test]
fn mul_div_floor_pins_u128_before_divide_order() {
    // floor(a*b/d) via u128. The order is consensus-determining: computing
    // (a/d)*b instead would floor early and diverge. (7/4)*3 = 3, but the
    // pinned u128-before-divide answer is floor(21/4) = 5.
    assert_eq!(mul_div_floor(7, 3, 4), Some(5));
    assert_eq!(mul_div_floor(1_000, 500, 1_000), Some(500));
    assert_eq!(mul_div_floor(1_000_000, 8_000, 24_000), Some(333_333));

    // d == 0 is a None, never a panic or a wrap.
    assert_eq!(mul_div_floor(5, 5, 0), None);

    // High-value vector: the u64 product a*b would overflow (8e22 >> u64::MAX),
    // so a correct result *requires* the u128 intermediate. The quotient fits
    // u64. This is the F-E8 / R1.B width discipline, pinned.
    assert_eq!(
        mul_div_floor(10_000_000_000_000_000_000, 8_000, 24_000),
        Some(3_333_333_333_333_333_333)
    );

    // Quotient that overflows u64 is a None (caller decides the fallback), never
    // a silent truncation.
    assert_eq!(mul_div_floor(u64::MAX, 2, 1), None);
}

#[test]
fn g_age_milli_golden() {
    // g(age) = 1 + age_weight·age, in milli, spanning [1000, 1000+age_weight].
    assert_eq!(g_age_milli(0, 2_000), 1_000); // age 0   -> 1.0
    assert_eq!(g_age_milli(500, 2_000), 2_000); // age 0.5 -> 2.0
    assert_eq!(g_age_milli(1_000, 2_000), 3_000); // age 1.0 -> 3.0
    assert_eq!(g_age_milli(500, 1_500), 1_750); // band-lo edge
    assert_eq!(g_age_milli(333, 2_000), 1_666); // floor of 666.0
}

#[test]
fn scarcity_milli_golden() {
    // scarcity = floor(g(age) / r_market), in milli.
    assert_eq!(scarcity_milli(0, 1_000, 2_000), 0); // r=0 dead
    assert_eq!(scarcity_milli(1, 1_000, 2_000), 3_000);
    assert_eq!(scarcity_milli(2, 1_000, 2_000), 1_500);
    assert_eq!(scarcity_milli(3, 500, 2_000), 666); // floor(2000/3)
    assert_eq!(scarcity_milli(7, 333, 1_500), 214); // floor(1499/7)
}

#[test]
fn curve_milli_golden_banded_pl() {
    // Default provisional: plateau_value 8000, plateau_work 16000,
    // breakpoints b1=4000 (slope 1.0), b2=8000 (slope 0.5), b3=16000 (slope 0.25).
    let p = BandedCurveParams::default_provisional();
    assert_eq!(curve_milli(0, &p), 0); // zero work
    assert_eq!(curve_milli(2_000, &p), 2_000); // seg 1, slope 1.0
    assert_eq!(curve_milli(4_000, &p), 4_000); // b1 boundary
    assert_eq!(curve_milli(6_000, &p), 5_000); // seg 2, slope 0.5
    assert_eq!(curve_milli(8_000, &p), 6_000); // b2 boundary
    assert_eq!(curve_milli(10_000, &p), 6_500); // seg 3, slope 0.25
    assert_eq!(curve_milli(12_000, &p), 7_000);
    assert_eq!(curve_milli(16_000, &p), 8_000); // plateau
    assert_eq!(curve_milli(32_000, &p), 8_000); // past plateau

    // Degenerate zero-plateau curve credits zero (not uncapped pass-through).
    let p0 = BandedCurveParams::from_sim_cap_milli(0);
    assert_eq!(curve_milli(5_000, &p0), 0);
}

#[test]
fn reward_share_floor_golden() {
    // floor(budget·capped / sigma); dust stays unminted.
    assert_eq!(reward_share_floor(1_000_000, 8_000, 8_000), 1_000_000); // sole claimer
    assert_eq!(reward_share_floor(1_000, 1_000, 3_000), 333); // 1 of 3 equal
    assert_eq!(reward_share_floor(1_000, 0, 3_000), 0); // zero capped
    assert_eq!(reward_share_floor(1_000, 1_000, 0), 0); // zero denominator

    // High-value vector forcing the u128 path (budget·capped overflows u64).
    assert_eq!(
        reward_share_floor(10_000_000_000_000_000_000, 8_000, 24_000),
        3_333_333_333_333_333_333
    );
}

#[test]
fn reward_share_floor_conserves_supply_with_burned_dust() {
    // R1.B / REWARD_EMISSION_LEG.md §4.0: Σ minted ≤ budget, with the remainder
    // (≤ N_P − 1 atomic units) unminted ("burn the dust"). Pin the property a
    // cohort of equal claimers exhibits: the floor never over-mints, and the
    // shortfall is strictly below the claimer count.
    for n in [2u64, 3, 7, 25, 100] {
        let budget = 1_000_000u64;
        // Equal claimers: each capped term is the same, denominator is n·capped.
        let capped = 8_000u64;
        let sigma = capped * n;
        let per = reward_share_floor(budget, capped, sigma);
        let minted = per * n;
        assert!(minted <= budget, "n={n}: minted {minted} > budget {budget}");
        let dust = budget - minted;
        assert!(dust < n, "n={n}: dust {dust} must be < claimer count {n}");
    }
}
