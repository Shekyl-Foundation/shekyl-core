// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The read plan's bounds (§5.3). Every test names the edit that turns it
//! red.

use rand::rngs::StdRng;
use rand::SeedableRng;

use super::*;

const W2: BlockCount = BlockCount::from_raw(500);

/// At most `K` attempts, consecutive ones at least the spacing apart, all
/// inside `(h, h + W₂ − M]`, over many daemon RNGs. Red edit: draw each
/// attempt from the whole window — the spacing assertion fails.
#[test]
fn a_plan_is_at_most_k_reads_spaced_inside_the_window() {
    let h = BlockHeight::from_raw(20_000);
    let last = h + W2 - FILING_MARGIN;
    for seed in 0..500u64 {
        let plan = ReadPlan::draw(&mut StdRng::seed_from_u64(seed), h, W2);
        let heights = plan.heights();
        assert_eq!(heights.len(), usize::from(CHALLENGE_READS), "seed {seed}");
        assert!(
            heights.iter().all(|&at| at > h && at <= last),
            "seed {seed}: {heights:?}"
        );
        for pair in heights.windows(2) {
            assert!(
                pair[1] >= pair[0] + READ_SPACING,
                "seed {seed}: {heights:?}"
            );
        }
        assert_eq!(plan.at(CHALLENGE_READS), None);
    }
}

/// The plan is drawn from the daemon's RNG and not from anything public:
/// two daemons with different randomness plan one block differently. Red
/// edit: seed the plan's RNG from `h` — the two plans are equal.
#[test]
fn a_plan_is_the_daemons_own_randomness() {
    let h = BlockHeight::from_raw(20_000);
    let a = ReadPlan::draw(&mut StdRng::seed_from_u64(1), h, W2);
    let b = ReadPlan::draw(&mut StdRng::seed_from_u64(2), h, W2);
    assert_ne!(a, b);
}

/// A window too short for `K` spaced reads plans fewer, and one too short
/// for any read past `h` still reads once, at `h + 1`. Red edit: plan `K`
/// regardless — the short window's plan breaks the spacing.
#[test]
fn a_short_window_plans_fewer_reads() {
    let h = BlockHeight::from_raw(100);
    // `W₂ − M = 40`: two reads fit at a spacing of 30.
    let two = ReadPlan::draw(&mut StdRng::seed_from_u64(3), h, BlockCount::from_raw(70));
    assert_eq!(two.heights().len(), 2);
    assert!(two.heights()[1] >= two.heights()[0] + READ_SPACING);
    assert!(two.heights()[1] <= h + BlockCount::from_raw(40));

    let none = ReadPlan::draw(&mut StdRng::seed_from_u64(4), h, BlockCount::from_raw(20));
    assert_eq!(none.heights(), &[h + BlockCount::ONE]);
}
