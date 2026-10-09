// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-G6 / G6b — the medians held at their boundaries, the early-chain
//! arm pinned deliberately, the C++'s median definition, and the verdict
//! carrying what the validator computed.

use super::*;
use crate::census::CenRow;
use crate::fault::{FormAttempt, PerHeightRecord};
use crate::harness::fixture::{candidate_on, chain_of, recorded, spendable_chain};
use crate::harness::{
    defined, expected_seed, judged, Faulted, FaultingView, MockChain, MockSubstrate, WithheldRead,
};
use crate::rule_set::RuleSet;
use crate::trust::Trust;
use crate::validate::{form, validate};
use shekyl_economics::BLOCK_WEIGHT_SURGE_FACTOR;
use shekyl_types::CurveTreeRoot;

const ZONE: u64 = FULL_REWARD_ZONE;
const S: u64 = BLOCK_WEIGHT_SURGE_FACTOR;

fn rw(weight: u64, long_term: u64) -> RecordedWeights {
    RecordedWeights {
        weight: BlockWeight::from_raw(weight),
        long_term_weight: LongTermWeight::from_raw(long_term),
    }
}

/// `n` rows all recording `(weight, long_term)`.
fn uniform(n: usize, weight: u64, long_term: u64) -> Vec<RecordedWeights> {
    vec![rw(weight, long_term); n]
}

fn ltem(m: &EffectiveMedian) -> u64 {
    m.long_term_effective_median.to_raw()
}

fn eff(m: &EffectiveMedian) -> u64 {
    m.effective_median.to_raw()
}

// ---------------------------------------------------------------------------
// The C++'s median
// ---------------------------------------------------------------------------

/// The reference: sort, then the C++'s two arms, written the slow way.
fn sorted_reference(values: &[u64]) -> u64 {
    let mut v = values.to_vec();
    v.sort_unstable();
    match v.len() {
        0 => 0,
        n if n % 2 == 1 => v[n / 2],
        n => {
            let (a, b) = (v[n / 2 - 1], v[n / 2]);
            a / 2 + b / 2 + (a % 2 + b % 2) / 2
        }
    }
}

#[test]
fn the_median_of_nothing_is_zero_and_of_one_is_itself() {
    assert_eq!(cxx_median(&mut []), 0);
    assert_eq!(cxx_median(&mut [7]), 7);
}

#[test]
fn an_odd_count_takes_the_middle_element() {
    assert_eq!(cxx_median(&mut [5, 1, 9]), 5);
    assert_eq!(cxx_median(&mut [4, 4, 1, 9, 9]), 4);
}

/// The arm that separates the C++'s median from "the lower middle": an
/// even count is the floor of the two middle elements' mean — `[1, 2]`
/// is `1`, `[2, 3]` is `2`, `[1, 4]` is `2`, and two odd middles round
/// down together.
#[test]
fn an_even_count_is_the_floored_mean_of_the_two_middle_elements() {
    assert_eq!(cxx_median(&mut [2, 1]), 1);
    assert_eq!(cxx_median(&mut [3, 2]), 2);
    assert_eq!(cxx_median(&mut [4, 1]), 2);
    assert_eq!(cxx_median(&mut [3, 3, 9, 0]), 3);
    assert_eq!(cxx_median(&mut [1, 3, 5, 7]), 4);
    assert_eq!(cxx_median(&mut [1, 3, 5, 8]), 4);
}

/// `get_mid` without the sum: two weights near `u64::MAX` do not wrap
/// into a small median (a wrapped median would clamp *down* and refuse
/// legal blocks).
#[test]
fn the_even_arm_does_not_overflow_near_u64_max() {
    assert_eq!(cxx_median(&mut [u64::MAX, u64::MAX - 1]), u64::MAX - 1);
    assert_eq!(cxx_median(&mut [u64::MAX, u64::MAX]), u64::MAX);
    assert_eq!(cxx_median(&mut [u64::MAX - 2, u64::MAX]), u64::MAX - 1);
}

/// The selection form against the sort form over both parities, with
/// duplicates and a skewed distribution — a deterministic LCG, not a
/// seedless random, so a failure names its input.
#[test]
fn the_selection_median_matches_the_sorted_reference() {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        // Skewed: mostly small values with the occasional very large one,
        // and plenty of duplicates from the `% 7` arm.
        match (state >> 60) & 0b11 {
            0 => state % 7,
            1 => u64::MAX - (state % 3),
            _ => (state >> 20) % 1_000_003,
        }
    };
    for len in 0..=257usize {
        let values: Vec<u64> = (0..len).map(|_| next()).collect();
        let mut scratch = values.clone();
        assert_eq!(
            cxx_median(&mut scratch),
            sorted_reference(&values),
            "len {len}: {values:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The medians at their boundaries (pure, over a window)
// ---------------------------------------------------------------------------

#[test]
fn an_empty_window_yields_the_zone_twice() {
    let m = medians_over(&[]);
    assert_eq!(ltem(&m), ZONE);
    assert_eq!(eff(&m), ZONE);
    assert_eq!(m.limit().to_raw(), 2 * ZONE);
}

/// The long-term floor: a median exactly at the zone and one under both
/// read as the zone; one over reads as itself.
#[test]
fn the_long_term_median_is_floored_at_the_zone() {
    assert_eq!(ltem(&medians_over(&uniform(5, 1, ZONE))), ZONE);
    assert_eq!(ltem(&medians_over(&uniform(5, 1, ZONE - 1))), ZONE);
    assert_eq!(ltem(&medians_over(&uniform(5, 1, ZONE + 1))), ZONE + 1);
}

/// The effective median's upper clamp at `S · LTEM`: exactly at the
/// ceiling passes through, one over is the ceiling.
#[test]
fn the_effective_median_is_clamped_at_s_times_the_long_term_median() {
    let ltem_value = ZONE + 1_000;
    let at_ceiling = medians_over(&uniform(5, S * ltem_value, ltem_value));
    assert_eq!(eff(&at_ceiling), S * ltem_value);
    let one_over = medians_over(&uniform(5, S * ltem_value + 1, ltem_value));
    assert_eq!(eff(&one_over), S * ltem_value);
    let one_under = medians_over(&uniform(5, S * ltem_value - 1, ltem_value));
    assert_eq!(eff(&one_under), S * ltem_value - 1);
}

/// The effective median's lower clamp at `LTEM`: a short-term median
/// below it reads as `LTEM`; exactly at it, `LTEM`; one over, itself.
#[test]
fn the_effective_median_is_floored_at_the_long_term_median() {
    let ltem_value = ZONE + 1_000;
    assert_eq!(eff(&medians_over(&uniform(5, 1, ltem_value))), ltem_value);
    assert_eq!(
        eff(&medians_over(&uniform(5, ltem_value, ltem_value))),
        ltem_value
    );
    assert_eq!(
        eff(&medians_over(&uniform(5, ltem_value + 1, ltem_value))),
        ltem_value + 1
    );
}

/// The C++ floors the clamped median at the zone a second time
/// (`blockchain.cpp:6096`); with `LTEM ≥ zone` the lower clamp already
/// holds it. Held so the redundancy stays a fact and not an assumption.
#[test]
fn the_effective_median_never_reads_below_the_zone() {
    let m = medians_over(&uniform(5, 1, 1));
    assert_eq!(ltem(&m), ZONE);
    assert_eq!(eff(&m), ZONE);
}

/// The short window is the long window's **suffix** of exactly `W_short`
/// rows. Old rows carry enormous weights (they would blow the short-term
/// median to the ceiling if read); the last `W_short` rows are half at
/// `LTEM + 5` and half at `LTEM + 50`, so the even-count median is their
/// floored mean, `LTEM + 27` — a value neither half carries, and one that
/// a suffix one row longer (an odd count, one huge row in, middle at the
/// upper half) or one row shorter (one small row out, middle at the upper
/// half) would both read as `LTEM + 50`. The mean is the witness that the
/// count is exactly even at `W_short`.
#[test]
fn the_short_term_median_reads_exactly_the_last_short_window_rows() {
    let short = usize::try_from(BLOCK_WEIGHT_SHORT_TERM_WINDOW).expect("fits");
    assert_eq!(
        short % 2,
        0,
        "the discriminator below assumes an even window"
    );
    let ltem_value = ZONE + 1_000;
    let mut window = uniform(short * 3, u64::MAX / 2, ltem_value);
    window.extend(uniform(short / 2, ltem_value + 5, ltem_value));
    window.extend(uniform(short / 2, ltem_value + 50, ltem_value));
    assert_eq!(eff(&medians_over(&window)), ltem_value + 27);
}

#[test]
fn the_limit_is_twice_the_effective_median_and_saturates() {
    let m = EffectiveMedian {
        long_term_effective_median: LongTermWeight::from_raw(ZONE),
        effective_median: BlockWeight::from_raw(ZONE + 7),
    };
    assert_eq!(m.limit().to_raw(), 2 * (ZONE + 7));
    let huge = EffectiveMedian {
        long_term_effective_median: LongTermWeight::from_raw(u64::MAX),
        effective_median: BlockWeight::from_raw(u64::MAX - 1),
    };
    assert_eq!(huge.limit().to_raw(), u64::MAX);
}

// ---------------------------------------------------------------------------
// The early-chain arm, pinned deliberately (C2-R2 Q2)
// ---------------------------------------------------------------------------

/// Below `W_long` the window **is** the chain: every block since genesis
/// is in the long-term median, and nothing has aged out. Held two ways on
/// a seven-block chain — the regime every test chain, and the chain's
/// first ~139 days, sit in: (i) moving **block 0's** recorded long-term
/// weight moves the median (on a chain past `W_long` it would have aged
/// out and could not); (ii) the read asks for the whole `W_long` and the
/// view cuts to `min(W_long, h)` — the store's conformance test holds
/// that cut (`at_most > end` yields exactly `end` rows), so the arm is the
/// view contract's, and this test names which one.
#[test]
fn the_long_window_is_the_chain_below_its_length() {
    let heavy = ZONE + 10_000;
    let light = ZONE + 100;
    // Six heavy blocks after a light genesis: the median of seven is the
    // fourth-smallest, heavy.
    let chain = (0..7u64).fold(MockChain::default(), |chain, h| {
        let lt = if h == 0 { light } else { heavy };
        chain.push_weighing(recorded(1_000 + h * 120), CurveTreeRoot::EMPTY, rw(lt, lt))
    });
    let seven =
        chain.with_view(|view| defined(effective_median_at(&view, BlockHeight::from_raw(7))));
    assert_eq!(ltem(&seven), heavy);
    // Make four of them light — the median flips; block 0 is one of the
    // four, so its weight is in the median: nothing aged out.
    let chain = (0..7u64).fold(MockChain::default(), |chain, h| {
        let lt = if h < 4 { light } else { heavy };
        chain.push_weighing(recorded(1_000 + h * 120), CurveTreeRoot::EMPTY, rw(lt, lt))
    });
    let flipped =
        chain.with_view(|view| defined(effective_median_at(&view, BlockHeight::from_raw(7))));
    assert_eq!(ltem(&flipped), light);
    // (ii) the definition asks the view for the full long window; the cut
    // to `min(W_long, h)` is the view's. A view that counted the asks
    // would see `at_most == W_long` — pinned here by the mock returning
    // exactly `h` rows for `h < W_long`, the contract the store's
    // conformance test holds against `BatchView`.
    let asked = chain.with_view(|view| {
        match view
            .weights_window(
                BlockHeight::from_raw(7),
                BlockCount::from_raw(BLOCK_WEIGHT_LONG_TERM_WINDOW),
            )
            .expect("infallible")
        {
            AtHeight::Recorded(rows) => rows.len(),
            AtHeight::AboveTip => panic!("seven blocks are recorded"),
        }
    });
    assert_eq!(asked, 7);
    const { assert!(7 < BLOCK_WEIGHT_LONG_TERM_WINDOW) };
}

/// The regime every fixture chain sits in, stated as a pin rather than
/// left implicit: a young, light chain's long-term median is **the zone**
/// — the floor arm, not a computed median — and its effective median is
/// the zone too. Every `chain_of(n)` fixture in this crate reads these
/// values; a test that believes it exercised the clamps on one of them
/// exercised the floor.
#[test]
fn a_young_light_chain_reads_the_zone_on_both_medians() {
    let chain = chain_of(12);
    let m = chain.with_view(|view| defined(effective_median_at(&view, BlockHeight::from_raw(12))));
    assert_eq!(ltem(&m), ZONE);
    assert_eq!(eff(&m), ZONE);
    assert_eq!(m.limit().to_raw(), 2 * ZONE);
}

#[test]
fn at_genesis_both_medians_are_the_zone() {
    let chain = MockChain::default();
    let m = chain.with_view(|view| defined(effective_median_at(&view, BlockHeight::ZERO)));
    assert_eq!(ltem(&m), ZONE);
    assert_eq!(eff(&m), ZONE);
}

// ---------------------------------------------------------------------------
// The verdict carries the weights (G6b)
// ---------------------------------------------------------------------------

fn validated_on(chain: &MockChain, candidate: Candidate) -> Weights {
    let formed = match form(
        candidate,
        &RuleSet::GENESIS,
        &MockSubstrate::default(),
        expected_seed(chain),
        FormAttempt::FIRST,
    ) {
        Ok(Ok(formed)) => formed,
        Ok(Err(refused)) => panic!("the fixture must form: {refused}"),
        Err(Faulted) => unreachable!("the default MockSubstrate never faults"),
    };
    chain.with_view(|view| {
        let valid = judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("the fixture must validate");
        assert!(valid.coverage().contains(CenRow::G6), "G6 recorded");
        assert!(valid.coverage().contains(CenRow::G6b), "G6b recorded");
        *valid.block().weights()
    })
}

/// The long-term weight is the block's weight clamped to
/// `[LTEM · 10/17, LTEM · 1.7]` — here the lower arm, since a fixture block
/// is far lighter than the zone's `10/17`. The block is coinbase-only, the
/// one a `MockChain` can hold (a fixture spend is refused at CEN-I13 on
/// any view; slice 6 row 6); that a listed body is the weight's addend is
/// witnessed where a listed body can exist — `shekyl-chain-ingest`'s
/// `scenario_spend_tests` reads `Mined::weights` against the bodies, and
/// the store's `conformance_tests` records the verdict's figure.
#[test]
fn the_verdict_carries_the_weight_and_its_long_term_clamp() {
    let chain = spendable_chain();
    let candidate = candidate_on(&chain, Vec::new());
    let expected_weight = candidate.block.miner_transaction.weight();
    let weights = validated_on(&chain, candidate);
    assert_eq!(
        weights.weight.to_raw(),
        u64::try_from(expected_weight).expect("fits")
    );
    assert_eq!(ltem(&weights.medians), ZONE);
    assert_eq!(eff(&weights.medians), ZONE);
    assert_eq!(weights.long_term_weight.to_raw(), ZONE * 10 / 17);
    assert!(weights.weight.to_raw() < ZONE * 10 / 17);
}

#[test]
fn a_coinbase_only_block_weighs_its_coinbase() {
    let chain = chain_of(3);
    let candidate = candidate_on(&chain, Vec::new());
    let expected = candidate.block.miner_transaction.weight();
    let weights = validated_on(&chain, candidate);
    assert_eq!(
        weights.weight.to_raw(),
        u64::try_from(expected).expect("fits")
    );
}

// ---------------------------------------------------------------------------
// Faults
// ---------------------------------------------------------------------------

#[test]
fn a_view_fault_on_the_window_read_is_the_views() {
    let view = FaultingView::default();
    assert!(matches!(
        effective_median_at(&view, BlockHeight::from_raw(3)),
        Err(ViewRead::View(Faulted))
    ));
}

/// A view whose tip says seven blocks are recorded and whose weights
/// projection answers `AboveTip` at that height is a store that does not
/// hold what it claims: `Corrupt`, at the tip's row, never a shorter
/// window a median would silently be taken over.
#[test]
fn a_withheld_weights_window_below_the_tip_is_corrupt_not_a_verdict() {
    let chain = chain_of(7);
    let read = chain.with_view(|view| {
        let view = view.withholding(WithheldRead::WeightsBelow(BlockHeight::from_raw(7)));
        effective_median_at(&view, BlockHeight::from_raw(7))
    });
    assert!(matches!(
        read,
        Err(ViewRead::Corrupt(Corrupt::HoleBelowTip {
            at,
            record: PerHeightRecord::Block,
        })) if at == BlockHeight::from_raw(6)
    ));
}
