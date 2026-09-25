// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Negative fixtures for census 4.C (`CHAIN_RULES_SLICE_2.md` §5): the FTL
//! boundary (C1), the strict median boundary (C2), the genesis padding
//! (C3), the genesis exemption (F3 / Q3), and the shared C2-R3 vectors
//! driven through the **rules** rather than only through
//! `shekyl-difficulty`.

use super::*;
use crate::block::Candidate;
use crate::fault::{Corrupt, FormAttempt};
use crate::harness::fixture::{candidate_on, recorded, root};
use crate::harness::{
    assert_refused, boundary_pair, expected_seed, formed_on, judged, Faulted, FaultingView,
    MockChain, MockSubstrate, WithheldRead,
};
use crate::rule_set::RuleSet;
use crate::rules::{BlockContext, BlockRule};
use crate::trust::Trust;
use crate::validate::{form, validate};
use crate::verdict::{ChainValid, Locus};
use crate::Target;
use shekyl_types::BlockHash;

/// Unwrap a parent-side read over a view that cannot fault: the view arm
/// is uninhabited, and a corrupt answer is a fixture failure unless the
/// test asked for one.
#[track_caller]
fn windowed<T>(read: Result<T, ViewRead<core::convert::Infallible>>) -> T {
    match read {
        Ok(value) => value,
        Err(ViewRead::View(never)) => match never {},
        Err(ViewRead::Corrupt(corrupt)) => panic!("unexpected corrupt view: {corrupt}"),
    }
}

/// A chain whose blocks carry `timestamps` in height order.
fn chain_with(timestamps: &[u64]) -> MockChain {
    timestamps
        .iter()
        .enumerate()
        .fold(MockChain::default(), |chain, (i, ts)| {
            chain.push(recorded(*ts), root(u8::try_from(i + 1).expect("small")))
        })
}

/// A candidate on `chain`'s tip carrying `timestamp`.
fn candidate_at(chain: &MockChain, timestamp: u64) -> Candidate {
    let mut candidate = candidate_on(chain, Vec::new());
    candidate.block.header.timestamp = timestamp;
    candidate
}

/// Both stages over `chain` with the substrate's clock at `clock`.
fn judge_at(chain: &MockChain, candidate: Candidate, clock: u64) -> Verdict<()> {
    let substrate = MockSubstrate {
        clock: Timestamp::from_raw(clock),
        ..MockSubstrate::default()
    };
    let formed = match form(
        candidate,
        &RuleSet::GENESIS,
        &substrate,
        expected_seed(chain),
        FormAttempt::FIRST,
    ) {
        Ok(Ok(formed)) => formed,
        Ok(Err(refused)) => return Err(refused),
        Err(Faulted) => unreachable!("the mock substrate never faults"),
    };
    chain.with_view(|view| {
        judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .map(|_valid: ChainValid<_>| ())
    })
}

/// One rule alone, with the window C3 derives for `chain`.
fn check_alone<R: BlockRule>(chain: &MockChain, candidate: Candidate, clock: u64) -> Verdict<()> {
    let substrate = MockSubstrate {
        clock: Timestamp::from_raw(clock),
        ..MockSubstrate::default()
    };
    let formed = form(
        candidate,
        &RuleSet::GENESIS,
        &substrate,
        expected_seed(chain),
        FormAttempt::FIRST,
    )
    .expect("no fault")
    .expect("the fixture passes the stateless stage");
    chain.with_view(|view| {
        let mut coverage = RuleCoverage::EMPTY;
        let connecting = BlockHeight::from_raw(chain.tip().map_or(0, |t| t.height.to_raw() + 1));
        let window = windowed(C3::window(&view, connecting, &mut coverage));
        crate::harness::infallible(R::check(
            &BlockContext::new(
                &formed,
                chain.tip(),
                window,
                Target::GENESIS_BLOCK,
                &Trust::UNANCHORED,
            ),
            &view,
        ))
    })
}

const CLOCK: u64 = 1_700_000_000;

// --- CEN-C1 ---------------------------------------------------------------

#[test]
fn cen_c1_the_ftl_bound_is_clock_plus_540_inclusive() {
    // One recorded block, so the candidate connects at height 1 and the
    // exemption does not apply; genesis at 0 so the median is no obstacle.
    let chain = chain_with(&[0]);
    boundary_pair(CLOCK + 540, CLOCK + 541, CenRow::C1, Locus::Block, |ts| {
        judge_at(&chain, candidate_at(&chain, ts), CLOCK)
    });
}

#[test]
fn cen_c1_reads_the_clock_form_took_not_the_view() {
    let chain = chain_with(&[0]);
    // The same candidate, refused or not depending only on the substrate's
    // clock at `form`.
    let ts = CLOCK + 541;
    assert_refused(
        judge_at(&chain, candidate_at(&chain, ts), CLOCK),
        CenRow::C1,
        Locus::Block,
    );
    judge_at(&chain, candidate_at(&chain, ts), CLOCK + 1).expect("one second later it passes");
}

#[test]
fn cen_c1_ftl_vectors_hold_through_the_rule() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/test_vectors/MTP_BOUNDARY_V1.json"
    ))
    .expect("the shared vectors parse");
    let chain = chain_with(&[0]);
    let mut seen = 0;
    for case in vectors["ftl_cases"]["cases"].as_array().expect("cases") {
        let candidate = case["candidate"].as_u64().expect("candidate");
        let clock = case["local_clock"].as_u64().expect("local_clock");
        let passes = case["verdict"].as_bool().expect("verdict");
        let verdict = check_alone::<C1>(&chain, candidate_at(&chain, candidate), clock);
        assert_eq!(
            verdict.is_ok(),
            passes,
            "{}: candidate {candidate} at clock {clock}",
            case["name"]
        );
        seen += 1;
    }
    assert!(seen >= 5, "the vector file carries FTL cases");
}

// --- CEN-C2 ---------------------------------------------------------------

#[test]
fn cen_c2_the_median_bound_is_strict() {
    // Block 0 at 0, then the eleven-block sorted window the vectors use;
    // the candidate connects at height 12 and its window is heights 1..=11.
    let window = [
        1000, 1120, 1240, 1360, 1480, 1600, 1720, 1840, 1960, 2080, 2200,
    ];
    let mut timestamps = vec![0];
    timestamps.extend_from_slice(&window);
    let chain = chain_with(&timestamps);
    boundary_pair(1601, 1600, CenRow::C2, Locus::Block, |ts| {
        judge_at(&chain, candidate_at(&chain, ts), CLOCK)
    });
}

#[test]
fn cen_c2_assembly_vectors_hold_through_the_rule() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/test_vectors/MTP_BOUNDARY_V1.json"
    ))
    .expect("the shared vectors parse");
    let mut seen = 0;
    for case in vectors["assembly_cases"]["cases"]
        .as_array()
        .expect("cases")
    {
        let genesis = case["genesis_ts"].as_u64().expect("genesis_ts");
        let mut history: Vec<u64> = case["history_newest_first"]
            .as_array()
            .expect("history")
            .iter()
            .map(|v| v.as_u64().expect("u64"))
            .collect();
        history.reverse(); // oldest first, as heights ascend
                           // Below eleven blocks the oldest history entry IS block 0; at eleven
                           // the window is full and block 0 sits below it.
        let timestamps: Vec<u64> = if history.len() < MTP_WINDOW_USIZE {
            assert_eq!(
                history[0], genesis,
                "{}: short history starts at genesis",
                case["name"]
            );
            history
        } else {
            let mut all = vec![genesis];
            all.extend(history);
            all
        };
        let chain = chain_with(&timestamps);
        let candidate = case["candidate"].as_u64().expect("candidate");
        let passes = case["verdict"].as_bool().expect("verdict");
        let verdict = check_alone::<C2>(&chain, candidate_at(&chain, candidate), CLOCK);
        assert_eq!(
            verdict.is_ok(),
            passes,
            "{}: candidate {candidate}",
            case["name"]
        );
        seen += 1;
    }
    assert!(seen >= 3, "the vector file carries assembly cases");
}

// --- CEN-C3 ---------------------------------------------------------------

#[test]
fn cen_c3_below_eleven_blocks_the_window_is_padded_with_genesis() {
    // Five recorded blocks: genesis at 0, then 20, 30, 40, 50. Padded to
    // eleven with 0 the sorted window is [0,0,0,0,0,0,0,20,30,40,50] and the
    // median (index 5) is 0; unpadded it would be 30. A candidate at 1 is
    // above the padded median and below the unpadded one — so the padding is
    // what decides it, and the fixture proves the padding is applied.
    let chain = chain_with(&[0, 20, 30, 40, 50]);
    judge_at(&chain, candidate_at(&chain, 1), CLOCK).expect("1 > padded median 0");
    assert_refused(
        judge_at(&chain, candidate_at(&chain, 0), CLOCK),
        CenRow::C2,
        Locus::Block,
    );
}

#[test]
fn cen_c3_records_and_yields_no_window_at_genesis() {
    MockChain::default().with_view(|view| {
        let mut coverage = RuleCoverage::EMPTY;
        let window = windowed(C3::window(&view, BlockHeight::ZERO, &mut coverage));
        assert_eq!(window, None);
        assert!(
            coverage.contains(CenRow::C3),
            "the definition row records as applied"
        );
    });
}

#[test]
fn cen_c3_window_is_the_preceding_eleven_oldest_first() {
    let timestamps: Vec<u64> = (0..15).map(|i| 100 + i).collect();
    let chain = chain_with(&timestamps);
    chain.with_view(|view| {
        let mut coverage = RuleCoverage::EMPTY;
        let window = windowed(C3::window(&view, BlockHeight::from_raw(15), &mut coverage))
            .expect("fifteen blocks have a window");
        assert_eq!(window.genesis, Timestamp::from_raw(100));
        assert_eq!(
            window.preceding,
            (4..15)
                .map(|h| Timestamp::from_raw(100 + h))
                .collect::<Vec<_>>()
        );
    });
}

#[test]
fn cen_c3_propagates_a_fault_and_derives_nothing() {
    let view = FaultingView::default();
    let mut coverage = RuleCoverage::EMPTY;
    assert_eq!(
        C3::window(&view, BlockHeight::from_raw(3), &mut coverage),
        Err(ViewRead::View(Faulted))
    );
}

#[test]
fn a_hole_below_the_tip_is_the_halting_fault_not_a_panic() {
    // Until 2026-09-24 the window's two `AboveTip` arms were `unreachable!`,
    // argued from SI-7. A view that breaks SI-7 now yields
    // `Corrupt::HoleBelowTip` at the height that was not recorded — the
    // class the connector halts the writer on — and the candidate is
    // neither refused nor admitted.
    let chain = chain_with(&[100, 220, 340, 460]);
    let hole = BlockHeight::from_raw(2);
    chain.with_view(|inner| {
        let view = inner.withholding(WithheldRead::BlockAt(hole));
        let mut coverage = RuleCoverage::EMPTY;
        assert_eq!(
            C3::window(&view, BlockHeight::from_raw(4), &mut coverage),
            Err(ViewRead::Corrupt(Corrupt::HoleBelowTip {
                at: hole,
                record: crate::fault::PerHeightRecord::Block,
            }))
        );
        // Through the stage: the same fault, in `Fault`'s clothing.
        let formed = formed_on(&chain, candidate_at(&chain, 500));
        let outcome = validate(formed, &view, &RuleSet::GENESIS, &Trust::UNANCHORED);
        assert!(
            matches!(
                outcome,
                Err(crate::fault::Fault::Corrupt(Corrupt::HoleBelowTip {
                    at,
                    record: crate::fault::PerHeightRecord::Block,
                })) if at == hole
            ),
            "{outcome:?}"
        );
    });
    // The producer's read of the same operand reports the same fault.
    chain.with_view(|inner| {
        let view = inner.withholding(WithheldRead::BlockAt(hole));
        assert_eq!(
            mtp_median_at(&view, BlockHeight::from_raw(4)),
            Err(ViewRead::Corrupt(Corrupt::HoleBelowTip {
                at: hole,
                record: crate::fault::PerHeightRecord::Block,
            }))
        );
    });
}

// --- genesis (F3 / Q3) --------------------------------------------------

#[test]
fn at_genesis_all_three_rows_record_as_applied_and_refuse_nothing() {
    // No predecessor: no window, no FTL — the C++ returns before either arm.
    // A timestamp far past the clock and equal to nothing is accepted.
    let chain = MockChain::default();
    let candidate = candidate_at(&chain, CLOCK + 1_000_000);
    let substrate = MockSubstrate {
        clock: Timestamp::from_raw(CLOCK),
        ..MockSubstrate::default()
    };
    let formed = form(
        candidate,
        &RuleSet::GENESIS,
        &substrate,
        BlockHash::NULL,
        FormAttempt::FIRST,
    )
    .expect("no fault")
    .expect("passes the stateless stage");
    chain.with_view(|view| {
        let valid = judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("genesis is exempt from both timestamp legs");
        for row in [CenRow::C1, CenRow::C2, CenRow::C3] {
            assert!(valid.coverage().contains(row), "{row} recorded at genesis");
        }
    });
}

#[test]
fn the_pipeline_orders_ftl_before_median() {
    // A candidate that fails both is refused on C1, as the C++ refuses it.
    let chain = chain_with(&[CLOCK + 5_000]);
    assert_refused(
        judge_at(&chain, candidate_at(&chain, CLOCK + 600), CLOCK),
        CenRow::C1,
        Locus::Block,
    );
}

#[test]
fn a_well_formed_candidate_covers_the_timestamp_rows() {
    let chain = chain_with(&[CLOCK - 120]);
    chain.with_view(|view| {
        let valid = judged(validate(
            formed_on(&chain, candidate_at(&chain, CLOCK)),
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("passes");
        for row in [CenRow::C1, CenRow::C2, CenRow::C3] {
            assert!(valid.coverage().contains(row), "{row}");
        }
    });
}
