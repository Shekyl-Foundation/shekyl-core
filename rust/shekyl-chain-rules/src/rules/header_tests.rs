// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Negative fixtures for census 4.B (`CHAIN_RULES_SLICE_1.md` §7): version
//! rows (B1, B2, B7), the curve-tree root (B5) and identity (B6). Each test
//! names its row; each asserts a *refusal* where the row refuses, and — for
//! the two rows whose statement is "does not reject" — that the mutated
//! field trips **no** row, or the row that does trip is the one the census
//! says. Pipeline coverage of the six landed rows lives in
//! `validate_tests.rs`.

use super::*;
use crate::block::Candidate;
use crate::census::CenRow;
use crate::fault::FormAttempt;
use crate::harness::fixture::{candidate, candidate_on, recorded, root};
use crate::harness::{
    assert_refused, boundary_pair, formed, formed_on, infallible, judged, MockChain,
};
use crate::harness::{Faulted, MockSubstrate};
use crate::rule_set::RuleSet;
use crate::rules::{BlockContext, FormContext, FormRule};
use crate::trust::Trust;
use crate::validate::{form, validate};
use crate::verdict::{ChainValid, Locus, Verdict};
use crate::view::{AtHeight, ChainView, Tip};
use shekyl_types::{BlockHash, CurveTreeRoot};

/// One bit off: the wrong-root fixtures, without indexing into a newtype.
fn flip_first_byte(root: CurveTreeRoot) -> CurveTreeRoot {
    let mut bytes = root.to_bytes();
    bytes[0] ^= 1;
    CurveTreeRoot::from_bytes(bytes)
}

fn with_versions(major: u8, minor: u8) -> Candidate {
    let mut candidate = candidate(Vec::new());
    candidate.block.header.major_version = major;
    candidate.block.header.minor_version = minor;
    candidate
}

/// Judge a candidate through both stages against an empty recorded chain
/// under `rule_set`; the mock never faults, so the outer positions are
/// discharged here. A stateless refusal is the verdict without the view
/// stage running — as in production.
fn judge_under(candidate: Candidate, rule_set: &RuleSet) -> Verdict<()> {
    let formed = match form(
        candidate,
        rule_set,
        &MockSubstrate::default(),
        BlockHash::NULL,
        FormAttempt::FIRST,
    ) {
        Ok(Ok(formed)) => formed,
        Ok(Err(refused)) => return Err(refused),
        Err(Faulted) => unreachable!("the default MockSubstrate never faults"),
    };
    MockChain::default().with_view(|view| {
        judged(validate(formed, &view, rule_set, &Trust::UNANCHORED))
            .map(|_valid: ChainValid<_>| ())
    })
}

fn judge(candidate: Candidate) -> Verdict<()> {
    judge_under(candidate, &RuleSet::GENESIS)
}

/// Run one stateless rule on its own — the stage stops at the first
/// refusal, so a rule behind B1 is only reachable this way for a header B1
/// refuses.
fn check_alone<R: FormRule>(candidate: &Candidate, rule_set: &RuleSet) -> Verdict<()> {
    R::check(&FormContext::new(candidate, rule_set))
}

/// Run one view-bound rule on its own against `chain`.
fn check_alone_on<R: BlockRule>(chain: &MockChain, candidate: &Candidate) -> Verdict<()> {
    let formed = formed_on(chain, candidate.clone());
    chain.with_view(|view| {
        infallible(R::check(
            &BlockContext::for_tests(&formed, chain.tip(), None),
            &view,
        ))
    })
}

// --- CEN-B1 ---------------------------------------------------------------

#[test]
fn cen_b1_major_version_must_be_the_admitted_one() {
    assert_eq!(RuleSet::GENESIS.header_major_version(), 1);
    boundary_pair(1, 2, CenRow::B1, Locus::Block, |major| {
        judge(with_versions(major, 0))
    });
    assert_refused(judge(with_versions(0, 0)), CenRow::B1, Locus::Block);
    assert_refused(judge(with_versions(u8::MAX, 0)), CenRow::B1, Locus::Block);
}

// --- CEN-B2 ---------------------------------------------------------------

#[test]
fn cen_b2_minor_version_is_unconstrained_under_genesis() {
    // The census's effect: any vote passes at the shipped table.
    for minor in [0, 1, 2, 0x7f, u8::MAX] {
        judge(with_versions(1, minor))
            .unwrap_or_else(|refused| panic!("minor_version {minor} was refused: {refused}"));
    }
}

#[test]
fn cen_b2_ports_the_predicate_not_the_effect() {
    // `hardfork.cpp:41–50`: `0` votes for `1`; everything else votes for
    // itself. The comparison is `vote >= admitted`, and under `GENESIS`
    // (`admitted == 1`) no `u8` can lose it — which is why the row reads
    // "unconstrained". Under a rule set admitting `2` the same comparison
    // refuses votes `0` and `1` exactly as `do_check` would; no such set is
    // issued, so the fixture uses the test-only constructor.
    assert_eq!(B2::normalised_vote(0), 1);
    assert_eq!(B2::normalised_vote(1), 1);
    assert_eq!(B2::normalised_vote(7), 7);

    let admits_two = RuleSet::admitting_for_tests(2);
    // The rule alone, so B1 (which also refuses `major != 2`) is out of the way.
    boundary_pair(2, 1, CenRow::B2, Locus::Block, |minor| {
        check_alone::<B2>(&with_versions(2, minor), &admits_two)
    });
    assert_refused(
        check_alone::<B2>(&with_versions(2, 0), &admits_two),
        CenRow::B2,
        Locus::Block,
    );
    // And through the pipeline: `major == 2` satisfies B1, so B2's refusal
    // is the verdict — the wiring, not only the predicate.
    assert_refused(
        judge_under(with_versions(2, 1), &admits_two),
        CenRow::B2,
        Locus::Block,
    );
    judge_under(with_versions(2, 2), &admits_two).expect("vote 2 under admitted 2 passes");
}

// --- CEN-B7 ---------------------------------------------------------------

#[test]
fn cen_b7_never_refuses_a_future_version_is_b1s_refusal() {
    // B7 called on its own passes the header that trips the C++'s warning
    // branch — the pipeline would stop at B1 first, so this is the only way
    // to observe B7 on such a header, and a B7 that started refusing future
    // versions fails here.
    for major in [2, 7, u8::MAX] {
        check_alone::<B7>(&with_versions(major, 0), &RuleSet::GENESIS)
            .unwrap_or_else(|refused| panic!("B7 refused major_version {major}: {refused}"));
    }
    // Through the pipeline the same header is refused — by B1, never by B7
    // (`assert_refused` bites on the wrong row).
    assert_refused(judge(with_versions(2, 0)), CenRow::B1, Locus::Block);
    assert_refused(judge(with_versions(u8::MAX, 0)), CenRow::B1, Locus::Block);
}

// --- CEN-B5 ---------------------------------------------------------------

fn three_blocks() -> MockChain {
    MockChain::default()
        .push(recorded(1_000), root(0xa0))
        .push(recorded(1_060), root(0xa1))
        .push(recorded(1_120), root(0xa2))
}

#[test]
fn cen_b5_header_root_is_the_root_at_the_connecting_height() {
    let chain = three_blocks();
    // The fixture carries root_at(3) = the root pushed with block 2.
    let good = candidate_on(&chain, Vec::new());
    assert_eq!(good.block.header.curve_tree_root, root(0xa2));
    check_alone_on::<B5>(&chain, &good).expect("the state at the connecting height passes B5");

    let mut wrong = good.clone();
    wrong.block.header.curve_tree_root = flip_first_byte(wrong.block.header.curve_tree_root);
    assert_refused(
        check_alone_on::<B5>(&chain, &wrong),
        CenRow::B5,
        Locus::Block,
    );
}

#[test]
fn cen_b5_reads_the_state_at_the_connecting_height_not_the_tips_own() {
    // SCW-19 from the rules side: the header must carry the root the parent's
    // connect *wrote* (`root_at(tip + 1)`), not the state the parent was
    // itself checked against (`root_at(tip)`). A chain whose two roots differ
    // makes the off-by-one observable: the tip's own root is refused.
    let chain = three_blocks();
    let mut stale = candidate_on(&chain, Vec::new());
    stale.block.header.curve_tree_root = root(0xa1); // root_at(2), the tip's own
    assert_refused(
        check_alone_on::<B5>(&chain, &stale),
        CenRow::B5,
        Locus::Block,
    );
}

#[test]
fn cen_b5_genesis_root_is_the_empty_tree() {
    let chain = MockChain::default();
    let genesis = candidate_on(&chain, Vec::new());
    assert_eq!(genesis.block.header.curve_tree_root, CurveTreeRoot::EMPTY);
    check_alone_on::<B5>(&chain, &genesis).expect("genesis carries the empty tree");

    let mut wrong = genesis;
    wrong.block.header.curve_tree_root = root(0x22);
    assert_refused(
        check_alone_on::<B5>(&chain, &wrong),
        CenRow::B5,
        Locus::Block,
    );
}

#[test]
fn cen_b5_above_tip_is_a_refusal_not_a_pass() {
    // Unreachable against a conforming view (SI-4 keeps tip + 1 recorded);
    // against one that has no state at the connecting height the arm is a
    // refusal, never a fall-through.
    struct NoRoots;
    impl<'id> ChainView<'id> for NoRoots {
        type Fault = core::convert::Infallible;
        fn has_key_image(&self, _: &shekyl_types::KeyImage) -> Result<bool, Self::Fault> {
            Ok(false)
        }
        fn block_at(
            &self,
            _: shekyl_types::BlockHeight,
        ) -> Result<AtHeight<crate::view::RecordedBlock>, Self::Fault> {
            Ok(AtHeight::AboveTip)
        }
        fn root_at(
            &self,
            _: shekyl_types::BlockHeight,
        ) -> Result<AtHeight<CurveTreeRoot>, Self::Fault> {
            Ok(AtHeight::AboveTip)
        }
        fn tip(&self) -> Result<Option<Tip>, Self::Fault> {
            Ok(None)
        }
    }
    let genesis = formed(candidate(Vec::new()));
    let verdict = infallible(B5::check(
        &BlockContext::for_tests(&genesis, None, None),
        &NoRoots,
    ));
    assert_refused(verdict, CenRow::B5, Locus::Block);
}

// --- CEN-B6 ---------------------------------------------------------------

#[test]
fn cen_b6_identity_is_block_hash_and_records_the_row() {
    let block = candidate(Vec::new()).block;
    let mut coverage = RuleCoverage::EMPTY;
    let identity = B6::identity(&block, &mut coverage);
    assert_eq!(identity, block.hash());
    assert!(coverage.contains(CenRow::B6));
    assert_eq!(coverage.len(), 1, "B6 records exactly its own row");
}

#[test]
fn a_refusal_leaves_no_coverage_behind_it() {
    // B1 refuses before B2/B7 run; the verdict is the refusal, and there is
    // no partial coverage to read — `validate` returns before the mint.
    assert_refused(judge(with_versions(2, 0)), CenRow::B1, Locus::Block);
}
