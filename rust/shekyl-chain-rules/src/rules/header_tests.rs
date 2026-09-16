// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Negative fixtures for census 4.B's version rows (`CHAIN_RULES_SLICE_1.md`
//! §7). Each test names its row; each asserts a *refusal* where the row
//! refuses, and — for the two rows whose statement is "does not reject" —
//! that the mutated field trips **no** row, or the row that does trip is the
//! one the census says.

use super::*;
use crate::block::Candidate;
use crate::census::CenRow;
use crate::harness::fixture::candidate;
use crate::harness::{assert_refused, boundary_pair, infallible, MockChain};
use crate::rule_set::RuleSet;
use crate::validate::validate;
use crate::verdict::{ChainValid, Locus, Verdict};

fn with_versions(major: u8, minor: u8) -> Candidate {
    let mut candidate = candidate(Vec::new());
    candidate.block.header.major_version = major;
    candidate.block.header.minor_version = minor;
    candidate
}

/// Judge a candidate against an empty recorded chain under `GENESIS`; the
/// mock never faults, so the outer position is discharged here.
fn judge(candidate: Candidate) -> Verdict<()> {
    MockChain::default().with_view(|view| {
        infallible(validate(candidate, &view, &RuleSet::GENESIS)).map(|_valid: ChainValid<_>| ())
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
    // "unconstrained". A rule set admitting `2` would refuse votes `0`/`1`
    // here exactly as `do_check` would; none is issued, so that boundary
    // has no fixture yet, and this test pins the pieces it will use.
    assert_eq!(B2::normalised_vote(0), 1);
    assert_eq!(B2::normalised_vote(1), 1);
    assert_eq!(B2::normalised_vote(7), 7);
    assert!(B2::normalised_vote(u8::MIN) >= RuleSet::GENESIS.header_major_version());
}

// --- CEN-B7 ---------------------------------------------------------------

#[test]
fn cen_b7_never_refuses_a_future_version_is_b1s_refusal() {
    // The header that trips the C++'s warning branch …
    assert!(B7::is_future_version(
        2,
        RuleSet::GENESIS.header_major_version()
    ));
    assert!(!B7::is_future_version(
        1,
        RuleSet::GENESIS.header_major_version()
    ));
    // … is refused, and by B1, never by B7: `assert_refused` bites on the
    // wrong row, so this is the fixture for "B7 does not reject".
    assert_refused(judge(with_versions(2, 0)), CenRow::B1, Locus::Block);
    assert_refused(judge(with_versions(u8::MAX, 0)), CenRow::B1, Locus::Block);
}

// --- coverage -------------------------------------------------------------

#[test]
fn slice_1_version_rows_are_exactly_what_a_pass_covers() {
    MockChain::default().with_view(|view| {
        let valid = infallible(validate(candidate(Vec::new()), &view, &RuleSet::GENESIS))
            .expect("a well-formed fixture passes the version rows");
        let covered: Vec<CenRow> = valid.coverage().iter().collect();
        assert_eq!(covered, [CenRow::B1, CenRow::B2, CenRow::B7]);
        assert!(valid.coverage().covers_landed(&RuleSet::GENESIS));
        // Three rows of 153 is not parity evidence.
        assert!(!valid.coverage().is_complete_for(&RuleSet::GENESIS));
    });
}

#[test]
fn a_refusal_leaves_no_coverage_behind_it() {
    // B1 refuses before B2/B7 run; the verdict is the refusal, and there is
    // no partial coverage to read — `validate` returns before the mint.
    assert_refused(judge(with_versions(2, 0)), CenRow::B1, Locus::Block);
}

#[test]
fn the_registry_binds_each_type_to_its_row() {
    // The compile-time pin (`census_pin!`) is what holds this; the runtime
    // echo makes the binding visible in a test name.
    assert_eq!(<B1 as Rule>::ROW, CenRow::B1);
    assert_eq!(<B2 as Rule>::ROW, CenRow::B2);
    assert_eq!(<B7 as Rule>::ROW, CenRow::B7);
    for row in [CenRow::B1, CenRow::B2, CenRow::B7] {
        assert_eq!(row.status(), crate::census::RowStatus::Implemented);
    }
}
