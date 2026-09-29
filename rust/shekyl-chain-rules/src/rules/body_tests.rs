// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-G2 — the declared list and the carried bodies: both arms at their
//! loci, the *first* mismatch and only it, the agreeing block recorded, and
//! the rule's place in `form` (a stateless refusal ends the stage before
//! the identity is derived).

use super::*;
use crate::block::Candidate;
use crate::fault::FormAttempt;
use crate::harness::fixture::{candidate, listed};
use crate::harness::{assert_refused, Faulted, MockSubstrate};
use crate::rule_set::RuleSet;
use crate::validate::form;
use shekyl_types::BlockHash;

/// Three distinct listed bodies, the header declaring exactly them.
fn three_bodies() -> Candidate {
    candidate(vec![listed([1; 32]), listed([2; 32]), listed([3; 32])])
}

fn check(candidate: &Candidate) -> Verdict<()> {
    G2::check(&FormContext::new(candidate, &RuleSet::GENESIS))
}

/// The stage, so the rule's position in it is under test too.
fn form_judges(candidate: Candidate) -> Verdict<RuleCoverage> {
    match form(
        candidate,
        &RuleSet::GENESIS,
        &MockSubstrate::default(),
        BlockHash::NULL,
        FormAttempt::FIRST,
    ) {
        Ok(Ok(formed)) => Ok(*formed.coverage()),
        Ok(Err(refused)) => Err(refused),
        Err(Faulted) => unreachable!("the default MockSubstrate never faults"),
    }
}

use crate::coverage::RuleCoverage;

#[test]
fn cen_g2_an_agreeing_block_passes_and_is_recorded() {
    check(&three_bodies()).expect("declared == carried");
    let coverage = form_judges(three_bodies()).expect("form admits it");
    assert!(coverage.contains(CenRow::G2), "G2 recorded as evaluated");
    // And the empty body: no hashes, no bodies, agreeing vacuously.
    check(&candidate(Vec::new())).expect("an empty list agrees with itself");
}

#[test]
fn cen_g2_a_length_mismatch_is_refused_at_the_block() {
    // One body dropped, its hash still declared (`MissingBody`).
    let mut missing = three_bodies();
    missing.transactions.pop();
    assert_refused(check(&missing), CenRow::G2, Locus::Block);
    // One body more than declared — the other direction of the same arm.
    let mut extra = three_bodies();
    extra.transactions.push(listed([4; 32]));
    assert_refused(check(&extra), CenRow::G2, Locus::Block);
    // A declared hash with no body at all.
    let mut none = candidate(Vec::new());
    none.block.transaction_hashes.push(listed([9; 32]).hash());
    assert_refused(check(&none), CenRow::G2, Locus::Block);
}

#[test]
fn cen_g2_the_first_mismatching_index_is_the_locus_and_only_it() {
    // Swap the first two (`ReorderedBodies`): index 0 disagrees first.
    let mut reordered = three_bodies();
    reordered.transactions.swap(0, 1);
    assert_refused(
        check(&reordered),
        CenRow::G2,
        Locus::Tx {
            slot: TxSlot::Listed(0),
        },
    );
    // Substitute the body at index 1 with one the header never lists
    // (`SubstitutedBody`): index 0 agrees, so the locus is 1 — the rule
    // computed the first mismatch, not "a mismatch exists".
    let mut substituted = three_bodies();
    substituted.transactions[1] = listed([7; 32]);
    assert_refused(
        check(&substituted),
        CenRow::G2,
        Locus::Tx {
            slot: TxSlot::Listed(1),
        },
    );
    // Two disagreeing slots: still the first.
    let mut two = three_bodies();
    two.transactions[1] = listed([7; 32]);
    two.transactions[2] = listed([8; 32]);
    assert_refused(
        check(&two),
        CenRow::G2,
        Locus::Tx {
            slot: TxSlot::Listed(1),
        },
    );
}

#[test]
fn cen_g2_length_is_judged_before_any_index() {
    // Shorter *and* disagreeing at index 0: the length arm speaks, so the
    // index arm never reads past the shorter list.
    let mut both = three_bodies();
    both.transactions.pop();
    both.transactions.swap(0, 1);
    assert_refused(check(&both), CenRow::G2, Locus::Block);
}

#[test]
fn cen_g2_refuses_in_form_before_the_identity_is_derived() {
    // Through the stage: the refusal is the stage's verdict, and it is
    // G2's — B1/B2/B7 pass this header, and the coinbase rows pass its
    // coinbase, so nothing earlier in `judge_form!` claims it.
    let mut reordered = three_bodies();
    reordered.transactions.swap(0, 1);
    assert_refused(
        form_judges(reordered),
        CenRow::G2,
        Locus::Tx {
            slot: TxSlot::Listed(0),
        },
    );
}
