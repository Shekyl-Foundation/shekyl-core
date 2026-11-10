// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bundle section through `form` and `validate` on the mock chain, and
//! its stateless half at arrival ([`bind_section`]).
//!
//! The mock holds no bundle rows: its bundle view answers nothing. So the
//! refusals pinned here are the ones decided before any row is read — the
//! parse, the order, the root and the window — and the one property the
//! mock can show about the rest: a view with no rows never turns that into
//! a verdict. The admission of a bundle against real rows, the cold memo
//! and the stale body are the store's tests (`connect_bundle_tests.rs`),
//! because only the store's view answers.
//!
//! B4's deletion moved two refusals it also made to the rows that already
//! made them in `form`: an unreadable coinbase extra is CEN-I19's, and a
//! `0x0B` attestation field is CEN-I20's. Both are pinned here so the
//! deletion is shown to have lost neither.

use super::*;
use crate::block::Candidate;
use crate::census::CenRow;
use crate::fault::{Corrupt, Fault};
use crate::harness::fixture::{candidate, candidate_on, chain_of};
use crate::harness::{assert_refused, formed_on, judge_on, judged, MockChain};
use crate::rule_set::RuleSet;
use crate::trust::Trust;
use crate::validate::validate;
use crate::verdict::{Locus, TxSlot};
use shekyl_archival_retention::{
    bundle_root, empty_bundle_root, BundleKept, BundleRef, PassBitmap, ATTESTATION_HEADER_LEN,
};
use shekyl_types::archival::BundleReferences;
use shekyl_types::{BlockHeight, BundleRoot};
use shekyl_wire::tx_extra::{parse, serialize, TxExtraField};

/// `candidate` with its header's `bundle_root` replaced.
fn with_root(mut candidate: Candidate, root: [u8; 32]) -> Candidate {
    candidate.block.header.bundle_root = BundleRoot::from_bytes(root);
    candidate
}

/// `candidate` with `field` appended to its coinbase extra.
fn with_coinbase_field(mut candidate: Candidate, field: TxExtraField) -> Candidate {
    let extra = &mut candidate.block.miner_transaction.prefix.extra;
    let mut fields = parse(extra).expect("the fixture coinbase extra parses");
    fields.push(field);
    *extra = serialize(&fields).expect("fields serialize");
    candidate
}

/// A well-formed reference to a zero-draw bundle for `h`.
fn reference_for(h: u64) -> BundleRef {
    let none = PassBitmap::new(0, &[]).expect("an empty bitmap");
    BundleRef::new(
        BundleKept {
            h: BlockHeight::from_raw(h),
            seed: [0x5E; 32],
            passes: none.clone(),
            support: none,
        },
        [0x77; 32],
    )
}

/// `candidate` carrying `refs` as its section, under the root they make.
fn carrying(candidate: Candidate, refs: &[BundleRef]) -> Candidate {
    let root = bundle_root(refs).expect("a countable section");
    let section = BundleReferences::new(refs.iter().map(BundleRef::encode).collect())
        .expect("a non-empty section of non-empty references");
    with_root(candidate, root).with_bundle_references(Some(section))
}

/// The nine rows the section judges.
const SECTION_ROWS: [CenRow; 9] = [
    CenRow::J29,
    CenRow::J30,
    CenRow::J31,
    CenRow::J32,
    CenRow::J33,
    CenRow::J34,
    CenRow::J35,
    CenRow::J36,
    CenRow::J37,
];

// --- the empty section (A3) ----------------------------------------------

/// A block with no references is the empty section under the empty root:
/// admitted, with nothing admitted, and all nine rows judged.
#[test]
fn j29_the_empty_section_under_the_empty_root_is_a_judged_pass() {
    let chain = chain_of(3);
    let candidate = candidate_on(&chain, Vec::new());
    assert!(candidate.bundle_references.is_none());
    assert_eq!(
        candidate.block.header.bundle_root.as_bytes(),
        &empty_bundle_root()
    );
    let formed = formed_on(&chain, candidate);
    chain.with_view(|view| {
        let valid = judged(validate(formed, &view, &RuleSet::GENESIS, &Trust::UNPINNED))
            .expect("the fixture candidate is valid");
        assert!(valid.block().admitted().is_empty());
        for row in SECTION_ROWS {
            assert!(valid.coverage().contains(row), "{row} is always judged");
        }
    });
}

/// The A3 falsifier: a root that is not the empty section's, with no
/// references, is refused as J29 at the block. Red edit: skip the root
/// comparison for an empty section — the block is admitted.
#[test]
fn j29_a_non_empty_root_with_no_references_is_refused() {
    let chain = chain_of(3);
    let candidate = with_root(candidate_on(&chain, Vec::new()), [0x33; 32]);
    assert_refused(judge_on(&chain, candidate), CenRow::J29, Locus::Block);
}

#[test]
fn j29_genesis_commits_the_empty_root_too() {
    let genesis = candidate(Vec::new());
    assert_refused(
        judge_on(&MockChain::default(), with_root(genesis, [0x33; 32])),
        CenRow::J29,
        Locus::Block,
    );
}

// --- what B4 also refused, and where it is refused now -------------------

/// An extra that does not parse is CEN-I19's, at the miner slot, in
/// `form`: never read as the committed empty set.
#[test]
fn i19_an_unreadable_coinbase_extra_is_refused_in_form() {
    let chain = chain_of(3);
    let mut candidate = candidate_on(&chain, Vec::new());
    candidate.block.miner_transaction.prefix.extra = vec![0xFF, 0x01, 0x02];
    assert!(parse(&candidate.block.miner_transaction.prefix.extra).is_err());
    assert_refused(
        judge_on(&chain, candidate),
        CenRow::I19,
        Locus::Tx {
            slot: TxSlot::Miner,
        },
    );
}

/// A `0x0B` attestation field in the coinbase is CEN-I20's, at the miner
/// slot, in `form`: the header commits to bundles (`SCS-P34`), and the
/// coinbase grammar admits no attestation field for a record to ride in.
#[test]
fn i20_an_attestation_field_in_the_coinbase_is_refused_in_form() {
    let chain = chain_of(3);
    let candidate = with_coinbase_field(
        candidate_on(&chain, Vec::new()),
        TxExtraField::ArchivalAttestation(vec![0u8; ATTESTATION_HEADER_LEN]),
    );
    assert_refused(
        judge_on(&chain, candidate),
        CenRow::I20,
        Locus::Tx {
            slot: TxSlot::Miner,
        },
    );
}

// --- the section's form, through `validate` ------------------------------

/// A reference that does not parse is J29 at its position.
#[test]
fn j29_a_reference_that_does_not_parse_is_refused_at_its_position() {
    let chain = chain_of(3);
    let good = reference_for(1);
    let section = BundleReferences::new(vec![good.encode(), vec![0xAB; 3]])
        .expect("two non-empty references");
    let candidate = with_root(candidate_on(&chain, Vec::new()), [0x44; 32])
        .with_bundle_references(Some(section));
    assert_refused(
        judge_on(&chain, candidate),
        CenRow::J29,
        Locus::Bundle { position: 1 },
    );
}

/// References that do not ascend are J29 at the one that does not.
#[test]
fn j29_references_out_of_order_are_refused_at_the_second() {
    let chain = chain_of(3);
    let candidate = carrying(
        candidate_on(&chain, Vec::new()),
        &[reference_for(2), reference_for(1)],
    );
    assert_refused(
        judge_on(&chain, candidate),
        CenRow::J29,
        Locus::Bundle { position: 1 },
    );
}

/// References under a root that is not theirs are J29 at the block.
#[test]
fn j29_references_under_another_root_are_refused() {
    let chain = chain_of(3);
    let candidate = with_root(
        carrying(candidate_on(&chain, Vec::new()), &[reference_for(1)]),
        empty_bundle_root(),
    );
    assert_refused(judge_on(&chain, candidate), CenRow::J29, Locus::Block);
}

/// A reference to a block the including block is not inside the window of
/// — here, its own height — is J31 at its position, before any row is read
/// (`SCS-P41`).
#[test]
fn j31_a_reference_outside_the_window_is_refused_before_any_read() {
    let chain = chain_of(3);
    let candidate = candidate_on(&chain, Vec::new());
    let connecting = chain.tip().map_or(0, |tip| tip.height.to_raw() + 1);
    let candidate = carrying(candidate, &[reference_for(connecting)]);
    assert_refused(
        judge_on(&chain, candidate),
        CenRow::J31,
        Locus::Bundle { position: 0 },
    );
}

/// A view with no bundle rows does not refuse a well-formed section inside
/// the window: it cannot answer for the blocks the section names, and that
/// is this node's rows, not the block's (`Corrupt::BundleUnanswered`).
/// Red edit: map `AdmissionFault::Awaiting` to a refusal — this test sees
/// a verdict.
#[test]
fn a_view_with_no_bundle_rows_faults_and_never_refuses() {
    let chain = chain_of(3);
    let candidate = carrying(candidate_on(&chain, Vec::new()), &[reference_for(1)]);
    let formed = formed_on(&chain, candidate);
    chain.with_view(
        |view| match validate(formed, &view, &RuleSet::GENESIS, &Trust::UNPINNED) {
            Err(Fault::Corrupt(
                Corrupt::BundleUnanswered { .. } | Corrupt::DrawableEpoch { .. },
            )) => {}
            Err(other) => panic!("expected the view's unanswered rows, got {other}"),
            Ok(verdict) => panic!("expected a fault, got a verdict: {:?}", verdict.err()),
        },
    );
}

// --- the stateless half at arrival ---------------------------------------

/// `bind_section` refuses what the section's form refuses, with no view:
/// a root that is not the references', a reference that does not parse,
/// and one outside the window. It admits the empty section under the empty
/// root and a well-formed section under its own.
#[test]
fn bind_section_holds_the_stateless_half() {
    let at = BlockHeight::from_raw(3);
    let rules = RuleSet::GENESIS;
    assert_eq!(bind_section(&[], &empty_bundle_root(), at, &rules), Ok(()));
    let one = reference_for(1);
    let root = bundle_root(std::slice::from_ref(&one)).expect("one reference");
    assert_eq!(bind_section(&[one.encode()], &root, at, &rules), Ok(()));
    assert_refused(
        bind_section(&[one.encode()], &empty_bundle_root(), at, &rules),
        CenRow::J29,
        Locus::Block,
    );
    assert_refused(
        bind_section(&[vec![0xAB; 3]], &root, at, &rules),
        CenRow::J29,
        Locus::Bundle { position: 0 },
    );
    let late = reference_for(3);
    let late_root = bundle_root(std::slice::from_ref(&late)).expect("one reference");
    assert_refused(
        bind_section(&[late.encode()], &late_root, at, &rules),
        CenRow::J31,
        Locus::Bundle { position: 0 },
    );
}
