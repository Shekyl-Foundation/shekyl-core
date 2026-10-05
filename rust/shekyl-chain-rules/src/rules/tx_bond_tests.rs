// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures for the bond-state rows on a serve-credit vin, CEN-J4/J5/J6 —
//! the arms a view with **no bonds** can witness. `MockChain` holds no
//! records by policy (`harness.rs`, `archival_reads!(empty)`; DRS-E4 §5.2,
//! *No `Mock*` archival state*), which is exactly J4's negative: a credit
//! for a persona with no record. J5 and J6 need a record to read a join
//! epoch and an interval log from, so their negatives are the ingest
//! driver's — a real chain that posted the bond, through `connect`
//! (`archival_admission_tests.rs`, the J5 and J6 pins) — never a record
//! constructed here. The three rows' vacuity on every other class is also
//! this file's.

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::harness::fixture::{
    anchored_on, candidate_on, coinbase, listed, point, serve_credit_only, spendable_chain,
};
use crate::harness::{assert_refused, defined, formed_on, judged, MockChain};
use crate::rule_set::RuleSet;
use crate::rules::tx_bond::judge_serve_credit_bond;
use crate::rules::TxContext;
use crate::trust::Trust;
use crate::validate::{tx_against, validate};
use crate::verdict::{Locus, TxSlot};

const P: [u8; 32] = [0x5e; 32];
const ROWS: [CenRow; 3] = [CenRow::J4, CenRow::J5, CenRow::J6];

/// CEN-J4 at the pool's slot: a credit for a persona the view has no
/// record for is refused on J4 at its **vin**, through `tx_against` — the
/// pool's call. Until E6 slice 8 row 3 this body passed every rule and met
/// the fold's L7 at connect (row 2's measurement); the refusal is now the
/// rule's, and the fold's arm is the backstop beneath it.
#[test]
fn j4_refuses_a_credit_for_a_persona_with_no_record_at_the_pool_slot() {
    let chain = spendable_chain();
    chain.with_view(|view| {
        assert_refused(
            defined(tx_against(
                &serve_credit_only(P),
                TxSlot::Lone,
                &view,
                &RuleSet::GENESIS,
            )),
            CenRow::J4,
            Locus::Input {
                slot: TxSlot::Lone,
                input: 0,
            },
        );
    });
}

/// The same body listed first in a block is refused by `validate` on J4 at
/// `Listed(0)`'s vin — one function, two sites — and **before** the
/// archival fold runs (L7 would refuse it there; the row that names the
/// reason is J4's, and the census pin in `scenario_archival_tests.rs`
/// moved from L7 to J4 with this rule).
#[test]
fn j4_refuses_the_same_credit_listed_before_the_fold_reaches_it() {
    let chain = spendable_chain();
    chain.with_view(|view| {
        let formed = formed_on(
            &chain,
            candidate_on(&chain, vec![anchored_on(&chain, serve_credit_only(P))]),
        );
        assert_refused(
            judged(validate(
                formed,
                &view,
                &RuleSet::GENESIS,
                &Trust::UNANCHORED,
            )),
            CenRow::J4,
            Locus::Input {
                slot: TxSlot::Listed(0),
                input: 0,
            },
        );
    });
}

/// A multi-vin credit is refused at the vin that fails, in vin order: two
/// credits for two personas with no record name vin 0, not the body.
#[test]
fn j4_names_the_first_failing_vin() {
    let chain = spendable_chain();
    let mut two = serve_credit_only(P);
    two.prefix
        .inputs
        .push(serve_credit_only([0x5f; 32]).prefix.inputs[0].clone());
    chain.with_view(|view| {
        let mut coverage = RuleCoverage::EMPTY;
        let cx = TxContext::derive(&two, TxSlot::Lone, &mut coverage)
            .expect("two serve-credit vins classify as serve-credit-only");
        assert_refused(
            judge_serve_credit_bond(&cx, &view, &mut coverage)
                .unwrap_or_else(|never| match never {}),
            CenRow::J4,
            Locus::Input {
                slot: TxSlot::Lone,
                input: 0,
            },
        );
        for row in ROWS {
            assert!(
                !coverage.contains(row),
                "{row}: a refusal records nothing — the rows are recorded after the loop"
            );
        }
    });
}

/// On every class that is not a serve credit the three rows are recorded
/// **vacuous, not absent** (slice 5 Q2): a spend and a coinbase have no
/// credit vin, and the sequence reads nothing.
#[test]
fn j4_j5_j6_are_vacuous_off_the_serve_credit_class() {
    let chain = MockChain::default();
    chain.with_view(|view| {
        for (name, tx, slot) in [
            ("spend", listed(point(9)), TxSlot::Lone),
            ("coinbase", coinbase(0), TxSlot::Miner),
        ] {
            let mut coverage = RuleCoverage::EMPTY;
            let cx = TxContext::derive(&tx, slot, &mut coverage)
                .unwrap_or_else(|refused| panic!("{name} classifies: {refused}"));
            judge_serve_credit_bond(&cx, &view, &mut coverage)
                .unwrap_or_else(|never| match never {})
                .unwrap_or_else(|refused| panic!("{name}: nothing to judge, but {refused}"));
            for row in ROWS {
                assert!(coverage.contains(row), "{name}: {row} recorded vacuous");
            }
        }
    });
}
