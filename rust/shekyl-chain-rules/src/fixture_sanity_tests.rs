// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Every transaction shape `harness::fixture` labels well-formed passes the
//! **stateless** rules that have landed — at every slot it is meant for,
//! through `tx_form`, the entry point production uses. This is the gate
//! that turns "a new row refused our own fixture" from a recurring
//! mid-commit discovery into a failure at the moment the bad fixture is
//! written (slice 5, after CEN-H5 met three of them — a `tx_form` finding,
//! which is where the gate earned its keep).
//!
//! The set it walks is [`TxShape`], a closed enum with an exhaustive chain:
//! a new shape without a gate arm does not compile. Negative fixtures are
//! not this module's — they live with their rows and are labelled by the
//! row.
//!
//! The view-bound half is not judged here, and cannot be: a fixture spend
//! carries a named key image and no membership proof, so CEN-I13/I15 refuse
//! it on any view (slice 6 row 6), a bond post's funding spend likewise,
//! and a serve credit needs a persona record the mock holds none of by
//! policy (CEN-J4; `archival_reads!(empty)`). The one well-formed block a
//! `MockChain` can hold is coinbase-only, and that is the one `validate`
//! judges here. Each listed shape's `validate` witness is a driven chain,
//! where the shape can exist: the spend in `shekyl-chain-ingest`'s
//! `scenario_spend_tests`, the bond post in `scenario_join_tests`, the
//! serve credit in the same file a block after its join.

use super::fixture::{candidate, candidate_on, coinbase, repriced, spendable_chain, TxShape};
use super::{formed, formed_on, judged, MockChain};
use crate::census::{CenRow, RowStatus};
use crate::rule_set::RuleSet;
use crate::trust::Trust;
use crate::validate::{tx_form, validate};
use crate::verdict::{InvalidBlock, TxSlot};
use shekyl_wire::Transaction;

/// Judge one shape at one slot: `tx_form` at that slot directly, and, for
/// the miner slot, through `validate` on a candidate whose coinbase it is —
/// the coinbase-only block being the one the mock can hold (module docs).
/// The chain is the youngest that can list a spend ([`spendable_chain`]),
/// so the coinbase is judged above genesis as well as at it.
fn judge_at(shape: TxShape, slot: TxSlot, tx: &Transaction) {
    tx_form(tx, slot, &RuleSet::GENESIS)
        .unwrap_or_else(|refused| panic!("{}", refused_message(shape, slot, "tx_form", &refused)));
    if slot != TxSlot::Miner {
        return;
    }
    let chain = spendable_chain();
    chain.with_view(|view| {
        let mut candidate = candidate_on(&chain, Vec::new());
        candidate.block.miner_transaction = tx.clone();
        let formed = formed_on(&chain, repriced(&chain, candidate));
        judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .unwrap_or_else(|refused| panic!("{}", refused_message(shape, slot, "validate", &refused)));
    });
}

/// The failure text for a fixture the current rules refuse. A fixture is
/// blessed only against the rows that exist, so when a new row lands and an
/// untouched fixture goes red here, that is the row finding a fixture that
/// was always wrong — not a regression, and not a reason to weaken either
/// the fixture or the rule. Says so, with the count, so the reader does not
/// have to work it out under time pressure.
fn refused_message(shape: TxShape, slot: TxSlot, site: &str, refused: &InvalidBlock) -> String {
    let implemented = CenRow::ALL
        .iter()
        .filter(|row| row.status() == RowStatus::Implemented)
        .count();
    format!(
        "{shape:?} is labelled valid at {slot:?} but {site} refused it on {row}.\n\
         Fixtures are judged against the {implemented} rows implemented today. If {row} just \
         landed, this fixture was ALWAYS invalid under it and nothing regressed: fix the fixture \
         to what the rule accepts — never the rule, and never by weakening the fixture's claim.",
        row = refused.rule
    )
}

/// The gate: every shape in the chain, at every slot it names.
#[test]
fn every_well_formed_shape_passes_at_every_slot_it_names() {
    let shapes = TxShape::all();
    assert_eq!(shapes.len(), 4, "the chain reaches every variant");
    for shape in shapes {
        let tx = shape.build();
        for &slot in shape.valid_at() {
            let tx = match slot {
                // The miner's `gen` height must be the connecting height (F5);
                // the chain above has five blocks.
                TxSlot::Miner => coinbase(5),
                _ => tx.clone(),
            };
            judge_at(shape, slot, &tx);
        }
    }
}

/// A non-coinbase shape is exactly that: not a coinbase, so it is a legal
/// body — a coinbase-shaped body in a listed slot is H5's refusal, not a
/// fixture.
#[test]
fn no_listed_shape_is_a_coinbase() {
    for shape in TxShape::all() {
        let tx = shape.build();
        let listable = shape.valid_at().contains(&TxSlot::Lone);
        assert_eq!(
            listable,
            !tx.is_coinbase(),
            "{shape:?}: listable shapes are the non-coinbase ones"
        );
    }
}

/// The coinbase fixture is a valid coinbase at genesis too (the chain in
/// [`judge_at`] is `MIN_AGE` blocks deep).
#[test]
fn the_coinbase_fixture_is_valid_at_genesis() {
    tx_form(&coinbase(0), TxSlot::Miner, &RuleSet::GENESIS).expect("at the miner slot");
    MockChain::default().with_view(|view| {
        judged(validate(
            formed(candidate(Vec::new())),
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("the genesis candidate");
    });
}

/// [`super::fixture::spend`] at two widths. One output is [`TxShape::Listed`];
/// two is what the store connects, and five is the first width whose
/// pseudo-out scalar leaves the pinned table (`multiple_of_g` → `point_at`).
/// Both have to pass, or the shared builder is only checked at N = 1.
#[test]
fn a_wider_spend_passes_including_past_the_point_table() {
    use super::fixture::{point, spend};
    for outputs in [2usize, 5] {
        let tx = spend(point(9), outputs);
        tx_form(&tx, TxSlot::Lone, &RuleSet::GENESIS).unwrap_or_else(|refused| {
            panic!(
                "spend(point(9), {outputs}) is the shared builder but tx_form refused it on {}",
                refused.rule
            )
        });
    }
}

// Two listed fixtures in one block — the shape the refusal tests reach for
// when they need "some bodies" — is no longer asserted valid here: the
// fixture spend is refused at CEN-I13 on any view (module docs), and its
// use in this crate is as the body a row *before* I13 refuses. The block
// with two real spends is `shekyl-chain-ingest`'s
// `scenario_spend_tests::two_spends_connect_and_the_per_slot_rows_record`
// (and `body_pairing_tests::two_body_chain`, which lists the same pair).
