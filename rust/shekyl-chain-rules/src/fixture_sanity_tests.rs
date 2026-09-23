// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Every transaction shape `harness::fixture` labels well-formed passes the
//! rules that have landed — at every slot it is meant for, through the same
//! entry points production uses. This is the gate that turns "a new row
//! refused our own fixture" from a recurring mid-commit discovery into a
//! failure at the moment the bad fixture is written (slice 5, after
//! CEN-H5 met three of them).
//!
//! The set it walks is [`TxShape`], a closed enum with an exhaustive chain:
//! a new shape without a gate arm does not compile. Negative fixtures are
//! not this module's — they live with their rows and are labelled by the
//! row. Block-level composition (`candidate`, `candidate_on`) is judged
//! below as the shapes are listed into blocks.

use super::fixture::{candidate, candidate_on, coinbase, recorded, root, TxShape};
use super::{formed, formed_on, judged, MockChain};
use crate::census::{CenRow, RowStatus};
use crate::rule_set::RuleSet;
use crate::trust::Trust;
use crate::validate::{tx_form, validate};
use crate::verdict::{InvalidBlock, TxSlot};
use shekyl_wire::Transaction;

/// A five-block chain to build candidates on, so the fixtures are exercised
/// above genesis as well as at it.
fn five_blocks() -> MockChain {
    (0..5u64).fold(MockChain::default(), |chain, i| {
        chain.push(recorded(100 + i), root(u8::try_from(i).expect("small")))
    })
}

/// Judge one shape at one slot the way production would reach it: `tx_form`
/// at that slot directly, and — for a listed slot — through `validate` with
/// the shape as the block's one body; for the miner slot, through
/// `validate` on a candidate whose coinbase it is.
fn judge_at(shape: TxShape, slot: TxSlot, tx: &Transaction) {
    tx_form(tx, slot, &RuleSet::GENESIS)
        .unwrap_or_else(|refused| panic!("{}", refused_message(shape, slot, "tx_form", &refused)));
    let chain = five_blocks();
    chain.with_view(|view| {
        let mut candidate = candidate_on(&chain, Vec::new());
        match slot {
            TxSlot::Miner => candidate.block.miner_transaction = tx.clone(),
            TxSlot::Listed(_) | TxSlot::Lone => candidate = candidate_on(&chain, vec![tx.clone()]),
        }
        let formed = formed_on(&chain, candidate);
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
    assert_eq!(shapes.len(), 3, "the chain reaches every variant");
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
/// [`judge_at`] is five blocks deep).
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

/// Two distinct listed fixtures in one block: the shape most tests reach
/// for when they need "some bodies".
#[test]
fn two_listed_fixtures_make_a_valid_block() {
    let chain = five_blocks();
    chain.with_view(|view| {
        let formed = formed_on(
            &chain,
            candidate_on(
                &chain,
                vec![
                    super::fixture::listed([0xC1; 32]),
                    super::fixture::listed([0xC2; 32]),
                ],
            ),
        );
        judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("two well-formed listed transactions connect");
    });
}
