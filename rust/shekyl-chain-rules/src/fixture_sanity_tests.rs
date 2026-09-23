// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Every fixture `harness::fixture` labels well-formed passes the rules
//! that have landed — at every slot it is meant for, through the same
//! entry points production uses. This is the gate that turns "a new row
//! refused our own fixture" from a recurring mid-commit discovery into a
//! failure at the moment the bad fixture is written (slice 5, after
//! CEN-H5 met three of them).
//!
//! The rule for extending it: a fixture added to `harness::fixture` as
//! valid is added here the same commit. Negative fixtures are not this
//! module's — they live with their rows and are labelled by the row.

use super::fixture::{
    candidate, candidate_on, coinbase, listed, recorded, root, serve_credit_only,
};
use super::{formed, formed_on, judged, MockChain};
use crate::rule_set::RuleSet;
use crate::trust::Trust;
use crate::validate::{tx_form, validate};
use crate::verdict::TxSlot;
use shekyl_wire::Transaction;

/// A five-block chain to build candidates on, so the fixtures are exercised
/// above genesis as well as at it.
fn five_blocks() -> MockChain {
    (0..5u64).fold(MockChain::default(), |chain, i| {
        chain.push(recorded(100 + i), root(u8::try_from(i).expect("small")))
    })
}

/// `tx_form` at the pool's slot and, listed, through `validate` on a chain.
fn passes_as_listed(tx: &Transaction) {
    tx_form(tx, TxSlot::Lone, &RuleSet::GENESIS)
        .unwrap_or_else(|refused| panic!("valid fixture refused at the pool's slot: {refused}"));
    let chain = five_blocks();
    chain.with_view(|view| {
        let formed = formed_on(&chain, candidate_on(&chain, vec![tx.clone()]));
        judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .unwrap_or_else(|refused| panic!("valid fixture refused when listed: {refused}"));
    });
}

/// The coinbase fixture is a valid coinbase at the miner slot at genesis
/// and above it — through `form` (4.F's stateless rows), `validate` (4.F's
/// view-bound rows and `tx_form` at `Miner`).
#[test]
fn the_coinbase_fixture_is_a_valid_coinbase_at_every_height_tried() {
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
    let chain = five_blocks();
    chain.with_view(|view| {
        let formed = formed_on(&chain, candidate_on(&chain, Vec::new()));
        judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("the candidate at height 5");
    });
}

/// The listed spend is a valid non-coinbase transaction at the pool's slot
/// and listed — and **not** a valid coinbase, which is what makes it the
/// right body for a block (a coinbase-shaped body in a listed slot is H5's
/// refusal, not a fixture).
#[test]
fn the_listed_fixture_is_a_valid_listed_transaction_and_not_a_coinbase() {
    let tx = listed([0xC1; 32]);
    assert!(!tx.is_coinbase());
    passes_as_listed(&tx);
}

/// The serve-credit-only fixture is a valid listed transaction with no key
/// image.
#[test]
fn the_serve_credit_fixture_is_a_valid_listed_transaction_without_a_key_image() {
    let tx = serve_credit_only([0x77; 32]);
    assert_eq!(tx.prefix.spend_input_count(), 0);
    passes_as_listed(&tx);
}

/// Two distinct listed fixtures in one block: the shape most tests reach
/// for when they need "some bodies".
#[test]
fn two_listed_fixtures_make_a_valid_block() {
    let chain = five_blocks();
    chain.with_view(|view| {
        let formed = formed_on(
            &chain,
            candidate_on(&chain, vec![listed([0xC1; 32]), listed([0xC2; 32])]),
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
