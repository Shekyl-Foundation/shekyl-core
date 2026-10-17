// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The door over the harness chain: what it can reach with fixture bodies
//! (filler signatures and proofs) is the stateless half, and that half is
//! the validator's own — a coinbase at `Lone` is CEN-H5's, as `tx_form`
//! names it. The admitted, chain-refused and policy-refused arms need real
//! spends and are `shekyl-chain-ingest`'s (`pool_door_tests.rs`).

use shekyl_chain_rules::harness::fixture::{coinbase, listed_on, spendable_chain};
use shekyl_chain_rules::{tx_form, AdmissionPolicy, CenRow, RuleSet, TxSlot};

use super::{judge, Judged};
use crate::view::KeyImages;

fn judged(tx: &shekyl_wire::Transaction) -> Judged {
    let chain = spendable_chain();
    chain.with_view(|view| {
        match judge(
            tx,
            &view,
            &KeyImages::default(),
            &RuleSet::GENESIS,
            &AdmissionPolicy::GENESIS,
            None,
        ) {
            Ok(judged) => judged,
            Err(fault) => panic!("the harness view never faults: {fault:?}"),
        }
    })
}

#[test]
fn a_coinbase_at_the_door_is_refused_on_the_row_tx_form_names() {
    let tx = coinbase(1);
    let Judged::Stateless(refused) = judged(&tx) else {
        panic!("a coinbase is refused on its bytes");
    };
    assert_eq!(refused.rule, CenRow::H5);
    let direct = tx_form(&tx, TxSlot::Lone, &RuleSet::GENESIS).expect_err("tx_form refuses");
    assert_eq!(
        refused, direct,
        "the door's refusal is tx_form's, slot and all"
    );
}

/// A fixture spend is refused on its bytes, before any chain read could
/// matter, on the row and slot `tx_form` names for it — the door adds no
/// rule and changes no answer.
#[test]
fn a_fixture_spend_is_refused_where_tx_form_refuses_it() {
    let chain = spendable_chain();
    let tx = listed_on(&chain, [0x31; 32]);
    let Judged::Stateless(refused) = judged(&tx) else {
        panic!("a fixture body is refused on its bytes");
    };
    let direct = tx_form(&tx, TxSlot::Lone, &RuleSet::GENESIS).expect_err("tx_form refuses");
    assert_eq!(refused, direct);
}
