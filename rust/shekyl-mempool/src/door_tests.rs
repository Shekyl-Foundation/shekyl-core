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
use shekyl_chain_rules::{
    tx_form, AdmissionPolicy, AtHeight, CenRow, Fault, RuleSet, TxSlot, ViewRead,
};
use shekyl_types::BlockHeight;

use super::{judge, priced_floors, DoorFault, Judged};
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

/// A window the tip has dropped under is unpriced. A recorded window is
/// the floors. A view fault stays the validator's. Equal heights after a
/// re-read are still unpriced: nothing fills the window in afterwards.
#[test]
fn a_window_above_the_tip_is_a_fault_and_a_recorded_one_is_the_floors() {
    let asked = BlockHeight::from_raw(4);
    let now = BlockHeight::from_raw(3);
    assert_eq!(
        priced_floors::<std::convert::Infallible>(Ok(AtHeight::AboveTip), asked, now),
        Err(DoorFault::TipMoved { asked, now })
    );
    assert_eq!(
        priced_floors::<std::convert::Infallible>(Ok(AtHeight::AboveTip), asked, asked),
        Err(DoorFault::TipMoved { asked, now: asked })
    );
    assert_eq!(
        priced_floors::<std::convert::Infallible>(Ok(AtHeight::Recorded(vec![7, 8])), asked, now),
        Ok(vec![7, 8])
    );
    assert_eq!(
        priced_floors(
            Err(ViewRead::View(())),
            BlockHeight::ZERO,
            BlockHeight::ZERO
        ),
        Err(DoorFault::Chain(Fault::View(())))
    );
}
