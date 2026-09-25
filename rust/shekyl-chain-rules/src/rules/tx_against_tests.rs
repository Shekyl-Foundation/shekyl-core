// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures for the view-bound 4.I rows landed so far — CEN-I7 through
//! `tx_against` at the pool's slot and through `validate` at a listed slot,
//! CEN-L1 through `validate` — and the two 4.I rows held by construction
//! (I2's falsifier lives here; I3's is `f2_the_wire_admits_one_transaction_version`).

use crate::census::CenRow;
use crate::harness::fixture::{
    anchored_on, candidate_on, coinbase, listed, listed_on, point, point_at, spend,
    spendable_chain, TWO_G,
};
use crate::harness::{
    assert_refused, credited_to_this_falsifier, formed_on, infallible, judged, Faulted,
    FaultingView, MockChain,
};
use crate::rule_set::RuleSet;
use crate::rules::tx::{refused_listed, refused_lone};
use crate::rules::tx_against::{REFERENCE_BLOCK_MAX_AGE, REFERENCE_BLOCK_MIN_AGE};
use crate::trust::Trust;
use crate::validate::{tx_against, validate};
use crate::verdict::{Locus, TxSlot};
use shekyl_types::KeyImage;
use shekyl_wire::transaction::CT_TYPE_FCMP;
use shekyl_wire::{Ct, CtBase, Input, Transaction};

const KI: [u8; 32] = point(9);

// ---- the reference window: pinned to the JSON authority ----------------

/// `REFERENCE_BLOCK_{MIN,MAX}_AGE` equal `config/consensus_constants.json`'s
/// `fcmp_reference_block_{min,max}_age` — read from the file, not from a
/// copy of the numbers, so an edit to the authority fails here rather than
/// leaving the validator's window behind the daemon's (slice 6 Q5, the
/// slice-5 Q5 pin shape over the JSON instead of the header: the header
/// derives from the JSON too).
#[test]
fn reference_window_is_the_json_authoritys() {
    let json: serde_json::Value =
        serde_json::from_str(include_str!("../../../../config/consensus_constants.json"))
            .expect("consensus_constants.json parses");
    let age = |key: &str| {
        json[key]
            .as_u64()
            .unwrap_or_else(|| panic!("consensus_constants.json carries {key} as an integer"))
    };
    assert_eq!(
        REFERENCE_BLOCK_MIN_AGE.to_raw(),
        age("fcmp_reference_block_min_age")
    );
    assert_eq!(
        REFERENCE_BLOCK_MAX_AGE.to_raw(),
        age("fcmp_reference_block_max_age")
    );
    assert!(
        REFERENCE_BLOCK_MAX_AGE.to_raw() > REFERENCE_BLOCK_MIN_AGE.to_raw(),
        "the window is non-empty (cryptonote_config.h's static_assert)"
    );
}

// ---- CEN-I7 -------------------------------------------------------------

/// A spend of a key image the chain has recorded is refused on I7 at the
/// pool's slot; the same body with a fresh image passes and records the
/// row. Both through `tx_against`, the entry point the pool calls.
#[test]
fn i7_a_spent_key_image_is_refused_and_a_fresh_one_records() {
    let chain = spendable_chain().with_key_image(KeyImage::from_bytes(KI));
    chain.with_view(|view| {
        assert_refused(
            infallible(tx_against(
                &listed_on(&chain, KI),
                TxSlot::Lone,
                &view,
                &RuleSet::GENESIS,
            )),
            CenRow::I7,
            Locus::Input {
                slot: TxSlot::Lone,
                input: 0,
            },
        );
        let fresh = infallible(tx_against(
            &listed_on(&chain, point(10)),
            TxSlot::Lone,
            &view,
            &RuleSet::GENESIS,
        ))
        .expect("an unspent image passes");
        assert!(fresh.contains(CenRow::I7));
    });
}

/// The same refusal at a listed slot through `validate`, re-homed from
/// `Lone` to `Listed(n)` — the transaction's position, not the pool's.
#[test]
fn i7_at_a_listed_slot_the_refusal_names_the_slot() {
    let chain = spendable_chain().with_key_image(KeyImage::from_bytes(point(11)));
    chain.with_view(|view| {
        let block = candidate_on(
            &chain,
            vec![listed_on(&chain, point(10)), listed_on(&chain, point(11))],
        );
        let formed = formed_on(&chain, block);
        assert_refused(
            judged(validate(
                formed,
                &view,
                &RuleSet::GENESIS,
                &Trust::UNANCHORED,
            )),
            CenRow::I7,
            Locus::Input {
                slot: TxSlot::Listed(1),
                input: 0,
            },
        );
    });
}

/// Every `ToKey` input is looked up, whichever class carries it: a bond
/// post's funding spend of a recorded image is I7's refusal, as the C++'s
/// archival arms make it.
#[test]
fn i7_looks_up_an_archival_shapes_funding_spend_too() {
    let funding = point_at(23);
    let chain = spendable_chain().with_key_image(KeyImage::from_bytes(funding));
    // A two-input spend whose second input is the recorded image; the
    // class does not matter to the lookup, and a plain spend keeps the
    // fixture out of H21's balance arithmetic.
    let mut tx = listed_on(&chain, KI);
    tx.prefix.inputs.push(Input::ToKey {
        amount: 0,
        key_offsets: Vec::new(),
        key_image: funding,
    });
    // Descending images (I5) and one auth per input (I8) so `tx_form`
    // admits the shape and `tx_against` is what judges it.
    tx.prefix
        .inputs
        .sort_by_key(|input| core::cmp::Reverse(key_image_of(input)));
    if let Ct::Fcmp {
        pqc_auths,
        prunable: Some(p),
        ..
    } = &mut tx.ct
    {
        pqc_auths.push(pqc_auths[0].clone());
        // H18: two pseudo-outs summing to the masks (`2·G + 3·G`).
        p.pseudo_outs = vec![TWO_G, point(3)];
    }
    // The refusal names the input the recorded image sits at, wherever the
    // sort put it.
    let spent_at = tx
        .prefix
        .inputs
        .iter()
        .position(|input| key_image_of(input) == funding)
        .expect("the funding image is an input");
    chain.with_view(|view| {
        assert_refused(
            infallible(tx_against(&tx, TxSlot::Lone, &view, &RuleSet::GENESIS)),
            CenRow::I7,
            Locus::Input {
                slot: TxSlot::Lone,
                input: spent_at,
            },
        );
    });
}

fn key_image_of(input: &Input) -> [u8; 32] {
    match input {
        Input::ToKey { key_image, .. } => *key_image,
        _ => unreachable!("the fixture's inputs are spends"),
    }
}

/// The coinbase has no key image to look up: I7 is vacuous at the miner
/// slot and recorded as evaluated.
#[test]
fn i7_is_vacuous_on_the_coinbase() {
    let chain = MockChain::default();
    chain.with_view(|view| {
        let formed = formed_on(&chain, candidate_on(&chain, Vec::new()));
        let valid = judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("a block of one coinbase");
        assert!(valid.coverage().contains(CenRow::I7));
        assert!(valid.coverage().contains(CenRow::L1));
    });
}

/// A view that cannot answer is a fault, never a verdict: `tx_against`
/// propagates it and derives nothing.
#[test]
fn i7_propagates_a_view_fault() {
    let view = FaultingView::default();
    assert_eq!(
        tx_against(&listed(KI), TxSlot::Lone, &view, &RuleSet::GENESIS)
            .expect_err("the view faulted"),
        Faulted
    );
}

// ---- CEN-L1 -------------------------------------------------------------

/// Two listed transactions spending one key image — each admissible on its
/// own, since the chain has neither — are refused on L1 at the **second**
/// occurrence, naming the slot and the input. Without this row the block
/// would pass `validate` and meet the store's fatal SI-1 at connect.
#[test]
fn l1_a_key_image_twice_across_a_blocks_transactions_is_refused_at_the_second() {
    let chain = spendable_chain();
    chain.with_view(|view| {
        // Distinct transactions (different outputs) over the same image.
        let first = listed_on(&chain, KI);
        let mut second = anchored_on(&chain, spend(KI, 3));
        second.prefix.extra = crate::harness::fixture::pqc_extra(3);
        let block = candidate_on(&chain, vec![first, second]);
        let formed = formed_on(&chain, block);
        assert_refused(
            judged(validate(
                formed,
                &view,
                &RuleSet::GENESIS,
                &Trust::UNANCHORED,
            )),
            CenRow::L1,
            Locus::Input {
                slot: TxSlot::Listed(1),
                input: 0,
            },
        );
    });
}

/// L1 runs after every slot has passed: a block whose second transaction
/// fails a per-transaction row is refused on that row, not on L1, even
/// when the images collide — the C++'s `add_spent_key` is the last check
/// too.
#[test]
fn l1_runs_after_the_per_transaction_rows() {
    let chain = spendable_chain();
    chain.with_view(|view| {
        let first = listed_on(&chain, KI);
        let mut second = listed_on(&chain, KI);
        // The second transaction fails H15 (a `Null` CT off the coinbase).
        second.ct = Ct::Null(CtBase {
            enc_amounts: vec![[0x11; 9]; 2],
            enc_labels: vec![[0x22; 9]; 2],
            commitments: vec![TWO_G; 2],
        });
        let formed = formed_on(&chain, candidate_on(&chain, vec![first, second]));
        assert_refused(
            judged(validate(
                formed,
                &view,
                &RuleSet::GENESIS,
                &Trust::UNANCHORED,
            )),
            CenRow::H15,
            Locus::Tx {
                slot: TxSlot::Listed(1),
            },
        );
    });
}

/// A block of distinct spends passes and records L1.
#[test]
fn l1_distinct_images_pass_and_record() {
    let chain = spendable_chain();
    chain.with_view(|view| {
        let formed = formed_on(
            &chain,
            candidate_on(
                &chain,
                vec![listed_on(&chain, point(10)), listed_on(&chain, point(11))],
            ),
        );
        let valid = judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .expect("distinct images");
        assert!(valid.coverage().contains(CenRow::L1));
    });
}

// ---- CEN-I2, by construction ------------------------------------------

/// CEN-I2 — a non-coinbase transaction's CT is `FcmpPlusPlusPqc` — holds
/// by construction on the wire's type set plus H15: `Ct` has two variants,
/// the parser admits exactly two type bytes, and the `Null` variant off
/// the coinbase is H15's landed refusal. List-and-iterate (slice 5 Q6):
/// the row this falsifier is credited to is named, the type set is
/// walked, and H15's refusal is re-asserted here so the two halves of the
/// property fail in one place.
#[test]
fn i2_the_wire_admits_two_ct_types_and_h15_refuses_null_off_the_coinbase() {
    credited_to_this_falsifier(
        &[CenRow::I2],
        "i2_the_wire_admits_two_ct_types_and_h15_refuses_null_off_the_coinbase",
    );
    // The type byte leads the CT section, which is the tail of the
    // transaction: `varint(TX_VERSION) ‖ prefix ‖ Ct::write`.
    let tx = listed(KI);
    let mut ct = Vec::new();
    tx.ct.write(&mut ct).expect("Vec");
    let bytes = tx.serialize();
    let type_at = bytes.len() - ct.len();
    assert_eq!(bytes[type_at], CT_TYPE_FCMP);
    assert_eq!(&bytes[type_at..], ct.as_slice());
    assert!(Transaction::from_bytes(&bytes).is_ok());
    for other in [0x02u8, 0x03, 0x7F, 0xFF] {
        let mut mutated = bytes.clone();
        mutated[type_at] = other;
        assert!(
            Transaction::from_bytes(&mutated).is_err(),
            "ct type {other:#04x} must not decode"
        );
    }
    // The one other type the wire admits is `Null`, and off the coinbase it
    // is H15's refusal at both sites.
    let mut null = listed(KI);
    null.ct = Ct::Null(CtBase {
        enc_amounts: vec![[0x11; 9]; 2],
        enc_labels: vec![[0x22; 9]; 2],
        commitments: vec![TWO_G; 2],
    });
    refused_lone(&null, CenRow::H15);
    refused_listed(&null, CenRow::H15);
    // And on the coinbase `Null` is the shape (F3): the type set has no
    // third member for either slot to reach.
    let _ = coinbase(1);
}
