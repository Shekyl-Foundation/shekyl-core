// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-H7, H11, H17, H18, H21 and H22. The balance fixtures live here so
//! `tx_tests` stays the classification, the limits, and the rows whose
//! subject is not a curve.

use super::{emission, refused_listed, refused_lone, with_inputs, KI};
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::harness::fixture::{
    anchored_on, balanced_emission, candidate_on, coinbase, emission_vin, join_market, listed,
    mask_committing, multiple_of_g, point, serve_credit_only, spendable_chain, G, TWO_G,
};
use crate::harness::{assert_refused, formed_on, judged};
use crate::rule_set::RuleSet;
use crate::rules::tx::{TxContext, H17, H7};
use crate::rules::TxRule;
use crate::trust::Trust;
use crate::validate::{tx_form, validate};
use crate::verdict::{Locus, TxSlot};
use shekyl_wire::{Ct, Input, Transaction};

// ---- the adopted crypto rows: H7, H17, H18, H21, H22 --------------------

/// A **balanced bond post** — the harness's [`join_market`] on `KI`
/// (slice 7 commit 7 moved the shape into the harness so the ingest's
/// mutation family can build the pair CEN-G10 refuses; DRS-E4 commit 4
/// made it the join, the one post that connects with no record to fold
/// over — CEN-L7 refuses a release or reinstate for a persona it does not
/// know). Its credit is the bond floor.
fn bond_post_tx() -> Transaction {
    join_market(KI, [0xB0; 32])
}

/// A **balanced emission** paying `reward` — the harness's
/// [`balanced_emission`] with the fee spend at point 13 and a parseable
/// vin claiming epoch 1 as the persona tagged `0x13` (slice 8 row 8: the
/// emission statics J19 and J20 read the vin and the slot's key, so the
/// positive control carries a vin they admit).
fn emission_tx(reward: u64) -> Transaction {
    let Input::ArchivalRewardEmission { canonical_bytes } = emission_vin(0x13, &[1]) else {
        unreachable!("emission_vin builds an emission input");
    };
    balanced_emission(point(13), canonical_bytes, reward)
}

/// The balanced archival fixtures pass every landed row at both sites —
/// the positive controls for H21 and H22, and a check that `mask_committing`
/// is doing what it claims (a balance that holds is the only witness a
/// test can have for it). **`h14_loud_amounts_are_refused_except_on_an_emission`
/// depends on this test** for the evidence that H14 is reached through
/// `tx_form` on an emission: it asserts its loud case on `H14::check`
/// alone because the whole form needs the balance fixtured here. Narrowing
/// this test narrows that one.
///
/// The join connects; the emission's form passes and its connect is not
/// judged here: a claim needs the claimant's record and a **settled**
/// epoch (CEN-L7 re-runs claimability at the connect), which no chain
/// short enough for a unit test carries — the connected claim is the
/// scenario driver's (`DRS_E4_ARCHIVAL_WRITER.md` §5.2, commit 5).
#[test]
fn balanced_bond_post_and_emission_fixtures_pass() {
    for tx in [bond_post_tx(), emission_tx(5)] {
        let form = tx_form(&tx, TxSlot::Lone, &RuleSet::GENESIS)
            .unwrap_or_else(|r| panic!("the balanced fixture passes: {r}"));
        assert!(form.contains(CenRow::H21) && form.contains(CenRow::H22));
    }
    refused_listed_never(&bond_post_tx());
}

/// The transaction, listed first, connects — on the youngest chain that
/// can list a spend, anchored on it. A spend's reference and an emission's
/// reference (CEN-J21, including no fee input) are a block the chain holds.
fn refused_listed_never(tx: &Transaction) {
    let chain = spendable_chain();
    chain.with_view(|view| {
        let formed = formed_on(
            &chain,
            candidate_on(&chain, vec![anchored_on(&chain, tx.clone())]),
        );
        judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .unwrap_or_else(|r| panic!("the fixture connects: {r}"));
    });
}

// ---- CEN-H7 -------------------------------------------------------------

/// An output key that is not a point is refused on H7 — listed at both
/// sites, and at the miner slot too (the C++ runs `check_outs_valid` on
/// the coinbase; F9 judges the same key under its own row in `form`, so
/// the miner case is asserted on the rule alone).
#[test]
fn h7_a_non_point_output_key_is_refused_everywhere() {
    let mut tx = listed(KI);
    tx.prefix.outputs[0].key = [0x80; 32];
    refused_lone(&tx, CenRow::H7);
    refused_listed(&tx, CenRow::H7);
    let mut miner = coinbase(1);
    miner.prefix.outputs[0].key = [0x80; 32];
    let mut coverage = RuleCoverage::EMPTY;
    let cx = TxContext::derive(&miner, TxSlot::Miner, &mut coverage).expect("the coinbase");
    assert_refused(
        H7::check(&cx),
        CenRow::H7,
        Locus::Tx {
            slot: TxSlot::Miner,
        },
    );
}

// ---- CEN-H11 ------------------------------------------------------------

/// A key image that is not a point, the identity, and a small-order point
/// are each refused on H11 (at both sites for the first); a table point
/// passes; archival vins carry no image and a serve credit records the row
/// vacuously satisfied.
#[test]
fn h11_a_non_point_identity_or_torsion_key_image_is_refused() {
    let with_image = |image: [u8; 32]| {
        with_inputs(vec![Input::ToKey {
            amount: 0,
            key_offsets: Vec::new(),
            key_image: image,
        }])
    };
    refused_lone(&with_image([0xC1; 32]), CenRow::H11);
    refused_listed(&with_image([0xC1; 32]), CenRow::H11);
    // The identity: `y = 1`, `x = 0`.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    refused_lone(&with_image(identity), CenRow::H11);
    // The order-2 point `(0, −1)`: `y = p − 1`, a valid canonical encoding
    // that is not in the prime-order subgroup — `order·ki ≠ identity`.
    let mut order_two = [0xFFu8; 32];
    order_two[0] = 0xEC;
    order_two[31] = 0x7F;
    refused_lone(&with_image(order_two), CenRow::H11);
    assert!(tx_form(&listed(KI), TxSlot::Lone, &RuleSet::GENESIS)
        .expect("a table point is a valid image")
        .contains(CenRow::H11));
    assert!(tx_form(
        &serve_credit_only([0x77; 32]),
        TxSlot::Lone,
        &RuleSet::GENESIS
    )
    .expect("no image to hold")
    .contains(CenRow::H11));
}

// ---- CEN-H17 ------------------------------------------------------------

/// A mask that is `G` (the trivial mask), a non-point mask, and a mask
/// count that differs from the output count are each refused on H17 for a
/// spend; and on the coinbase, `zeroCommit(amount)` — `G` for a zero
/// amount — is refused where F10 refuses it too (asserted on the rule).
#[test]
fn h17_trivial_or_invalid_or_miscounted_masks_are_refused() {
    let with_mask = |mask: [u8; 32]| {
        let mut tx = listed(KI);
        if let Ct::Fcmp { base, .. } = &mut tx.ct {
            base.commitments = vec![mask];
        }
        tx
    };
    refused_lone(&with_mask(G), CenRow::H17);
    refused_listed(&with_mask(G), CenRow::H17);
    refused_lone(&with_mask([0xa0; 32]), CenRow::H17);
    let mut two_masks = listed(KI);
    if let Ct::Fcmp { base, .. } = &mut two_masks.ct {
        base.commitments.push(TWO_G);
    }
    refused_lone(&two_masks, CenRow::H17);
    let mut miner = coinbase(1);
    if let Ct::Null(base) = &mut miner.ct {
        base.commitments = vec![G];
    }
    let mut coverage = RuleCoverage::EMPTY;
    let cx = TxContext::derive(&miner, TxSlot::Miner, &mut coverage).expect("the coinbase");
    assert_refused(
        H17::check(&cx),
        CenRow::H17,
        Locus::Tx {
            slot: TxSlot::Miner,
        },
    );
}

// ---- CEN-H18 ------------------------------------------------------------

/// A spend whose pseudo-out does not equal its mask plus the fee is refused
/// on H18: a non-zero fee against an otherwise balanced pair, and a
/// pseudo-out of `G` against a mask of `2·G`. The archival shapes record
/// H18 vacuous.
#[test]
fn h18_an_unbalanced_spend_is_refused() {
    let mut fee = listed(KI);
    if let Ct::Fcmp { fee: f, .. } = &mut fee.ct {
        *f = 1;
    }
    refused_lone(&fee, CenRow::H18);
    refused_listed(&fee, CenRow::H18);
    let mut short = listed(KI);
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut short.ct
    {
        p.pseudo_outs = vec![G];
    }
    refused_lone(&short, CenRow::H18);
    assert!(tx_form(
        &serve_credit_only([0x77; 32]),
        TxSlot::Lone,
        &RuleSet::GENESIS
    )
    .expect("a serve credit")
    .contains(CenRow::H18));
}

/// The balance is over the **amounts**, not only the blindings. Every other
/// H18 fixture has pure `k·G` masks — zero hidden amounts — so an
/// implementation that summed only the `G` components of the commitments
/// and dropped each `amount·H` would balance them exactly and pass. Here
/// two masks commit to distinct non-zero hidden amounts (`3` and `4`) under
/// blindings `2·G` and `3·G`, and the one pseudo-out must carry `5·G + 7·H`;
/// with a fee of `2` it must carry `5·G + 9·H`. A pseudo-out carrying the
/// blindings alone (`5·G`) is refused, as is one off by one amount.
#[test]
fn h18_the_balance_is_over_the_hidden_amounts_not_only_the_blindings() {
    let with_pseudo_out = |fee: u64, pseudo_out: [u8; 32]| {
        // `listed` already carries two outputs (I1); only the masks and the
        // pseudo-out change.
        let mut tx = listed(KI);
        if let Ct::Fcmp {
            fee: f,
            base,
            prunable: Some(p),
            ..
        } = &mut tx.ct
        {
            *f = fee;
            base.commitments = vec![mask_committing(2, 3), mask_committing(3, 4)];
            p.pseudo_outs = vec![pseudo_out];
        }
        tx
    };
    let balanced = with_pseudo_out(0, mask_committing(5, 7));
    assert!(tx_form(&balanced, TxSlot::Lone, &RuleSet::GENESIS)
        .expect("the amounts sum")
        .contains(CenRow::H18));
    refused_listed_never(&balanced);
    let with_fee = with_pseudo_out(2, mask_committing(5, 9));
    assert!(tx_form(&with_fee, TxSlot::Lone, &RuleSet::GENESIS)
        .expect("the amounts and the fee sum")
        .contains(CenRow::H18));
    // Blindings alone: what a G-only sum would accept.
    refused_lone(&with_pseudo_out(0, mask_committing(5, 0)), CenRow::H18);
    // The amounts summed wrong by one.
    refused_lone(&with_pseudo_out(0, mask_committing(5, 8)), CenRow::H18);
}

// ---- CEN-H21 ------------------------------------------------------------

/// Each departure from the bond-post shape, and an unbalanced credit, is
/// refused on H21: an auth count off by one, no funding spend, a pseudo-out
/// count off, an empty proof, both credit and debit set, a credit the
/// pseudo-out does not cover.
#[test]
fn h21_every_departure_from_the_bond_post_shape_or_balance_is_refused() {
    let base = bond_post_tx;
    let mut one_auth = base();
    if let Ct::Fcmp { pqc_auths, .. } = &mut one_auth.ct {
        pqc_auths.pop();
    }
    refused_lone(&one_auth, CenRow::H21);
    refused_listed(&one_auth, CenRow::H21);
    // No funding spend: a bond post alone — the class is BondPost{spends: 0}.
    let mut alone = base();
    alone.prefix.inputs.remove(0);
    if let Ct::Fcmp {
        pqc_auths,
        prunable: Some(p),
        ..
    } = &mut alone.ct
    {
        pqc_auths.pop();
        p.pseudo_outs.clear();
    }
    refused_lone(&alone, CenRow::H21);
    let mut two_pseudo = base();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut two_pseudo.ct
    {
        p.pseudo_outs.push(TWO_G);
    }
    refused_lone(&two_pseudo, CenRow::H21);
    let mut no_proof = base();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut no_proof.ct
    {
        p.fcmp_proof.clear();
    }
    refused_lone(&no_proof, CenRow::H21);
    let mut both_terms = base();
    if let Input::BondPost(bond) = &mut both_terms.prefix.inputs[1] {
        bond.bond_debit = 1;
    }
    refused_lone(&both_terms, CenRow::H21);
    let mut wrong_credit = base();
    if let Input::BondPost(bond) = &mut wrong_credit.prefix.inputs[1] {
        bond.bond_credit = 999;
    }
    refused_lone(&wrong_credit, CenRow::H21);
}

// ---- CEN-H22 ------------------------------------------------------------

/// Each departure from the emission shape, and an unbalanced reward, is
/// refused on H22: a zero reward, an auth count off, a pseudo-out count
/// off, a proof present with no fee spend (and absent with one), and a
/// reward the mask does not commit to. An overflowing reward is H9's first.
#[test]
fn h22_every_departure_from_the_emission_shape_or_balance_is_refused() {
    let base = || emission_tx(5);
    let mut zero = base();
    zero.prefix.outputs[0].amount = 0;
    if let Ct::Fcmp { base: b, .. } = &mut zero.ct {
        b.commitments = vec![TWO_G, multiple_of_g(3)];
    }
    refused_lone(&zero, CenRow::H22);
    refused_listed(&zero, CenRow::H22);
    let mut one_auth = base();
    if let Ct::Fcmp { pqc_auths, .. } = &mut one_auth.ct {
        pqc_auths.pop();
    }
    refused_lone(&one_auth, CenRow::H22);
    let mut two_pseudo = base();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut two_pseudo.ct
    {
        p.pseudo_outs.push(TWO_G);
    }
    refused_lone(&two_pseudo, CenRow::H22);
    // No fee spend, but a proof present: the class is Emission{spends: 0}.
    let mut no_spend_with_proof = with_inputs(vec![emission()]);
    no_spend_with_proof.prefix.outputs[0].amount = 5;
    if let Ct::Fcmp {
        base: b,
        prunable: Some(p),
        ..
    } = &mut no_spend_with_proof.ct
    {
        b.commitments = vec![mask_committing(2, 5), multiple_of_g(3)];
        p.pseudo_outs.clear();
    }
    refused_lone(&no_spend_with_proof, CenRow::H22);
    let mut spend_without_proof = base();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut spend_without_proof.ct
    {
        p.fcmp_proof.clear();
    }
    refused_lone(&spend_without_proof, CenRow::H22);
    let mut wrong_reward = base();
    wrong_reward.prefix.outputs[0].amount = 6;
    refused_lone(&wrong_reward, CenRow::H22);
}
