// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures for the emission statics (`CHAIN_RULES_SLICE_8.md` §5 row 8).
//! Each refusal is asserted at both sites — the pool's `Lone` slot through
//! `tx_form`, and a `Listed` slot through `validate` — where the row is the
//! first to refuse; where an earlier row names the body first (H22 on a
//! missing commitment, H9 on an overflowing sum), the row is asked alone.
//! The positive control is the harness's parseable vin in a balanced body;
//! the positive witness for the rows' *meaning* — a claim the verify
//! accepts — is row 7's driven claim, not a body built here.

use super::{J19, J20, J22, J24};
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::harness::fixture::{
    balanced_emission, coinbase, emission_vin, listed, mask_committing, persona, point, signed,
};
use crate::rule_set::RuleSet;
use crate::rules::tx::{refused_listed, refused_lone};
use crate::rules::{TxContext, TxRule};
use crate::validate::tx_form;
use crate::verdict::TxSlot;
use shekyl_archival_retention::RewardCommit;
use shekyl_wire::{Ct, Input, Transaction};

/// The claimant's tag; `persona([TAG; 32])` is who the vin names.
const TAG: u8 = 0x19;

/// The bytes of a parseable vin claiming epoch 1 as [`TAG`]'s persona.
fn vin_bytes() -> Vec<u8> {
    let Input::ArchivalRewardEmission { canonical_bytes } = emission_vin(TAG, &[1]) else {
        unreachable!("emission_vin builds an emission input");
    };
    canonical_bytes
}

/// A balanced emission paying `reward` with the parseable vin: the body
/// every row here admits through `tx_form`.
fn claim(reward: u64) -> Transaction {
    balanced_emission(point(13), vin_bytes(), reward)
}

/// `claim(5)` with the emission vin's bytes replaced.
fn claim_with_vin(canonical_bytes: Vec<u8>) -> Transaction {
    balanced_emission(point(13), canonical_bytes, 5)
}

/// The emission slot's auth — index 1, after the fee spend.
fn slot_key(tx: &mut Transaction) -> &mut Vec<u8> {
    let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct else {
        panic!("an emission is an Fcmp ct");
    };
    &mut pqc_auths[1].hybrid_public_key
}

/// The transaction's context at the pool's slot.
fn lone<'tx>(tx: &'tx Transaction, coverage: &mut RuleCoverage) -> TxContext<'tx> {
    TxContext::derive(tx, TxSlot::Lone, coverage).expect("the body classifies")
}

/// The positive control passes every row at the pool's slot, and the four
/// are recorded — on the emission, and vacuous on a spend and the coinbase.
#[test]
fn the_balanced_claim_passes_the_four_statics_and_they_record_vacuous_off_class() {
    for (name, tx, slot) in [
        ("claim", claim(5), TxSlot::Lone),
        ("spend", listed(point(9)), TxSlot::Lone),
        ("coinbase", coinbase(0), TxSlot::Miner),
    ] {
        let form = tx_form(&tx, slot, &RuleSet::GENESIS).unwrap_or_else(|r| panic!("{name}: {r}"));
        for row in [CenRow::J19, CenRow::J20, CenRow::J22, CenRow::J24] {
            assert!(form.contains(row), "{name}: {row:?} not recorded");
        }
    }
}

/// CEN-J19: the vin's bytes parse as an emission vin and are consumed
/// exactly — the type's minimum (empty), a truncated vin, a vin with a
/// trailing byte and a tag with no body are refused at both sites. The
/// balanced shape has already passed H22, so the parse is what names them.
#[test]
fn j19_the_vin_parses_and_is_consumed_exactly() {
    let whole = vin_bytes();
    let mut truncated = whole.clone();
    truncated.truncate(whole.len() - 1);
    let mut trailing = whole.clone();
    trailing.push(0x00);
    for (name, bytes) in [
        ("empty", Vec::new()),
        ("truncated", truncated),
        ("trailing byte", trailing),
        ("tag and nothing", vec![0x04, 0]),
    ] {
        assert!(J19::parse(&bytes).is_none(), "{name}: parses");
        let refused = claim_with_vin(bytes);
        refused_lone(&refused, CenRow::J19);
        refused_listed(&refused, CenRow::J19);
    }
    assert!(J19::parse(&whole).is_some());
}

/// CEN-J20: the emission slot's hybrid key derives the vin's
/// `P_canonical_id`. A stranger persona's key in the slot is refused at
/// both sites; a key of the wrong length is I16's first through `tx_form`
/// and this row's alone, as is a slot the body does not carry and a vin
/// the row cannot read. Signing the body ([`signed`]) keeps the slot the
/// persona's: the fixture signer derives the slot's key from the identity
/// seed of the persona the vin names, so what reaches `tx_against` still
/// passes this row.
#[test]
fn j20_the_slot_key_derives_the_vins_persona() {
    let stranger = persona([0x4c; 32]);
    let mut strangers_key = claim(5);
    *slot_key(&mut strangers_key) = stranger.identity;
    refused_lone(&strangers_key, CenRow::J20);
    refused_listed(&strangers_key, CenRow::J20);

    let alone_refuses = |name: &str, tx: &Transaction| {
        let mut coverage = RuleCoverage::EMPTY;
        let cx = lone(tx, &mut coverage);
        assert!(J20::check(&cx).is_err(), "{name}: J20 admits it");
    };
    let mut short = claim(5);
    slot_key(&mut short).truncate(5);
    alone_refuses("short key", &short);
    let mut empty = claim(5);
    slot_key(&mut empty).clear();
    alone_refuses("empty key", &empty);
    let mut no_slot = claim(5);
    if let Ct::Fcmp { pqc_auths, .. } = &mut no_slot.ct {
        pqc_auths.pop();
    }
    alone_refuses("no slot", &no_slot);
    alone_refuses("unreadable vin", &claim_with_vin(Vec::new()));

    let claimant = persona([TAG; 32]);
    let signed_claim = signed(claim(5));
    let Ct::Fcmp { pqc_auths, .. } = &signed_claim.ct else {
        panic!("an emission is an Fcmp ct");
    };
    assert_eq!(
        pqc_auths[1].hybrid_public_key, claimant.identity,
        "the signer keys the emission slot with the claimant's identity"
    );
    let mut coverage = RuleCoverage::EMPTY;
    J20::check(&lone(&signed_claim, &mut coverage)).expect("the signed claim passes J20");
}

/// CEN-J22: the signable hash is the prefix hash with the emission vin
/// removed — equal to the wire's hash of the prefix so edited, unequal to
/// the full prefix hash (the erase is load-bearing), and independent of
/// the vin's bytes (two claims differing only in the vin sign over the
/// same hash: the vin is re-bound by the Q1 auth message, not by this).
/// `None` off the emission class.
#[test]
fn j22_the_signable_hash_is_the_prefix_without_the_vin() {
    let tx = claim(5);
    let mut coverage = RuleCoverage::EMPTY;
    let signable = J22::signable_hash(&lone(&tx, &mut coverage)).expect("an emission");

    let mut erased = tx.clone();
    erased.prefix.inputs.remove(1);
    assert_eq!(
        signable,
        erased.prefix_hash(),
        "the wire's hash of the vin-less prefix"
    );
    assert_ne!(signable, tx.prefix_hash(), "the erase is load-bearing");

    let Input::ArchivalRewardEmission { canonical_bytes } = emission_vin(TAG, &[1, 2]) else {
        unreachable!("emission_vin builds an emission input");
    };
    let other_vin = claim_with_vin(canonical_bytes);
    assert_ne!(other_vin.prefix_hash(), tx.prefix_hash());
    assert_eq!(
        J22::signable_hash(&lone(&other_vin, &mut coverage)).expect("an emission"),
        signable,
        "the vin's bytes are outside the signable hash"
    );

    let spend = listed(point(9));
    assert!(J22::signable_hash(&lone(&spend, &mut coverage)).is_none());
}

/// CEN-J24: the reward commit set is the loud vouts in vout order as
/// `(commitment, amount, one-time key)`, and the total is their checked
/// sum. One loud vout gives one entry; making the second vout loud too
/// (re-balanced) gives two, in order, summing to both. A missing
/// commitment and an overflowing sum are refused — H17 (one mask per
/// output) and H9 name those first through `tx_form`, so the row is asked
/// alone. `None` off class.
#[test]
fn j24_the_reward_commit_set_is_the_loud_vouts_in_order() {
    let mut coverage = RuleCoverage::EMPTY;
    let one = claim(5);
    let (commits, sum) = J24::reward_commits(&lone(&one, &mut coverage))
        .expect("well-defined")
        .expect("an emission");
    let Ct::Fcmp { base, .. } = &one.ct else {
        panic!("an emission is an Fcmp ct");
    };
    assert_eq!(
        commits,
        vec![RewardCommit {
            commitment: base.commitments[0],
            amount_plain: 5,
            one_time_key: one.prefix.outputs[0].key,
        }]
    );
    assert_eq!(sum, 5);

    // Both vouts loud: `2·G + 5·H` and `3·G + 3·H` against the pseudo-out
    // `5·G` with a reward of 8 — still balanced, so `tx_form` admits it.
    let mut two = claim(5);
    two.prefix.outputs[1].amount = 3;
    if let Ct::Fcmp { base, .. } = &mut two.ct {
        base.commitments[1] = mask_committing(3, 3);
    }
    tx_form(&two, TxSlot::Lone, &RuleSet::GENESIS).expect("two loud vouts balance");
    let (commits, sum) = J24::reward_commits(&lone(&two, &mut coverage))
        .expect("well-defined")
        .expect("an emission");
    let Ct::Fcmp { base, .. } = &two.ct else {
        panic!("an emission is an Fcmp ct");
    };
    assert_eq!(commits.len(), 2);
    assert_eq!(
        (
            commits[1].commitment,
            commits[1].amount_plain,
            commits[1].one_time_key
        ),
        (base.commitments[1], 3, two.prefix.outputs[1].key),
        "vout order"
    );
    assert_eq!(sum, 8);

    let mut missing_commitment = claim(5);
    if let Ct::Fcmp { base, .. } = &mut missing_commitment.ct {
        base.commitments.pop();
    }
    assert!(J24::check(&lone(&missing_commitment, &mut coverage)).is_err());
    refused_lone(&missing_commitment, CenRow::H17);

    let mut overflowing = claim(u64::MAX);
    overflowing.prefix.outputs[1].amount = 1;
    assert!(J24::check(&lone(&overflowing, &mut coverage)).is_err());
    refused_lone(&overflowing, CenRow::H9);

    let spend = listed(point(9));
    assert!(J24::reward_commits(&lone(&spend, &mut coverage))
        .expect("well-defined")
        .is_none());
}

/// The band's order is the C++ arm's: a body whose vin does not parse and
/// whose slot key is a stranger's is J19's, not J20's.
#[test]
fn the_parse_is_judged_before_the_slot() {
    let mut both = claim_with_vin(Vec::new());
    *slot_key(&mut both) = persona([0x4c; 32]).identity;
    refused_lone(&both, CenRow::J19);
}
