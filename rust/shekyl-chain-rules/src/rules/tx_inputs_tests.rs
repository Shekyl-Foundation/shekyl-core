// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures for the stateless 4.I rows. Each refusal is asserted at both
//! sites — the pool's `Lone` slot through `tx_form`, and a `Listed` slot
//! through `validate`.

use super::{I14, I5};
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::harness::fixture::{coinbase, listed, point, serve_credit_only, G, TWO_G};
use crate::rule_set::RuleSet;
use crate::rules::tx::{emission, refused_listed, refused_lone, spend, with_inputs};
use crate::rules::TxContext;
use crate::rules::TxRule;
use crate::validate::tx_form;
use crate::verdict::TxSlot;
use shekyl_wire::{Ct, Input, Transaction};

/// The fixture spend's key image, the same point `tx_tests` pins.
const KI: [u8; 32] = point(9);

// ---- census 4.I, the stateless rows (slice 6 commit 2) ------------------
//
// Each row's refusal at both sites (the pool's `Lone` slot through
// `tx_form`; a `Listed` slot through `validate`), the last admitted value
// beside the first refused where the row has an edge, and the vacuous
// record on the coinbase. The wire twin's self-arming arms in
// `tx_conformance_tests` hold the crate to seven of these rows on the
// twin's own trips; these are the rows' own fixtures.

/// A well-formed two-input spend: images descending (I5), one auth per
/// input (I8), two pseudo-outs summing to the masks (`4·G + G = 2·G +
/// 3·G`, H18), the fixture's two outputs (I1).
fn two_input_spend() -> Transaction {
    // The pinned table has sixteen points; images past it are computed.
    let (a, b) = (
        crate::harness::fixture::point_at(21),
        crate::harness::fixture::point_at(22),
    );
    let (hi, lo) = if a > b { (a, b) } else { (b, a) };
    let image = |key_image| Input::ToKey {
        amount: 0,
        key_offsets: Vec::new(),
        key_image,
    };
    let mut tx = with_inputs(vec![image(hi), image(lo)]);
    if let Ct::Fcmp {
        pqc_auths,
        prunable: Some(p),
        ..
    } = &mut tx.ct
    {
        pqc_auths.push(crate::harness::fixture::pqc_auth_filler());
        p.pseudo_outs = vec![crate::harness::fixture::multiple_of_g(4), G];
    }
    tx
}

/// The 4.I rows a coinbase records as vacuous: every one is `NonCoinbase`,
/// so the miner slot evaluates the premise and holds trivially.
#[test]
fn the_stateless_4i_rows_are_vacuous_on_the_coinbase() {
    let form = tx_form(&coinbase(3), TxSlot::Miner, &RuleSet::GENESIS).expect("a coinbase");
    for row in [
        CenRow::I1,
        CenRow::I4,
        CenRow::I5,
        CenRow::I6,
        CenRow::I8,
        CenRow::I9,
        CenRow::I14,
        CenRow::I16,
    ] {
        assert!(
            form.contains(row),
            "{row} recorded vacuous at the miner slot"
        );
    }
}

/// CEN-I1: two outputs are the last admitted count and one the first
/// refused, on a spend and on a bond post; a serve-credit response has
/// none and is exempt.
#[test]
fn i1_fewer_than_two_outputs_is_refused_except_on_a_serve_credit() {
    let one = crate::harness::fixture::spend(KI, 1);
    refused_lone(&one, CenRow::I1);
    refused_listed(&one, CenRow::I1);
    assert!(tx_form(&listed(KI), TxSlot::Lone, &RuleSet::GENESIS)
        .expect("two outputs")
        .contains(CenRow::I1));
    assert!(tx_form(
        &serve_credit_only([0x51; 32]),
        TxSlot::Lone,
        &RuleSet::GENESIS
    )
    .expect("a serve credit has no outputs and is exempt")
    .contains(CenRow::I1));
}

/// CEN-I4: eight inputs are admitted (the cap is `MAX_FCMP_INPUTS`, the
/// wire's mirror of `FCMP_MAX_INPUTS_PER_TX`), nine refused — at both
/// sites, and on what would be a Fakechain node: the C++ gates this on
/// `m_nettype != FAKECHAIN`; the rule does not read the nettype (rule 71).
#[test]
fn i4_the_ninth_input_is_refused_and_the_eighth_admitted() {
    let with_n = |n: usize| {
        // Images strictly descending, one auth each, and pseudo-outs that
        // still sum to the masks: `n − 1` of `G` and one of `5 − (n − 1)`
        // — kept positive by the counts used here.
        let mut images: Vec<[u8; 32]> = (30..30 + n as u64)
            .map(crate::harness::fixture::point_at)
            .collect();
        images.sort_unstable_by(|a, b| b.cmp(a));
        let mut tx = with_inputs(
            images
                .into_iter()
                .map(|key_image| Input::ToKey {
                    amount: 0,
                    key_offsets: Vec::new(),
                    key_image,
                })
                .collect(),
        );
        // Balance kept so H18 (which runs first) passes: `n` pseudo-outs of
        // `G` sum to `n·G`, and the two masks are set to `2·G + (n−2)·G`.
        // `n ≥ 8` here, so neither mask is `G` (H17's trivial mask).
        if let Ct::Fcmp {
            pqc_auths,
            base,
            prunable: Some(p),
            ..
        } = &mut tx.ct
        {
            *pqc_auths = vec![crate::harness::fixture::pqc_auth_filler(); n];
            p.pseudo_outs = vec![G; n];
            base.commitments = vec![
                TWO_G,
                crate::harness::fixture::multiple_of_g(u64::try_from(n).expect("small") - 2),
            ];
        }
        tx
    };
    let eight = with_n(shekyl_wire::transaction::MAX_FCMP_INPUTS);
    assert!(tx_form(&eight, TxSlot::Lone, &RuleSet::GENESIS)
        .expect("eight inputs are admitted")
        .contains(CenRow::I4));
    let nine = with_n(shekyl_wire::transaction::MAX_FCMP_INPUTS + 1);
    refused_lone(&nine, CenRow::I4);
    refused_listed(&nine, CenRow::I4);
}

/// CEN-I5: the images must strictly descend — an ascending pair is refused
/// at both sites, and an equal pair is refused (on H10 first, as the order
/// runs; on I5 when asked alone). Archival inputs between two spends are
/// skipped, not a reset.
#[test]
fn i5_ascending_or_equal_key_images_are_refused() {
    let mut ascending = two_input_spend();
    ascending.prefix.inputs.swap(0, 1);
    refused_lone(&ascending, CenRow::I5);
    refused_listed(&ascending, CenRow::I5);
    assert!(tx_form(&two_input_spend(), TxSlot::Lone, &RuleSet::GENESIS)
        .expect("descending passes")
        .contains(CenRow::I5));
    // Equal: H10 is first in `tx_form`; I5 alone refuses the same bytes.
    let equal = with_inputs(vec![spend(11), spend(11)]);
    refused_lone(&equal, CenRow::H10);
    let mut coverage = RuleCoverage::EMPTY;
    let cx = TxContext::derive(&equal, TxSlot::Lone, &mut coverage).expect("classifies");
    assert!(I5::check(&cx).is_err(), "I5 refuses a repeat on its own");
    // An archival input between two descending spends does not reset the
    // comparison: still admitted through I5 (the shape is H6's business).
    let mut interleaved = two_input_spend();
    interleaved.prefix.inputs.insert(1, emission());
    let mut coverage = RuleCoverage::EMPTY;
    let cx = TxContext::derive(&interleaved, TxSlot::Lone, &mut coverage).expect("classifies");
    assert!(I5::check(&cx).is_ok());
}

/// CEN-I6: any non-empty `key_offsets` is refused at both sites; the
/// offset list `[7, 0]` is CEN-H24's own trip, which can no longer be
/// reached on an admitted transaction (`h24_cannot_fire_on_an_input_i6_admits`).
#[test]
fn i6_key_offsets_are_refused() {
    let mut one_offset = listed(KI);
    if let Some(Input::ToKey { key_offsets, .. }) = one_offset.prefix.inputs.get_mut(0) {
        *key_offsets = vec![1];
    }
    refused_lone(&one_offset, CenRow::I6);
    refused_listed(&one_offset, CenRow::I6);
}

/// CEN-I8: a spend's auth count off the input count — one too few, one too
/// many — is refused at both sites. The bond post's and emission's counts
/// are H21's and H22's; the serve-credit's zero is H20's.
#[test]
fn i8_the_auth_count_must_equal_the_input_count_on_a_spend() {
    let mut fewer = two_input_spend();
    if let Ct::Fcmp { pqc_auths, .. } = &mut fewer.ct {
        pqc_auths.pop();
    }
    refused_lone(&fewer, CenRow::I8);
    refused_listed(&fewer, CenRow::I8);
    let mut more = listed(KI);
    if let Ct::Fcmp { pqc_auths, .. } = &mut more.ct {
        pqc_auths.push(crate::harness::fixture::pqc_auth_filler());
    }
    refused_lone(&more, CenRow::I8);
    refused_listed(&more, CenRow::I8);
}

/// CEN-I9: a spend's pseudo-out count off the input count is refused at
/// both sites — with the balance kept, so H18 is not what decides: two
/// inputs against one pseudo-out of `5·G` (the masks' sum).
#[test]
fn i9_the_pseudo_out_count_must_equal_the_input_count_on_a_spend() {
    let mut one_for_two = two_input_spend();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut one_for_two.ct
    {
        p.pseudo_outs = vec![crate::harness::fixture::multiple_of_g(5)];
    }
    refused_lone(&one_for_two, CenRow::I9);
    refused_listed(&one_for_two, CenRow::I9);
}

/// CEN-I14: a spend whose FCMP++ proof is empty is refused at both sites;
/// so is the storage-pruned form (no prunable region at all — its BP+
/// layout is H19's refusal first, so I14 is asked alone there).
#[test]
fn i14_an_empty_proof_on_a_spend_is_refused() {
    let mut empty = listed(KI);
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut empty.ct
    {
        p.fcmp_proof.clear();
    }
    refused_lone(&empty, CenRow::I14);
    refused_listed(&empty, CenRow::I14);
    let mut pruned = listed(KI);
    if let Ct::Fcmp { prunable, .. } = &mut pruned.ct {
        *prunable = None;
    }
    let mut coverage = RuleCoverage::EMPTY;
    let cx = TxContext::derive(&pruned, TxSlot::Lone, &mut coverage).expect("classifies");
    assert!(I14::check(&cx).is_err(), "no prunable region is no proof");
}

/// CEN-I16: each structural departure is refused at both sites — the
/// version, the flags, an unknown scheme, a solo key blob one byte off
/// either way, a multisig blob below the header and above the cap — and
/// the solo shape and a minimal multisig shape are admitted.
#[test]
fn i16_every_structural_departure_of_a_pqc_auth_is_refused() {
    use shekyl_crypto_pq::multisig::HYBRID_SCHEME_ID_MULTISIG;
    use shekyl_wire::transaction::{PQC_HYBRID_SINGLE_KEY_LEN, PQC_MAX_PUBLIC_KEY_BLOB};
    let with_auth = |edit: &dyn Fn(&mut shekyl_wire::PqcAuth)| {
        let mut tx = listed(KI);
        if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
            edit(&mut pqc_auths[0]);
        }
        tx
    };
    for (what, tx) in [
        ("version 2", with_auth(&|a| a.auth_version = 2)),
        ("flags set", with_auth(&|a| a.flags = 1)),
        ("scheme 3", with_auth(&|a| a.scheme_id = 3)),
        (
            "solo key one short",
            with_auth(&|a| a.hybrid_public_key.truncate(PQC_HYBRID_SINGLE_KEY_LEN - 1)),
        ),
        (
            "solo key one long",
            with_auth(&|a| a.hybrid_public_key.push(0)),
        ),
        (
            "multisig key below the header",
            with_auth(&|a| {
                a.scheme_id = HYBRID_SCHEME_ID_MULTISIG;
                a.hybrid_public_key = vec![0; 2];
            }),
        ),
        (
            "multisig key above the cap",
            with_auth(&|a| {
                a.scheme_id = HYBRID_SCHEME_ID_MULTISIG;
                a.hybrid_public_key = vec![0; PQC_MAX_PUBLIC_KEY_BLOB + 1];
            }),
        ),
    ] {
        let lone = tx_form(&tx, TxSlot::Lone, &RuleSet::GENESIS);
        assert!(
            matches!(&lone, Err(refused) if refused.rule == CenRow::I16),
            "{what}: {lone:?}"
        );
        refused_listed(&tx, CenRow::I16);
    }
    assert!(tx_form(&listed(KI), TxSlot::Lone, &RuleSet::GENESIS)
        .expect("the solo shape")
        .contains(CenRow::I16));
    let minimal_multisig = with_auth(&|a| {
        a.scheme_id = HYBRID_SCHEME_ID_MULTISIG;
        a.hybrid_public_key = vec![0; 3];
    });
    assert!(tx_form(&minimal_multisig, TxSlot::Lone, &RuleSet::GENESIS)
        .expect("the multisig header alone is I16's floor; the parse is I17/I18's")
        .contains(CenRow::I16));
}
