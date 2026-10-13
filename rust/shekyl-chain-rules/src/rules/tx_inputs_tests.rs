// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures for the stateless 4.I rows. Each refusal is asserted at both
//! sites — the pool's `Lone` slot through `tx_form`, and a `Listed` slot
//! through `validate`.

use super::{I14, I5, J12, J2, J28};
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::harness::fixture::{
    coinbase, join_market, listed, persona, point, serve_credit_only, G, TWO_G,
};
use crate::rule_set::RuleSet;
use crate::rules::tx::{emission, refused_listed, refused_lone, spend, with_inputs};
use crate::rules::TxContext;
use crate::rules::TxRule;
use crate::validate::tx_form;
use crate::verdict::TxSlot;
use shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridPublicKey;
use shekyl_types::archival::{ReceiptSignPk, RECEIPT_SIGN_PK_LEN};
use shekyl_wire::transaction::PQC_HYBRID_SINGLE_KEY_LEN;
use shekyl_wire::{BondPost, BondPostKind, Ct, Input, Transaction};

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
/// so is the storage-pruned form (no prunable region at all — its
/// pseudo-outs are gone with it, so H18's balance refuses first, measured
/// by `g5_the_storage_pruned_spend_is_refused_before_any_block_rule_sees_it`;
/// I14 is asked alone here).
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

/// CEN-G5, by construction (E6 slice 7 §3.3, commit 2 (b)): the C++ refuses
/// a block it holds only pruned bodies for because a pruned body has no
/// weight. In Rust a storage-pruned spend never reaches the block-level
/// rules at all — `tx_form` refuses it at both sites before any weight is
/// summed, and it names the row: **H18**, the cleartext balance, because the
/// pseudo-outs it sums live in the prunable region and are gone with it
/// (measured 2026-09-26; the plan's first guess was H19's layout half, and
/// the I14 test above said so too — both corrected to what `tx_form` does).
/// This is the fixture G5's registry entry credits; if the form stage ever
/// admitted a pruned body, this is the test that reds.
#[test]
fn g5_the_storage_pruned_spend_is_refused_before_any_block_rule_sees_it() {
    let mut pruned = listed(KI);
    if let Ct::Fcmp { prunable, .. } = &mut pruned.ct {
        *prunable = None;
    }
    refused_lone(&pruned, CenRow::H18);
    refused_listed(&pruned, CenRow::H18);
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

/// CEN-J2: one pruned pass record per serve-credit vin, each non-empty and
/// within `ARCHIVAL_SERVE_CREDIT_PRUNED_MAX_BYTES`. None, one too many and
/// an empty record are refused on J2, alone and listed; one record per
/// credit passes, for one credit and for two. The row is vacuous on a spend.
///
/// The upper bound is held on the rule itself: through `tx_form` a record
/// past it never reaches J2, because the bound (1,053,185 B) is above
/// `MAX_TX_SIZE` and CEN-H1 refuses the transaction first, as the C++ does.
#[test]
fn j2_one_bounded_record_per_serve_credit_vin() {
    use shekyl_wire::transaction::ARCHIVAL_SERVE_CREDIT_PRUNED_MAX_BYTES;
    let with_records = |credits: usize, records: Vec<Vec<u8>>| {
        let mut tx = serve_credit_only([0x77; 32]);
        let vin = tx.prefix.inputs[0].clone();
        tx.prefix.inputs = vec![vin; credits];
        if let Ct::Fcmp {
            prunable: Some(p), ..
        } = &mut tx.ct
        {
            p.serve_credit_pruned = records;
        }
        tx
    };
    let record = || vec![0x01, 0x02];
    for refused in [
        with_records(1, Vec::new()),
        with_records(1, vec![record(), record()]),
        with_records(2, vec![record()]),
        with_records(1, vec![Vec::new()]),
    ] {
        refused_lone(&refused, CenRow::J2);
        refused_listed(&refused, CenRow::J2);
    }
    for admitted in [
        with_records(1, vec![record()]),
        with_records(2, vec![record(), record()]),
    ] {
        assert!(tx_form(&admitted, TxSlot::Lone, &RuleSet::GENESIS)
            .expect("one bounded record per credit")
            .contains(CenRow::J2));
    }

    let on_the_rule = |tx: &Transaction| {
        let mut coverage = RuleCoverage::EMPTY;
        let cx = TxContext::derive(tx, TxSlot::Lone, &mut coverage).expect("a serve credit");
        J2::check(&cx)
    };
    let max = ARCHIVAL_SERVE_CREDIT_PRUNED_MAX_BYTES;
    let over = with_records(1, vec![vec![0x01; max + 1]]);
    assert!(on_the_rule(&over).is_err(), "a record past the bound");
    refused_lone(&over, CenRow::H1);
    assert!(
        on_the_rule(&with_records(1, vec![vec![0x01; max]])).is_ok(),
        "a record at the bound"
    );

    assert!(tx_form(&listed(KI), TxSlot::Lone, &RuleSet::GENESIS)
        .expect("a spend")
        .contains(CenRow::J2));
}

// ---- census 4.J, the stateless bond-post rows (slice 8 row 4) -----------

/// The persona every bond-post fixture here posts for.
const P: [u8; 32] = [0x4b; 32];

/// The fixture JoinMarket with its post edited: [`join_market`] is
/// balanced for the shape rows, so the row that fires is the one the edit
/// is for.
fn join_with(edit: impl FnOnce(&mut BondPost)) -> Transaction {
    let mut tx = join_market(KI, P);
    let post = tx
        .prefix
        .inputs
        .iter_mut()
        .find_map(|item| match item {
            Input::BondPost(post) => Some(post),
            _ => None,
        })
        .expect("the fixture join carries one post");
    edit(post);
    tx
}

/// CEN-J11: a post whose `p_canonical_id` is not the recompute over its
/// `hybrid_public_key` is refused, alone and listed — the hint naming
/// another persona (slice 8 row 2's pin, now the rule's), and the hint
/// one bit off. A short key and a long one are refused on the same row:
/// the length arm is the C++'s first, and a key of another length has no
/// recompute to match. The fixture join — the persona's key, its
/// recompute — passes; the row is vacuous on a spend and a coinbase.
#[test]
fn j11_the_hint_is_the_recompute_over_a_canonical_key() {
    let stranger = persona([0x4c; 32]);
    let one_bit_off = {
        let mut bytes = *persona(P).id.as_bytes();
        bytes[0] ^= 0x01;
        shekyl_types::PCanonicalId::from_bytes(bytes)
    };
    for refused in [
        join_with(|post| post.p_canonical_id = stranger.id),
        join_with(|post| post.p_canonical_id = one_bit_off),
        join_with(|post| post.hybrid_public_key.truncate(5)),
        join_with(|post| post.hybrid_public_key.push(0x00)),
        join_with(|post| post.hybrid_public_key.clear()),
    ] {
        refused_lone(&refused, CenRow::J11);
        refused_listed(&refused, CenRow::J11);
    }
    assert!(
        tx_form(&join_market(KI, P), TxSlot::Lone, &RuleSet::GENESIS)
            .expect("the fixture join recomputes")
            .contains(CenRow::J11)
    );
    for (name, tx, slot) in [
        ("spend", listed(KI), TxSlot::Lone),
        ("coinbase", coinbase(0), TxSlot::Miner),
    ] {
        assert!(
            tx_form(&tx, slot, &RuleSet::GENESIS)
                .unwrap_or_else(|r| panic!("{name}: {r}"))
                .contains(CenRow::J11),
            "{name}: J11 recorded vacuous"
        );
    }
}

/// CEN-J12: a JoinMarket whose `bond_spend_pk` is not canonical-length is
/// refused, alone and listed — short, long, empty. The fixture join
/// commits the persona's bond-spend key and passes; a Release carries no
/// key by the wire type and passes the row (the C++'s
/// `join_market_coupled_fields_absent`, unrepresentable here); the row is
/// vacuous on a spend. A short key with a bad hint is J11's: the C++
/// judges the key and hint first.
#[test]
fn j12_a_join_market_commits_a_canonical_bond_spend_pk() {
    let with_bond_spend_pk = |edit: fn(&mut Vec<u8>)| {
        join_with(|post| {
            if let BondPostKind::JoinMarket { bond_spend_pk, .. } = &mut post.kind {
                edit(bond_spend_pk);
            }
        })
    };
    for refused in [
        with_bond_spend_pk(|pk| pk.truncate(5)),
        with_bond_spend_pk(|pk| pk.push(0x00)),
        with_bond_spend_pk(Vec::clear),
    ] {
        refused_lone(&refused, CenRow::J12);
        refused_listed(&refused, CenRow::J12);
    }
    let release = join_with(|post| {
        post.kind = BondPostKind::Other(shekyl_archival_retention::BondPostKind::Release as u8);
        post.bond_credit = 0;
    });
    for (name, tx) in [("join", join_market(KI, P)), ("release", release)] {
        let mut coverage = RuleCoverage::EMPTY;
        let cx = TxContext::derive(&tx, TxSlot::Lone, &mut coverage)
            .unwrap_or_else(|r| panic!("{name} classifies: {r}"));
        J12::check(&cx).unwrap_or_else(|r| panic!("{name} passes J12: {r}"));
    }
    assert!(
        tx_form(&join_market(KI, P), TxSlot::Lone, &RuleSet::GENESIS)
            .expect("the fixture join commits its key")
            .contains(CenRow::J12)
    );
    assert!(tx_form(&listed(KI), TxSlot::Lone, &RuleSet::GENESIS)
        .expect("a spend")
        .contains(CenRow::J12));

    let both = join_with(|post| {
        post.hybrid_public_key.truncate(5);
        if let BondPostKind::JoinMarket { bond_spend_pk, .. } = &mut post.kind {
            bond_spend_pk.truncate(5);
        }
    });
    refused_lone(&both, CenRow::J11);
}

// ---- census 4.J, the JoinMarket's receipt key (FN-DSA increment 3) -------

/// The fixture JoinMarket with its receipt key replaced by `key`.
fn join_committing(key: ReceiptSignPk) -> Transaction {
    join_with(|post| match &mut post.kind {
        BondPostKind::JoinMarket {
            receipt_sign_pk, ..
        } => *receipt_sign_pk = key,
        BondPostKind::Other(_) => panic!("the fixture join is a JoinMarket"),
    })
}

/// The canonical encoding's offsets (`hybrid_combiner::encode_canonical`):
/// `version ‖ scheme ‖ reserved(2) ‖ len(4) ‖ ed25519(32) ‖ len(4) ‖ fn_dsa`.
const VERSION_AT: usize = 0;
const SCHEME_AT: usize = 1;
const RESERVED_AT: usize = 2;
const ED25519_LEN_AT: usize = 4;
const ED25519_AT: usize = 8;
const FN_DSA_LEN_AT: usize = 40;
const FN_DSA_AT: usize = 44;

/// CEN-J28, the accept: the fixture JoinMarket commits its persona's real
/// derived receipt key and passes `tx_form` with the row recorded; it
/// re-parses to the same JoinMarket with the same key. A Release carries no
/// receipt key and passes the row; it is recorded on a spend and a coinbase.
/// There is no keyless JoinMarket to try: the type has no such value and
/// the wire refuses the retired byte (below).
#[test]
fn j28_a_join_market_s_receipt_key_that_is_a_key_is_admitted() {
    let key = persona(P).receipt;
    FnDsaHybridPublicKey::from_receipt_sign_pk(&key).expect("the derived key parses");

    let join = join_market(KI, P);
    assert!(tx_form(&join, TxSlot::Lone, &RuleSet::GENESIS)
        .expect("a JoinMarket committing a real receipt key forms")
        .contains(CenRow::J28));
    let reparsed = Transaction::from_bytes(&join.serialize()).expect("re-parses");
    assert_eq!(reparsed, join);
    let carried = reparsed.prefix.inputs.iter().find_map(|item| match item {
        Input::BondPost(post) => match &post.kind {
            BondPostKind::JoinMarket {
                receipt_sign_pk, ..
            } => Some(receipt_sign_pk.clone()),
            BondPostKind::Other(_) => None,
        },
        _ => None,
    });
    assert_eq!(carried, Some(key));

    let release = join_with(|post| {
        post.kind = BondPostKind::Other(shekyl_archival_retention::BondPostKind::Release as u8);
        post.bond_credit = 0;
    });
    let mut coverage = RuleCoverage::EMPTY;
    let cx = TxContext::derive(&release, TxSlot::Lone, &mut coverage).expect("classifies");
    J28::check(&cx).expect("a release carries no receipt key");
    for (name, tx, slot) in [
        ("spend", listed(KI), TxSlot::Lone),
        ("coinbase", coinbase(0), TxSlot::Miner),
    ] {
        assert!(
            tx_form(&tx, slot, &RuleSet::GENESIS)
                .unwrap_or_else(|r| panic!("{name}: {r}"))
                .contains(CenRow::J28),
            "{name}: J28 recorded"
        );
    }
}

/// One edit of a canonical receipt key's bytes. The key type has no
/// mutator — a chain-carried type is not edited in place — so a test edits
/// a copy of the bytes and wraps it with `ReceiptSignPk::from_bytes`.
type KeyEdit = Box<dyn Fn(&mut [u8; RECEIPT_SIGN_PK_LEN])>;

/// CEN-J28, the refusals — one per way the canonical parse fails, each
/// **one edit** of the real key (the type holds the length, so a string of
/// 1,837 bytes is all that can reach the rule), alone and listed:
///
/// - the FN-DSA half does not decode — its header byte, and a coefficient
///   past the modulus (fourteen set bits is 16,383 > q = 12,289);
/// - the Ed25519 half is not a curve point;
/// - the version is not 1; the scheme byte is not 3 (the identity key's
///   scheme, 1, among them: an ML-DSA header on FN-DSA bytes is not a
///   receipt key); the reserved field is not zero;
/// - an inner length prefix disagrees with the scheme's fixed length.
///
/// **Red edit:** delete `J28` from `tx_form`'s `judge_tx!` line in
/// `validate.rs` (or make `J28::check` return `Ok(())`) and every refusal
/// below is admitted — nothing else in `tx_form` reads the key's content.
#[test]
fn j28_a_receipt_key_that_does_not_parse_is_refused() {
    let key = persona(P).receipt;
    // A compressed Edwards y with no x on the curve. Asserted below, with
    // every other mutation, to be a string the parse refuses.
    let not_a_point = {
        let mut y = [0u8; 32];
        y[0] = 2;
        y
    };
    let edits: [(&str, KeyEdit); 9] = [
        ("fn-dsa header byte", Box::new(|k| k[FN_DSA_AT] ^= 0xff)),
        (
            "fn-dsa coefficient past q",
            Box::new(|k| k[FN_DSA_AT + 1..FN_DSA_AT + 8].fill(0xff)),
        ),
        (
            "fn-dsa half all ones",
            Box::new(|k| k[FN_DSA_AT..].fill(0xff)),
        ),
        (
            "ed25519 half not a point",
            Box::new(move |k| {
                k[ED25519_AT..FN_DSA_LEN_AT].copy_from_slice(&not_a_point);
            }),
        ),
        ("version 2", Box::new(|k| k[VERSION_AT] = 2)),
        ("scheme 1 (ML-DSA)", Box::new(|k| k[SCHEME_AT] = 1)),
        ("reserved non-zero", Box::new(|k| k[RESERVED_AT] = 1)),
        ("ed25519 length 31", Box::new(|k| k[ED25519_LEN_AT] = 31)),
        (
            "fn-dsa length off by one",
            Box::new(|k| k[FN_DSA_LEN_AT] ^= 1),
        ),
    ];
    for (name, edit) in &edits {
        let mut bytes = *key.as_bytes();
        edit(&mut bytes);
        let bad = ReceiptSignPk::from_bytes(bytes);
        assert_ne!(bad, key, "{name}: the edit changed the key");
        assert!(
            FnDsaHybridPublicKey::from_receipt_sign_pk(&bad).is_err(),
            "{name}: the mutation is a string the parse refuses"
        );
        let refused = join_committing(bad);
        // It is on the wire: the parser admits the length, so the rule is
        // what stands between this string and the record.
        assert_eq!(
            Transaction::from_bytes(&refused.serialize()).expect("canonical length parses"),
            refused,
            "{name}"
        );
        refused_lone(&refused, CenRow::J28);
        refused_listed(&refused, CenRow::J28);
    }

    // All zeros and all ones: no header at all.
    for fill in [0x00u8, 0xff] {
        let refused = join_committing(ReceiptSignPk::from_bytes([fill; RECEIPT_SIGN_PK_LEN]));
        refused_lone(&refused, CenRow::J28);
        refused_listed(&refused, CenRow::J28);
    }
}

/// A JoinMarket with no receipt key does not exist for CEN-J28 to judge:
/// the fixture join's bytes with the kind byte set back to the retired
/// keyless `0` do not parse, and neither do they with the key cut out under
/// kind 5. And the older rows name first: a post wrong in `bond_spend_pk`
/// too is J12's, and one wrong in its hint J11's.
#[test]
fn j28_no_join_market_without_a_key_parses_and_older_rows_name_first() {
    let join = join_market(KI, P);
    let bytes = join.serialize();
    let post_bytes = {
        let mut out = Vec::new();
        join.prefix
            .inputs
            .iter()
            .find(|item| matches!(item, Input::BondPost(_)))
            .expect("the fixture join carries one post")
            .write(&mut out)
            .expect("the post writes");
        out
    };
    let post_at = bytes
        .windows(post_bytes.len())
        .position(|w| w == post_bytes)
        .expect("the post's bytes are in the transaction's");
    // tag ‖ varint(1996) ‖ identity ‖ hint, then the kind byte.
    let kind_at = post_at + 1 + 2 + PQC_HYBRID_SINGLE_KEY_LEN + 32;
    assert_eq!(
        bytes[kind_at],
        shekyl_wire::transaction::BOND_POST_KIND_JOINMARKET
    );
    let mut retired = bytes.clone();
    retired[kind_at] = 0;
    let err = Transaction::from_bytes(&retired).expect_err("post_kind 0 does not parse");
    assert!(
        err.to_string()
            .contains("post_kind 0 is the retired keyless JoinMarket"),
        "{err}"
    );
    // The keyless layout under the live byte: cut `varint(1837) ‖ key`.
    let key_field_at = kind_at + 1 + 2 + PQC_HYBRID_SINGLE_KEY_LEN;
    let mut keyless = bytes.clone();
    keyless.drain(key_field_at..key_field_at + 2 + RECEIPT_SIGN_PK_LEN);
    assert!(Transaction::from_bytes(&keyless).is_err());

    let bad_key = ReceiptSignPk::from_bytes([0u8; RECEIPT_SIGN_PK_LEN]);
    let with = |edit: fn(&mut BondPost)| {
        let mut tx = join_committing(bad_key.clone());
        for item in &mut tx.prefix.inputs {
            if let Input::BondPost(post) = item {
                edit(post);
            }
        }
        tx
    };
    refused_lone(&with(|_| {}), CenRow::J28);
    let both_keys = with(|post| {
        if let BondPostKind::JoinMarket { bond_spend_pk, .. } = &mut post.kind {
            bond_spend_pk.truncate(5);
        }
    });
    refused_lone(&both_keys, CenRow::J12);
    let hint_too = with(|post| post.hybrid_public_key.truncate(5));
    refused_lone(&hint_too, CenRow::J11);
}
