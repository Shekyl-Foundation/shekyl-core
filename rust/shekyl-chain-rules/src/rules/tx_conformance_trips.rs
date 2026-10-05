// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The transactions that trip `shekyl_wire::Transaction::validate`, one
//! function per arm of the conformance table. The table and the assertions
//! live in `tx_conformance_tests`.

use crate::harness::fixture::{
    bp_plus_layout_for, coinbase, coinbase_extra, listed, point, pqc_auth_filler, pqc_extra,
    serve_credit_only, G, TWO_G,
};
use shekyl_wire::transaction::{
    MAX_TX_EXTRA, MAX_TX_SIZE, PQC_HYBRID_SINGLE_KEY_LEN, PQC_MAX_PUBLIC_KEY_BLOB,
    TAG_INPUT_SERVE_CREDIT, UNLOCK_TIME_BLOCK_SENTINEL,
};
use shekyl_wire::tx_extra::{self, conforming_pqc_leaf_blob, TxExtraField, HYBRID_KEM_CT_BYTES};
use shekyl_wire::{BondPost, BondPostKind, Ct, Holdings, Input, Output, Transaction};

// ---- the baseline ---------------------------------------------------------

/// `tx` with the `extra` CEN-I19 requires for its **current** output count
/// — [`pqc_extra`], re-applied after a trip changed the outputs. The
/// fixtures carry it already (slice 6 commit 3); a trip that truncates or
/// adds outputs must re-fit the field, or I19 refuses before the arm the
/// trip is aimed at.
pub(super) fn with_pqc_extra(mut tx: Transaction) -> Transaction {
    tx.prefix.extra = pqc_extra(tx.prefix.outputs.len());
    tx
}

/// A two-output spend both copies accept: keys `G` and `4·G`, masks `2·G`
/// and `3·G` against one pseudo-out `5·G` (fee 0, so H18 balances), the
/// canonical BP+ layout for two outputs, one auth for its one input, and
/// I19's `extra`. Two outputs because the twin holds I1 (`>= 2`) at every
/// height and the crate does not yet.
pub(super) fn spend2() -> Transaction {
    let mut tx = listed(point(9));
    tx.prefix.outputs = vec![
        Output {
            amount: 0,
            key: G,
            view_tag: 2,
        },
        Output {
            amount: 0,
            key: point(4),
            view_tag: 3,
        },
    ];
    if let Ct::Fcmp {
        base,
        prunable: Some(p),
        ..
    } = &mut tx.ct
    {
        base.enc_amounts = vec![[0x11; 9]; 2];
        base.enc_labels = vec![[0x22; 9]; 2];
        base.commitments = vec![TWO_G, point(3)];
        p.bulletproofs = vec![bp_plus_layout_for(2)];
        p.pseudo_outs = vec![point(5)];
    }
    with_pqc_extra(tx)
}

/// A serve-credit both copies accept: the fixture with the prunable region
/// `RF-D1` gave it — one pruned pass record for its one vin, and no spend
/// material.
pub(super) fn serve_credit_ok() -> Transaction {
    let mut tx = serve_credit_only([0x51; 32]);
    if let Ct::Fcmp { prunable, .. } = &mut tx.ct {
        *prunable = Some(shekyl_wire::Prunable {
            bulletproofs: Vec::new(),
            tree_depth: 0,
            fcmp_proof: Vec::new(),
            pseudo_outs: Vec::new(),
            serve_credit_pruned: vec![vec![0x01; 4]],
        });
    }
    tx
}

/// The fixture coinbase — which carries CEN-I20's grammar since slice 6
/// commit 3 (`fixture::coinbase_extra`); kept as the trips' name for it.
pub(super) fn coinbase_ok(height: u64) -> Transaction {
    coinbase(height)
}

/// The grammar's `extra` for `n` outputs: the fixture's, re-fit after a
/// trip changed the coinbase's output count.
pub(super) fn coinbase_extra_for(n: usize) -> Vec<u8> {
    coinbase_extra(n)
}

/// A bond-post input with a canonical hybrid key and `kind`; the type's
/// minimum otherwise.
pub(super) fn bond_post_input(hybrid_key_len: usize, kind: BondPostKind) -> Input {
    Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![0xB1; hybrid_key_len],
        p_canonical_id: shekyl_types::PCanonicalId::from_bytes([0xB0; 32]),
        kind,
        holdings: Holdings::CompleteTree,
        bonded_total_atomic: 0,
        bond_credit: 0,
        bond_debit: 0,
    }))
}

pub(super) fn serve_credit_input() -> Input {
    let mut canonical_bytes = vec![TAG_INPUT_SERVE_CREDIT];
    canonical_bytes.extend_from_slice(&[0x52; 32]);
    Input::ServeCredit { canonical_bytes }
}

pub(super) fn emission_input() -> Input {
    Input::ArchivalRewardEmission {
        canonical_bytes: vec![
            shekyl_wire::transaction::TAG_INPUT_ARCHIVAL_REWARD_EMISSION,
            0,
        ],
    }
}

pub(super) fn spend_input(k: usize) -> Input {
    Input::ToKey {
        amount: 0,
        key_offsets: Vec::new(),
        key_image: point(k),
    }
}

/// `spend2()` with `input` appended and an auth for it.
pub(super) fn spend2_plus(input: Input) -> Transaction {
    let mut tx = spend2();
    tx.prefix.inputs.push(input);
    if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
        pqc_auths.push(pqc_auth_filler());
    }
    tx
}

/// A bond post standing alone (no funding spend) with `outputs` outputs and
/// `prunable` as given — the shape the twin's fee-only arm is reached by.
pub(super) fn bond_post_alone(
    outputs: usize,
    prunable: Option<shekyl_wire::Prunable>,
) -> Transaction {
    let mut tx = spend2();
    tx.prefix.inputs = vec![bond_post_input(
        PQC_HYBRID_SINGLE_KEY_LEN,
        BondPostKind::Other(2),
    )];
    tx.prefix.outputs.truncate(outputs);
    if let Ct::Fcmp {
        base,
        pqc_auths,
        prunable: p,
        ..
    } = &mut tx.ct
    {
        base.enc_amounts.truncate(outputs);
        base.enc_labels.truncate(outputs);
        base.commitments.truncate(outputs);
        *pqc_auths = vec![pqc_auth_filler()];
        *p = prunable;
    }
    with_pqc_extra(tx)
}

// ---- the trips ------------------------------------------------------------

pub(super) fn j2_empty_pass_record() -> Transaction {
    let mut tx = serve_credit_ok();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut tx.ct
    {
        p.serve_credit_pruned = vec![Vec::new()];
    }
    tx
}

pub(super) fn j11_short_hybrid_key() -> Transaction {
    spend2_plus(bond_post_input(5, BondPostKind::Other(2)))
}

pub(super) fn j12_short_bond_spend_pk() -> Transaction {
    spend2_plus(bond_post_input(
        PQC_HYBRID_SINGLE_KEY_LEN,
        BondPostKind::JoinMarket {
            bond_spend_pk: vec![0xC0; 5],
            endpoint: [0xE0; shekyl_wire::transaction::BOND_POST_ENDPOINT_LEN],
        },
    ))
}

pub(super) fn h4_no_inputs() -> Transaction {
    let mut tx = spend2();
    tx.prefix.inputs.clear();
    tx
}

pub(super) fn h19_seventeen_outputs() -> Transaction {
    let mut tx = spend2();
    let out = tx.prefix.outputs[0].clone();
    tx.prefix.outputs = vec![out; 17];
    tx
}

pub(super) fn h5_gen_beside_a_spend() -> Transaction {
    spend2_plus(Input::Gen(0))
}

pub(super) fn h6_serve_credit_beside_a_spend() -> Transaction {
    spend2_plus(serve_credit_input())
}

pub(super) fn h20_serve_credit_with_an_auth() -> Transaction {
    let mut tx = serve_credit_ok();
    if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
        pqc_auths.push(pqc_auth_filler());
    }
    tx
}

pub(super) fn h6_two_bond_posts() -> Transaction {
    let one = bond_post_input(PQC_HYBRID_SINGLE_KEY_LEN, BondPostKind::Other(2));
    let mut tx = spend2_plus(one);
    tx.prefix.inputs.push(bond_post_input(
        PQC_HYBRID_SINGLE_KEY_LEN,
        BondPostKind::Other(3),
    ));
    tx
}

pub(super) fn h6_two_emissions() -> Transaction {
    let mut tx = spend2_plus(emission_input());
    tx.prefix.inputs.push(emission_input());
    tx
}

pub(super) fn h6_emission_beside_a_bond_post() -> Transaction {
    let mut tx = spend2_plus(emission_input());
    tx.prefix.inputs.push(bond_post_input(
        PQC_HYBRID_SINGLE_KEY_LEN,
        BondPostKind::Other(2),
    ));
    tx
}

/// Two outputs whose amounts sum past `u64::MAX`. Reaches the twin's
/// overflow arm before the `gen`/archival classification (it is the third
/// check), and `tx_form`'s H9 before H14 would see the loud amounts.
pub(super) fn h9_output_amounts_overflow() -> Transaction {
    let mut tx = spend2();
    tx.prefix.outputs[0].amount = u64::MAX;
    tx.prefix.outputs[1].amount = 1;
    tx
}

/// An `extra` past the relay cap that **parses and satisfies I19**: the two
/// PQC fields the outputs require, then a `0x09` view-tag-hints blob of
/// `MAX_TX_EXTRA` bytes. Raw filler (the first cut, `[0xEE; MAX + 1]`) would
/// reach the twin's cap arm all the same — it checks the length before it
/// parses — but the crate would refuse it on I19 for not parsing, and the
/// entry would record a shape disagreement, not the policy one it is for.
/// The `0x09` blob is admissible on a listed transaction under I19 (the
/// general subject bounds the PQC fields and bans the nonce; the parser's
/// `READ_LEN_CAP` is the only limit on a hints blob), which is itself a
/// finding — recorded on the census-sweep FOLLOWUPS row.
pub(super) fn m4_extra_over_the_relay_cap() -> Transaction {
    let mut tx = spend2();
    let n = tx.prefix.outputs.len();
    tx.prefix.extra = tx_extra::serialize(&[
        TxExtraField::PqcKemCiphertext(vec![0x5A; HYBRID_KEM_CT_BYTES * n]),
        TxExtraField::PqcLeafEntries(conforming_pqc_leaf_blob(n)),
        TxExtraField::PqcViewTagHints(vec![0x99; MAX_TX_EXTRA]),
    ])
    .expect("three fields serialize");
    tx
}

/// The baseline spend with its `extra` emptied: two outputs and no `0x06`
/// / `0x07` fields, which CEN-I19 refuses as `Missing`.
pub(super) fn i19_no_pqc_fields() -> Transaction {
    let mut tx = spend2();
    tx.prefix.extra.clear();
    tx
}

pub(super) fn h1_a_megabyte_proof() -> Transaction {
    let mut tx = spend2();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut tx.ct
    {
        p.fcmp_proof = vec![0xF0; MAX_TX_SIZE];
    }
    tx
}

pub(super) fn h16_the_sentinel() -> Transaction {
    let mut tx = spend2();
    tx.prefix.unlock_time = UNLOCK_TIME_BLOCK_SENTINEL;
    tx
}

pub(super) fn i4_nine_inputs() -> Transaction {
    let mut tx = spend2();
    tx.prefix.inputs = (1..=9).map(spend_input).collect();
    tx
}

pub(super) fn i6_offsets() -> Transaction {
    let mut tx = spend2();
    if let Some(Input::ToKey { key_offsets, .. }) = tx.prefix.inputs.get_mut(0) {
        *key_offsets = vec![7, 0];
    }
    tx
}

pub(super) fn i5_ascending_key_images() -> Transaction {
    let mut tx = spend2();
    let (mut a, mut b) = (point(9), point(10));
    if a > b {
        core::mem::swap(&mut a, &mut b);
    }
    tx.prefix.inputs = [a, b]
        .into_iter()
        .map(|key_image| Input::ToKey {
            amount: 0,
            key_offsets: Vec::new(),
            key_image,
        })
        .collect();
    tx
}

pub(super) fn h15_null_ct_on_a_spend() -> Transaction {
    let mut tx = spend2();
    let Ct::Fcmp { base, .. } = &tx.ct else {
        unreachable!("spend2 is Fcmp")
    };
    tx.ct = Ct::Null(base.clone());
    tx
}

pub(super) fn f4_no_outputs(cb: &mut Transaction) {
    cb.prefix.outputs.clear();
    // A leafless coinbase still carries pubkey and nonce (I20).
    cb.prefix.extra = coinbase_extra_for(0);
    if let Ct::Null(base) = &mut cb.ct {
        base.enc_amounts.clear();
        base.enc_labels.clear();
        base.commitments.clear();
    }
}

pub(super) fn f3_fcmp_ct(cb: &mut Transaction) {
    let Ct::Null(base) = &cb.ct else {
        unreachable!("the fixture coinbase is Null")
    };
    cb.ct = Ct::Fcmp {
        fee: 0,
        reference_block: shekyl_types::BlockHash::from_bytes([0x99; 32]),
        base: base.clone(),
        pqc_auths: Vec::new(),
        prunable: None,
    };
}

pub(super) fn i16_oversized_key_blob() -> Transaction {
    let mut tx = spend2();
    if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
        pqc_auths[0].hybrid_public_key = vec![0xAB; PQC_MAX_PUBLIC_KEY_BLOB + 1];
    }
    tx
}

pub(super) fn h8_short_base_arrays() -> Transaction {
    let mut tx = spend2();
    if let Ct::Fcmp { base, .. } = &mut tx.ct {
        base.enc_amounts.truncate(1);
    }
    tx
}

pub(super) fn i1_one_output_spend() -> Transaction {
    // `listed` grew to two outputs when I1 landed; the trip is the one it
    // left behind.
    with_pqc_extra(crate::harness::fixture::spend(point(9), 1))
}

/// A bond post standing alone with one output — the shape that reaches the
/// twin's `spend/bond_post` face of its output-count arm (a funding spend
/// would trip its `spend has` face first). The crate refuses it on H21,
/// not I1: no funding spend, and `ver_non_input_consensus`'s arm refuses
/// that (`spend_input_count == 0`) before `check_tx_inputs` reads an output
/// count — recorded as the site's divergence.
pub(super) fn i1_one_output_bond_post() -> Transaction {
    let prunable = shekyl_wire::Prunable {
        bulletproofs: vec![bp_plus_layout_for(1)],
        tree_depth: 0,
        fcmp_proof: vec![0xF0],
        pseudo_outs: Vec::new(),
        serve_credit_pruned: Vec::new(),
    };
    bond_post_alone(1, Some(prunable))
}

pub(super) fn i8_no_auths() -> Transaction {
    let mut tx = spend2();
    if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
        pqc_auths.clear();
    }
    tx
}

pub(super) fn h19_no_proof() -> Transaction {
    let mut tx = spend2();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut tx.ct
    {
        p.bulletproofs.clear();
    }
    tx
}

pub(super) fn h19_layout_for_the_wrong_output_count() -> Transaction {
    let mut tx = spend2();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut tx.ct
    {
        p.bulletproofs = vec![bp_plus_layout_for(1)];
    }
    tx
}

/// Two inputs, one pseudo-out — and the one pseudo-out still balances the
/// masks (`5·G`), so H18 passes and the count is what refuses. Clearing the
/// pseudo-outs instead would be refused on H18 first, in the crate and in
/// the C++ alike (`ver_non_input_consensus`' balance runs before
/// `check_tx_inputs`' count); the trip must reach the arm it is keyed to.
/// The second input's image is placed so the pair descends (I5).
pub(super) fn i9_one_pseudo_out_for_two_inputs() -> Transaction {
    let mut tx = spend2_plus(spend_input(10));
    if point(10) > point(9) {
        tx.prefix.inputs.swap(0, 1);
    }
    tx
}

pub(super) fn pruned_form_bond_post_with_an_output() -> Transaction {
    // Two outputs so the fixture satisfies I1 regardless, and the arm's
    // subject — the pruned form — is what H21 judges. (H21 runs before I1
    // here as in the C++'s caller order; the output count is kept valid so
    // no reader has to reason about which of the two would have fired.)
    bond_post_alone(2, None)
}

pub(super) fn pruned_form_bond_post_with_an_auth() -> Transaction {
    bond_post_alone(0, None)
}
