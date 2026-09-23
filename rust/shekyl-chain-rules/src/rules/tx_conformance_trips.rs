// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The transactions that trip `shekyl_wire::Transaction::validate`, one
//! function per arm of the conformance table. The table and the assertions
//! live in `tx_conformance_tests`.

use crate::harness::fixture::{
    bp_plus_layout_for, coinbase, listed, point, pqc_auth_filler, serve_credit_only, G, TWO_G,
};
use shekyl_wire::transaction::{
    MAX_TX_EXTRA, MAX_TX_SIZE, PQC_HYBRID_SINGLE_KEY_LEN, PQC_MAX_PUBLIC_KEY_BLOB,
    TAG_INPUT_SERVE_CREDIT, UNLOCK_TIME_BLOCK_SENTINEL,
};
use shekyl_wire::tx_extra::{
    self, build_coinbase_extra, conforming_pqc_leaf_blob, TxExtraField, COINBASE_NONCE_BYTES,
    HYBRID_KEM_CT_BYTES,
};
use shekyl_wire::{BondPost, BondPostKind, Ct, Holdings, Input, Output, Transaction};

// ---- the baseline ---------------------------------------------------------

/// `tx` with the `extra` CEN-I19 requires for its output count: one `0x06`
/// of `1120·n` and one `0x07` of `64·n` conforming leaf entries — what the
/// twin's `validate` demands of every transaction, and what the crate's
/// fixtures do not carry (I19 is slice 6's).
pub(super) fn with_pqc_extra(mut tx: Transaction) -> Transaction {
    let n = tx.prefix.outputs.len();
    tx.prefix.extra = if n == 0 {
        Vec::new()
    } else {
        tx_extra::serialize(&[
            TxExtraField::PqcKemCiphertext(vec![0x5A; HYBRID_KEM_CT_BYTES * n]),
            TxExtraField::PqcLeafEntries(conforming_pqc_leaf_blob(n)),
        ])
        .expect("two capped fields serialize")
    };
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

/// The fixture coinbase with the `extra` CEN-I20 requires of a coinbase
/// (`TX_EXTRA_RUST_CUTOVER.md`, landed on `dev` at `50256487f`): the one
/// grammar — a `0x01` pubkey, an 8-byte `0x02` nonce, then I19's two PQC
/// fields sized to the outputs. Built by the wire's own builder, so a
/// grammar change moves this fixture with it.
pub(super) fn coinbase_ok(height: u64) -> Transaction {
    let mut cb = coinbase(height);
    cb.prefix.extra = coinbase_extra_for(cb.prefix.outputs.len());
    cb
}

pub(super) fn coinbase_extra_for(n: usize) -> Vec<u8> {
    build_coinbase_extra(
        [0x71; 32],
        &[0x4E; COINBASE_NONCE_BYTES],
        n,
        &vec![0x5A; HYBRID_KEM_CT_BYTES * n],
        &conforming_pqc_leaf_blob(n),
    )
    .expect("the grammar's one layout builds")
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

pub(super) fn m4_extra_over_the_relay_cap() -> Transaction {
    let mut tx = spend2();
    tx.prefix.extra = vec![0xEE; MAX_TX_EXTRA + 1];
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
    with_pqc_extra(listed(point(9)))
}

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

pub(super) fn i9_no_pseudo_outs() -> Transaction {
    let mut tx = spend2();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut tx.ct
    {
        p.pseudo_outs.clear();
    }
    tx
}

pub(super) fn pruned_form_bond_post_with_an_output() -> Transaction {
    bond_post_alone(1, None)
}

pub(super) fn pruned_form_bond_post_with_an_auth() -> Transaction {
    bond_post_alone(0, None)
}
