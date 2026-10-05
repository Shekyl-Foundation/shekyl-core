// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures for CEN-I19 and CEN-I20. Each I19 refusal is asserted at both
//! listed sites (the pool's `Lone` slot through `tx_form`, a `Listed` slot
//! through `validate`) and, where the shape applies, at `Miner`; each I20
//! refusal at `Miner`, where alone it runs.

use crate::census::CenRow;
use crate::harness::assert_refused;
use crate::harness::fixture::{coinbase, coinbase_extra, listed, point, pqc_extra, G};
use crate::rule_set::RuleSet;
use crate::rules::tx::{refused_listed, refused_lone};
use crate::validate::tx_form;
use crate::verdict::{Locus, TxSlot};
use shekyl_wire::tx_extra::{
    self, conforming_pqc_leaf_blob, TxExtraField, COINBASE_NONCE_BYTES, HYBRID_KEM_CT_BYTES,
};
use shekyl_wire::Transaction;

const KI: [u8; 32] = point(9);

fn refused_at_miner(tx: &Transaction, row: CenRow) {
    assert_refused(
        tx_form(tx, TxSlot::Miner, &RuleSet::GENESIS),
        row,
        Locus::Tx {
            slot: TxSlot::Miner,
        },
    );
}

/// `listed(KI)` with its `extra` replaced.
fn listed_with_extra(extra: Vec<u8>) -> Transaction {
    let mut tx = listed(KI);
    tx.prefix.extra = extra;
    tx
}

/// `coinbase(1)` with its `extra` replaced.
fn coinbase_with_extra(extra: Vec<u8>) -> Transaction {
    let mut cb = coinbase(1);
    cb.prefix.extra = extra;
    cb
}

fn two_fields(kem: Vec<u8>, leaf: Vec<u8>) -> Vec<u8> {
    tx_extra::serialize(&[
        TxExtraField::PqcKemCiphertext(kem),
        TxExtraField::PqcLeafEntries(leaf),
    ])
    .expect("two fields serialize")
}

// ---- CEN-I19 ------------------------------------------------------------

/// The fixtures pass I19 at every slot they name, and both rows record.
#[test]
fn i19_the_fixtures_carry_the_shape_and_the_rows_record() {
    let lone = tx_form(&listed(KI), TxSlot::Lone, &RuleSet::GENESIS).expect("a spend");
    assert!(lone.contains(CenRow::I19));
    // I20 is vacuous off the coinbase — recorded as evaluated, not run.
    assert!(lone.contains(CenRow::I20));
    let miner = tx_form(&coinbase(1), TxSlot::Miner, &RuleSet::GENESIS).expect("a coinbase");
    assert!(miner.contains(CenRow::I19) && miner.contains(CenRow::I20));
}

/// *`tx_extra` must parse*: an unknown tag and a truncated field are I19's
/// refusal at every site — on the coinbase too, where I19 runs ahead of
/// the grammar (I20 would also refuse; I19 is first, as in the C++, where
/// the parse failure is the adapter's first exit).
#[test]
fn i19_an_extra_that_does_not_parse_is_refused_everywhere() {
    let unknown_tag = vec![0xEE; 40];
    refused_lone(&listed_with_extra(unknown_tag.clone()), CenRow::I19);
    refused_listed(&listed_with_extra(unknown_tag.clone()), CenRow::I19);
    refused_at_miner(&coinbase_with_extra(unknown_tag), CenRow::I19);
    // A KEM field whose declared length runs past the bytes.
    let mut truncated = pqc_extra(2);
    truncated.truncate(truncated.len() / 2);
    refused_lone(&listed_with_extra(truncated), CenRow::I19);
}

/// The field shape against the output count: missing fields, a field per
/// output too few, a field too many, and fields present when there are
/// no outputs — each refused on I19 at both listed sites.
#[test]
fn i19_every_departure_from_the_field_shape_is_refused() {
    let n = listed(KI).prefix.outputs.len();
    assert_eq!(n, 2, "the fixture has two outputs");
    // No fields at all.
    refused_lone(&listed_with_extra(Vec::new()), CenRow::I19);
    refused_listed(&listed_with_extra(Vec::new()), CenRow::I19);
    // Sized for one output where there are two.
    refused_lone(&listed_with_extra(pqc_extra(1)), CenRow::I19);
    // Sized for three.
    refused_lone(&listed_with_extra(pqc_extra(3)), CenRow::I19);
    // The KEM field right, the leaf field short by one byte.
    let leaf = conforming_pqc_leaf_blob(n);
    refused_lone(
        &listed_with_extra(two_fields(
            vec![0x5A; HYBRID_KEM_CT_BYTES * n],
            leaf[..leaf.len() - 1].to_vec(),
        )),
        CenRow::I19,
    );
    // Two KEM fields.
    let doubled = tx_extra::serialize(&[
        TxExtraField::PqcKemCiphertext(vec![0x5A; HYBRID_KEM_CT_BYTES * n]),
        TxExtraField::PqcKemCiphertext(vec![0x5A; HYBRID_KEM_CT_BYTES * n]),
        TxExtraField::PqcLeafEntries(conforming_pqc_leaf_blob(n)),
    ])
    .expect("three fields serialize");
    refused_lone(&listed_with_extra(doubled), CenRow::I19);
}

/// The leaf content half (`PL-D3`): a `0x07` entry whose leading 32 bytes
/// are not a canonical prime-order point is refused on I19 even when every
/// length is right.
#[test]
fn i19_a_non_canonical_leaf_point_is_refused() {
    let n = 2;
    let mut leaf = conforming_pqc_leaf_blob(n);
    // The identity is a canonical encoding of a point I19 refuses.
    leaf[..32].copy_from_slice(&[0u8; 32]);
    leaf[0] = 1;
    refused_lone(
        &listed_with_extra(two_fields(vec![0x5A; HYBRID_KEM_CT_BYTES * n], leaf)),
        CenRow::I19,
    );
}

/// The clause the census words under I20 and the C++ emits from I19's
/// site: a `0x02` nonce on a listed transaction is refused on I19 (module
/// docs, `rules::tx_extra`). The same fields on the coinbase are the
/// grammar's, and pass.
#[test]
fn i19_a_nonce_off_the_coinbase_is_refused_on_i19() {
    let n = 2;
    let with_nonce = tx_extra::serialize(&[
        TxExtraField::Nonce(vec![0; COINBASE_NONCE_BYTES]),
        TxExtraField::PqcKemCiphertext(vec![0x5A; HYBRID_KEM_CT_BYTES * n]),
        TxExtraField::PqcLeafEntries(conforming_pqc_leaf_blob(n)),
    ])
    .expect("three fields serialize");
    refused_lone(&listed_with_extra(with_nonce.clone()), CenRow::I19);
    refused_listed(&listed_with_extra(with_nonce), CenRow::I19);
}

/// I19 on the coinbase judges the PQC fields alone: a coinbase with the
/// right fields but no pubkey is I20's refusal, not I19's.
#[test]
fn i19_on_the_coinbase_leaves_the_grammar_to_i20() {
    let cb = coinbase_with_extra(pqc_extra(1));
    refused_at_miner(&cb, CenRow::I20);
}

// ---- CEN-I20 ------------------------------------------------------------

/// Every departure from the coinbase grammar is I20's refusal at `Miner`:
/// no pubkey, no nonce, a nonce of the wrong width, a duplicate pubkey, a
/// foreign tag, the fields out of order, and a trailing field.
#[test]
fn i20_every_departure_from_the_grammar_is_refused_at_miner() {
    let n = 1;
    let kem = || TxExtraField::PqcKemCiphertext(vec![0x5A; HYBRID_KEM_CT_BYTES * n]);
    let leaf = || TxExtraField::PqcLeafEntries(conforming_pqc_leaf_blob(n));
    let nonce = || TxExtraField::Nonce(vec![0; COINBASE_NONCE_BYTES]);
    let pubkey = || TxExtraField::PubKey(G);
    let ser = |fields: &[TxExtraField]| tx_extra::serialize(fields).expect("fields serialize");
    // Baseline: the fixture's own extra is the grammar and passes.
    assert_eq!(coinbase(1).prefix.extra, coinbase_extra(1));
    tx_form(&coinbase(1), TxSlot::Miner, &RuleSet::GENESIS).expect("the grammar");

    let departures: [Vec<u8>; 7] = [
        ser(&[nonce(), kem(), leaf()]),
        ser(&[pubkey(), kem(), leaf()]),
        ser(&[pubkey(), TxExtraField::Nonce(vec![0; 7]), kem(), leaf()]),
        ser(&[pubkey(), pubkey(), nonce(), kem(), leaf()]),
        ser(&[
            pubkey(),
            nonce(),
            kem(),
            leaf(),
            TxExtraField::PqcViewTagHints(vec![1]),
        ]),
        ser(&[nonce(), pubkey(), kem(), leaf()]),
        ser(&[pubkey(), nonce(), kem(), leaf(), TxExtraField::Padding(1)]),
    ];
    for extra in departures {
        refused_at_miner(&coinbase_with_extra(extra), CenRow::I20);
    }
}

/// A leafless coinbase (no outputs) carries pubkey and nonce and nothing
/// else; the same two fields with an output are I19's refusal first.
#[test]
fn i20_a_leafless_coinbase_is_pubkey_and_nonce_only() {
    let mut cb = coinbase(1);
    cb.prefix.outputs.clear();
    cb.prefix.extra = coinbase_extra(0);
    if let shekyl_wire::Ct::Null(base) = &mut cb.ct {
        base.enc_amounts.clear();
        base.enc_labels.clear();
        base.commitments.clear();
    }
    // F4 (one output) is `form`'s; `tx_form` at `Miner` judges the extra.
    tx_form(&cb, TxSlot::Miner, &RuleSet::GENESIS).expect("pubkey and nonce only");
    // Two fields on a coinbase that has an output: I19's missing fields.
    refused_at_miner(&coinbase_with_extra(coinbase_extra(0)), CenRow::I19);
}

/// Q6's pin. A coinbase-shaped body at `Lone` is **not** judged under I20:
/// it is refused as a non-coinbase transaction — H5 at the derivation, the
/// sole `gen` input — and I20 never ran. Give that body a spend's input so
/// the derivation admits it and the grammar's nonce is what is left: I19's
/// refusal (the `General` subject), still not I20's. A listed-shaped body
/// at `Miner` **is** judged under I20 and refused for lacking the grammar.
#[test]
fn i20_is_the_slots_rule_not_the_bytes() {
    // The coinbase body itself: H5, the class derivation, before any rule.
    refused_lone(&coinbase(1), CenRow::H5);
    // The coinbase's grammar on a spend body at the pool's slot: I19's
    // nonce ban, and I20 vacuous — recorded, never run.
    let spend_with_grammar = listed_with_extra(coinbase_extra(2));
    refused_lone(&spend_with_grammar, CenRow::I19);
    refused_listed(&spend_with_grammar, CenRow::I19);
    // A spend body at the miner slot: the extra is I19-conformant for two
    // outputs, so I19 passes on the PQC fields, and I20 refuses the
    // grammar — no pubkey, no nonce.
    refused_at_miner(&listed(KI), CenRow::I20);
}
