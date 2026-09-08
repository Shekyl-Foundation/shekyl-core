// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The archival reward-emission input arm (dense tag `0x04`, C-1).
//!
//! The C++ oracle is the *transport* struct `txin_archival_reward_emission`
//! (`cryptonote_basic.h:298-311`): an opaque varint-length-prefixed blob whose
//! leading byte echoes the wire tag, bounded to
//! `2..=ARCHIVAL_EMISSION_VIN_MAX_BYTES`. The blob's *contents* are
//! `shekyl-archival-retention::emission_wire`'s codec — out of scope here.
//!
//! The load-bearing test is **whole-transaction parse survival**, not the blob
//! round-trip: before this arm landed, `Input::read` hit the unknown-tag arm on
//! `0x04` and the error propagated out of `Transaction::read` — killing the
//! parse of the *entire transaction*, which is what would have broken the
//! wallet scanner on the first mined emission tx. The round-trip proves the
//! happy path; `whole_transaction_with_emission_input_parses` proves the
//! failure mode that was actually latent on dev is closed, and
//! `unknown_input_tag_still_kills_whole_tx_parse` proves the mechanism the fix
//! removed for `0x04` still bites for a genuinely unknown tag (`0x05`).

mod common;
use common::conforming_pqc_extra;

use shekyl_wire::transaction::{
    ARCHIVAL_EMISSION_VIN_MAX_BYTES, TAG_INPUT_ARCHIVAL_REWARD_EMISSION,
};
use shekyl_wire::{
    BondPost, BondPostKind, BpPlus, Ct, CtBase, Holdings, Input, Output, PqcAuth, Prunable,
    Transaction, TxPrefix,
};

fn emission_input(blob_payload: &[u8]) -> Input {
    let mut canonical_bytes = vec![TAG_INPUT_ARCHIVAL_REWARD_EMISSION];
    canonical_bytes.extend_from_slice(blob_payload);
    Input::ArchivalRewardEmission { canonical_bytes }
}

fn ki(byte: u8) -> Input {
    Input::ToKey {
        amount: 0,
        key_offsets: vec![],
        key_image: [byte; 32],
    }
}

fn out() -> Output {
    Output {
        amount: 0,
        key: [0u8; 32],
        view_tag: 0,
    }
}

/// A Bp+ whose `|L|`/`|R|` are consistent with `n_out` outputs
/// (`6 + ceil(log2(next_pow2(n_out)))` — the §10 canonical-form corollary).
fn bp(n_out: usize) -> BpPlus {
    let lr = 6 + n_out.next_power_of_two().trailing_zeros() as usize;
    BpPlus {
        a: [0u8; 32],
        a1: [0u8; 32],
        b: [0u8; 32],
        r1: [0u8; 32],
        s1: [0u8; 32],
        d1: [0u8; 32],
        l: vec![[0u8; 32]; lr],
        r: vec![[0u8; 32]; lr],
    }
}

/// An emission-shaped tx: the emission vin plus `ToKey` fee inputs, loud-vout
/// outputs, `pqc_auths == nvin` (the emission vin occupies an auth slot), and
/// `pseudoOuts == ToKey subset` (the emission vin carries no pseudo-out —
/// C++ `count_spend_inputs`, `cryptonote_basic.h:322`).
fn emission_tx(inputs: Vec<Input>, outputs: Vec<Output>) -> Transaction {
    let n_in = inputs.len();
    let n_ki = inputs
        .iter()
        .filter(|i| matches!(i, Input::ToKey { .. }))
        .count();
    let n_out = outputs.len();
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs,
            outputs,
            extra: conforming_pqc_extra(n_out),
        },
        ct: Ct::Fcmp {
            fee: 0,
            reference_block: [0u8; 32],
            base: CtBase {
                enc_amounts: vec![[0u8; 9]; n_out],
                enc_labels: vec![[0u8; 9]; n_out],
                commitments: vec![[0u8; 32]; n_out],
            },
            pqc_auths: (0..n_in)
                .map(|_| PqcAuth {
                    auth_version: 1,
                    scheme_id: 1,
                    flags: 0,
                    hybrid_public_key: vec![],
                    hybrid_signature: vec![],
                })
                .collect(),
            prunable: Some(Prunable {
                serve_credit_pruned: Vec::new(),
                bulletproofs: vec![bp(n_out)],
                tree_depth: 1,
                fcmp_proof: vec![],
                pseudo_outs: vec![[0u8; 32]; n_ki],
            }),
        },
    }
}

#[test]
fn emission_input_round_trips() {
    let input = emission_input(&[0xAA; 64]);
    let mut bytes = Vec::new();
    input.write(&mut bytes).expect("write emission arm");
    let mut cursor = &bytes[..];
    let parsed = Input::read(&mut cursor).expect("read emission arm");
    assert!(cursor.is_empty(), "emission arm left trailing bytes");
    assert_eq!(parsed, input);
}

/// The bite-check for the latent scanner break: a transaction *containing* a
/// `0x04` input — alongside ordinary `ToKey` fee inputs — must parse whole,
/// round-trip byte-identically, and validate. Before this commit, `Input::read`
/// erred on the `0x04` tag and the error failed the entire transaction parse.
#[test]
fn whole_transaction_with_emission_input_parses() {
    // Key images strictly descending (memcmp) per the §12 canonical-form rule.
    let tx = emission_tx(
        vec![ki(2), ki(1), emission_input(&[0xBB; 96])],
        vec![out(), out()],
    );
    let blob = tx.serialize();
    let parsed = Transaction::from_bytes(&blob)
        .expect("a transaction containing a 0x04 input must parse whole");
    assert_eq!(parsed, tx);
    assert_eq!(parsed.serialize(), blob, "must round-trip byte-identically");
    parsed
        .validate()
        .expect("the emission-shaped tx must pass context-free validation");
}

/// The mechanism the fix removed for `0x04` must still bite for a genuinely
/// unknown tag: splice the emission arm's tag byte to `0x05` inside the
/// serialized transaction and the *whole* parse must die on it.
#[test]
fn unknown_input_tag_still_kills_whole_tx_parse() {
    let emission = emission_input(&[0xBB; 96]);
    let tx = emission_tx(vec![ki(2), ki(1), emission.clone()], vec![out(), out()]);
    let mut blob = tx.serialize();

    // Locate the emission arm's serialization inside the tx blob and flip its
    // leading tag byte. The arm bytes (tag + varint len + 0x04-leading payload)
    // are long and distinctive enough to be unique in this fixture — nothing
    // else in the tx emits a 96-byte 0xBB run.
    let mut arm_bytes = Vec::new();
    emission.write(&mut arm_bytes).expect("write emission arm");
    let pos = blob
        .windows(arm_bytes.len())
        .position(|w| w == arm_bytes)
        .expect("emission arm bytes must appear in the tx blob");
    assert_eq!(blob[pos], TAG_INPUT_ARCHIVAL_REWARD_EMISSION);
    blob[pos] = 0x05;

    let err = Transaction::from_bytes(&blob).expect_err("unknown tag must fail the whole parse");
    assert!(
        err.to_string().contains("unsupported input tag"),
        "unexpected error: {err}"
    );
}

#[test]
fn emission_blob_shorter_than_two_bytes_rejected_on_read() {
    // A 1-byte blob (the bare tag) is below the C++ transport minimum.
    let input = Input::ArchivalRewardEmission {
        canonical_bytes: vec![TAG_INPUT_ARCHIVAL_REWARD_EMISSION],
    };
    let mut bytes = Vec::new();
    input.write(&mut bytes).expect("write is faithful");
    let err = Input::read(&mut &bytes[..]).expect_err("undersized blob must be rejected");
    assert!(err.to_string().contains("outside 2..="), "{err}");
}

#[test]
fn emission_blob_wrong_leading_byte_rejected_on_read() {
    // The blob's first byte must echo the wire tag (cryptonote_basic.h:308).
    let input = Input::ArchivalRewardEmission {
        canonical_bytes: vec![0x00, 0x00],
    };
    let mut bytes = Vec::new();
    input.write(&mut bytes).expect("write is faithful");
    let err = Input::read(&mut &bytes[..]).expect_err("wrong leading byte must be rejected");
    assert!(err.to_string().contains("leading byte"), "{err}");
}

#[test]
fn emission_blob_transport_guard_also_armed_in_validate() {
    // validate() is the in-memory gate (write is faithful): a hand-built tx with
    // an invalid blob must reject *before* it serializes to unparseable bytes.
    let tx = emission_tx(
        vec![Input::ArchivalRewardEmission {
            canonical_bytes: vec![0x00, 0x00],
        }],
        vec![out(), out()],
    );
    let err = tx.validate().expect_err("invalid blob must fail validate");
    assert!(err.to_string().contains("leading byte"), "{err}");
}

#[test]
fn emission_blob_over_transport_max_rejected_on_read() {
    // One byte over ARCHIVAL_EMISSION_VIN_MAX_BYTES. The read-side bound rejects
    // on the length *prefix*, before allocating — so hand-build the head bytes
    // rather than a real >1 MiB blob. (In a full tx the `MAX_TX_SIZE` cap also
    // rejects independently, since the transport cap exceeds the tx cap — the
    // constant's doc-comment pins that deliberate mirroring of the C++ bound.)
    let mut bytes = vec![TAG_INPUT_ARCHIVAL_REWARD_EMISSION];
    shekyl_wire::varint::write_varint(ARCHIVAL_EMISSION_VIN_MAX_BYTES as u64 + 1, &mut bytes)
        .expect("Vec write is infallible");
    let err = Input::read(&mut &bytes[..]).expect_err("oversized blob must be rejected");
    assert!(err.to_string().contains("exceeds"), "{err}");
}

/// C++ `check_money_overflow` parity (`check_outs_overflow`): loud vout
/// amounts whose sum overflows `u64` must reject context-free. This arm was
/// vacuous while every non-coinbase amount was 0; the emission claim's loud
/// reward vout legitimized non-zero amounts, so a hostile pair like
/// `[u64::MAX, 1]` now exercises the checked sum — the C++ daemon rejects
/// the same bytes, and accept/reject parity demands the Rust gate does too.
#[test]
fn loud_vout_amount_overflow_rejected() {
    let loud = |amount| Output {
        amount,
        key: [0u8; 32],
        view_tag: 0,
    };
    let tx = emission_tx(
        vec![ki(2), ki(1), emission_input(&[0xBB; 96])],
        vec![loud(u64::MAX), loud(1)],
    );
    let err = tx
        .validate()
        .expect_err("overflowing loud amounts must reject");
    assert!(err.to_string().contains("check_money_overflow"), "{err}");

    // Premise arm: the same shape with a non-overflowing loud amount passes,
    // so the reject above is the overflow, not the loudness.
    let ok = emission_tx(
        vec![ki(2), ki(1), emission_input(&[0xBB; 96])],
        vec![loud(u64::MAX), loud(0)],
    );
    ok.validate()
        .expect("a non-overflowing loud amount is legal on the emission arm");
}

#[test]
fn two_emission_inputs_rejected() {
    // check_inputs_types_supported:731 — Q3 arity 1.
    let tx = emission_tx(
        vec![emission_input(&[0x01]), emission_input(&[0x02])],
        vec![out(), out()],
    );
    let err = tx.validate().expect_err("two emission vins must reject");
    assert!(err.to_string().contains("at most one emission"), "{err}");
}

#[test]
fn emission_mixed_with_bond_post_rejected() {
    // check_inputs_types_supported:737 — emission cannot mix with a bond_post;
    // key-imaged ToKey fee spends are the only permitted co-residents (Q11).
    let bond = Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![0x01; shekyl_wire::transaction::PQC_HYBRID_SINGLE_KEY_LEN],
        p_canonical_id: [0x02; 32],
        kind: BondPostKind::JoinMarket {
            bond_spend_pk: vec![0x03; shekyl_wire::transaction::PQC_HYBRID_SINGLE_KEY_LEN],
        },
        holdings: Holdings::CompleteTree,
        bonded_total_atomic: 1,
        bond_credit: 1,
        bond_debit: 0,
    }));
    let tx = emission_tx(vec![emission_input(&[0x01]), bond], vec![out(), out()]);
    let err = tx.validate().expect_err("emission + bond_post must reject");
    assert!(err.to_string().contains("must not mix"), "{err}");
}
