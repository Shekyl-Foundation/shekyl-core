// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FCMP++ spend serializer tests.
//!
//! **Synthetic round-trip**: a full-shape `Ct::Fcmp` transaction (spend input,
//! tagged_key outputs, committed base, tx-level pqc_auths, prunable with a
//! Bulletproof+) is written and re-read, proving the serializer is internally
//! consistent (`read(write(x)) == x`) across every FCMP++ field with arbitrary
//! byte values. The byte layout is transcribed from the C++ oracle source
//! (`rctTypes.h` `serialize_rctsig_base`/`serialize_rctsig_prunable`,
//! `cryptonote_basic.h` `pqc_authentication`) — see `src/transaction.rs`.
//!
//! The byte-identity proof on a *real, consensus-valid* spend lives in
//! `tests/fcmp_spend_e2e.rs` (stage 11). It supersedes the former
//! `#[ignore]`d "live-oracle" KAT, which planned to capture a known-good
//! transaction blob from the C++ daemon — unsound, because the C++ FCMP++
//! spend path never produced a daemon-accepted transaction, so there was no
//! known-good blob to capture. The e2e test builds the spend in Rust and
//! self-validates it against `shekyl_fcmp::proof::verify` (the consensus rule),
//! then round-trips it through this serializer.

use shekyl_wire::{
    BpPlus, Ct, CtBase, Input, Output, PqcAuth, Prunable, ServeCredit, Transaction, TxPrefix,
};

/// Build a representative 1-in / 2-out FCMP++ spend. Field *sizes* mirror the
/// real shape (single-key PQC pk/sig, one Bp+, per-input pseudo-out); the byte
/// *values* are arbitrary — this exercises serialization structure, not crypto.
fn synthetic_spend() -> Transaction {
    let base = CtBase {
        enc_amounts: vec![[1u8; 9], [2u8; 9]],
        enc_labels: vec![[3u8; 9], [4u8; 9]],
        commitments: vec![[5u8; 32], [6u8; 32]],
    };
    let pqc_auths = vec![PqcAuth {
        auth_version: 1,
        scheme_id: 1,
        flags: 0,
        hybrid_public_key: vec![0xAB; 1996],
        hybrid_signature: vec![0xCD; 3385],
    }];
    let prunable = Prunable {
        bulletproofs: vec![BpPlus {
            a: [0x10; 32],
            a1: [0x11; 32],
            b: [0x12; 32],
            r1: [0x13; 32],
            s1: [0x14; 32],
            d1: [0x15; 32],
            l: vec![[0x20; 32]; 7],
            r: vec![[0x21; 32]; 7],
        }],
        tree_depth: 3,
        fcmp_proof: vec![0xEF; 2500],
        pseudo_outs: vec![[0x30; 32]],
    };
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::ToKey {
                amount: 0,
                key_offsets: vec![],
                key_image: [0x77; 32],
            }],
            outputs: vec![
                Output {
                    amount: 0,
                    key: [0x22; 32],
                    view_tag: 7,
                },
                Output {
                    amount: 0,
                    key: [0x33; 32],
                    view_tag: 9,
                },
            ],
            extra: vec![0x06, 0xAA, 0xBB, 0xCC],
        },
        ct: Ct::Fcmp {
            fee: 12_345,
            reference_block: [0x44; 32],
            base,
            pqc_auths,
            prunable: Some(prunable),
        },
    }
}

#[test]
fn fcmp_spend_round_trips_self_consistently() {
    let tx = synthetic_spend();
    let bytes = tx.serialize();

    let parsed = Transaction::from_bytes(&bytes).expect("parse synthetic FCMP++ spend");
    assert_eq!(parsed, tx, "read(write(x)) must equal x");
    assert_eq!(parsed.serialize(), bytes, "write must be deterministic");

    // The ct dispatched to Fcmp and the per-input/per-output counts survived.
    match parsed.ct {
        Ct::Fcmp {
            pqc_auths,
            prunable,
            base,
            ..
        } => {
            assert_eq!(pqc_auths.len(), parsed.prefix.inputs.len());
            let prunable = prunable.expect("full spend carries a prunable proof");
            assert_eq!(prunable.pseudo_outs.len(), parsed.prefix.inputs.len());
            assert_eq!(base.commitments.len(), parsed.prefix.outputs.len());
        }
        Ct::Null(_) => panic!("expected Fcmp ct"),
    }
}

#[test]
fn fcmp_spend_rejects_trailing_bytes() {
    let mut bytes = synthetic_spend().serialize();
    bytes.push(0x00);
    let err = Transaction::from_bytes(&bytes).expect_err("trailing byte must be rejected");
    assert!(
        err.to_string().contains("trailing"),
        "unexpected error: {err}"
    );
}

#[test]
fn fee_only_serve_credit_round_trips_and_validates() {
    // The non-spend fee-only Fcmp shape (§2.5 serve-credit): one non-spending
    // serve_credit input, no outputs, empty pqc_auths, no prunable. Ct::read's
    // EOF-tolerant tail must parse it, and the shape-aware validate() must accept it.
    let serve_credit = Input::ServeCredit(Box::new(ServeCredit {
        p_canonical_id: [0x11; 32],
        shard_id: 7,
        settlement_epoch: 42,
        segment_subroot_rk: [0x22; 32],
        leaf_index_in_segment: 0x0403_0201,
        leaf_bytes: [0x33; 128],
        c1_layers: vec![vec![[0x44; 32]]],
        c2_layers: vec![vec![[0x55; 32]]],
        hybrid_signature: vec![0x66; 3385],
    }));
    let tx = Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![serve_credit],
            outputs: vec![],
            extra: vec![],
        },
        ct: Ct::Fcmp {
            fee: 0,
            reference_block: [0x44; 32],
            base: CtBase {
                enc_amounts: vec![],
                enc_labels: vec![],
                commitments: vec![],
            },
            pqc_auths: vec![],
            prunable: None,
        },
    };
    let parsed = Transaction::from_bytes(&tx.serialize()).expect("parse fee-only serve-credit tx");
    assert_eq!(parsed, tx, "fee-only form must round-trip");
    assert!(
        matches!(parsed.ct, Ct::Fcmp { prunable: None, .. }),
        "fee-only ct parses with no prunable"
    );
    tx.validate()
        .expect("fee-only serve-credit tx must validate");
    // Distinct 3-part (no-pqc) hash form — just exercise it (live parity deferred).
    let _ = tx.hash();
}

#[test]
fn fcmp_spend_rejects_oversized_pqc_blob() {
    // Consensus parity: a pqc_auths public key beyond PQC_MAX_PUBLIC_KEY_BLOB must be
    // rejected at parse, matching the C++ oracle's deserialization bound.
    let mut tx = synthetic_spend();
    if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
        pqc_auths[0].hybrid_public_key =
            vec![0u8; shekyl_wire::transaction::PQC_MAX_PUBLIC_KEY_BLOB + 1];
    }
    let err = Transaction::from_bytes(&tx.serialize())
        .expect_err("oversized pqc public key must be rejected");
    assert!(err.to_string().contains("hybrid_public_key"), "{err}");
}

#[test]
fn synthetic_spend_hash_preimage_is_pinned() {
    // Regression guard for the 4-part FCMP++ spend hash (§11):
    //   cn_fast_hash( H(prefix) ‖ H(base) ‖ H(varint(N)·pqc_auths) ‖ H(prunable) ).
    // There is no live spend-hash oracle yet (the KAT is deferred), so this pins the
    // *preimage structure* against accidental drift — most importantly the leading
    // varint(N) count prefix on the pqc_auths component, which the C++ oracle emits
    // because the hash uses the generic std::vector serializer (begin_array(cnt) ->
    // serialize_varint), unlike the prefix-less tx body. If this value changes,
    // either the layout regressed or the live KAT just landed — confirm against the
    // daemon before updating.
    let h: String = synthetic_spend()
        .hash()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        h, "d6cb346f02830be0a91c395dcf64ba1492b05e47c17e6b2f54f0858735a0d03e",
        "synthetic FCMP++ spend hash preimage drifted (see the §11 note above)"
    );
}
