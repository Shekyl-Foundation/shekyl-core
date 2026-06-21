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

use shekyl_wire::{BpPlus, Ct, CtBase, Input, Output, PqcAuth, Prunable, Transaction, TxPrefix};

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
            prunable,
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
