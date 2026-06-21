// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Structural / canonical-form validation tests (GENESIS_TX_WIRE_FORMAT.md §10 +
//! the context-free parts of §12): resource bounds, key-image ordering, the
//! unlock_time block-height form, and `nbp == 1`. Chain-context rules (§13) are
//! the consensus layer's and are not exercised here.

use shekyl_wire::{
    Block, BpPlus, Ct, CtBase, Input, Output, PqcAuth, Prunable, Transaction, TxPrefix,
};

fn out() -> Output {
    Output {
        amount: 0,
        key: [0u8; 32],
        view_tag: 0,
    }
}

fn ki(byte: u8) -> Input {
    Input::ToKey {
        amount: 0,
        key_offsets: vec![],
        key_image: [byte; 32],
    }
}

fn bp() -> BpPlus {
    BpPlus {
        a: [0u8; 32],
        a1: [0u8; 32],
        b: [0u8; 32],
        r1: [0u8; 32],
        s1: [0u8; 32],
        d1: [0u8; 32],
        l: vec![],
        r: vec![],
    }
}

/// A minimal well-formed FCMP++ spend with the given inputs/outputs/unlock/nbp.
fn spend(inputs: Vec<Input>, outputs: Vec<Output>, unlock_time: u64, nbp: usize) -> Transaction {
    let n_in = inputs.len();
    let n_out = outputs.len();
    Transaction {
        prefix: TxPrefix {
            unlock_time,
            inputs,
            outputs,
            extra: vec![],
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
                bulletproofs: (0..nbp).map(|_| bp()).collect(),
                tree_depth: 1,
                fcmp_proof: vec![],
                pseudo_outs: vec![[0u8; 32]; n_in],
            }),
        },
    }
}

#[test]
fn valid_coinbase_validates() {
    let blk = Block::from_bytes(include_bytes!("vectors/regtest_coinbase_h0.block")).unwrap();
    blk.miner_transaction
        .validate()
        .expect("a real coinbase must validate");
}

#[test]
fn valid_spend_validates() {
    spend(vec![ki(1), ki(2)], vec![out(), out()], 0, 1)
        .validate()
        .expect("a well-formed spend must validate");
}

#[test]
fn too_many_outputs_rejected() {
    let outs = (0..17).map(|_| out()).collect();
    assert!(spend(vec![ki(1)], outs, 0, 1).validate().is_err());
}

#[test]
fn unsorted_key_images_rejected() {
    let err = spend(vec![ki(2), ki(1)], vec![out()], 0, 1)
        .validate()
        .unwrap_err();
    assert!(err.to_string().contains("ascending"), "{err}");
}

#[test]
fn duplicate_key_images_rejected() {
    assert!(spend(vec![ki(1), ki(1)], vec![out()], 0, 1)
        .validate()
        .is_err());
}

#[test]
fn too_many_fcmp_inputs_rejected() {
    let ins: Vec<Input> = (1u8..=9).map(ki).collect(); // 9 > MAX_FCMP_INPUTS (8)
    assert!(spend(ins, vec![out()], 0, 1).validate().is_err());
}

#[test]
fn timestamp_unlock_time_rejected() {
    assert!(spend(vec![ki(1)], vec![out()], 500_000_000, 1)
        .validate()
        .is_err());
}

#[test]
fn wrong_nbp_rejected() {
    assert!(spend(vec![ki(1)], vec![out()], 0, 2).validate().is_err());
    assert!(spend(vec![ki(1)], vec![out()], 0, 0).validate().is_err());
}

#[test]
fn gen_input_must_be_sole_input() {
    // §2.5 coinbase shape: a `gen` input mixed with any other input is rejected
    // (otherwise it would be misclassified as coinbase and skip the tx_extra cap).
    let err = spend(vec![Input::Gen(0), ki(1)], vec![out()], 0, 1)
        .validate()
        .unwrap_err();
    assert!(err.to_string().contains("sole input"), "{err}");
}

#[test]
fn mismatched_ct_base_length_rejected() {
    // The committed base arrays are per-output; a length != vout must reject.
    let mut tx = spend(vec![ki(1)], vec![out(), out()], 0, 1); // 2 outputs
    if let Ct::Fcmp { base, .. } = &mut tx.ct {
        base.enc_amounts.pop();
    }
    let err = tx.validate().unwrap_err();
    assert!(err.to_string().contains("ct base arrays"), "{err}");
}

#[test]
fn mismatched_pqc_auths_length_rejected() {
    // pqc_auths are per-input (count == nvin); a length != vin must reject.
    let mut tx = spend(vec![ki(1), ki(2)], vec![out()], 0, 1); // 2 inputs
    if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
        pqc_auths.pop();
    }
    let err = tx.validate().unwrap_err();
    assert!(err.to_string().contains("pqc_auths"), "{err}");
}

#[test]
fn null_ct_on_non_coinbase_rejected() {
    // §2.5: a Null ct (no proof material) is coinbase-only; a tx with spend inputs
    // and a Null ct must reject (it would otherwise pass structural validation).
    let mut tx = spend(vec![ki(1)], vec![out()], 0, 1);
    tx.ct = Ct::Null(CtBase {
        enc_amounts: vec![[0u8; 9]],
        enc_labels: vec![[0u8; 9]],
        commitments: vec![[0u8; 32]],
    });
    let err = tx.validate().unwrap_err();
    assert!(err.to_string().contains("coinbase-only"), "{err}");
}

#[test]
fn fcmp_ct_on_coinbase_rejected() {
    // §2.5 dual: a coinbase (gen input) must carry a Null ct, never Fcmp.
    let tx = spend(vec![Input::Gen(0)], vec![out()], 0, 1); // gen input + Fcmp ct
    let err = tx.validate().unwrap_err();
    assert!(err.to_string().contains("Null ct"), "{err}");
}

#[test]
fn pqc_auth_oversized_blob_rejected() {
    // validate() is the in-memory gate for the PQC blob caps (write is faithful):
    // a public key beyond PQC_MAX_PUBLIC_KEY_BLOB must reject.
    let mut tx = spend(vec![ki(1)], vec![out()], 0, 1);
    if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
        pqc_auths[0].hybrid_public_key =
            vec![0u8; shekyl_wire::transaction::PQC_MAX_PUBLIC_KEY_BLOB + 1];
    }
    let err = tx.validate().unwrap_err();
    assert!(err.to_string().contains("public key"), "{err}");
}

#[test]
fn block_rejects_non_coinbase_miner_tx() {
    // The block miner tx must be coinbase-shaped (sole gen input, Null ct): the
    // embedded EOF-based ct discrimination is only sound for a Null coinbase.
    let blk = Block::from_bytes(include_bytes!("vectors/regtest_coinbase_h0.block")).unwrap();
    let mut bad = blk;
    bad.miner_transaction = spend(vec![ki(1)], vec![out()], 0, 1);
    let err = Block::from_bytes(&bad.serialize()).unwrap_err();
    assert!(err.to_string().contains("miner tx"), "{err}");
}
