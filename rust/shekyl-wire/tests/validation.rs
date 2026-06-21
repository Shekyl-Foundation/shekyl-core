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
            prunable: Prunable {
                bulletproofs: (0..nbp).map(|_| bp()).collect(),
                tree_depth: 1,
                fcmp_proof: vec![],
                pseudo_outs: vec![[0u8; 32]; n_in],
            },
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
