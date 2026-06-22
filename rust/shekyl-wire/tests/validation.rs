// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Structural / canonical-form validation tests (GENESIS_TX_WIRE_FORMAT.md §10 +
//! the context-free parts of §12): resource bounds, key-image ordering, the
//! unlock_time block-height form, and `nbp == 1`. Chain-context rules (§13) are
//! the consensus layer's and are not exercised here.

use shekyl_wire::{
    Block, BondPost, BondPostKind, BpPlus, Ct, CtBase, Holdings, Input, Output, PqcAuth, Prunable,
    ServeCredit, Transaction, TxPrefix,
};

/// A minimal fee-only-shaped tx (no outputs, empty pqc, no prunable) wrapping a
/// single non-spending archival input — enough to reach the per-arm bound checks.
fn fee_only_with(input: Input) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![input],
            outputs: vec![],
            extra: vec![],
        },
        ct: Ct::Fcmp {
            fee: 0,
            reference_block: [0u8; 32],
            base: CtBase {
                enc_amounts: vec![],
                enc_labels: vec![],
                commitments: vec![],
            },
            pqc_auths: vec![],
            prunable: None,
        },
    }
}

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
    // Key images strictly descending in byte order (memcmp), per the C++ oracle.
    spend(vec![ki(2), ki(1)], vec![out(), out()], 0, 1)
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
    // Ascending order is the *unsorted* case now — the oracle requires descending.
    let err = spend(vec![ki(1), ki(2)], vec![out()], 0, 1)
        .validate()
        .unwrap_err();
    assert!(err.to_string().contains("descending"), "{err}");
}

#[test]
fn duplicate_key_images_rejected() {
    assert!(spend(vec![ki(1), ki(1)], vec![out()], 0, 1)
        .validate()
        .is_err());
}

#[test]
fn nonempty_key_offsets_rejected() {
    // FCMP++ spend inputs carry no ring offsets — the C++ oracle rejects a non-empty
    // key_offsets (blockchain.cpp:3715); the field is vestigial until §5 removes it.
    let tx = spend(
        vec![Input::ToKey {
            amount: 0,
            key_offsets: vec![1],
            key_image: [1u8; 32],
        }],
        vec![out()],
        0,
        1,
    );
    let err = tx.validate().unwrap_err();
    assert!(err.to_string().contains("key_offsets"), "{err}");
}

#[test]
fn too_many_inputs_rejected() {
    // The cap is on total inputs (C++ caps vin.size()); 9 descending key images
    // (so the ordering check passes) must be rejected by the input-count cap alone.
    let ins: Vec<Input> = (1u8..=9).rev().map(ki).collect(); // 9 > MAX_FCMP_INPUTS (8)
    let err = spend(ins, vec![out()], 0, 1).validate().unwrap_err();
    assert!(err.to_string().contains("inputs exceed"), "{err}");
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
    // pqc_auths are per-input (count == nvin); a length != vin must reject. Key images
    // descending so the ordering check passes and we reach the pqc-length check.
    let mut tx = spend(vec![ki(2), ki(1)], vec![out()], 0, 1); // 2 inputs
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
fn serve_credit_oversized_signature_rejected() {
    // validate() mirrors the read caps for the archival arms: an oversized
    // hybrid_signature must reject (else it would serialize to unparseable bytes).
    let sc = ServeCredit {
        p_canonical_id: [0u8; 32],
        shard_id: 0,
        settlement_epoch: 0,
        segment_subroot_rk: [0u8; 32],
        leaf_index_in_segment: 0,
        leaf_bytes: [0u8; 128],
        c1_layers: vec![],
        c2_layers: vec![],
        hybrid_signature: vec![0u8; shekyl_wire::transaction::PQC_HYBRID_SINGLE_SIG_LEN + 1],
    };
    let err = fee_only_with(Input::ServeCredit(Box::new(sc)))
        .validate()
        .unwrap_err();
    assert!(err.to_string().contains("hybrid_signature"), "{err}");
}

#[test]
fn serve_credit_must_not_mix_with_a_spend() {
    // §2.5: serve_credit is the entire tx. Mixed with a key-image spend it would
    // otherwise pass the spend branch's lenient pseudoOuts coupling — reject the shape.
    let sc = ServeCredit {
        p_canonical_id: [0u8; 32],
        shard_id: 0,
        settlement_epoch: 0,
        segment_subroot_rk: [0u8; 32],
        leaf_index_in_segment: 0,
        leaf_bytes: [0u8; 128],
        c1_layers: vec![],
        c2_layers: vec![],
        hybrid_signature: vec![],
    };
    let tx = Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::ServeCredit(Box::new(sc)), ki(1)],
            outputs: vec![out()],
            extra: vec![],
        },
        // Counts here are irrelevant: the shape check rejects before the ct coupling.
        ct: Ct::Fcmp {
            fee: 0,
            reference_block: [0u8; 32],
            base: CtBase {
                enc_amounts: vec![[0u8; 9]],
                enc_labels: vec![[0u8; 9]],
                commitments: vec![[0u8; 32]],
            },
            pqc_auths: vec![],
            prunable: None,
        },
    };
    let err = tx.validate().unwrap_err();
    assert!(err.to_string().contains("Serve-credit shape"), "{err}");
}

#[test]
fn bond_post_oversized_pubkey_rejected() {
    let bp = BondPost {
        hybrid_public_key: vec![0u8; shekyl_wire::transaction::PQC_HYBRID_SINGLE_KEY_LEN + 1],
        p_canonical_id: [0u8; 32],
        kind: BondPostKind::Other(3),
        holdings: Holdings::CompleteTree,
        bonded_total_atomic: 0,
        bond_credit: 0,
        bond_debit: 0,
    };
    let err = fee_only_with(Input::BondPost(Box::new(bp)))
        .validate()
        .unwrap_err();
    assert!(err.to_string().contains("hybrid_public_key"), "{err}");
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
