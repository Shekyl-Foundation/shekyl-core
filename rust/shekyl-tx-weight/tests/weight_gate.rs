// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **The weight gate** (`FEE_LADDER_DERIVATION.md` §11.6 PR B item 3).
//!
//! `predict_weight` prices a transaction the wallet has not built yet. Until
//! FL-R20 that prediction had a 2% cushion under it: `check_fee` admitted at
//! `needed - needed/50`, so a one-byte prediction error cost nothing. FL-R23
//! pins `RELAY_ADMISSION_SLACK_BP = 0`, and at zero slack a one-byte error on
//! any shape is a hard bounce — one the lookback-min admission cannot absorb,
//! because the shortfall is structural, not temporal.
//!
//! The whole justification for deleting that cushion rested on a **single**
//! equality assertion, at one shape, in
//! `shekyl-engine-core/src/engine/transfer/transfer_pending_tx_tests.rs`. This
//! file replaces that one point with the shape space.
//!
//! # Why this needs no proving, and where the circularity is
//!
//! Weight is a property of the *serialization*, and
//! [`shekyl_tx_weight::predict_weight`] is pure arithmetic over counts: nothing
//! in it consults a proof's validity, only its **length**. So the builder can
//! be fed proof bytes of the right length and the assembly it produces is
//! byte-exact — real `Extra` serializer, real Bp+ (`prove_plus`), real PQC
//! field lengths, real `Transaction::write`.
//!
//! One term is stubbed, and it is the one that would otherwise make this
//! circular: the FCMP++ proof blob's length comes from
//! [`shekyl_tx_weight::fcmp_proof_size`], which `predict_weight` also reads. A
//! test that supplied the length from the table it is checking would assert
//! nothing about that table (rule 47). It is anchored **elsewhere**, by real
//! proving, and this file deliberately does not duplicate that oracle
//! (rule 15):
//!
//! * `kat_fcmp_proof_size_grid` (engine-core `tx_fee_model.rs`, `#[ignore]`d as
//!   slow) re-measures every cell of the `1..=8 x 1..=24` table against
//!   `measure_fcmp_proof_len`, which does real proving;
//! * `kat_fcmp_proof_size_depth1_row` guards the depth-1 column in CI.
//!
//! This file therefore asserts the **assembly**: given a correct proof size,
//! does every other field of the predictor match the bytes the builder emits.
//!
//! # Coverage boundary, stated rather than implied
//!
//! `predict_weight`'s `tree_depth` is the FCMP++ **layer count** `L`; the wire
//! field is the LMDB depth `L - 1`. `build_wire_tx` rejects `L < 2`, so a
//! spend at `L = 1` is unbuildable and the gate covers `2..=MAX_TREE_DEPTH`.
//! The `L = 1` column of the proof-size table is covered by the KATs above,
//! which measure the prover directly and are not bound by the builder's floor.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::kem::HYBRID_KEM_CT_LEN;
use shekyl_crypto_pq::output::EncryptedOutputField;
use shekyl_scanner::extra::Extra;
use shekyl_tx_builder::{encode_final_tx, PqcAuth, WireEncodeInput};
use shekyl_tx_weight::{
    fcmp_proof_size, predict_weight, InputCount, OutputCount, MAX_OUTPUTS, MAX_TREE_DEPTH,
};
use shekyl_wire::transaction::{PQC_HYBRID_SINGLE_KEY_LEN, PQC_HYBRID_SINGLE_SIG_LEN};
use shekyl_wire::Transaction;

/// `MAX_INPUTS` is crate-internal to `shekyl-tx-weight` on purpose (it comes
/// from `shekyl-fcmp`, its upstream home). Read it from that home, not from a
/// re-export, for the same reason the crate itself does.
const MAX_INPUTS: usize = shekyl_fcmp::MAX_INPUTS;

/// Distinct filler byte for index `i`. Weight depends only on field LENGTHS,
/// never on their contents, so these bytes carry no meaning beyond being
/// distinct — but they are derived rather than cast, because `i` is bounded by
/// `MAX_INPUTS` / `MAX_OUTPUTS` and a silent truncation would make two indices
/// collide without saying so.
fn filler(i: usize, tag: u8) -> u8 {
    u8::try_from(i).expect("index is bounded by MAX_INPUTS / MAX_OUTPUTS") ^ tag
}

/// `EncryptedOutputField` has no byte constructor outside its `Deserialize`
/// impl, deliberately (a test-only one could not be gated out of the
/// production archive). Same route the builder's own fixtures take.
fn enc_field() -> EncryptedOutputField {
    serde_json::from_str("\"000000000000000000\"").expect("fixture hex is valid")
}

/// A real Bp+ over `n_out` commitments. Proving is the one genuinely slow part
/// here and depends only on `n_out`, so callers cache one per count.
fn bulletproof_for(n_out: usize) -> Bulletproof {
    let commitments = (0..n_out)
        .map(|i| {
            shekyl_curve_primitives::Commitment::new(
                curve25519_dalek::scalar::Scalar::from(u64::from(filler(i, 0)) + 1),
                100,
            )
        })
        .collect();
    Bulletproof::prove_plus(&mut rand_core::OsRng, commitments).expect("bp+ prove")
}

/// The `tx_extra` the transfer path actually appends (`sign_bridge.rs`): the
/// hybrid-transfer pubkey + per-output KEM ciphertexts, plus the `0x07`
/// leaf-hash blob. Real serializer — so the `tx_extra` term is validated
/// against bytes, not against the predictor's own model of them.
fn transfer_extra(n_out: usize) -> Vec<u8> {
    let mut e = Extra::for_hybrid_transfer(
        ED25519_BASEPOINT_POINT,
        (0..n_out).map(|_| vec![0u8; HYBRID_KEM_CT_LEN]),
    );
    e.push_pqc_leaf_hashes(vec![0u8; n_out * 32]);
    e.serialize()
}

/// Assemble the transaction the builder would produce for this shape and
/// return its canonical `weight()`.
fn built_weight(n_in: usize, n_out: usize, layers: u8, fee: u64, bp: &Bulletproof) -> usize {
    let input = WireEncodeInput {
        key_images: (0..n_in).map(|i| [filler(i, 0x00); 32]).collect(),
        extra_inputs: Vec::new(),
        output_keys: (0..n_out).map(|i| [filler(i, 0x5A); 32]).collect(),
        output_amounts: vec![0; n_out],
        view_tags: vec![Some(3); n_out],
        tx_extra: transfer_extra(n_out),
        fee,
        enc_amounts: vec![enc_field(); n_out],
        enc_labels: vec![enc_field(); n_out],
        out_commitments: (0..n_out).map(|i| [filler(i, 0xA5); 32]).collect(),
        pseudo_outs: (0..n_in).map(|i| [filler(i, 0x3C); 32]).collect(),
        bulletproof: bp.clone(),
        reference_block: [0xAB; 32],
        // The one stubbed term. Length from the table; the table is anchored by
        // real proving in the KATs named in this file's header.
        fcmp_proof: vec![0xCC; fcmp_proof_size(InputCount::clamped(n_in), layers)],
        pqc_auths: (0..n_in)
            .map(|_| PqcAuth {
                auth_version: 1,
                signature: vec![0xDD; PQC_HYBRID_SINGLE_SIG_LEN],
                public_key: vec![0xEE; PQC_HYBRID_SINGLE_KEY_LEN],
            })
            .collect(),
        fcmp_layers: layers,
    };

    let bytes = encode_final_tx(&input).expect("the builder must encode every in-range shape");
    Transaction::from_bytes(&bytes)
        .expect("the builder's own bytes must re-parse")
        .weight()
}

/// Every `n_in x n_out x L` the builder can produce, asserted exactly.
///
/// `n_out` spans both sides of every power-of-two Bp+ clawback boundary
/// (1, 2 | 3, 4 | 5..8 | 9..16), which is the term most likely to drift: the
/// clawback is zero at `n_padded <= 2` and steps at each doubling.
#[test]
fn predict_weight_equals_built_weight_over_the_shape_space() {
    let bps: Vec<Bulletproof> = (1..=MAX_OUTPUTS).map(bulletproof_for).collect();
    let mut checked = 0usize;

    for n_in in 1..=MAX_INPUTS {
        for n_out in 1..=MAX_OUTPUTS {
            for layers in 2..=MAX_TREE_DEPTH {
                let fee = 1_000_000u64;
                let predicted = predict_weight(
                    InputCount::clamped(n_in),
                    OutputCount::clamped(n_out),
                    layers,
                    fee,
                );
                let built = built_weight(n_in, n_out, layers, fee, &bps[n_out - 1]);
                assert_eq!(
                    predicted, built,
                    "weight mismatch at n_in={n_in} n_out={n_out} L={layers} fee={fee}: \
                     predicted {predicted}, built {built}"
                );
                checked += 1;
            }
        }
    }

    // Rule 47: the gate asserts its own subject exists. An empty enumeration
    // would pass silently and read as coverage.
    assert_eq!(
        checked,
        MAX_INPUTS * MAX_OUTPUTS * usize::from(MAX_TREE_DEPTH - 1),
        "the shape enumeration must cover the full grid"
    );
}

/// The fee is a *field of the thing it prices*: the wire carries `varint(fee)`,
/// so the predicted weight steps at every `2^(7k)`. This is the axis
/// engine-core's `converge_fee` iterates to a fixed point, and at zero relay
/// slack a one-byte error here is exactly the hard bounce FL-R23 cannot cover.
///
/// Swept on both sides of every varint boundary a `u64` fee can reach.
#[test]
fn predict_weight_equals_built_weight_across_every_fee_varint_boundary() {
    let shapes = [(1usize, 1usize, 2u8), (2, 2, 8), (8, 16, MAX_TREE_DEPTH)];
    let bps: Vec<Bulletproof> = (1..=MAX_OUTPUTS).map(bulletproof_for).collect();

    let mut fees = vec![0u64, 1];
    for bits in [7u32, 14, 21, 28, 35, 42, 49, 56, 63] {
        let b = 1u64 << bits;
        fees.extend_from_slice(&[b - 1, b, b + 1]);
    }
    fees.push(u64::MAX);

    let mut varint_lengths = std::collections::BTreeSet::new();
    for &(n_in, n_out, layers) in &shapes {
        for &fee in &fees {
            let predicted = predict_weight(
                InputCount::clamped(n_in),
                OutputCount::clamped(n_out),
                layers,
                fee,
            );
            let built = built_weight(n_in, n_out, layers, fee, &bps[n_out - 1]);
            assert_eq!(
                predicted, built,
                "weight mismatch at n_in={n_in} n_out={n_out} L={layers} fee={fee}: \
                 predicted {predicted}, built {built}"
            );
            varint_lengths.insert(shekyl_curve_io::varint_len(fee));
        }
    }

    // Rule 47 again, and on the axis that matters: sweeping a hundred fees that
    // all encode to four bytes would assert nothing about the boundaries. A
    // `u64` varint is 1..=10 bytes and every length must have been reached.
    assert_eq!(
        varint_lengths.into_iter().collect::<Vec<_>>(),
        (1..=10).collect::<Vec<_>>(),
        "the fee sweep must reach every u64 varint length"
    );
}
