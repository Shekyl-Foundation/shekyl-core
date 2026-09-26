// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `PL-D1` fix-falsifier: a spend must not identify the output it spends.
//!
//! The defect (`docs/design/FCMP_SPEND_LINKABILITY.md` §0, ruled and fixed
//! 2026-09-14): every FCMP++ spend reveals `pqc_auths[i].hybrid_public_key`;
//! before `PL-D3` consensus hashed it with the leaf-hash function and handed
//! the result to the verifier as a public input — the same value published
//! per output in `tx_extra` `0x07` at creation and copied into the leaf's 4th
//! scalar. An observer hashed the revealed key and looked it up.
//!
//! This test is that observer, on the fixed construction. It builds a real
//! multi-layer tree in which **every output carries its own real `0x07`
//! entry** (the sibling e2e test fills every decoy with the spent output's
//! value, which would hide a defect behind a wall of false matches), signs
//! one spend on the production path, derives from the key the spend reveals
//! everything a verifier derives — the key scalar `k`, its point `K = k·G_k`,
//! and `K.x` — and searches the two surfaces an observer holds:
//!
//! 1. every 64-byte entry of every `0x07` field the chain published (the
//!    commitment half against `K`, the record half against nothing — the
//!    record is `cSHAKE256(pk ‖ r_h)` under a blind the observer lacks);
//! 2. every leaf 4th scalar the chain serves — the assembled leaf chunk, the
//!    surface an archival shard or a wallet-side leaf stream carries —
//!    against `K.x`.
//!
//! It expects **zero** matches on both. On the pre-`PL-D3` tree (the same
//! test against the leaf hash) it was red with exactly one match on each, at
//! the spent index — the defect observed rather than described. It is green
//! only while the published value is hiding: `CM = K + r·J` equals `K` only
//! for `r = 0`, which the exceptional-value guard refuses. It is separate
//! from the binding-falsifier (`test_wrong_opening_fails`), which checks the
//! other direction.
//!
//! The setup is observed by the test itself: the published commitments must
//! be pairwise distinct, otherwise a zero-match result could come from a
//! degenerate tree rather than from hiding.

mod common;
use common::random_wallet;

use std::collections::HashSet;

use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use shekyl_crypto_pq::output::{
    compute_output_key_image, construct_output, recover_combined_ss, OutputData,
};
use shekyl_curve_tree::{
    AssembleInput, BlockHash, BlockHeight, BlockLeaves, CurveTreeClient, Gindex, RawOutput,
    ReferenceBlock, TargetKind, TxLeafInputs,
};
use shekyl_fcmp::{tree::ed25519_point_to_selene_scalar, PqcKeyScalar};
use shekyl_tx_builder::{sign_pqc_auths, tx_prefix_hash_from_parts, LeafEntry, SpendInput};
use shekyl_types::SigningPayloadHash;
use shekyl_units::AtomicUnits;

const COINBASE_LOCK_WINDOW: u64 = shekyl_consensus::COINBASE_LOCK_WINDOW as u64;
/// Past the depth-2 capacity (`38 * 18 = 684`) so both branch layers exist.
const TREE_OUTPUTS: usize = 700;
const RNG_SEED: u64 = 0x504c_2d44_3120_6631; // "PL-D1 f1"

/// A real output for a real (throwaway) recipient: its own KEM ciphertexts,
/// its own per-output hybrid key, its own `0x07` entry.
fn real_output(rng: &mut ChaCha20Rng, amount: u64) -> OutputData {
    let recipient = random_wallet(rng);
    let tx_secret = Scalar::random(rng).to_bytes();
    construct_output(
        &tx_secret,
        &recipient.x25519_pk,
        &recipient.ml_kem_ek,
        &recipient.spend_public,
        amount,
        0,
    )
    .expect("construct decoy output")
}

#[test]
fn pl_d1_revealed_key_does_not_identify_the_spent_output() {
    let mut rng = ChaCha20Rng::seed_from_u64(RNG_SEED);
    let wallet = random_wallet(&mut rng);
    let input_amount: u64 = 1_000_000_000;
    let spent_index: u64 = 0;

    // ── Our output, at genesis vout 0 ─────────────────────────────────────
    let tx_secret = Scalar::random(&mut rng).to_bytes();
    let spent = construct_output(
        &tx_secret,
        &wallet.x25519_pk,
        &wallet.ml_kem_ek,
        &wallet.spend_public,
        input_amount,
        spent_index,
    )
    .expect("construct spent output");
    let combined_ss = recover_combined_ss(
        &wallet.x25519_sk,
        &wallet.ml_kem_dk,
        &spent.kem_ciphertext_x25519,
        &spent.kem_ciphertext_ml_kem,
    )
    .expect("recover combined shared secret");
    let hp_of_o = shekyl_curve_generators::biased_hash_to_point(spent.output_key)
        .compress()
        .to_bytes();
    let ki = compute_output_key_image(&combined_ss.0, spent_index, &wallet.spend_secret, &hp_of_o)
        .expect("compute key image");

    // ── The chain: every output with its own real 0x07 entry ──────────────
    // `published_0x07` is the observer's table: every 0x07 entry the chain
    // carries, in publication order.
    let mut genesis_outputs: Vec<RawOutput> = Vec::with_capacity(TREE_OUTPUTS);
    let mut genesis_blob: Vec<u8> = Vec::with_capacity(TREE_OUTPUTS * 64);
    let mut published_0x07: Vec<[u8; 64]> = Vec::new();

    genesis_outputs.push(RawOutput {
        output_key: shekyl_curve_tree::OneTimePubkey::from_bytes(spent.output_key),
        commitment: Some(shekyl_curve_tree::CommitmentBytes::from_bytes(
            spent.commitment,
        )),
        target: TargetKind::TaggedKey,
    });
    genesis_blob.extend_from_slice(&spent.pqc_leaf.entry_bytes());
    published_0x07.push(spent.pqc_leaf.entry_bytes());
    for _ in 1..TREE_OUTPUTS {
        let decoy = real_output(&mut rng, 1);
        genesis_outputs.push(RawOutput {
            output_key: shekyl_curve_tree::OneTimePubkey::from_bytes(decoy.output_key),
            commitment: Some(shekyl_curve_tree::CommitmentBytes::from_bytes(
                decoy.commitment,
            )),
            target: TargetKind::TaggedKey,
        });
        genesis_blob.extend_from_slice(&decoy.pqc_leaf.entry_bytes());
        published_0x07.push(decoy.pqc_leaf.entry_bytes());
    }

    let reference_height = COINBASE_LOCK_WINDOW + 1;
    let mut client = CurveTreeClient::new();
    for height in 0..=reference_height {
        let (outputs, blob): (Vec<RawOutput>, Vec<u8>) = if height == 0 {
            (genesis_outputs.clone(), genesis_blob.clone())
        } else {
            let filler = real_output(&mut rng, 1);
            published_0x07.push(filler.pqc_leaf.entry_bytes());
            (
                vec![RawOutput {
                    output_key: shekyl_curve_tree::OneTimePubkey::from_bytes(filler.output_key),
                    commitment: Some(shekyl_curve_tree::CommitmentBytes::from_bytes(
                        filler.commitment,
                    )),
                    target: TargetKind::TaggedKey,
                }],
                filler.pqc_leaf.entry_bytes().to_vec(),
            )
        };
        let txs = [TxLeafInputs {
            is_miner: true,
            leaf_entry_blob: Some(blob.as_slice()),
            outputs: outputs.as_slice(),
        }];
        client
            .ingest_block(BlockLeaves {
                height: BlockHeight::from_raw(height),
                txs: &txs,
            })
            .expect("ingest block");
    }

    // The test observes its own setup: a zero-match result must come from
    // hiding, never from a degenerate table.
    let distinct: HashSet<[u8; 32]> = published_0x07
        .iter()
        .map(|e| <[u8; 32]>::try_from(&e[..32]).expect("entry point"))
        .collect();
    assert_eq!(
        distinct.len(),
        published_0x07.len(),
        "setup: every published leaf commitment must be distinct"
    );

    let (tree_root, tree_depth) = client
        .root_and_depth_at(BlockHeight::from_raw(reference_height))
        .expect("tree root + depth at reference height");
    assert!(
        tree_depth >= 3,
        "expected a depth-3 tree; got depth {tree_depth}"
    );

    // ── The spend, on the production path ────────────────────────────────
    let reference = ReferenceBlock {
        height: BlockHeight::from_raw(reference_height),
        curve_tree_root: tree_root,
        block_hash: BlockHash::from_bytes([0xAB; 32]),
    };
    let path = client
        .assemble_path(
            &AssembleInput {
                gindex: Gindex::from_raw(spent_index),
                output_key: shekyl_curve_tree::OneTimePubkey::from_bytes(spent.output_key),
                commitment: shekyl_curve_tree::CommitmentBytes::from_bytes(spent.commitment),
            },
            &reference,
        )
        .expect("assemble membership path");
    let leaf_chunk: Vec<LeafEntry> = path
        .leaf_chunk
        .iter()
        .map(|cl| LeafEntry {
            output_key: cl.output_key.to_bytes(),
            key_image_gen: cl.key_image_gen,
            commitment: cl.commitment.to_bytes(),
            cm_x: cl.cm_x,
        })
        .collect();
    let spend_input = SpendInput {
        output_key: spent.output_key,
        commitment: spent.commitment,
        amount: AtomicUnits::from_raw(input_amount),
        spend_key_x: *ki.spend_secret_x,
        spend_key_y: spent.y,
        commitment_mask: spent.z,
        combined_ss: combined_ss.0.to_vec(),
        output_index: spent_index,
        leaf_chunk,
        c1_layers: path.c1_layers.clone(),
        c2_layers: path.c2_layers.clone(),
    };
    // A payment to a random recipient; the prefix hash is what the PQC auth
    // signs, and the auth is what reveals the key.
    let recipient = random_wallet(&mut rng);
    let payment = construct_output(
        &Scalar::random(&mut rng).to_bytes(),
        &recipient.x25519_pk,
        &recipient.ml_kem_ek,
        &recipient.spend_public,
        input_amount - 1_000_000,
        0,
    )
    .expect("construct payment output");
    let tx_prefix_hash = tx_prefix_hash_from_parts(
        &[*ki.key_image.as_bytes()],
        &[payment.output_key],
        &[Some(payment.view_tag_prefilter)],
        &[],
    );
    let pqc_auths = sign_pqc_auths(
        // A stand-in message: the prefix hash's bytes, not the §1.1 per-input
        // payload (`phase1_payload_hashes`). These auths are never verified
        // here; `.to_bytes()` then `SigningPayloadHash::from_bytes` is the
        // deliberate, visible un-typing and re-typing — both newtypes refuse
        // the silent form (RTN-7 Q3), which is why a stand-in has to say so.
        &[SigningPayloadHash::from_bytes(tx_prefix_hash.to_bytes())],
        std::slice::from_ref(&spend_input),
    )
    .expect("PQC auth signing");
    assert_eq!(pqc_auths.len(), 1, "one PQC auth per input");
    let revealed_key: &[u8] = &pqc_auths[0].public_key;

    // ── The observer ─────────────────────────────────────────────────────
    // Exactly what consensus derives from the revealed key
    // (`PqcKeyScalar::from_pqc_public_key` → `K = k·G_k`, the circuit's public
    // value), plus the leaf-scalar form `K.x` for the served-chunk surface.
    let key = PqcKeyScalar::from_pqc_public_key(revealed_key);
    let observed_point = key.point();
    let observed_x = ed25519_point_to_selene_scalar(&observed_point).expect("K decompresses");

    // Surface 1: every published 0x07 entry's commitment half against K.
    let extra_matches: Vec<usize> = published_0x07
        .iter()
        .enumerate()
        .filter(|(_, e)| e[..32] == observed_point)
        .map(|(i, _)| i)
        .collect();
    // Surface 2: every leaf 4th scalar the chain serves in the assembled
    // chunk (the served-leaf surface) against K.x.
    let chunk_matches: Vec<usize> = path
        .leaf_chunk
        .iter()
        .enumerate()
        .filter(|(_, cl)| cl.cm_x == observed_x)
        .map(|(i, _)| i)
        .collect();

    assert!(
        extra_matches.is_empty() && chunk_matches.is_empty(),
        "PL-D1: the point derived from the key the spend reveals identifies the spent output \
         (spent index {spent_index}) — matches at published-0x07 index {extra_matches:?} and at \
         served-chunk position {chunk_matches:?}; both must be empty"
    );
}
