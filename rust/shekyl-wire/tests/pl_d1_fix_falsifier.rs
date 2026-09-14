// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `PL-D1` fix-falsifier: a spend must not identify the output it spends.
//!
//! The defect (`docs/design/FCMP_SPEND_LINKABILITY.md` §0): every FCMP++
//! spend reveals `pqc_auths[i].hybrid_public_key`; consensus hashes it with
//! the leaf-hash function and hands the result to the verifier as a public
//! input; the same value was published per output in `tx_extra` `0x07` at
//! creation and copied into the leaf's 4th scalar. An observer hashes the
//! revealed key and looks it up.
//!
//! This test is that observer. It builds a real multi-layer tree in which
//! **every output carries its own real `h_pqc`** (the sibling e2e test fills
//! every decoy with the spent output's value, which would hide the defect
//! behind a wall of false matches), signs one spend on the production path,
//! hashes the key the spend reveals with the production leaf-hash function,
//! and searches the two surfaces an observer holds:
//!
//! 1. every 32-byte entry of every `0x07` field the chain published;
//! 2. every leaf 4th scalar the chain serves — the assembled leaf chunk,
//!    which is the daemon's `get_curve_tree_path` `chunk_outputs` surface.
//!
//! It expects **zero** matches on both. On today's tree it is red with
//! exactly one match on each, at the spent index — that is the defect,
//! observed rather than described. It goes green only when the published
//! value stops being a deterministic function of the key the spend reveals
//! (`PL-D3`: a hiding commitment opened in-circuit). It is the first thing
//! the implementation writes (round doc §10), and it is separate from the
//! binding-falsifier (`test_wrong_opening_fails`), which checks the other
//! direction.
//!
//! The setup is observed by the test itself: the published values must be
//! pairwise distinct, otherwise a zero-match result could come from a
//! degenerate tree rather than from hiding.

use std::collections::HashSet;

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use shekyl_crypto_pq::kem::{HybridX25519MlKem, KeyEncapsulation};
use shekyl_crypto_pq::output::{
    compute_output_key_image, construct_output, recover_combined_ss, OutputData,
};
use shekyl_curve_tree::{
    AssembleInput, BlockHeight, BlockLeaves, CurveTreeClient, Gindex, RawOutput, ReferenceBlock,
    TargetKind, TxLeafInputs,
};
use shekyl_fcmp::PqcLeafScalar;
use shekyl_tx_builder::{sign_pqc_auths, tx_prefix_hash_from_parts, LeafEntry, SpendInput};
use shekyl_units::AtomicUnits;

const COINBASE_LOCK_WINDOW: u64 = shekyl_consensus::COINBASE_LOCK_WINDOW as u64;
/// Past the depth-2 capacity (`38 * 18 = 684`) so both branch layers exist.
const TREE_OUTPUTS: usize = 700;
const RNG_SEED: u64 = 0x504c_2d44_3120_6631; // "PL-D1 f1"

struct Wallet {
    spend_secret: [u8; 32],
    spend_public: [u8; 32],
    x25519_pk: [u8; 32],
    x25519_sk: [u8; 32],
    ml_kem_ek: Vec<u8>,
    ml_kem_dk: Vec<u8>,
}

fn random_wallet(rng: &mut ChaCha20Rng) -> Wallet {
    let b = Scalar::random(rng);
    let spend_public = (ED25519_BASEPOINT_POINT * b).compress().to_bytes();
    let (pk, sk) = HybridX25519MlKem
        .keypair_generate()
        .expect("hybrid KEM keypair generation");
    Wallet {
        spend_secret: b.to_bytes(),
        spend_public,
        x25519_pk: pk.x25519,
        x25519_sk: sk.x25519,
        ml_kem_ek: pk.ml_kem,
        ml_kem_dk: sk.ml_kem.clone(),
    }
}

/// A real output for a real (throwaway) recipient: its own KEM ciphertexts,
/// its own per-output hybrid key, its own `h_pqc`.
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

    // ── The chain: every output with its own real h_pqc ───────────────────
    // `published_0x07` is the observer's table: every 0x07 field the chain
    // carries, concatenated in publication order.
    let mut genesis_outputs: Vec<RawOutput> = Vec::with_capacity(TREE_OUTPUTS);
    let mut genesis_blob: Vec<u8> = Vec::with_capacity(TREE_OUTPUTS * 32);
    let mut published_0x07: Vec<[u8; 32]> = Vec::new();

    genesis_outputs.push(RawOutput {
        output_key: spent.output_key,
        commitment: Some(spent.commitment),
        target: TargetKind::TaggedKey,
    });
    genesis_blob.extend_from_slice(&spent.h_pqc);
    published_0x07.push(spent.h_pqc);
    for _ in 1..TREE_OUTPUTS {
        let decoy = real_output(&mut rng, 1);
        genesis_outputs.push(RawOutput {
            output_key: decoy.output_key,
            commitment: Some(decoy.commitment),
            target: TargetKind::TaggedKey,
        });
        genesis_blob.extend_from_slice(&decoy.h_pqc);
        published_0x07.push(decoy.h_pqc);
    }

    let reference_height = COINBASE_LOCK_WINDOW + 1;
    let mut client = CurveTreeClient::new();
    for height in 0..=reference_height {
        let (outputs, blob): (Vec<RawOutput>, Vec<u8>) = if height == 0 {
            (genesis_outputs.clone(), genesis_blob.clone())
        } else {
            let filler = real_output(&mut rng, 1);
            published_0x07.push(filler.h_pqc);
            (
                vec![RawOutput {
                    output_key: filler.output_key,
                    commitment: Some(filler.commitment),
                    target: TargetKind::TaggedKey,
                }],
                filler.h_pqc.to_vec(),
            )
        };
        let txs = [TxLeafInputs {
            is_miner: true,
            leaf_hash_blob: Some(blob.as_slice()),
            outputs: outputs.as_slice(),
        }];
        client
            .ingest_block(BlockLeaves {
                height: BlockHeight(height),
                txs: &txs,
            })
            .expect("ingest block");
    }

    // The test observes its own setup: a zero-match result must come from
    // hiding, never from a degenerate table.
    let distinct: HashSet<[u8; 32]> = published_0x07.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        published_0x07.len(),
        "setup: every published 0x07 value must be distinct"
    );

    let (tree_root, tree_depth) = client
        .root_and_depth_at(BlockHeight(reference_height))
        .expect("tree root + depth at reference height");
    assert!(
        tree_depth >= 3,
        "expected a depth-3 tree; got depth {tree_depth}"
    );

    // ── The spend, on the production path ────────────────────────────────
    let reference = ReferenceBlock {
        height: BlockHeight(reference_height),
        curve_tree_root: tree_root,
        block_hash: [0xAB; 32],
    };
    let path = client
        .assemble_path(
            &AssembleInput {
                gindex: Gindex(spent_index),
                output_key: spent.output_key,
                commitment: spent.commitment,
            },
            &reference,
        )
        .expect("assemble membership path");
    let leaf_chunk: Vec<LeafEntry> = path
        .leaf_chunk
        .iter()
        .map(|cl| LeafEntry {
            output_key: cl.output_key,
            key_image_gen: cl.key_image_gen,
            commitment: cl.commitment,
            h_pqc: cl.h_pqc,
        })
        .collect();
    let spend_input = SpendInput {
        output_key: spent.output_key,
        commitment: spent.commitment,
        amount: AtomicUnits::from_raw(input_amount),
        spend_key_x: *ki.spend_secret_x,
        spend_key_y: spent.y,
        commitment_mask: spent.z,
        h_pqc: spent.h_pqc,
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
    let pqc_auths = sign_pqc_auths(&[tx_prefix_hash], std::slice::from_ref(&spend_input))
        .expect("PQC auth signing");
    assert_eq!(pqc_auths.len(), 1, "one PQC auth per input");
    let revealed_key: &[u8] = &pqc_auths[0].public_key;

    // ── The observer ─────────────────────────────────────────────────────
    // Exactly what consensus does with the revealed key
    // (`shekyl_fcmp_pqc_leaf_hash` / `PqcLeafScalar::from_pqc_public_key`).
    let observed = PqcLeafScalar::from_pqc_public_key(revealed_key).0;

    // Surface 1: every published 0x07 value.
    let extra_matches: Vec<usize> = published_0x07
        .iter()
        .enumerate()
        .filter(|(_, v)| **v == observed)
        .map(|(i, _)| i)
        .collect();
    // Surface 2: every leaf 4th scalar the chain serves in the assembled
    // chunk (the `get_curve_tree_path` `chunk_outputs` surface).
    let chunk_matches: Vec<usize> = path
        .leaf_chunk
        .iter()
        .enumerate()
        .filter(|(_, cl)| cl.h_pqc == observed)
        .map(|(i, _)| i)
        .collect();

    assert!(
        extra_matches.is_empty() && chunk_matches.is_empty(),
        "PL-D1: the hash of the key the spend reveals identifies the spent output (spent index \
         {spent_index}) — matches at published-0x07 index {extra_matches:?} and at served-chunk \
         position {chunk_matches:?}; both must be empty"
    );
}
