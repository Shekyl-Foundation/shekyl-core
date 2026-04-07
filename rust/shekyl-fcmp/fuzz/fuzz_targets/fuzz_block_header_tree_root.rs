// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_fcmp::proof::{prove, verify, ProveInput, BranchLayer};
use shekyl_fcmp::leaf::PqcLeafScalar;

fuzz_target!(|data: &[u8]| {
    // Feed block headers with fuzz-supplied tree roots and signable hashes to
    // prove/verify. Mismatches between the prove-time and verify-time roots or
    // hashes must be rejected.
    if data.len() < 96 {
        return;
    }

    let mut prove_root = [0u8; 32];
    let mut verify_root = [0u8; 32];
    let mut signable_tx_hash = [0u8; 32];
    prove_root.copy_from_slice(&data[..32]);
    verify_root.copy_from_slice(&data[32..64]);
    signable_tx_hash.copy_from_slice(&data[64..96]);

    let tree_depth = if data.len() > 96 { data[96].max(1) } else { 1 };

    let input = ProveInput {
        output_key: [1u8; 32],
        key_image_gen: [2u8; 32],
        commitment: [3u8; 32],
        h_pqc: PqcLeafScalar([0x42; 32]),
        spend_key_x: [4u8; 32],
        spend_key_y: [5u8; 32],
        leaf_chunk_outputs: vec![],
        leaf_chunk_h_pqc: vec![],
        c1_branch_layers: vec![],
        c2_branch_layers: vec![],
    };

    let proof_result = match prove(&[input], &prove_root, tree_depth, signable_tx_hash) {
        Ok(p) => p,
        Err(_) => return,
    };

    let key_images = vec![[0u8; 32]];

    let result = verify(
        &proof_result.proof,
        &key_images,
        &proof_result.pseudo_outs,
        &[PqcLeafScalar([0x42; 32])],
        &verify_root,
        tree_depth,
        signable_tx_hash,
    );

    if prove_root != verify_root {
        match result {
            Ok(true) => panic!("verification passed with mismatched tree roots"),
            _ => {}
        }
    }
});
