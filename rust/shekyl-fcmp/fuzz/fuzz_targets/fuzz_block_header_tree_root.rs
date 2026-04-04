// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_fcmp::proof::{prove, verify, ProveInput, ShekylFcmpProof};
use shekyl_fcmp::leaf::{PqcLeafScalar, ShekylLeaf};

fuzz_target!(|data: &[u8]| {
    // Feed block headers with mismatched curve_tree_root values to validation.
    // We construct a proof against one tree root, then verify against a
    // fuzz-supplied root — mismatches must be rejected.
    if data.len() < 64 {
        return;
    }

    let mut prove_root = [0u8; 32];
    let mut verify_root = [0u8; 32];
    prove_root.copy_from_slice(&data[..32]);
    verify_root.copy_from_slice(&data[32..64]);

    let tree_depth = if data.len() > 64 { data[64] } else { 20 };

    let pqc_hash = PqcLeafScalar([0x42; 32]);
    let input = ProveInput {
        leaf: ShekylLeaf {
            o_x: [1u8; 32],
            i_x: [2u8; 32],
            c_x: [3u8; 32],
            h_pqc: pqc_hash,
        },
        tree_path: vec![0u8; 64],
        key_image: [4u8; 32],
        pseudo_out: [5u8; 32],
        pqc_hash,
    };

    let proof = match prove(&[input.clone()], &prove_root, tree_depth) {
        Ok(p) => p,
        Err(_) => return,
    };

    let result = verify(
        &proof,
        &[input.key_image],
        &[input.pseudo_out],
        &[input.pqc_hash],
        &verify_root,
        tree_depth,
    );

    if prove_root != verify_root {
        // Mismatched roots must be rejected
        match result {
            Ok(true) => panic!("verification passed with mismatched tree roots"),
            _ => {} // Rejection is correct
        }
    }
});
