// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_fcmp::proof::{verify, ShekylFcmpProof};
use shekyl_fcmp::leaf::PqcLeafScalar;

fuzz_target!(|data: &[u8]| {
    // Attempt to interpret raw bytes as an FCMP++ proof and verify it.
    // The proof header is: version(1) + num_inputs(1) + tree_depth(1) + tree_root(32).
    if data.len() < 35 {
        let proof = ShekylFcmpProof {
            data: data.to_vec(),
            num_inputs: 1,
            tree_depth: 8,
        };
        let _ = verify(&proof, &[[0u8; 32]], &[[0u8; 32]], &[PqcLeafScalar([0u8; 32])], &[0u8; 32], 8);
        return;
    }

    let num_inputs = data[1].max(1);
    let tree_depth = data[2];

    let proof = ShekylFcmpProof {
        data: data.to_vec(),
        num_inputs: num_inputs as u32,
        tree_depth,
    };

    let mut tree_root = [0u8; 32];
    tree_root.copy_from_slice(&data[3..35]);

    let key_images: Vec<[u8; 32]> = (0..num_inputs as usize)
        .map(|i| {
            let mut ki = [0u8; 32];
            if let Some(chunk) = data.get(35 + i * 32..35 + (i + 1) * 32) {
                ki[..chunk.len()].copy_from_slice(chunk);
            }
            ki
        })
        .collect();

    let pseudo_outs: Vec<[u8; 32]> = vec![[0u8; 32]; num_inputs as usize];
    let pqc_hashes: Vec<PqcLeafScalar> = vec![PqcLeafScalar([0u8; 32]); num_inputs as usize];

    let _ = verify(&proof, &key_images, &pseudo_outs, &pqc_hashes, &tree_root, tree_depth);

    // Also test with truncated data
    for cut in [1, 2, 4, 8, 16, 32] {
        if data.len() > cut {
            let truncated = ShekylFcmpProof {
                data: data[..data.len() - cut].to_vec(),
                num_inputs: num_inputs as u32,
                tree_depth,
            };
            let _ = verify(&truncated, &key_images, &pseudo_outs, &pqc_hashes, &tree_root, tree_depth);
        }
    }

    // Test oversized proof
    let mut oversized = data.to_vec();
    oversized.extend_from_slice(&[0xff; 256]);
    let big_proof = ShekylFcmpProof {
        data: oversized,
        num_inputs: num_inputs as u32,
        tree_depth,
    };
    let _ = verify(&big_proof, &key_images, &pseudo_outs, &pqc_hashes, &tree_root, tree_depth);
});
