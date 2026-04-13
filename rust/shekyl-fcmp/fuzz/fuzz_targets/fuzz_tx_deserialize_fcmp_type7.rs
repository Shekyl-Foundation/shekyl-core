// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_fcmp::proof::{verify, ShekylFcmpProof};
use shekyl_fcmp::leaf::PqcLeafScalar;

/// Simulates deserializing the prunable portion of an RCTTypeFcmpPlusPlusPqc
/// transaction. The fuzzer provides arbitrary bytes which are interpreted as
/// a concatenation of: pseudoOuts (N*32 bytes) + fcmp_pp_proof (variable) +
/// pqc_pk_hashes (N*32 bytes). The number of inputs is derived from the first
/// byte. Any data that doesn't parse cleanly must not cause panics or OOM.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let num_inputs = (data[0] % 16).max(1) as usize;
    let rest = &data[1..];

    let pseudo_outs_len = num_inputs * 32;
    let pqc_hashes_len = num_inputs * 32;
    let min_len = pseudo_outs_len + pqc_hashes_len;

    // Extract pseudoOuts (zero-pad if short)
    let pseudo_outs: Vec<[u8; 32]> = (0..num_inputs)
        .map(|i| {
            let mut po = [0u8; 32];
            let start = i * 32;
            if let Some(chunk) = rest.get(start..start + 32) {
                po.copy_from_slice(chunk);
            } else if let Some(partial) = rest.get(start..) {
                po[..partial.len()].copy_from_slice(partial);
            }
            po
        })
        .collect();

    // Remaining bytes after pseudoOuts go to the proof blob
    let proof_start = pseudo_outs_len.min(rest.len());
    let after_pseudo = &rest[proof_start..];

    // Split: last pqc_hashes_len bytes are pqc hashes, middle is proof
    let (proof_data, pqc_data) = if after_pseudo.len() > pqc_hashes_len {
        let split = after_pseudo.len() - pqc_hashes_len;
        (&after_pseudo[..split], &after_pseudo[split..])
    } else {
        (&[][..], after_pseudo)
    };

    let pqc_hashes: Vec<PqcLeafScalar> = (0..num_inputs)
        .map(|i| {
            let mut h = [0u8; 32];
            let start = i * 32;
            if let Some(chunk) = pqc_data.get(start..start + 32) {
                h.copy_from_slice(chunk);
            } else if let Some(partial) = pqc_data.get(start..) {
                h[..partial.len()].copy_from_slice(partial);
            }
            PqcLeafScalar(h)
        })
        .collect();

    // Construct a proof from the middle section and attempt verification.
    // Tree depth derived from a data byte or defaulted.
    let tree_depth = if data.len() > 1 { data[1] } else { 8 };
    let mut tree_root = [0u8; 32];
    if data.len() >= 34 {
        tree_root.copy_from_slice(&data[2..34]);
    }

    let key_images: Vec<[u8; 32]> = vec![[0u8; 32]; num_inputs];

    let mut signable_tx_hash = [0u8; 32];
    if data.len() >= 66 {
        signable_tx_hash.copy_from_slice(&data[34..66]);
    }

    // Main proof verification attempt
    if !proof_data.is_empty() {
        let proof = ShekylFcmpProof {
            data: proof_data.to_vec(),
            num_inputs: num_inputs as u32,
            tree_depth,
        };
        let _ = verify(&proof, &key_images, &pseudo_outs, &pqc_hashes, &tree_root, tree_depth, signable_tx_hash);
    }

    // Empty proof
    {
        let empty = ShekylFcmpProof {
            data: vec![],
            num_inputs: num_inputs as u32,
            tree_depth,
        };
        let _ = verify(&empty, &key_images, &pseudo_outs, &pqc_hashes, &tree_root, tree_depth, signable_tx_hash);
    }

    // Wrong number of inputs (mismatched arrays)
    if num_inputs > 1 {
        let fewer_ki: Vec<[u8; 32]> = vec![[0u8; 32]; num_inputs - 1];
        if !proof_data.is_empty() {
            let proof = ShekylFcmpProof {
                data: proof_data.to_vec(),
                num_inputs: (num_inputs - 1) as u32,
                tree_depth,
            };
            let _ = verify(&proof, &fewer_ki, &pseudo_outs[..num_inputs - 1], &pqc_hashes[..num_inputs - 1], &tree_root, tree_depth, signable_tx_hash);
        }
    }

    // Corrupted type byte: flip bits in proof data
    if proof_data.len() > 4 {
        let mut corrupted = proof_data.to_vec();
        corrupted[0] ^= 0xFF;
        let proof = ShekylFcmpProof {
            data: corrupted,
            num_inputs: num_inputs as u32,
            tree_depth,
        };
        let _ = verify(&proof, &key_images, &pseudo_outs, &pqc_hashes, &tree_root, tree_depth, signable_tx_hash);
    }
});
