// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Functional test matrix: happy-path and edge-case coverage for
//! the V3.1 multisig protocol flow. The ceremony file's tests are beside
//! its code (`envelope.rs`), where they can build plaintexts an insider
//! could.

use crate::intent::ChainStateFingerprint;
use shekyl_units::AtomicUnits;

#[test]
fn chain_state_fingerprint_includes_all_fields() {
    let fp1 = ChainStateFingerprint {
        reference_block_hash: [0xAA; 32],
        input_global_indices: vec![1, 2, 3],
        input_eligible_heights: vec![100, 200, 300],
        input_amounts: vec![
            AtomicUnits::from_raw(10),
            AtomicUnits::from_raw(20),
            AtomicUnits::from_raw(30),
        ],
    };

    let h1 = fp1.compute();

    let fp2 = ChainStateFingerprint {
        input_global_indices: vec![1, 2, 4],
        ..ChainStateFingerprint {
            reference_block_hash: [0xAA; 32],
            input_global_indices: vec![1, 2, 4],
            input_eligible_heights: vec![100, 200, 300],
            input_amounts: vec![
                AtomicUnits::from_raw(10),
                AtomicUnits::from_raw(20),
                AtomicUnits::from_raw(30),
            ],
        }
    };
    assert_ne!(h1, fp2.compute());

    let fp3 = ChainStateFingerprint {
        reference_block_hash: [0xBB; 32],
        input_global_indices: vec![1, 2, 3],
        input_eligible_heights: vec![100, 200, 300],
        input_amounts: vec![
            AtomicUnits::from_raw(10),
            AtomicUnits::from_raw(20),
            AtomicUnits::from_raw(30),
        ],
    };
    assert_ne!(h1, fp3.compute());
}
