// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_fcmp::leaf::{PqcLeafScalar, ShekylLeaf};
use shekyl_fcmp::tree::construct_leaf;

fuzz_target!(|data: &[u8]| {
    // Test ShekylLeaf::new / from_bytes with arbitrary 4x32-byte inputs
    if data.len() >= 128 {
        let leaf = ShekylLeaf::from_bytes(data[..128].try_into().unwrap());
        let roundtrip = ShekylLeaf::from_bytes(&leaf.to_bytes());
        assert_eq!(leaf, roundtrip);
    }

    // Test PqcLeafScalar::from_pqc_public_key with arbitrary input
    if !data.is_empty() {
        let scalar = PqcLeafScalar::from_pqc_public_key(data);
        // High bit must always be cleared for scalar range validity
        assert_eq!(scalar.0[31] & 0x80, 0);
    }

    // Test construct_leaf with pairs of 32-byte inputs
    if data.len() >= 64 {
        let mut output_key = [0u8; 32];
        let mut commitment = [0u8; 32];
        output_key.copy_from_slice(&data[..32]);
        commitment.copy_from_slice(&data[32..64]);
        // construct_leaf may fail on non-canonical curve points; that's expected
        let _ = construct_leaf(&output_key, &commitment);
    }

    // Test boundary values: all zeros, all ones, all 0x7f, all 0x80
    for fill in [0x00u8, 0xff, 0x7f, 0x80, 0x01, 0xfe] {
        let pk = vec![fill; 1952];
        let scalar = PqcLeafScalar::from_pqc_public_key(&pk);
        assert_eq!(scalar.0[31] & 0x80, 0);
    }
});
