// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_fcmp::leaf::{PqcKeyScalar, PqcLeafScalar, ShekylLeaf};
use shekyl_fcmp::tree::construct_leaf;

fuzz_target!(|data: &[u8]| {
    // Test ShekylLeaf::new / from_bytes with arbitrary 4x32-byte inputs
    if data.len() >= 128 {
        let leaf = ShekylLeaf::from_bytes(data[..128].try_into().unwrap());
        let roundtrip = ShekylLeaf::from_bytes(&leaf.to_bytes());
        assert_eq!(leaf, roundtrip);
    }

    // The PQC key scalar k = H_l(pqc_pk) (PL-D3) over arbitrary key bytes must
    // always be a canonical, non-zero Ed25519 scalar, and its point K = k*G_k
    // must always be a valid prime-order point.
    if !data.is_empty() {
        let k = PqcKeyScalar::from_pqc_public_key(data);
        assert_eq!(k.as_bytes()[31] & 0x80, 0);
        assert_ne!(*k.as_bytes(), [0u8; 32]);
        assert!(shekyl_curve_generators::pqc_leaf_point_valid(&k.point()).is_some());
    }

    // The published commitment point: the leaf scalar is defined iff the bytes
    // decompress, and admission is at least as strict as that.
    if data.len() >= 32 {
        let cm: [u8; 32] = data[..32].try_into().unwrap();
        let admitted = shekyl_curve_generators::pqc_leaf_point_valid(&cm).is_some();
        let scalar = PqcLeafScalar::from_commitment_point(&cm);
        if admitted {
            assert!(scalar.is_some());
        }
    }

    // construct_leaf over three 32-byte inputs (O, C, CM): it may fail on
    // bytes that are not points; when it succeeds the 4th scalar is CM.x.
    if data.len() >= 96 {
        let mut output_key = [0u8; 32];
        let mut commitment = [0u8; 32];
        let mut cm = [0u8; 32];
        output_key.copy_from_slice(&data[..32]);
        commitment.copy_from_slice(&data[32..64]);
        cm.copy_from_slice(&data[64..96]);
        if let Some(leaf) = construct_leaf(&output_key, &commitment, &cm) {
            let x =
                PqcLeafScalar::from_commitment_point(&cm).expect("leaf built, so CM decompresses");
            assert_eq!(&leaf[96..128], &x.0);
        }
    }

    // Boundary key bytes: all zeros, all ones, all 0x7f, all 0x80
    for fill in [0x00u8, 0xff, 0x7f, 0x80, 0x01, 0xfe] {
        let pk = vec![fill; 1952];
        let k = PqcKeyScalar::from_pqc_public_key(&pk);
        assert_eq!(k.as_bytes()[31] & 0x80, 0);
        assert_ne!(*k.as_bytes(), [0u8; 32]);
    }
});
