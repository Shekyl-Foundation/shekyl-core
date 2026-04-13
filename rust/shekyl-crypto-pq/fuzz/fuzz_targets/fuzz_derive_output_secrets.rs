// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_crypto_pq::derivation::derive_output_secrets;

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }

    let output_index = u64::from_le_bytes(data[..8].try_into().unwrap());
    let combined_ss = &data[8..];

    // Cap at 1200 bytes to cover X25519 + ML-KEM combined SS range
    if combined_ss.len() > 1200 {
        return;
    }

    let s1 = derive_output_secrets(combined_ss, output_index);

    // Determinism: same input must always produce same output
    let s2 = derive_output_secrets(combined_ss, output_index);
    assert_eq!(s1.ho, s2.ho, "ho not deterministic");
    assert_eq!(s1.y, s2.y, "y not deterministic");
    assert_eq!(s1.z, s2.z, "z not deterministic");
    assert_eq!(s1.k_amount, s2.k_amount, "k_amount not deterministic");
    assert_eq!(
        s1.view_tag_combined, s2.view_tag_combined,
        "view_tag_combined not deterministic"
    );
    assert_eq!(s1.amount_tag, s2.amount_tag, "amount_tag not deterministic");
    assert_eq!(
        s1.ml_dsa_seed, s2.ml_dsa_seed,
        "ml_dsa_seed not deterministic"
    );
    assert_eq!(
        s1.ed25519_pqc_seed, s2.ed25519_pqc_seed,
        "ed25519_pqc_seed not deterministic"
    );

    // Non-zero assertions for non-empty combined_ss.
    // The hard asserts inside derive_output_secrets catch this too, but
    // exercising the check here makes failures attributable to the fuzz target.
    if !combined_ss.is_empty() {
        assert_ne!(s1.ho, [0u8; 32], "ho is zero for non-empty combined_ss");
        assert_ne!(s1.y, [0u8; 32], "y is zero for non-empty combined_ss");
    }
});
