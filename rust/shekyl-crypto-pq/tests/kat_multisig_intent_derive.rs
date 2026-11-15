// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The multisig intent derivations against their pinned vectors (R-14,
//! `PQC_MULTISIG.md` §9.5): from an intent's seed, the transaction key, each
//! input's pseudo-out blind and rerandomization seed, and the seed's replay
//! fingerprint.
//!
//! Corpus: `docs/test_vectors/MULTISIG_INTENT_DERIVE_V1.json`, written by
//! `scripts/kat/multisig_intent_derive_oracle.py`, which derives every value
//! from the design text through stdlib Python that shares nothing with this
//! crate (RFC 5869 and RFC 8032 by hand, anchored). The docs gates run the
//! oracle; this test holds the Rust to the same file.

use serde_json::Value;
use shekyl_crypto_pq::multisig_intent::{IntentSeed, INTENT_SEED_LEN};

const VECTORS: &str = include_str!("../../../docs/test_vectors/MULTISIG_INTENT_DERIVE_V1.json");

fn bytes32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().expect("a hex string"))
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

fn hex_list(v: &Value) -> Vec<[u8; 32]> {
    v.as_array().expect("a list").iter().map(bytes32).collect()
}

#[test]
fn the_intent_derivations_match_the_oracle() {
    let corpus: Value = serde_json::from_str(VECTORS).expect("the corpus parses");
    let vectors = corpus["vectors"].as_array().expect("a vector list");
    assert!(!vectors.is_empty(), "the corpus pins no vector");
    for (n, v) in vectors.iter().enumerate() {
        let seed: [u8; INTENT_SEED_LEN] = bytes32(&v["seed_hex"]);
        let seed = IntentSeed::new(&seed);
        let inputs = usize::try_from(v["inputs"].as_u64().expect("an input count")).unwrap();
        let masks = hex_list(&v["output_masks_hex"]);
        let expected = &v["expected"];

        let tx_key = seed.tx_key();
        assert_eq!(
            *tx_key.secret,
            bytes32(&expected["tx_key_secret_hex"]),
            "vector {n}: r"
        );
        assert_eq!(
            tx_key.public,
            bytes32(&expected["tx_key_public_hex"]),
            "vector {n}: R"
        );

        let blinds: Vec<[u8; 32]> = seed
            .pseudo_out_blinds(inputs, &masks)
            .expect("the blinds derive")
            .iter()
            .map(|b| **b)
            .collect();
        assert_eq!(
            blinds,
            hex_list(&expected["pseudo_out_blinds_hex"]),
            "vector {n}: blinds"
        );

        let rerandomizations: Vec<[u8; 32]> =
            (0..inputs).map(|j| *seed.rerandomization_seed(j)).collect();
        assert_eq!(
            rerandomizations,
            hex_list(&expected["rerandomization_seeds_hex"]),
            "vector {n}: rerandomization seeds"
        );

        assert_eq!(
            seed.fingerprint().as_bytes(),
            &bytes32(&expected["seed_fingerprint_hex"]),
            "vector {n}: fingerprint"
        );
    }
}
