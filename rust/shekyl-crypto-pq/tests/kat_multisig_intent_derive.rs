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

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::Scalar;
use rand::RngCore as _;
use serde_json::Value;
use shekyl_crypto_pq::multisig_intent::{IntentSeed, INTENT_SEED_LEN};
use shekyl_crypto_pq::output_mask::OutputMask;
use shekyl_crypto_pq::seeded_rng::SeededRng;
use shekyl_crypto_pq::TxKey;

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
        let masks: Vec<OutputMask> = hex_list(&v["output_masks_hex"])
            .iter()
            .map(|bytes| {
                OutputMask::from_canonical_bytes_for_tests(bytes)
                    .unwrap_or_else(|| panic!("vector {n}: a mask is not a canonical scalar"))
            })
            .collect();
        let expected = &v["expected"];

        // The key hands out no bytes, so `r` is held through its point:
        // the vector's `r` is canonical and its `r·G` is the vector's `R`,
        // and the derived key's `R` is that point. `r ↦ r·G` is one-to-one
        // on canonical scalars, so this pins `r` byte for byte.
        let r = Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes32(
            &expected["tx_key_secret_hex"],
        )))
        .unwrap_or_else(|| panic!("vector {n}: r is not a canonical scalar"));
        let public = bytes32(&expected["tx_key_public_hex"]);
        assert_eq!(
            (&r * ED25519_BASEPOINT_TABLE).compress().to_bytes(),
            public,
            "vector {n}: the vector's R is its r·G"
        );
        assert_eq!(
            TxKey::from_intent_seed(&seed).public_bytes(),
            public,
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

        // A rerandomization seed hands out no bytes either; it is held
        // through its stream, ChaCha20 keyed by the seed, against the same
        // stream keyed by the vector's bytes.
        let expected_seeds = hex_list(&expected["rerandomization_seeds_hex"]);
        assert_eq!(
            expected_seeds.len(),
            inputs,
            "vector {n}: one seed per input"
        );
        for (j, expected_seed) in expected_seeds.iter().enumerate() {
            let [mut got, mut want] = [[0u8; 64]; 2];
            seed.rerandomization_seed(j).rng().fill_bytes(&mut got);
            SeededRng::from_seed(expected_seed).fill_bytes(&mut want);
            assert_eq!(got, want, "vector {n}: input {j}'s rerandomization seed");
        }

        assert_eq!(
            seed.fingerprint().as_bytes(),
            &bytes32(&expected["seed_fingerprint_hex"]),
            "vector {n}: fingerprint"
        );
    }
}
