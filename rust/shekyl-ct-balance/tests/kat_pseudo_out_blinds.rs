// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A group's pseudo-out blinds against their pinned vectors (R-14,
//! `PQC_MULTISIG.md` §9.5): every input's blind but the last derived from
//! the intent's seed, the last balancing the outputs' masks.
//!
//! Corpus: `docs/test_vectors/MULTISIG_INTENT_DERIVE_V1.json`, written by
//! `scripts/kat/multisig_intent_derive_oracle.py`, which derives every value
//! from the design text through stdlib Python that shares nothing with these
//! crates. `shekyl-crypto-pq`'s `tests/kat_multisig_intent_derive.rs` holds
//! the derived blinds to the same file; this test holds the whole balanced
//! set, as [`PseudoOutBlinds::from_intent`] makes it.

use std::num::NonZeroUsize;

use curve25519_dalek::Scalar;
use serde_json::Value;
use shekyl_crypto_pq::multisig_intent::{IntentSeed, INTENT_SEED_LEN};
use shekyl_ct_balance::PseudoOutBlinds;
use shekyl_curve_primitives::Commitment;

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
fn a_groups_blinds_match_the_oracle() {
    let corpus: Value = serde_json::from_str(VECTORS).expect("the corpus parses");
    let vectors = corpus["vectors"].as_array().expect("a vector list");
    assert!(!vectors.is_empty(), "the corpus pins no vector");
    for (n, v) in vectors.iter().enumerate() {
        let seed: [u8; INTENT_SEED_LEN] = bytes32(&v["seed_hex"]);
        let inputs = usize::try_from(v["inputs"].as_u64().expect("an input count"))
            .ok()
            .and_then(NonZeroUsize::new)
            .unwrap_or_else(|| panic!("vector {n}: a spend has at least one input"));
        // The blinds read only the outputs' masks; the amount is the
        // opening's, and does not enter.
        let outputs: Vec<Commitment> = hex_list(&v["output_masks_hex"])
            .iter()
            .map(|bytes| {
                let mask = Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
                    .unwrap_or_else(|| panic!("vector {n}: a mask is not a canonical scalar"));
                Commitment::new(mask, 0)
            })
            .collect();
        let blinds: Vec<[u8; 32]> =
            PseudoOutBlinds::from_intent(&IntentSeed::new(&seed), inputs, &outputs)
                .into_bytes()
                .iter()
                .map(|blind| **blind)
                .collect();
        assert_eq!(
            blinds,
            hex_list(&v["expected"]["pseudo_out_blinds_hex"]),
            "vector {n}: blinds"
        );
    }
}
