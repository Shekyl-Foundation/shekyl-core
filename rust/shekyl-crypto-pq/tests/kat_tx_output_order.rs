// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A transaction's output order against its pinned vectors (R-24):
//! `TxKey::output_order` for each key and output count.
//!
//! Corpus: `docs/test_vectors/TX_OUTPUT_ORDER_V1.json`, written by
//! `scripts/kat/tx_output_order_oracle.py`, which derives every order from
//! the design text through stdlib Python that shares nothing with this
//! crate. The docs gates run the oracle; this test holds the Rust to the
//! same file. The keys are intent keys, so any build can make them.

use serde_json::Value;
use shekyl_crypto_pq::multisig_intent::{IntentSeed, INTENT_SEED_LEN};
use shekyl_crypto_pq::TxKey;

const VECTORS: &str = include_str!("../../../docs/test_vectors/TX_OUTPUT_ORDER_V1.json");

fn indices(v: &Value) -> Vec<usize> {
    v.as_array()
        .expect("a list")
        .iter()
        .map(|i| usize::try_from(i.as_u64().expect("an index")).expect("an index fits"))
        .collect()
}

#[test]
fn the_output_orders_match_the_oracle() {
    let corpus: Value = serde_json::from_str(VECTORS).expect("the corpus parses");
    let vectors = corpus["vectors"].as_array().expect("a vector list");
    assert!(!vectors.is_empty(), "the corpus pins no vector");
    for (n, v) in vectors.iter().enumerate() {
        let seed: [u8; INTENT_SEED_LEN] = hex::decode(v["intent_seed_hex"].as_str().unwrap())
            .expect("hex")
            .try_into()
            .expect("an intent seed's length");
        let key = TxKey::from_intent_seed(&IntentSeed::new(&seed));
        let public: [u8; 32] = hex::decode(v["tx_key_public_hex"].as_str().unwrap())
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        assert_eq!(key.public_bytes(), public, "vector {n}: the vector's key");
        let outputs = usize::try_from(v["outputs"].as_u64().expect("a count")).unwrap();
        let order = key.output_order(outputs);
        assert_eq!(
            order.recipients().collect::<Vec<_>>(),
            indices(&v["recipient_at"]),
            "vector {n}: recipient_at"
        );
        let position_of: Vec<usize> = (0..outputs)
            .map(|r| {
                order
                    .position_of(r)
                    .expect("every recipient has a position")
            })
            .collect();
        assert_eq!(
            position_of,
            indices(&v["position_of"]),
            "vector {n}: position_of"
        );
    }
}
