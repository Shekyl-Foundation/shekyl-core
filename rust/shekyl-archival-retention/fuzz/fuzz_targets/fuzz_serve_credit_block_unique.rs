// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fuzz the D-SC-C block-level uniqueness mirror and the SCE-1 key-encoding
//! split (ARCHIVAL_SERVE_CREDIT_EQUIVALENCE_AUDIT.md §5 fuzz plan).
//! Invariants hunted:
//!
//! - **No false negative on a planted duplicate:** appending a copy of any
//!   existing triple to a unique list is always caught, at the appended
//!   index.
//! - **No false positive:** a list whose triples are pairwise distinct is
//!   always `Unique` (checked against a field-level set, independent of the
//!   key encoding).
//! - **SCE-1 decision-invariance:** the uniqueness verdict computed over the
//!   native-endian block keys equals the verdict computed over the
//!   big-endian persistent keys — the A-vs-C encoding split is
//!   behavior-irrelevant for the decision (the finding is a drift hazard,
//!   not a live bug; this is the §3 cross-check as an executable property).
//! - Both encodings of one triple are injective on the triple (field-swap
//!   never collides).

#![no_main]

use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use shekyl_archival_retention::serve_credit_decisions::{
    serve_credit_block_key, serve_credit_block_unique, serve_credit_key_be, BlockUniqueVerdict,
};

fuzz_target!(|data: &[u8]| {
    // Decode a triple list: each 12-byte chunk is (p_seed, shard, epoch) with
    // small ranges so collisions actually occur in the corpus.
    let mut triples: Vec<([u8; 32], u64, u64)> = Vec::new();
    for chunk in data.chunks_exact(12) {
        let p = [chunk[0] % 4; 32];
        let shard = u64::from(u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]) % 8);
        let epoch = u64::from(u32::from_le_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]) % 8);
        triples.push((p, shard, epoch));
    }

    let verdict = serve_credit_block_unique(&triples);

    // Field-level oracle: the first index whose (P, shard, E) already
    // appeared, independent of any byte encoding.
    let mut seen = BTreeSet::new();
    let mut expected = BlockUniqueVerdict::Unique;
    for (index, triple) in triples.iter().enumerate() {
        if !seen.insert(*triple) {
            expected = BlockUniqueVerdict::DuplicateAt { index };
            break;
        }
    }
    assert_eq!(verdict, expected, "verdict must match the field-level set");

    // No false negative on a planted duplicate: re-append any element of a
    // unique list and the copy must be caught at the appended index.
    if expected == BlockUniqueVerdict::Unique && !triples.is_empty() {
        let planted_source = usize::from(data.first().copied().unwrap_or(0)) % triples.len();
        let mut planted = triples.clone();
        planted.push(planted[planted_source]);
        assert_eq!(
            serve_credit_block_unique(&planted),
            BlockUniqueVerdict::DuplicateAt {
                index: planted.len() - 1
            },
            "planted duplicate must be caught"
        );
    }

    // SCE-1 decision-invariance: the same uniqueness pass over the BE
    // (D-SC-A) encoding reaches the same verdict as the native-endian
    // (D-SC-C) encoding the mirror uses.
    let mut be_set = BTreeSet::new();
    let mut be_verdict = BlockUniqueVerdict::Unique;
    for (index, (p, shard, epoch)) in triples.iter().enumerate() {
        if !be_set.insert(serve_credit_key_be(p, *shard, *epoch)) {
            be_verdict = BlockUniqueVerdict::DuplicateAt { index };
            break;
        }
    }
    assert_eq!(
        verdict, be_verdict,
        "SCE-1: uniqueness verdict must not depend on the key encoding"
    );

    // Encoding injectivity on the triple: distinct triples never share a key
    // in either encoding (field-swap safety at the byte level).
    let mut le_keys = BTreeSet::new();
    let mut be_keys = BTreeSet::new();
    let mut distinct = BTreeSet::new();
    for (p, shard, epoch) in &triples {
        if distinct.insert((*p, *shard, *epoch)) {
            assert!(le_keys.insert(serve_credit_block_key(p, *shard, *epoch)));
            assert!(be_keys.insert(serve_credit_key_be(p, *shard, *epoch)));
        }
    }
});
