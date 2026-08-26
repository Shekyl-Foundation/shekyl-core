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
//!   unified big-endian keys equals the verdict computed over the *retired*
//!   native-endian encoding the pre-unify C++ used — the property that
//!   licensed the SCE-1 unify commit as behavior-preserving, held standing
//!   (the §3 cross-check as an executable property).
//! - The key encoding is injective on the triple (field-swap never
//!   collides).

#![no_main]

use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use shekyl_archival_retention::serve_credit_decisions::{
    pair_epoch_key_be, serve_credit_block_key, serve_credit_block_unique, BlockUniqueVerdict,
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

    // SCE-1 decision-invariance, held standing: the verdict over the unified
    // BE keys (what the mirror and the post-unify C++ use) equals the verdict
    // over the retired pre-unify native-endian encoding, reconstructed here
    // as the invariance oracle.
    let le_key = |p: &[u8; 32], shard: u64, epoch: u64| {
        let mut key = [0u8; 48];
        key[..32].copy_from_slice(p);
        key[32..40].copy_from_slice(&shard.to_le_bytes());
        key[40..48].copy_from_slice(&epoch.to_le_bytes());
        key
    };
    let mut le_set = BTreeSet::new();
    let mut le_verdict = BlockUniqueVerdict::Unique;
    for (index, (p, shard, epoch)) in triples.iter().enumerate() {
        if !le_set.insert(le_key(p, *shard, *epoch)) {
            le_verdict = BlockUniqueVerdict::DuplicateAt { index };
            break;
        }
    }
    assert_eq!(
        verdict, le_verdict,
        "SCE-1: uniqueness verdict must not depend on the key encoding"
    );

    // Encoding injectivity on the triple: distinct triples never share a key
    // (field-swap safety at the byte level); the block key must be the
    // unified BE key.
    let mut be_keys = BTreeSet::new();
    let mut distinct = BTreeSet::new();
    for (p, shard, epoch) in &triples {
        if distinct.insert((*p, *shard, *epoch)) {
            assert!(be_keys.insert(pair_epoch_key_be(p, *shard, *epoch)));
        }
        assert_eq!(
            serve_credit_block_key(p, *shard, *epoch),
            pair_epoch_key_be(p, *shard, *epoch),
            "post-unify: one encoding for the logical key"
        );
    }
});
