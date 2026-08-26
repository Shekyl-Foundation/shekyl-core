// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! TJ-G (RED-1) — **the challenge's scope is the whole segment**
//! (`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md` §4 TJ-G; the D1 red-test
//! pattern).
//!
//! Phrased at the **challenge-construction** level, deliberately: under
//! TJ-A's receipt-attested branch the on-chain artifact is compact by design,
//! so any assertion about response payload size would be wrong and would
//! break the moment the right answer landed. **Scope-of-challenge is the
//! invariant; witnessing is what TJ-A decides.** The assertion mechanically
//! rejects sub-shard sampling: any `k < SEGMENT_LEAF_COUNT` named leaves keeps
//! it red — §5.6's finding (sampling fails on its own cost ledger against the
//! zero-storage + reacquire responder, 8C §4) as a CI gate rather than a
//! paragraph someone must re-derive.

use std::collections::BTreeSet;

use shekyl_archival_retention::{
    challenge_leaf_index, CHALLENGES_PER_PAIR_PER_EPOCH, SEGMENT_LEAF_COUNT,
};

/// The set of segment-leaf indices the challenge derivation names for one
/// `(P, s, E)`, across all `CHALLENGES_PER_PAIR_PER_EPOCH` of its challenges.
///
/// **`PC-D3` moved this from one index to at most three** — the derivation now
/// takes the challenge's block, so a pair-epoch's three challenges sample three
/// leaves instead of one. That is a real step toward TJ-G and nowhere near it:
/// three of `SEGMENT_LEAF_COUNT` is still sampling, so this test stays red for
/// exactly the reason it was written. Recorded here rather than left implicit,
/// because "the number went up" is the kind of change that quietly reads as
/// progress toward a threshold it does not approach.
fn named_leaf_indices(p_id: &[u8; 32], shard_id: u64, settlement_epoch: u64) -> BTreeSet<u32> {
    let mut named = BTreeSet::new();
    for challenge in 0..CHALLENGES_PER_PAIR_PER_EPOCH {
        // Distinct blocks stand in for the epoch's distinct challenge blocks;
        // under PC-D2 each is the block its record rode in on.
        let mut prev_block_hash = [0u8; 32];
        prev_block_hash[0] = u8::try_from(challenge).expect("lambda fits a byte");
        named.insert(challenge_leaf_index(
            p_id,
            shard_id,
            settlement_epoch,
            &prev_block_hash,
            SEGMENT_LEAF_COUNT,
        ));
    }
    named
}

#[test]
#[ignore = "RED: documents TJ-G — the challenge names one leaf, not the segment; \
un-ignores when TJ-A's challenge spec lands (ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md)"]
fn tj_g_red_challenge_names_every_segment_leaf() {
    let p_id = [0x5Au8; 32];
    let named = named_leaf_indices(&p_id, 7, 5);
    assert_eq!(
        named.len() as u64,
        SEGMENT_LEAF_COUNT,
        "test≡job: a challenge for (P, s, E) must name all {SEGMENT_LEAF_COUNT} segment \
         leaves — a subset prices the test below the job and re-opens the free-rider \
         margin (TJ R1); any k-sampling keeps this red"
    );
}
