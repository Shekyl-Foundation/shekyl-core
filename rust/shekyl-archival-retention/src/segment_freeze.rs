// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The segment partition's consensus pin
//! ([`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](../../docs/design/ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)
//! §5.1, §5.2; the pipeline is retired by `PDM-Q12`, and its code is deleted
//! with the archival C++ path, `DEL-008`).
//!
//! What stays here, and why: the compile-time pin of the config-generated
//! `SEGMENT_LEAF_COUNT` to the tree's own partition derivation (below), a
//! consensus guard independent of any reader. The frozen-segment count that
//! the C++ validator, the coverage RPC and the C++ pop revert read through the
//! FFI is deleted with those callers; the Rust validator's operand is the
//! closed archival-shard count of the recorded fold,
//! `shekyl_chain_rules::closed_shards_before` (DRS-E4 ARW-Q6).
//!
//! # `SEGMENT_LEAF_COUNT` (pipeline doc §5.2)
//!
//! The level-`SEGMENT_LAYER_J` (= 2) subtree leaf count under the production
//! curve-tree widths: `38 * 18 * 38 = 25 992`. The value flows from
//! `config/consensus_constants.json` through `build.rs` like every
//! cross-language consensus constant, and the compile-time assert below ties
//! it to `shekyl_fcmp::tree::leaves_per_segment()` — the one partition
//! derivation, which the wallet-side shard store also takes from that crate
//! (`V3_WALLET_DECISION_LOG.md` 2026-09-17, two stores) — so neither a width
//! change nor a config edit can move a consensus reader away from the
//! store. Bond admission's shard predicate was ruled 2026-09-19 and is
//! **unbuilt**; see `docs/design/ARCHIVAL_BOND_ADD_ADMISSION.md` §3. Level 2
//! was gate-2's provisional sizing; the freeze pipeline round pinned it
//! (`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` §5.2).
//!
//! Not a tunable. Reversion criteria per the pipeline doc §5.2: a CT
//! sizing re-review before genesis moving the subtree level (constants
//! bump + fixture regen), or a V4 tree migration changing widths (that
//! migration's own design round).

use shekyl_fcmp::tree::{leaves_per_segment, SELENE_CHUNK_WIDTH};

include!(concat!(env!("OUT_DIR"), "/segment_leaf_count_generated.rs"));

// Partition pin (V3_WALLET_DECISION_LOG.md 2026-09-17, "two stores"): the
// config-generated SEGMENT_LEAF_COUNT must equal the partition derivation
// that lives in `shekyl_fcmp::tree` — the one home both stores consume. The
// wallet-side shard store partitions by `leaves_per_segment()`; the
// challenge-path helpers below and every reader of `SEGMENT_LEAF_COUNT`
// take the same number, so the two can never drift apart.
const _: () = assert!(
    SEGMENT_LEAF_COUNT == leaves_per_segment() as u64,
    "SEGMENT_LEAF_COUNT (consensus, config-generated) must equal \
     shekyl_fcmp::tree::leaves_per_segment() (the partition both stores take \
     from that crate): a divergent partition forks bond admission and pop \
     revert away from the shard store (V3_WALLET_DECISION_LOG.md 2026-09-17; \
     ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §5.2)"
);

// Chunk alignment: segment bases are leaf-chunk-aligned, which the §6.2
// direct-read derivation depends on. Holds by construction (any level's
// leaf count is a product that includes the level-0 width); asserted so
// the dependency is structural, not textual.
const _: () = assert!(
    SEGMENT_LEAF_COUNT.is_multiple_of(SELENE_CHUNK_WIDTH as u64),
    "SEGMENT_LEAF_COUNT must be a multiple of the leaf-chunk width \
     (segment bases leaf-chunk-aligned, pipeline doc §1.1/§6.2)"
);

#[cfg(test)]
mod tests {
    use super::*;

    const E: u64 = SEGMENT_LEAF_COUNT;
    const W: u64 = SELENE_CHUNK_WIDTH as u64;

    #[test]
    fn segment_leaf_count_is_pinned_value() {
        // The §5.2 pin, as a literal: a JSON edit that drifts from the
        // width product already fails the const assert; this test pins
        // the human-readable number the docs cite.
        assert_eq!(E, 25_992);
    }

    #[test]
    fn segment_is_whole_chunks() {
        assert_eq!(E % W, 0);
    }
}
