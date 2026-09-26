// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Segment-freeze arithmetic — the first-crossing rule and the
//! challenge-path leaf-chunk derivation
//! ([`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md`](../../docs/design/ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md)
//! §5.1).
//!
//! Archival shard `k` is frozen on a branch iff the branch's curve-tree
//! leaf count has reached `(k + 1) * SEGMENT_LEAF_COUNT` — so the number
//! of frozen segments is `⌊leaf_count / SEGMENT_LEAF_COUNT⌋`, and nothing
//! else. Both daemon hooks (the `add_block` freeze processor and the
//! `pop_block` revert) call [`frozen_segment_count`] through the FFI;
//! C++ never performs the division inline (division one-site tripwire,
//! pipeline doc §8). Two sites computing the same boundary predicate
//! independently is the M1-1 off-by-one-drift shape this module exists
//! to foreclose.
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
//! change nor a config edit can move this crate's pop revert away from the
//! store. (*Corrected 2026-09-19:* this sentence previously said "admission
//! and pop revert". **`frozen_segment_count` is not read by bond admission** —
//! its consumers are the D2 escalation operand, the coverage RPC and
//! freeze / pop-revert. Bond admission's shard predicate was ruled
//! 2026-09-19 and is **unbuilt**; see
//! `docs/design/ARCHIVAL_BOND_ADD_ADMISSION.md` §3.) Level 2 was gate-2's provisional sizing; the freeze
//! pipeline round pinned it (`ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` §5.2).
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
// wallet-side shard store partitions by `leaves_per_segment()`; this crate's
// consensus reader (`frozen_segment_count`: the D2 escalation operand, the
// coverage RPC, and pop revert — **not** bond admission; see the module doc)
// partitions by the JSON value. Until this assert the two agreed only because
// the JSON value happened to equal the width product `38 · 18 · 38`; a
// `SEGMENT_LAYER_J` move, or a config edit that reads as a tune, would have
// forked admission and revert away from the store with nothing failing.
// Compile-time, in the production graph — a consensus equality must not
// depend on which tests ran. (Replaces the earlier hand-written
// `SELENE * HELIOS * SELENE` pin, which restated the derivation instead of
// taking it from its owner.)
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

/// Number of frozen segments at a given curve-tree leaf count — the
/// first-crossing rule (pipeline doc §1): segment `k` is frozen iff
/// `leaf_count >= (k + 1) * SEGMENT_LEAF_COUNT`.
///
/// Deterministic in its one consensus input (O-1); non-decreasing on a
/// branch because leaf count is (O-2); the pop revert deletes exactly the
/// rows with `shard_id >= frozen_segment_count(post_trim_leaf_count)`
/// (O-3). Both daemon hooks consume this function via
/// `shekyl_archival_frozen_segment_count`.
#[must_use]
pub const fn frozen_segment_count(leaf_count: u64) -> u64 {
    leaf_count / SEGMENT_LEAF_COUNT
}

/// The leaf-layer chunk containing a challenged leaf, as a global
/// position range over the daemon's leaf table (pipeline doc §6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeafChunkBounds {
    /// Global leaf position of the chunk's first leaf.
    pub first_leaf_position: u64,
    /// Leaves in the chunk — always the leaf-chunk width (a frozen
    /// segment's chunks are all full; 38 | SEGMENT_LEAF_COUNT).
    pub leaf_count: u64,
}

/// Where the challenged leaf sits inside its chunk, as an index into the
/// chunk's leaves: `(shard · SEGMENT_LEAF_COUNT + leaf_index) − first_leaf_position`.
///
/// One home for this arithmetic (RF-D8). `first_leaf_position` is a GLOBAL
/// tree position while `leaf_index_in_segment` is segment-relative, and
/// subtracting them directly is the mistake a first FFI draft made -- it
/// selected leaf 0 of every chunk for every shard past the first, so every
/// signature verified against the wrong leaf and the C++ end-to-end path
/// rejected what the Rust KATs (which had the arithmetic right, locally)
/// accepted. `None` if the index is outside the segment.
#[must_use]
pub fn challenged_leaf_offset_in_chunk(shard_id: u64, leaf_index_in_segment: u64) -> Option<usize> {
    let bounds = challenge_leaf_chunk_bounds(shard_id, leaf_index_in_segment)?;
    let global = shard_id
        .checked_mul(SEGMENT_LEAF_COUNT)?
        .checked_add(leaf_index_in_segment)?;
    usize::try_from(global.checked_sub(bounds.first_leaf_position)?).ok()
}

/// Derive the leaf-layer chunk backing challenged index
/// `leaf_index_in_segment` of frozen shard `shard_id`.
///
/// `global = shard_id * SEGMENT_LEAF_COUNT + leaf_index_in_segment`;
/// the chunk is `[⌊global / W⌋ * W, +W)` with `W = SELENE_CHUNK_WIDTH`.
/// Returns `None` when `leaf_index_in_segment` is out of segment range
/// or the global position overflows `u64` — both are verifier-input
/// rejections, not panics. After RF-D6 the index is **verifier-derived**
/// (`challenge_leaf_index`), never a wire field; an out-of-range value is
/// a geometry disagreement with the registry, not a prover-chosen index.
#[must_use]
pub fn challenge_leaf_chunk_bounds(
    shard_id: u64,
    leaf_index_in_segment: u64,
) -> Option<LeafChunkBounds> {
    if leaf_index_in_segment >= SEGMENT_LEAF_COUNT {
        return None;
    }
    let width = SELENE_CHUNK_WIDTH as u64;
    let global = shard_id
        .checked_mul(SEGMENT_LEAF_COUNT)?
        .checked_add(leaf_index_in_segment)?;
    let first = (global / width) * width;
    // The chunk must not extend past the segment end; full-chunk coverage
    // holds because segment bases are chunk-aligned (const assert above).
    Some(LeafChunkBounds {
        first_leaf_position: first,
        leaf_count: width,
    })
}

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
    fn frozen_segment_count_boundary_table() {
        // (leaf_count, expected frozen segments) — first-crossing rule.
        let table: &[(u64, u64)] = &[
            (0, 0),
            (1, 0),
            (E - 1, 0),
            (E, 1),
            (E + 1, 1),
            (2 * E - 1, 1),
            (2 * E, 2),
            // multi-segment jump: one drain crossing several boundaries
            (5 * E + 7, 5),
            (u64::MAX, u64::MAX / E),
        ];
        for &(leaf_count, expected) in table {
            assert_eq!(
                frozen_segment_count(leaf_count),
                expected,
                "leaf_count = {leaf_count}"
            );
        }
    }

    #[test]
    fn chunk_bounds_at_segment_base_is_aligned() {
        // ℓ = 0 of any shard: chunk starts exactly at the segment base
        // (segment bases are chunk-aligned by the const assert).
        for shard in [0u64, 1, 2, 1000] {
            let b = challenge_leaf_chunk_bounds(shard, 0).expect("in range");
            assert_eq!(b.first_leaf_position, shard * E);
            assert_eq!(b.leaf_count, W);
        }
    }

    #[test]
    fn chunk_bounds_last_chunk_of_segment() {
        // ℓ = E − 1: last chunk of the segment, ending exactly at the
        // segment end (full-chunk coverage; E % W == 0).
        let b = challenge_leaf_chunk_bounds(3, E - 1).expect("in range");
        assert_eq!(b.first_leaf_position, 3 * E + (E - W));
        assert_eq!(b.first_leaf_position + b.leaf_count, 4 * E);
    }

    #[test]
    fn chunk_bounds_interior_index_floors_to_chunk() {
        // An interior ℓ floors to its chunk start.
        let l = W + 5; // second chunk, offset 5
        let b = challenge_leaf_chunk_bounds(2, l).expect("in range");
        assert_eq!(b.first_leaf_position, 2 * E + W);
    }

    #[test]
    fn chunk_bounds_rejects_out_of_segment_index() {
        assert_eq!(challenge_leaf_chunk_bounds(0, E), None);
        assert_eq!(challenge_leaf_chunk_bounds(7, u64::MAX), None);
    }

    #[test]
    fn chunk_bounds_rejects_global_overflow() {
        // shard_id large enough that shard_id * E overflows u64.
        assert_eq!(challenge_leaf_chunk_bounds(u64::MAX / E + 1, 0), None);
    }

    #[test]
    fn segment_is_whole_chunks() {
        assert_eq!(E % W, 0);
    }
}
