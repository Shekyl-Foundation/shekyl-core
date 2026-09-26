// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The incremental grow equals the rebuild — the property the C++ lost
//! (the depth-3 divergence) and the reason every layer here is incremental
//! rather than recomposed.

use std::collections::BTreeMap;

use shekyl_fcmp::tree::{
    layer_count_for_leaves, selene_hash_init, try_build_layers, HELIOS_CHUNK_WIDTH,
    SCALARS_PER_LEAF, SELENE_CHUNK_WIDTH,
};
use shekyl_types::{CurveTreeRoot, TreeLeaf};

use super::{grow, GrowFault, TreeFrontier};

/// A deterministic leaf whose four scalars are small integers — canonical
/// field elements on both curves, distinct per leaf and per slot.
fn leaf(i: u64) -> TreeLeaf {
    let mut bytes = [0u8; TreeLeaf::LEN];
    for slot in 0..SCALARS_PER_LEAF {
        let v = i * 4 + slot as u64 + 1;
        bytes[slot * 32..slot * 32 + 8].copy_from_slice(&v.to_le_bytes());
    }
    TreeLeaf::from_bytes(bytes)
}

fn scalars_of(leaves: &[TreeLeaf]) -> Vec<[u8; 32]> {
    leaves
        .iter()
        .flat_map(|l| {
            let b = l.as_bytes();
            (0..SCALARS_PER_LEAF).map(move |i| {
                let mut s = [0u8; 32];
                s.copy_from_slice(&b[i * 32..(i + 1) * 32]);
                s
            })
        })
        .collect()
}

/// Grow in `batches`, accumulating the latest write per `(layer, chunk)`,
/// and hold the result equal to `try_build_layers` over every leaf at
/// every step: root, depth, and every stored chunk hash.
fn grow_in_batches_equals_rebuild(batches: &[usize]) {
    let mut frontier = TreeFrontier::EMPTY;
    let mut all: Vec<TreeLeaf> = Vec::new();
    let mut stored: BTreeMap<(u8, u64), [u8; 32]> = BTreeMap::new();
    for &n in batches {
        let start = all.len() as u64;
        let batch: Vec<TreeLeaf> = (start..start + n as u64).map(leaf).collect();
        let growth = grow(&frontier, &batch).expect("grows");
        assert_eq!(growth.leaf_count_before, start);
        all.extend_from_slice(&batch);
        for w in &growth.layer_writes {
            stored.insert((w.layer, w.chunk), w.hash);
        }
        let built = try_build_layers(&scalars_of(&all)).expect("rebuild");
        let layers = layer_count_for_leaves(all.len() as u64);
        assert_eq!(built.len(), usize::from(layers), "layer count");
        assert_eq!(growth.depth, layers - 1, "depth after {} leaves", all.len());
        assert_eq!(
            growth.root,
            CurveTreeRoot::from_bytes(*built.last().expect("root layer").first().expect("root")),
            "root after {} leaves",
            all.len()
        );
        // Every chunk the rebuild has, the incremental store has, equal.
        let mut expected = 0usize;
        for (layer, chunks) in built.iter().enumerate() {
            let layer = u8::try_from(layer).expect("depth fits u8");
            for (chunk, hash) in chunks.iter().enumerate() {
                expected += 1;
                assert_eq!(
                    stored.get(&(layer, chunk as u64)),
                    Some(hash),
                    "layer {layer} chunk {chunk} after {} leaves",
                    all.len()
                );
            }
        }
        // And nothing the rebuild lacks — except chunks from a *retired*
        // top layer, which no longer exist in the rebuilt tree but were
        // written when they were the root's layer (a stale row the store's
        // grow leaves behind only if the tree ever shrank, which it does
        // not: growth only adds layers). So the counts match exactly.
        assert_eq!(stored.len(), expected, "no stray chunk writes");
        frontier = growth.frontier_after();
        assert_eq!(frontier.leaf_count, all.len() as u64);
    }
}

#[test]
fn one_leaf_then_one_more() {
    grow_in_batches_equals_rebuild(&[1, 1]);
}

#[test]
fn a_chunk_filled_exactly_then_a_fresh_chunk() {
    // The old last chunk is full: the grow must skip it and start a fresh
    // one, whose parent position was never written (existing_child = 0).
    grow_in_batches_equals_rebuild(&[SELENE_CHUNK_WIDTH, 1, SELENE_CHUNK_WIDTH - 1, 1]);
}

#[test]
fn crossing_into_a_third_layer_keeps_the_sibling() {
    // The divergence the C++ hit: the layer-2 root is born when layer 1
    // gains its second chunk, and the new root chunk must include the
    // pre-existing sibling's x-coordinate, not only the deepening child.
    let two_layers = SELENE_CHUNK_WIDTH * HELIOS_CHUNK_WIDTH;
    grow_in_batches_equals_rebuild(&[two_layers - 5, 3, 2, 1, 40]);
}

#[test]
fn a_block_that_spans_several_parent_chunks_at_once() {
    // One grow large enough that layer 0 gains chunks under two different
    // layer-1 parents, one existing and one fresh.
    let two_layers = SELENE_CHUNK_WIDTH * HELIOS_CHUNK_WIDTH;
    grow_in_batches_equals_rebuild(&[7, two_layers + 300, 5]);
}

#[test]
fn many_small_batches_walk_every_boundary() {
    let batches: Vec<usize> = (1..=60).map(|i| (i * 7) % 41 + 1).collect();
    grow_in_batches_equals_rebuild(&batches);
}

#[test]
fn the_frontier_shape_is_checked_before_arithmetic() {
    let bad = TreeFrontier {
        leaf_count: 5,
        last_chunks: vec![selene_hash_init(); 3],
    };
    assert_eq!(
        grow(&bad, &[leaf(0)]),
        Err(GrowFault::FrontierShape {
            layers: 3,
            expected: layer_count_for_leaves(5),
        })
    );
    assert_eq!(grow(&TreeFrontier::EMPTY, &[]), Err(GrowFault::NoLeaves));
}

#[test]
fn a_frontier_hash_off_the_curve_is_refused_at_its_layer() {
    let first = grow(&TreeFrontier::EMPTY, &[leaf(0)]).expect("grows");
    let mut frontier = first.frontier_after();
    frontier.last_chunks[1] = [0xff; 32];
    // Layer 1's stored hash is not a Helios point: its x-coordinate cannot
    // be taken, and the grow says so at layer 1, not with a wrong root.
    let out = grow(&frontier, &[leaf(1)]);
    assert!(
        matches!(out, Err(GrowFault::NotOnCurve { layer: 1 })),
        "{out:?}"
    );
}
