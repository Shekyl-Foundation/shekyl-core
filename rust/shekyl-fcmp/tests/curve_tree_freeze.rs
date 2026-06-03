// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CT-0 gate: G1 value-invariance (frozen subtree) + within-Rust extractability.
//!
//! See `docs/design/CURVE_TREE_CLIENT.md` §7.7 and Appendix A. G1 fail =>
//! position-aligned segment boundary reopens to height-anchored (§7.2). G2
//! end-to-end (Rust-composed root == C++ consensus header root) is CT-2's
//! reconstruct-root KAT, not this file.

use ciphersuite::{
    group::ff::{Field, PrimeField},
    Ciphersuite,
};
use helioselene::Selene;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use shekyl_fcmp::tree::{
    hash_grow_helios, hash_grow_selene, helios_hash_init, helios_point_to_selene_scalar,
    layer_is_selene, selene_hash_init, selene_point_to_helios_scalar, HELIOS_CHUNK_WIDTH,
    LEAF_CHUNK_SCALARS, SCALARS_PER_LEAF, SELENE_CHUNK_WIDTH,
};

const ZERO: [u8; 32] = [0u8; 32];

fn seeded(s: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(s)
}

/// A random *valid* (canonical) Selene base-field element — leaf scalars must be.
fn rand_scalar(rng: &mut ChaCha20Rng) -> [u8; 32] {
    <Selene as Ciphersuite>::F::random(rng).to_repr()
}

/// `n_outputs` worth of leaf scalars (SCALARS_PER_LEAF each), flat.
fn rand_leaves(rng: &mut ChaCha20Rng, n_outputs: usize) -> Vec<[u8; 32]> {
    (0..n_outputs * SCALARS_PER_LEAF)
        .map(|_| rand_scalar(rng))
        .collect()
}

/// Build every internal layer from a flat leaf-scalar stream using ONLY the
/// per-chunk primitives — the same composition CT-2's local assembler will use.
/// `layers[0]` = leaf-layer Selene nodes; alternating Helios/Selene above; the
/// final layer holds the single root.
fn build_layers(leaf_scalars: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    let leaf_nodes: Vec<[u8; 32]> = leaf_scalars
        .chunks(LEAF_CHUNK_SCALARS)
        .map(|c| hash_grow_selene(&selene_hash_init(), 0, &ZERO, c).expect("leaf chunk"))
        .collect();
    let mut layers = vec![leaf_nodes];

    let mut layer_idx: u8 = 1;
    while layers.last().unwrap().len() > 1 {
        let prev = layers.last().unwrap();
        let next: Vec<[u8; 32]> = if layer_is_selene(layer_idx) {
            // even layer (Selene): children are x-coords of the Helios pts below
            let s: Vec<[u8; 32]> = prev
                .iter()
                .map(|p| helios_point_to_selene_scalar(p).expect("h->s"))
                .collect();
            s.chunks(SELENE_CHUNK_WIDTH)
                .map(|c| hash_grow_selene(&selene_hash_init(), 0, &ZERO, c).expect("selene node"))
                .collect()
        } else {
            // odd layer (Helios): children are x-coords of the Selene pts below
            let s: Vec<[u8; 32]> = prev
                .iter()
                .map(|p| selene_point_to_helios_scalar(p).expect("s->h"))
                .collect();
            s.chunks(HELIOS_CHUNK_WIDTH)
                .map(|c| hash_grow_helios(&helios_hash_init(), 0, &ZERO, c).expect("helios node"))
                .collect()
        };
        layers.push(next);
        layer_idx += 1;
    }
    layers
}

/// Outputs covered by one node at sub-root layer `j` (= segment size E).
/// Levels: j=0 -> 38, j=1 -> 684, j=2 -> 25_992 (real fork widths).
fn outputs_per_node(j: usize) -> usize {
    let mut e = SELENE_CHUNK_WIDTH; // chunk_width(0)
    for layer in 1..=j {
        e *= if layer_is_selene(layer as u8) {
            SELENE_CHUNK_WIDTH
        } else {
            HELIOS_CHUNK_WIDTH
        };
    }
    e
}

// Sub-root layers swept by the fast tests. Level 2 (~26k outputs) is heavy;
// `freeze_under_grow_g1_level2` covers it behind `#[ignore]`.
const LEVELS: [usize; 2] = [0, 1];

#[test]
fn freeze_under_grow_g1() {
    // G1(a): a completed subtree's value is invariant under right-side append.
    for &j in &LEVELS {
        let e = outputs_per_node(j);
        for trial in 0..16u64 {
            let mut rng = seeded(1_000 + (j as u64) * 100 + trial);
            let seg0 = rand_leaves(&mut rng, e);
            let small = build_layers(&seg0);
            let r0 = small[j][0]; // segment 0 alone: its root sits at layer j
            let extra = e + (rng.next_u32() as usize % (3 * e + 1)); // crosses deepen pts
            let mut big_scalars = seg0.clone();
            big_scalars.extend(rand_leaves(&mut rng, extra));
            let big = build_layers(&big_scalars);
            assert!(big.len() >= small.len(), "big tree must be ≥ as deep");
            assert_eq!(
                r0, big[j][0],
                "G1 grow: completed R_0 moved (j={j}, trial={trial})"
            );
        }
    }
}

#[test]
fn freeze_under_trim_g1() {
    // G1(b): a buried subtree's value is invariant under right-side trim (reorg).
    // Trim modelled as rebuild-from-surviving-prefix; completed left segments are
    // never re-passed to hash_trim, so R_0 must be unchanged. (CT-1 additionally
    // proves the incremental hash_trim path == rebuild-from-prefix.)
    for &j in &LEVELS {
        let e = outputs_per_node(j);
        for trial in 0..16u64 {
            let mut rng = seeded(2_000 + (j as u64) * 100 + trial);
            let l = 2 * e + (rng.next_u32() as usize % (2 * e + 1));
            let full = rand_leaves(&mut rng, l);
            let r0 = build_layers(&full)[j][0];
            // L' strictly inside the frontier: e < L' < l (segment 0 untouched).
            let lp = e + 1 + (rng.next_u32() as usize % (l - e - 1).max(1));
            let trimmed = build_layers(&full[..lp * SCALARS_PER_LEAF]);
            assert!(lp > e && lp < l);
            assert_eq!(
                r0, trimmed[j][0],
                "G1 trim: buried R_0 moved (j={j}, trial={trial})"
            );
        }
    }
}

#[test]
fn extract_matches_in_tree() {
    // Within-Rust extractability: standalone recompute of segment k's E leaves ==
    // the internal node at (layer j, index k) of the full tree. Catches absolute-
    // layer domain separation, which the fixed-generator, index-free API lacks.
    for &j in &LEVELS {
        let e = outputs_per_node(j);
        let mut rng = seeded(3_000 + j as u64);
        let n = 3;
        let all = rand_leaves(&mut rng, n * e);
        let big = build_layers(&all);
        for k in 0..n {
            let seg = &all[k * e * SCALARS_PER_LEAF..(k + 1) * e * SCALARS_PER_LEAF];
            assert_eq!(
                build_layers(seg)[j][0],
                big[j][k],
                "extractability: standalone segment {k} root != in-tree node (j={j})"
            );
        }
    }
}

#[test]
fn frontier_changes_on_append() {
    // Negative sanity: the partial rightmost chunk DOES change on append — proves
    // G1 is non-trivial (not "everything is constant").
    let mut rng = seeded(4_000);
    let s = rand_leaves(&mut rng, 1); // 4 scalars, well under one full chunk (152)
    let a = hash_grow_selene(&selene_hash_init(), 0, &ZERO, &s[..3]).unwrap();
    let b = hash_grow_selene(&selene_hash_init(), 0, &ZERO, &s[..4]).unwrap();
    assert_ne!(
        a, b,
        "appending to a partial frontier chunk must change its hash"
    );
}

#[test]
#[ignore = "heavy: level-2 segment is ~26k outputs (~104k leaf scalars)"]
fn freeze_under_grow_g1_level2() {
    // G1(a) at sub-root layer 2 (≈25,992 outputs per segment).
    let j = 2usize;
    let e = outputs_per_node(j);
    let mut rng = seeded(5_000);
    let seg0 = rand_leaves(&mut rng, e);
    let r0 = build_layers(&seg0)[j][0];
    let mut big_scalars = seg0.clone();
    big_scalars.extend(rand_leaves(&mut rng, e + 1)); // one more segment + 1
    let big = build_layers(&big_scalars);
    assert_eq!(r0, big[j][0], "G1 grow (level 2): completed R_0 moved");
}
