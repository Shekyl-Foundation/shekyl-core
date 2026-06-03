// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CT-0 gate + stateful-primitive agreement for the curve-tree client.
//!
//! See `docs/design/CURVE_TREE_CLIENT.md` §7.7 and Appendix A.
//!
//! ## Pinned assembly strategy (read before extending this file)
//!
//! The **wallet** assembles segments by *batch composition* ([`build_layers`])
//! and handles reorg by *truncate-the-leaf-array + rebuild the surviving
//! prefix*. It does **not** carry a stateful frontier and does **not** call the
//! incremental `hash_grow`(prev/offset/old/new) or `hash_trim` primitives. A
//! wallet is not the daemon: it is not perf-bound at consensus scale, and
//! prefix-rebuild is simpler than stateful rollback (freeze, G1, guarantees the
//! buried `R_k` survive untouched, so prefix-rebuild is just freeze-under-grow
//! restricted to a shorter input).
//!
//! Consequences this file encodes:
//!   * The CT-0 **gate** is batch-only: `freeze_under_grow_g1`,
//!     `freeze_under_prefix_rebuild`, `extract_matches_in_tree`,
//!     `freeze_at_exact_boundaries`. `freeze_under_prefix_rebuild` is the
//!     wallet's actual reorg path (truncate + rebuild); it deliberately does
//!     NOT exercise the `hash_trim` primitive — incremental trim is a
//!     daemon-side primitive the wallet never calls.
//!   * The **Tier-2** section below proves the daemon's incremental
//!     `hash_grow`/`hash_trim` primitives produce values identical to the
//!     wallet's batch composition. That cross-implementation agreement is what
//!     `R_k`-as-infohash content-addressing (a daemon-built and wallet-built
//!     segment must hash identically) and CT-2's reconstruct-root KAT rest on.
//!     It is not "the wallet uses these primitives."

use ciphersuite::{
    group::ff::{Field, PrimeField},
    Ciphersuite,
};
use helioselene::{Helios, Selene};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use shekyl_fcmp::tree::{
    build_layers, hash_grow_helios, hash_grow_selene, hash_trim_helios, hash_trim_selene,
    helios_hash_init, helios_point_to_selene_scalar, layer_is_selene, selene_hash_init,
    selene_point_to_helios_scalar, HELIOS_CHUNK_WIDTH, LEAF_CHUNK_SCALARS, SCALARS_PER_LEAF,
    SELENE_CHUNK_WIDTH,
};

const ZERO: [u8; 32] = [0u8; 32];

fn seeded(s: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(s)
}

/// A random *valid* (canonical) Selene base-field element — leaf scalars must be.
fn rand_scalar(rng: &mut ChaCha20Rng) -> [u8; 32] {
    <Selene as Ciphersuite>::F::random(rng).to_repr()
}

/// A random *valid* (canonical) Helios base-field element — Helios-layer children.
fn rand_helios_scalar(rng: &mut ChaCha20Rng) -> [u8; 32] {
    <Helios as Ciphersuite>::F::random(rng).to_repr()
}

/// `n_outputs` worth of leaf scalars (SCALARS_PER_LEAF each), flat.
fn rand_leaves(rng: &mut ChaCha20Rng, n_outputs: usize) -> Vec<[u8; 32]> {
    (0..n_outputs * SCALARS_PER_LEAF)
        .map(|_| rand_scalar(rng))
        .collect()
}

/// Outputs covered by one node at sub-root layer `j` (= segment size E).
/// Levels: j=0 -> 38, j=1 -> 684, j=2 -> 25_992 (real fork widths).
fn outputs_per_node(j: usize) -> usize {
    let mut e = SELENE_CHUNK_WIDTH; // chunk_width(0)
    for layer in 1..=j {
        let layer = u8::try_from(layer).expect("tree layer fits u8");
        e *= if layer_is_selene(layer) {
            SELENE_CHUNK_WIDTH
        } else {
            HELIOS_CHUNK_WIDTH
        };
    }
    e
}

// Sub-root layers swept by the fast gate. [0, 1] is *mechanism-complete*, not a
// shortcut: level 0 crossing into layer 1 exercises the Helios-over-Selene
// deepen, and level 1's grow pushes `big` into a layer-2 Selene node, exercising
// the Selene-over-Helios deepen — the two distinct deepen types. Because the
// node hash is context-free (no absolute-layer domain separation; see
// `extract_matches_in_tree`), the freeze mechanism is identical at every level,
// so deeper levels add no new G1 behavior. The ~25,992-leaf level-2 segment is
// shard-size *realism* and belongs to CT-2's reconstruct-root KAT against a real
// header, not to G1 coverage; it is exercised behind `#[ignore]` below.
const LEVELS: [usize; 2] = [0, 1];

// ===========================================================================
// CT-0 GATE (batch composition only — the wallet's actual assembly path)
// ===========================================================================

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
fn freeze_at_exact_boundaries() {
    // Deepen off-by-ones live at "the node that just completed vs the one that
    // just opened." The random `extra` in freeze_under_grow_g1 crosses deepen
    // points but does not reliably land on them — pin R_0 invariant at the exact
    // boundary totals and one past each.
    for &j in &LEVELS {
        let e = outputs_per_node(j);
        let totals = [e, e + 1, 2 * e, 2 * e + 1, 3 * e];
        let mut rng = seeded(15_000 + j as u64);
        let seg0 = rand_leaves(&mut rng, e);
        let r0 = build_layers(&seg0)[j][0];
        let pool = rand_leaves(&mut rng, 3 * e); // shared trailing pool
        for &total in &totals {
            assert!(total >= e);
            let mut scalars = seg0.clone();
            scalars.extend_from_slice(&pool[..(total - e) * SCALARS_PER_LEAF]);
            let layers = build_layers(&scalars);
            assert_eq!(
                r0, layers[j][0],
                "boundary freeze: R_0 moved at total={total} (j={j})"
            );
        }
    }
}

#[test]
fn freeze_under_prefix_rebuild() {
    // G1(b) AS THE WALLET RUNS IT: reorg = truncate the leaf array + rebuild the
    // surviving prefix via build_layers. This is the wallet's actual reorg path,
    // NOT the incremental hash_trim primitive (which is daemon-side and exercised
    // in the Tier-2 section). A buried R_0 must survive a right-side truncation.
    for &j in &LEVELS {
        let e = outputs_per_node(j);
        for trial in 0..16u64 {
            let mut rng = seeded(2_000 + (j as u64) * 100 + trial);
            let l = 2 * e + (rng.next_u32() as usize % (2 * e + 1));
            let full = rand_leaves(&mut rng, l);
            let r0 = build_layers(&full)[j][0];
            // L' strictly inside the frontier: e < L' < l (segment 0 untouched).
            let lp = e + 1 + (rng.next_u32() as usize % (l - e - 1).max(1));
            let rebuilt = build_layers(&full[..lp * SCALARS_PER_LEAF]);
            assert!(lp > e && lp < l);
            assert_eq!(
                r0, rebuilt[j][0],
                "G1 prefix-rebuild: buried R_0 moved (j={j}, trial={trial})"
            );
        }
    }
}

#[test]
fn extract_matches_in_tree() {
    // Within-Rust extractability: standalone recompute of segment k's E leaves ==
    // the internal node at (layer j, index k) of the full tree. This is the test
    // that would catch absolute-layer domain separation (the fixed-generator,
    // index-free API should have none) — so it must not be under-sampled.
    for &j in &LEVELS {
        let e = outputs_per_node(j);
        let trials = if j == 0 { 16u64 } else { 4 };
        for trial in 0..trials {
            let mut rng = seeded(3_000 + (j as u64) * 100 + trial);
            let n = 3;
            let all = rand_leaves(&mut rng, n * e);
            let big = build_layers(&all);
            for k in 0..n {
                let seg = &all[k * e * SCALARS_PER_LEAF..(k + 1) * e * SCALARS_PER_LEAF];
                assert_eq!(
                    build_layers(seg)[j][0],
                    big[j][k],
                    "extractability: standalone segment {k} root != in-tree node \
                     (j={j}, trial={trial})"
                );
            }
        }
    }
}

#[test]
fn node_conversions_are_total() {
    // The production assembler inherits build_layers' point↔scalar `expect`s. If a
    // conversion can return None for a *legitimately-occurring* node (not just
    // adversarial input), that is a tree-assembly liveness bug, not a test bug.
    // The 2-cycle is designed to compose, so the prior is total — assert it over
    // a sweep of tree sizes spanning several deepen boundaries.
    for size in [1usize, 2, 37, 38, 39, 76, 100, 684, 685, 1000] {
        let mut rng = seeded(14_000 + size as u64);
        let leaves = rand_leaves(&mut rng, size);
        let layers = build_layers(&leaves);
        for (idx, layer) in layers.iter().enumerate() {
            if idx + 1 == layers.len() {
                break; // top layer feeds no parent
            }
            // The parent layer (idx+1) parity decides which conversion its
            // children (this layer's nodes) feed through.
            let parent_layer = u8::try_from(idx + 1).expect("tree layer fits u8");
            let parent_is_selene = layer_is_selene(parent_layer);
            for node in layer {
                let converted = if parent_is_selene {
                    helios_point_to_selene_scalar(node)
                } else {
                    selene_point_to_helios_scalar(node)
                };
                assert!(
                    converted.is_some(),
                    "conversion returned None at layer {idx}, size {size} — \
                     tree-assembly liveness bug"
                );
            }
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
    // G1(a) at sub-root layer 2 (≈25,992 outputs per segment). Mechanism is
    // identical to levels 0/1 (context-free hash); this is shard-size realism.
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

// ===========================================================================
// TIER 2 — daemon-incremental ↔ wallet-batch agreement
//
// These prove the stateful primitives (incremental hash_grow, hash_trim) that
// the *daemon* runs produce node values byte-identical to the wallet's batch
// build_layers composition. Required so a daemon-built segment and a wallet-built
// segment share the same R_k (content-addressing) and so CT-2's KAT is sound.
// ===========================================================================

/// Build a Selene chunk hash one child at a time via the *incremental*
/// prev/offset/old/new grow signature (the daemon's append path).
fn incremental_grow_selene(scalars: &[[u8; 32]]) -> [u8; 32] {
    let mut h = selene_hash_init();
    for (i, s) in scalars.iter().enumerate() {
        h = hash_grow_selene(&h, i, &ZERO, &[*s]).expect("incremental selene grow");
    }
    h
}

/// Build a Helios chunk hash one child at a time (incremental append path).
fn incremental_grow_helios(scalars: &[[u8; 32]]) -> [u8; 32] {
    let mut h = helios_hash_init();
    for (i, s) in scalars.iter().enumerate() {
        h = hash_grow_helios(&h, i, &ZERO, &[*s]).expect("incremental helios grow");
    }
    h
}

#[test]
fn incremental_grow_equals_batch_selene() {
    // Daemon appends children one at a time; wallet batches the full chunk. The
    // resulting chunk hash must be identical.
    for trial in 0..16u64 {
        let mut rng = seeded(10_000 + trial);
        let n = 1 + (rng.next_u32() as usize % LEAF_CHUNK_SCALARS); // partial chunk
        let s: Vec<[u8; 32]> = (0..n).map(|_| rand_scalar(&mut rng)).collect();
        let batch = hash_grow_selene(&selene_hash_init(), 0, &ZERO, &s).expect("batch");
        assert_eq!(
            incremental_grow_selene(&s),
            batch,
            "selene incremental != batch (trial={trial}, n={n})"
        );
    }
}

#[test]
fn incremental_grow_equals_batch_helios() {
    for trial in 0..16u64 {
        let mut rng = seeded(16_000 + trial);
        let n = 1 + (rng.next_u32() as usize % HELIOS_CHUNK_WIDTH);
        let s: Vec<[u8; 32]> = (0..n).map(|_| rand_helios_scalar(&mut rng)).collect();
        let batch = hash_grow_helios(&helios_hash_init(), 0, &ZERO, &s).expect("batch");
        assert_eq!(
            incremental_grow_helios(&s),
            batch,
            "helios incremental != batch (trial={trial}, n={n})"
        );
    }
}

#[test]
fn grow_update_equals_rebatch_selene() {
    // The non-zero old-child path: when a child's subtree grows, its parent
    // updates that child in place (offset, old_child != 0). Updating in place must
    // equal rebuilding the chunk with the new child value.
    for trial in 0..16u64 {
        let mut rng = seeded(11_000 + trial);
        let n = 2 + (rng.next_u32() as usize % (LEAF_CHUNK_SCALARS - 1));
        let mut s: Vec<[u8; 32]> = (0..n).map(|_| rand_scalar(&mut rng)).collect();
        let off = rng.next_u32() as usize % n;
        let old = s[off];
        let grown = hash_grow_selene(&selene_hash_init(), 0, &ZERO, &s).expect("grow");
        let new_val = rand_scalar(&mut rng);
        let updated = hash_grow_selene(&grown, off, &old, &[new_val]).expect("in-place update");
        s[off] = new_val;
        let rebatch = hash_grow_selene(&selene_hash_init(), 0, &ZERO, &s).expect("rebatch");
        assert_eq!(
            updated, rebatch,
            "in-place child update != rebatch (trial={trial}, off={off})"
        );
    }
}

#[test]
fn trim_inverts_partial_grow_selene() {
    // The daemon's reorg primitive: trimming children [m..n) at offset m (grow
    // back zero) must equal the batch build of the surviving prefix [0..m).
    for trial in 0..16u64 {
        let mut rng = seeded(12_000 + trial);
        let n = 2 + (rng.next_u32() as usize % (LEAF_CHUNK_SCALARS - 1));
        let m = 1 + (rng.next_u32() as usize % (n - 1)); // 1..=n-1
        let s: Vec<[u8; 32]> = (0..n).map(|_| rand_scalar(&mut rng)).collect();
        let full = hash_grow_selene(&selene_hash_init(), 0, &ZERO, &s).expect("grow");
        let trimmed = hash_trim_selene(&full, m, &s[m..], &ZERO).expect("trim");
        let prefix = hash_grow_selene(&selene_hash_init(), 0, &ZERO, &s[..m]).expect("prefix");
        assert_eq!(
            trimmed, prefix,
            "selene trim to m != batch prefix (trial={trial}, n={n}, m={m})"
        );
    }
}

#[test]
fn trim_inverts_partial_grow_helios() {
    for trial in 0..16u64 {
        let mut rng = seeded(17_000 + trial);
        let n = 2 + (rng.next_u32() as usize % (HELIOS_CHUNK_WIDTH - 1));
        let m = 1 + (rng.next_u32() as usize % (n - 1));
        let s: Vec<[u8; 32]> = (0..n).map(|_| rand_helios_scalar(&mut rng)).collect();
        let full = hash_grow_helios(&helios_hash_init(), 0, &ZERO, &s).expect("grow");
        let trimmed = hash_trim_helios(&full, m, &s[m..], &ZERO).expect("trim");
        let prefix = hash_grow_helios(&helios_hash_init(), 0, &ZERO, &s[..m]).expect("prefix");
        assert_eq!(
            trimmed, prefix,
            "helios trim to m != batch prefix (trial={trial}, n={n}, m={m})"
        );
    }
}

#[test]
fn trim_undeepen_returns_to_prefix() {
    // Tree-level deepen/undeepen via the real hash_trim primitive — the most
    // divergence-prone point (a layer collapsing from 2 chunks back to 1). Grow
    // exactly one output past the first deepen (leaf layer 1->2 chunks), trim it
    // back via hash_trim, and confirm the tree returns to its pre-deepen state.
    // E = SELENE_CHUNK_WIDTH outputs == one full leaf chunk == a depth-1 tree.
    let mut rng = seeded(13_000);
    let e = SELENE_CHUNK_WIDTH; // 38 outputs
    let base = rand_leaves(&mut rng, e); // depth-1 tree (single full leaf chunk)
    let extra = rand_leaves(&mut rng, 1); // 1 more output -> deepen to depth 2

    let root_38 = build_layers(&base)[0][0]; // pre-deepen root == the single leaf node
    let chunk0 = hash_grow_selene(&selene_hash_init(), 0, &ZERO, &base).expect("chunk0");
    assert_eq!(
        chunk0, root_38,
        "pre-deepen root must be the single full leaf chunk"
    );

    // Deepen: a second (partial) leaf chunk holds output 38, with a Helios parent.
    let chunk1 = hash_grow_selene(&selene_hash_init(), 0, &ZERO, &extra).expect("chunk1");
    let c0_h = selene_point_to_helios_scalar(&chunk0).expect("s->h c0");
    let c1_h = selene_point_to_helios_scalar(&chunk1).expect("s->h c1");
    let root_39 = hash_grow_helios(&helios_hash_init(), 0, &ZERO, &[c0_h, c1_h]).expect("root39");
    let mut all = base.clone();
    all.extend_from_slice(&extra);
    assert_eq!(
        root_39,
        build_layers(&all)[1][0],
        "deepened root via primitives != batch build_layers"
    );

    // Undeepen via real hash_trim: remove output 38's scalars from chunk1, which
    // must return it to the empty-chunk init. The leaf layer then has one
    // non-empty chunk, so the tree depth returns to 1 and the root reverts to
    // chunk0 (the Helios parent is structurally dropped, not kept as a 1-child
    // node) — matching build_layers(base), which stops while-deepening at len==1.
    let chunk1_trimmed = hash_trim_selene(&chunk1, 0, &extra, &ZERO).expect("trim chunk1");
    assert_eq!(
        chunk1_trimmed,
        selene_hash_init(),
        "trimmed frontier chunk did not return to init"
    );
    assert_eq!(
        chunk0, root_38,
        "undeepen: root did not return to the pre-deepen value"
    );
}
