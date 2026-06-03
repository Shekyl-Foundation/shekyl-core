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
// TIER 2 — the daemon's incremental reorg primitive reproduces the canonical
// tree under REPLACEMENT (consensus-grade de-risking)
//
// Whose path this is: the daemon maintains the *consensus* curve tree in C++ and
// calls these Rust primitives over FFI, so incremental `hash_trim` IS the
// consensus reorg primitive. If it ever produces a tree whose root diverges from
// a rebuild, every membership proof anchored after that reorg is invalid — a
// consensus catastrophe, not a wallet inconvenience. (The *wallet* reorgs by
// truncate-and-rebuild, covered by `freeze_under_prefix_rebuild`; this section
// owns the *daemon's* incremental path. Both paths get coverage.)
//
// The sharp point: reorgs REPLACE, they do not truncate. A reorg orphans
// B_{k+1..tip} and substitutes B'_{k+1..tip'}; the orphaned leaves are removed
// and new leaves are written at the same vacated positions with different
// values. So the consensus-relevant chunk operation is trim-to-offset-then-grow-
// different, and the consensus-relevant tree operation is undeepen-and-reopen.
// All of this is writable today against the real primitives, no maintainer.
// ===========================================================================

// --- small primitive wrappers (batch-compose one chunk / convert one node) ---

fn selene_chunk(scalars: &[[u8; 32]]) -> [u8; 32] {
    if scalars.is_empty() {
        return selene_hash_init(); // an empty chunk is the init point
    }
    hash_grow_selene(&selene_hash_init(), 0, &ZERO, scalars).expect("selene chunk")
}
fn helios_chunk(scalars: &[[u8; 32]]) -> [u8; 32] {
    if scalars.is_empty() {
        return helios_hash_init();
    }
    hash_grow_helios(&helios_hash_init(), 0, &ZERO, scalars).expect("helios chunk")
}
fn s2h(selene_point: &[u8; 32]) -> [u8; 32] {
    selene_point_to_helios_scalar(selene_point).expect("selene->helios")
}

// ---------------------------------------------------------------------------
// Tier 2a — chunk-level algebra (replace / to-empty / path-independence)
// ---------------------------------------------------------------------------

#[test]
fn incremental_grow_equals_batch_selene() {
    // Daemon appends children one at a time; wallet batches the full chunk. The
    // resulting chunk hash must be identical.
    for trial in 0..16u64 {
        let mut rng = seeded(10_000 + trial);
        let n = 1 + (rng.next_u32() as usize % LEAF_CHUNK_SCALARS); // partial chunk
        let mut h = selene_hash_init();
        let mut s = Vec::with_capacity(n);
        for i in 0..n {
            let c = rand_scalar(&mut rng);
            s.push(c);
            h = hash_grow_selene(&h, i, &ZERO, &[c]).expect("incremental selene grow");
        }
        assert_eq!(
            h,
            selene_chunk(&s),
            "selene incremental != batch (trial={trial}, n={n})"
        );
    }
}

#[test]
fn incremental_grow_equals_batch_helios() {
    for trial in 0..16u64 {
        let mut rng = seeded(16_000 + trial);
        let n = 1 + (rng.next_u32() as usize % HELIOS_CHUNK_WIDTH);
        let mut h = helios_hash_init();
        let mut s = Vec::with_capacity(n);
        for i in 0..n {
            let c = rand_helios_scalar(&mut rng);
            s.push(c);
            h = hash_grow_helios(&h, i, &ZERO, &[c]).expect("incremental helios grow");
        }
        assert_eq!(
            h,
            helios_chunk(&s),
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
        let grown = selene_chunk(&s);
        let new_val = rand_scalar(&mut rng);
        let updated = hash_grow_selene(&grown, off, &old, &[new_val]).expect("in-place update");
        s[off] = new_val;
        assert_eq!(
            updated,
            selene_chunk(&s),
            "in-place child update != rebatch (trial={trial}, off={off})"
        );
    }
}

#[test]
fn chunk_replace_equals_fresh_selene() {
    // THE reorg, at chunk level: orphan the suffix [fork..n), then write a
    // DIFFERENT suffix at the same positions. trim-to-fork-then-grow-different
    // must equal a fresh build of prefix ++ new_suffix. The single-scalar inverse
    // and pure-truncation cases never reach this.
    for trial in 0..32u64 {
        let mut rng = seeded(20_000 + trial);
        let n = 2 + (rng.next_u32() as usize % (LEAF_CHUNK_SCALARS - 1));
        let fork = rng.next_u32() as usize % n; // first replaced offset (< n)
        let s: Vec<[u8; 32]> = (0..n).map(|_| rand_scalar(&mut rng)).collect();
        let full = selene_chunk(&s);

        // orphan the suffix
        let trimmed = hash_trim_selene(&full, fork, &s[fork..], &ZERO).expect("trim suffix");
        assert_eq!(
            trimmed,
            selene_chunk(&s[..fork]),
            "trim-to-fork != prefix (trial={trial}, fork={fork})"
        );
        // write a different suffix at the vacated positions
        let new_suffix: Vec<[u8; 32]> = (fork..n).map(|_| rand_scalar(&mut rng)).collect();
        let replaced = hash_grow_selene(&trimmed, fork, &ZERO, &new_suffix).expect("regrow");
        let mut fresh = s[..fork].to_vec();
        fresh.extend_from_slice(&new_suffix);
        assert_eq!(
            replaced,
            selene_chunk(&fresh),
            "replace != fresh build (trial={trial}, n={n}, fork={fork})"
        );
    }
}

#[test]
fn chunk_replace_equals_fresh_helios() {
    for trial in 0..32u64 {
        let mut rng = seeded(21_000 + trial);
        let n = 2 + (rng.next_u32() as usize % (HELIOS_CHUNK_WIDTH - 1));
        let fork = rng.next_u32() as usize % n;
        let s: Vec<[u8; 32]> = (0..n).map(|_| rand_helios_scalar(&mut rng)).collect();
        let full = helios_chunk(&s);
        let trimmed = hash_trim_helios(&full, fork, &s[fork..], &ZERO).expect("trim suffix");
        assert_eq!(trimmed, helios_chunk(&s[..fork]), "trim-to-fork != prefix");
        let new_suffix: Vec<[u8; 32]> = (fork..n).map(|_| rand_helios_scalar(&mut rng)).collect();
        let replaced = hash_grow_helios(&trimmed, fork, &ZERO, &new_suffix).expect("regrow");
        let mut fresh = s[..fork].to_vec();
        fresh.extend_from_slice(&new_suffix);
        assert_eq!(
            replaced,
            helios_chunk(&fresh),
            "helios replace != fresh build (trial={trial}, n={n}, fork={fork})"
        );
    }
}

#[test]
fn chunk_trim_to_empty_and_multi_selene() {
    // Multi-element trim and trim-to-empty (the latter is what undeepen needs at
    // the chunk level): the chunk must return to init when fully trimmed.
    let mut rng = seeded(22_000);
    let s: Vec<[u8; 32]> = (0..3).map(|_| rand_scalar(&mut rng)).collect();
    let full = selene_chunk(&s);
    // trim [1..3) (multi-element) -> prefix [0]
    let one = hash_trim_selene(&full, 1, &s[1..], &ZERO).expect("multi trim");
    assert_eq!(one, selene_chunk(&s[..1]), "multi-element trim != prefix");
    // trim all -> init
    let empty = hash_trim_selene(&full, 0, &s, &ZERO).expect("trim all");
    assert_eq!(empty, selene_hash_init(), "trim-to-empty != init");
}

#[test]
fn chunk_path_independence_selene() {
    // A stateful primitive could carry grow-history into its result; a rebuild
    // cannot. Reaching the same final children by different grow schedules must
    // yield the same hash, and the same subsequent trim must too.
    for trial in 0..16u64 {
        let mut rng = seeded(23_000 + trial);
        let final_children: Vec<[u8; 32]> = (0..6).map(|_| rand_scalar(&mut rng)).collect();
        // path A: one shot
        let a = selene_chunk(&final_children);
        // path B: [0..2], then [2..5], then [5..6]
        let mut b = selene_chunk(&final_children[..2]);
        b = hash_grow_selene(&b, 2, &ZERO, &final_children[2..5]).expect("b grow 1");
        b = hash_grow_selene(&b, 5, &ZERO, &final_children[5..6]).expect("b grow 2");
        assert_eq!(a, b, "grow path-dependence in chunk hash (trial={trial})");
        // same trim of the [3..6) suffix from both must agree and equal prefix[..3]
        let ta = hash_trim_selene(&a, 3, &final_children[3..], &ZERO).expect("trim a");
        let tb = hash_trim_selene(&b, 3, &final_children[3..], &ZERO).expect("trim b");
        assert_eq!(ta, tb, "trim carries grow history (trial={trial})");
        assert_eq!(ta, selene_chunk(&final_children[..3]), "trim != prefix");
    }
}

#[test]
fn chunk_path_independence_helios() {
    for trial in 0..16u64 {
        let mut rng = seeded(24_000 + trial);
        let final_children: Vec<[u8; 32]> = (0..6).map(|_| rand_helios_scalar(&mut rng)).collect();
        let a = helios_chunk(&final_children);
        let mut b = helios_chunk(&final_children[..1]);
        b = hash_grow_helios(&b, 1, &ZERO, &final_children[1..4]).expect("b grow 1");
        b = hash_grow_helios(&b, 4, &ZERO, &final_children[4..6]).expect("b grow 2");
        assert_eq!(a, b, "helios grow path-dependence (trial={trial})");
        let ta = hash_trim_helios(&a, 2, &final_children[2..], &ZERO).expect("trim a");
        let tb = hash_trim_helios(&b, 2, &final_children[2..], &ZERO).expect("trim b");
        assert_eq!(ta, tb, "helios trim carries grow history (trial={trial})");
        assert_eq!(
            ta,
            helios_chunk(&final_children[..2]),
            "helios trim != prefix"
        );
    }
}

// ---------------------------------------------------------------------------
// Tier 2b — tree-level undeepen (both collapse types) + compound + capstone.
// Asserts the FULL layer vector against build_layers, not just the root: a
// structural mismatch that coincidentally agrees at the root is exactly what a
// deepen/undeepen test should catch.
// ---------------------------------------------------------------------------

#[test]
fn undeepen_helios_collapse_39_to_38() {
    // First deepen (39 outputs) adds a Helios layer over two leaf chunks; the
    // root is that Helios node. Trimming the 39th output empties the second leaf
    // chunk, the Helios layer is dropped, and the root reverts to the (Selene)
    // leaf node — a HELIOS collapse with a Selene-curve root.
    let mut rng = seeded(30_000);
    let base = rand_leaves(&mut rng, SELENE_CHUNK_WIDTH); // 38 outputs (one full leaf chunk)
    let o38 = rand_leaves(&mut rng, 1); // the 39th output

    let leaf0 = selene_chunk(&base);
    let leaf1 = selene_chunk(&o38);
    let root39 = helios_chunk(&[s2h(&leaf0), s2h(&leaf1)]);

    let mut all39 = base.clone();
    all39.extend_from_slice(&o38);
    assert_eq!(
        build_layers(&all39),
        vec![vec![leaf0, leaf1], vec![root39]],
        "forward 39 via primitives != build_layers (full layers)"
    );

    // reorg: trim the 39th output out of leaf1 via the real primitive
    let leaf1_t = hash_trim_selene(&leaf1, 0, &o38, &ZERO).expect("trim leaf1");
    assert_eq!(
        leaf1_t,
        selene_hash_init(),
        "Helios-collapse: leaf1 did not empty"
    );

    // undeepen target == build_layers(38): single Selene leaf node, depth 1
    assert_eq!(
        build_layers(&base),
        vec![vec![leaf0]],
        "undeepen target != build_layers(38) (full layers)"
    );
    assert_eq!(
        build_layers(&all39).len(),
        2,
        "39 should be depth 2 (Helios root)"
    );
    assert_eq!(
        build_layers(&base).len(),
        1,
        "38 should be depth 1 (Helios layer dropped)"
    );
}

#[test]
fn undeepen_selene_collapse_685_to_684() {
    // Second deepen (685 outputs) adds a SELENE layer (layer 2) over two Helios
    // nodes; the root is that Selene node. Trimming the 685th output empties the
    // 19th leaf chunk, the layer-2 Selene node is dropped, and the root reverts to
    // a Helios (layer-1) node — a SELENE collapse with a Helios-curve root. This
    // is a distinct code path from the 39->38 Helios collapse.
    let e1 = outputs_per_node(1); // 684 = 18 full leaf chunks under one Helios node
    let mut rng = seeded(31_000);
    let leaves684 = rand_leaves(&mut rng, e1);
    let o684 = rand_leaves(&mut rng, 1); // the 685th output (opens leaf chunk 18)

    let mut all685 = leaves684.clone();
    all685.extend_from_slice(&o684);
    let big = build_layers(&all685);
    let small = build_layers(&leaves684);

    assert_eq!(big.len(), 3, "685 should be depth 3 (Selene layer 2 added)");
    assert_eq!(
        small.len(),
        2,
        "684 should be depth 2 (Selene layer 2 dropped)"
    );

    // The frontier leaf chunk (index 18) holds exactly output 684; trim it.
    let leaf18 = big[0][18];
    assert_eq!(leaf18, selene_chunk(&o684), "frontier leaf != fresh build");
    let leaf18_t = hash_trim_selene(&leaf18, 0, &o684, &ZERO).expect("trim leaf18");
    assert_eq!(
        leaf18_t,
        selene_hash_init(),
        "Selene-collapse: leaf18 did not empty"
    );

    // The 18 completed leaf chunks are frozen across the undeepen, and the
    // surviving root is the single Helios layer-1 node.
    assert_eq!(
        big[0][..18],
        small[0][..],
        "first 18 leaf nodes not frozen across Selene collapse"
    );
    assert_eq!(small[1].len(), 1, "684 root should be a single Helios node");
}

#[test]
fn reorg_compound_45_to_35() {
    // A real multi-block reorg, not a clean tip removal: 45 -> 35 trims away the
    // partial frontier chunk (outputs 38..44), undeepens (drops the Helios
    // parent), AND re-opens the first leaf chunk from full (38) down to partial
    // (35). The undeepen-and-reopen compound logic lives here.
    let mut rng = seeded(32_000);
    let l45 = rand_leaves(&mut rng, 45);
    let sp = SCALARS_PER_LEAF;

    let leaf0 = selene_chunk(&l45[..38 * sp]); // outputs 0..37 (full)
    let frontier = &l45[38 * sp..45 * sp]; // outputs 38..44 (partial, 7 outputs)
    let leaf1 = selene_chunk(frontier);
    let root45 = helios_chunk(&[s2h(&leaf0), s2h(&leaf1)]);
    assert_eq!(
        build_layers(&l45),
        vec![vec![leaf0, leaf1], vec![root45]],
        "forward 45 via primitives != build_layers"
    );

    // empty the frontier chunk
    let leaf1_t = hash_trim_selene(&leaf1, 0, frontier, &ZERO).expect("empty leaf1");
    assert_eq!(leaf1_t, selene_hash_init(), "frontier chunk did not empty");
    // shrink the first chunk 38 -> 35: remove outputs 35,36,37 at offset 35*4
    let removed = &l45[35 * sp..38 * sp]; // 12 scalars
    let leaf0_t = hash_trim_selene(&leaf0, 35 * sp, removed, &ZERO).expect("shrink leaf0");

    // undeepen (drop Helios): result is a single partial Selene leaf node == 35
    assert_eq!(
        build_layers(&l45[..35 * sp]),
        vec![vec![leaf0_t]],
        "compound reorg 45->35 != build_layers(35) (full layers)"
    );
}

#[test]
fn reorg_capstone_replace_at_boundary_39() {
    // The nastiest structural case: a reorg landing exactly on a deepen boundary
    // with DIFFERENT new content. Grow to 39 (deepened) -> trim the 39th
    // (undeepen to 38) -> grow a different 39' (re-deepen). The frozen leaf0 is
    // carried untouched through the whole deepen/undeepen/re-deepen cycle; the
    // result must equal a fresh build of base ++ 39'.
    let mut rng = seeded(33_000);
    let base = rand_leaves(&mut rng, SELENE_CHUNK_WIDTH); // 38 outputs
    let o38_a = rand_leaves(&mut rng, 1); // original 39th output
    let o38_b = rand_leaves(&mut rng, 1); // replacement 39th output (different)

    let leaf0 = selene_chunk(&base); // computed ONCE, carried through the cycle
    let leaf1_a = selene_chunk(&o38_a);
    let _root39_a = helios_chunk(&[s2h(&leaf0), s2h(&leaf1_a)]); // deepened with original

    // reorg: orphan the original 39th -> leaf1 empties, tree undeepens to 38
    let leaf1_empty = hash_trim_selene(&leaf1_a, 0, &o38_a, &ZERO).expect("trim a");
    assert_eq!(
        leaf1_empty,
        selene_hash_init(),
        "undeepen: leaf1 did not empty"
    );

    // re-deepen with the DIFFERENT 39th, written into the vacated chunk
    let leaf1_b = hash_grow_selene(&leaf1_empty, 0, &ZERO, &o38_b).expect("regrow b");
    assert_eq!(
        leaf1_b,
        selene_chunk(&o38_b),
        "re-grown chunk carries stale state"
    );
    let root39_b = helios_chunk(&[s2h(&leaf0), s2h(&leaf1_b)]);

    let mut all_b = base.clone();
    all_b.extend_from_slice(&o38_b);
    assert_eq!(
        build_layers(&all_b),
        vec![vec![leaf0, leaf1_b], vec![root39_b]],
        "capstone: deepen->undeepen->re-deepen with different content != fresh build"
    );
}
