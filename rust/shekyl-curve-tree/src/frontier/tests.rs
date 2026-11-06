// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Frontier oracles: finalized chunks and open branches against `build_layers`.

use super::*;
use shekyl_fcmp::tree::{try_build_layers, HELIOS_CHUNK_WIDTH, SELENE_CHUNK_WIDTH};

/// Distinct, valid leaf bytes: four copies of a Selene scalar derived
/// from `i`. Canonical by construction (the high byte stays clear).
fn leaf(i: u64) -> [u8; LEAF_BYTES] {
    let mut out = [0u8; LEAF_BYTES];
    for (s, slot) in out.chunks_exact_mut(32).enumerate() {
        let index = u64::try_from(s).expect("scalar index fits u64");
        let mixed = i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(index);
        slot[..8].copy_from_slice(&mixed.to_le_bytes());
        slot[8] = u8::try_from(s).expect("scalar index fits u8");
    }
    out
}

fn oracle_root(n: u64) -> [u8; 32] {
    if n == 0 {
        return selene_hash_init();
    }
    let mut scalars = Vec::new();
    for i in 0..n {
        for chunk in leaf(i).chunks_exact(32) {
            let mut s = [0u8; 32];
            s.copy_from_slice(chunk);
            scalars.push(s);
        }
    }
    let layers = try_build_layers(&scalars).expect("oracle builds");
    *layers.last().unwrap().first().unwrap()
}

fn frontier_through(n: u64) -> Frontier {
    let mut f = Frontier::new();
    for i in 0..n {
        f.push_leaf(&leaf(i)).expect("advance");
    }
    f
}

/// The derivation in [`Frontier::expected_shape`] is written from the
/// fold rule, so it is graded against frontiers the fold actually built
/// — never against a second copy of the same reasoning.
#[test]
fn expected_shape_matches_every_frontier_the_advance_builds() {
    let selene = u64::try_from(SELENE_CHUNK_WIDTH).expect("width fits u64");
    let helios = u64::try_from(HELIOS_CHUNK_WIDTH).expect("width fits u64");
    // Both layer-count discontinuities (`0 -> 1` and the first cascade),
    // their neighbours, and a dense run that crosses the leaf fold many
    // times. A flat region alone cannot see a shape error.
    let mut counts: Vec<u64> = (0..=(selene * 3)).collect();
    for edge in [selene * helios, selene * helios * selene] {
        counts.extend([edge - 1, edge, edge + 1]);
    }
    for n in counts {
        let f = frontier_through(n);
        let (scalars, widths) =
            Frontier::expected_shape(n).expect("production counts are in range");
        assert_eq!(
            scalars,
            f.leaf_chunk.len(),
            "leaf-chunk scalars disagree at n = {n}"
        );
        assert_eq!(
            widths,
            f.partial.iter().map(Vec::len).collect::<Vec<_>>(),
            "partial widths disagree at n = {n}"
        );
    }
}

/// The body length is the shape of the count. Rewriting the count over a
/// body built for a different count is a short or long buffer, which is
/// [`FrontierError::Malformed`]. There is no width byte that could keep
/// the old boundaries under the new count.
#[test]
fn decode_refuses_a_count_whose_body_belongs_to_another_shape() {
    let selene = u64::try_from(SELENE_CHUNK_WIDTH).expect("width fits u64");
    let n = selene * 3;
    let bytes = frontier_through(n).encode();
    assert_eq!(
        Frontier::decode(&bytes).expect("the unmutated encoding decodes"),
        frontier_through(n),
        "the control must decode before a mutation of it means anything"
    );
    let (scalars, widths) = Frontier::expected_shape(n).expect("production count is in range");
    let implied =
        Frontier::HEADER_LEN + scalars * 32 + widths.iter().map(|width| width * 32).sum::<usize>();
    assert_eq!(
        bytes.len(),
        implied,
        "encode wrote a length the shape does not name"
    );

    let successor = n + 1;
    let (next_scalars, next_widths) =
        Frontier::expected_shape(successor).expect("the successor is in range");
    let successor_len = Frontier::HEADER_LEN
        + next_scalars * 32
        + next_widths.iter().map(|width| width * 32).sum::<usize>();
    assert_ne!(
        bytes.len(),
        successor_len,
        "this count's successor must change the layout, or the mutation below is a no-op"
    );
    let mut forged = bytes.clone();
    forged[..Frontier::HEADER_LEN].copy_from_slice(&successor.to_le_bytes());
    assert_eq!(Frontier::decode(&forged), Err(FrontierError::Malformed));
}

/// A chunk at capacity folds in the same [`Frontier::push_leaf`], so no
/// reachable count has a full leaf chunk or a full partial chunk. The
/// encoding has no way to claim one: the layout never asks for it.
#[test]
fn a_reachable_shape_never_holds_a_full_chunk() {
    let selene = u64::try_from(SELENE_CHUNK_WIDTH).expect("width fits u64");
    let helios = u64::try_from(HELIOS_CHUNK_WIDTH).expect("width fits u64");
    let mut counts: Vec<u64> = (0..=(selene * 3)).collect();
    for edge in [selene * helios, selene * helios * selene] {
        counts.extend([edge - 1, edge, edge + 1]);
    }
    for n in counts {
        let (scalars, widths) =
            Frontier::expected_shape(n).expect("production counts are in range");
        assert!(
            scalars < LEAF_CHUNK_SCALARS,
            "n = {n} asks for a full leaf chunk, which push_leaf folds away"
        );
        for (k, width) in widths.iter().enumerate() {
            assert!(
                *width < Frontier::partial_capacity(k),
                "n = {n} layer {k} asks for a full chunk, which the carry folds away"
            );
        }
    }
}

#[test]
fn partial_capacity_is_the_parent_layers_width() {
    // `partial[0]` holds layer-0 nodes chunked into a layer-1 (Helios)
    // parent, so its capacity is the parent's width. Reading layer 0's
    // own width here is the off-by-one this asserts against.
    assert_eq!(Frontier::partial_capacity(0), HELIOS_CHUNK_WIDTH);
    assert_ne!(HELIOS_CHUNK_WIDTH, SELENE_CHUNK_WIDTH);
    assert_eq!(Frontier::partial_capacity(1), SELENE_CHUNK_WIDTH);
}

#[test]
fn root_matches_the_batch_oracle_across_every_fold_boundary() {
    // Graded at every count through the first two leaf-chunk folds, and
    // then at the three counts around the first *cascade* — where a full
    // Helios chunk of layer-0 nodes folds into a layer-1 node. The dense
    // low range catches a partial-chunk error; the cascade triple catches
    // the carry. Re-deriving the oracle at all 684 counts is quadratic in
    // curve hashes and buys no case these do not cover.
    let selene = u64::try_from(SELENE_CHUNK_WIDTH).expect("width fits u64");
    let cascade =
        u64::try_from(SELENE_CHUNK_WIDTH * HELIOS_CHUNK_WIDTH).expect("boundary fits u64");
    // Past the first cascade the layer-0 fold has to happen REPEATEDLY
    // for the root to stay right, and `folded` is the first count at
    // which a partial chunk sized by the WRONG layer's width stops being
    // invisible: the closure computes the correct root from an unfolded
    // chunk, so an over-wide chunk agrees with the oracle until it
    // finally fills and promotes to more than one node. `selene * selene`
    // is where a chunk sized by layer 0's own width (38) would fill;
    // correct code has folded twice by then, at 18 and 36 layer-0 nodes.
    let folded = selene * selene + 1;
    let dense_through = selene * 2 + 1;
    let graded: Vec<u64> = (0..=dense_through)
        .chain([cascade - 1, cascade, cascade + 1, folded])
        .collect();

    let mut f = Frontier::new();
    let mut next = 0u64;
    let mut folds = 0usize;
    let mut cascades = 0usize;
    for n in graded {
        while next < n {
            f.push_leaf(&leaf(next)).expect("advance");
            next += 1;
        }
        assert_eq!(f.leaf_count(), n, "leaf count at n={n}");
        assert_eq!(
            f.root().expect("close"),
            oracle_root(n),
            "frontier root disagrees with build_layers at n={n}"
        );
        assert_eq!(f.depth(), layer_count_for_leaves(n), "depth at n={n}");
        if n > 0 && n.is_multiple_of(selene) {
            folds += 1;
        }
        if n == cascade {
            cascades += 1;
        }
    }
    assert!(folds > 1, "no leaf-chunk fold was graded");
    assert_eq!(cascades, 1, "the layer-1 cascade was not graded");
    assert!(
        folded > cascade * 2,
        "the graded range never reaches a second layer-1 fold, so a partial chunk \
         sized by the wrong layer's width would agree with the oracle at every \
         count here — the closure computes the right root from an unfolded chunk"
    );
    // The two depths in the graded set differ, so a depth taken from the
    // wrong leaf count is visible rather than coincidentally equal.
    assert_ne!(
        layer_count_for_leaves(1),
        layer_count_for_leaves(cascade + 1),
        "the graded range spans no depth step"
    );
}

#[test]
fn closing_does_not_consume_the_frontier() {
    let mut f = frontier_through(5);
    let before = f.clone();
    let first = f.root().expect("close");
    assert_eq!(f, before, "root() mutated the frontier");
    assert_eq!(f.root().expect("close"), first, "root() is not idempotent");
    f.push_leaf(&leaf(5)).expect("advance");
    assert_ne!(f.root().expect("close"), first, "advance changed no root");
}

#[test]
fn encode_round_trips_at_each_shape() {
    let boundary =
        u64::try_from(SELENE_CHUNK_WIDTH * HELIOS_CHUNK_WIDTH).expect("boundary fits u64");
    let selene_width = u64::try_from(SELENE_CHUNK_WIDTH).expect("width fits u64");
    for n in [
        0,
        1,
        selene_width - 1,
        selene_width,
        selene_width + 1,
        boundary,
        boundary + 1,
    ] {
        let f = frontier_through(n);
        let bytes = f.encode();
        assert!(
            bytes.len() <= Frontier::max_encoded_len(),
            "n={n} encodes to {} bytes, past the derived bound {}",
            bytes.len(),
            Frontier::max_encoded_len()
        );
        let back = Frontier::decode(&bytes).expect("round trip");
        assert_eq!(back, f, "round trip at n={n}");
        assert_eq!(back.root().expect("close"), f.root().expect("close"));
    }
}

#[test]
fn decode_refuses_trailing_bytes_and_short_input() {
    let bytes = frontier_through(3).encode();
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(Frontier::decode(&longer), Err(FrontierError::Malformed));
    assert_eq!(
        Frontier::decode(&bytes[..bytes.len() - 1]),
        Err(FrontierError::Malformed)
    );
}

/// Every finalized chunk the observer reports **equals the corresponding
/// slice of the canonical tree** at that layer.
///
/// This is the oracle that matters for capture: a captured chunk is only
/// usable if it is bit-identical to what `build_layers` would have put
/// there. The frontier reaches it incrementally and `build_layers` from
/// the whole leaf set, so agreement is a real cross-check rather than a
/// restatement — the same relationship `curve_tree_freeze` pins for roots,
/// applied to the chunks beneath them.
/// `open_branches()[L - 1]` is the canonical tree's rightmost layer-`L`
/// node's child set — and is empty exactly when that chunk has closed.
///
/// [`Frontier::root`] pins the *hash* this vector composes to, at every
/// height; it does not pin the mapping a path reader depends on, which
/// is that entry `k` is the open layer-`k + 1` node's children. That is
/// checked here directly against `build_layers`, both ways: when the
/// rightmost chunk at a layer is open, the entry is the tail slice of the
/// layer below; when it has closed, the entry is empty, because a reader
/// that consults it then is asking for a captured chunk.
///
/// Sampled around both layer steps rather than at every height, because
/// `build_layers` per height is `O(n)` and the interesting heights are
/// the ones beside a fold.
#[test]
fn open_branches_equal_the_canonical_tree_tail() {
    let width0 = u64::try_from(SELENE_CHUNK_WIDTH).expect("fits");
    let fold1 = width0 * u64::try_from(HELIOS_CHUNK_WIDTH).expect("fits");
    let heights: Vec<u64> = (1..=width0 + 2)
        .chain(fold1 - 2..=fold1 + width0 + 1)
        .collect();
    let last = *heights.last().expect("heights");

    let mut scalars: Vec<[u8; 32]> = Vec::new();
    let mut f = Frontier::new();
    let mut checked_open = 0usize;
    let mut checked_closed = 0usize;
    for i in 0..last {
        let l = leaf(i);
        for c in l.chunks_exact(32) {
            let mut sc = [0u8; 32];
            sc.copy_from_slice(c);
            scalars.push(sc);
        }
        f.push_leaf(&l).expect("advance");
        let n = i + 1;
        if !heights.contains(&n) {
            continue;
        }

        let layers = shekyl_fcmp::tree::build_layers(&scalars);
        let depth = layers.len();
        let open = f.open_branches().expect("branches");
        for layer in 1..depth {
            let below = &layers[layer - 1];
            let width = chunk_width(u8::try_from(layer).expect("fits"));
            let covered =
                u64::try_from(outputs_per_node(u8::try_from(layer).expect("fits"))).expect("fits");
            let idx = (below.len() - 1) / width;
            let end_leaf = (u64::try_from(idx).expect("fits") + 1) * covered - 1;
            let entry = open.get(layer - 1).map(Vec::as_slice).unwrap_or(&[]);
            if end_leaf < n {
                assert!(
                    entry.is_empty(),
                    "n={n}: layer-{layer} chunk {idx} closed at {end_leaf}, so the open \
                     branch must be empty; a reader must take the capture"
                );
                checked_closed += 1;
            } else {
                assert_eq!(
                    entry,
                    &below[idx * width..],
                    "n={n}: layer-{layer} open branch is not the canonical tail"
                );
                checked_open += 1;
            }
        }
    }
    assert!(
        checked_open > 0 && checked_closed > 0,
        "both arms must have run"
    );
}

#[test]
fn folded_chunks_equal_the_canonical_tree_slice() {
    // Past the first layer-1 fold (684 leaves) so both layers are covered.
    const LEAVES: u64 = 700;

    let mut scalars: Vec<[u8; 32]> = Vec::new();
    let mut folds: Vec<(u8, u64, u64, Vec<[u8; 32]>)> = Vec::new();
    let mut f = Frontier::new();
    for i in 0..LEAVES {
        let l = leaf(i);
        for c in l.chunks_exact(32) {
            let mut sc = [0u8; 32];
            sc.copy_from_slice(c);
            scalars.push(sc);
        }
        f.push_leaf_observed(&l, &mut |chunk| {
            folds.push((
                chunk.layer,
                chunk.index,
                chunk.end_leaf,
                chunk.children.to_vec(),
            ));
        })
        .expect("advance");
    }

    let layers = shekyl_fcmp::tree::build_layers(&scalars);
    assert!(
        folds.iter().any(|(layer, ..)| *layer == 1),
        "the fixture must cross a layer-1 fold, or the upper shape is untested"
    );

    for (layer, index, end_leaf, children) in &folds {
        let covered = u64::try_from(outputs_per_node(*layer)).expect("node capacity fits u64");
        // The identity that makes the chunk addressable at all.
        assert_eq!(
            *end_leaf,
            (index + 1) * covered - 1,
            "layer-{layer} chunk {index} must end where its capacity says"
        );

        if *layer == 0 {
            // Layer 0's children are leaf scalars, so they are compared
            // against the scalar stream rather than against a tree layer.
            let start = usize::try_from(index * covered * SCALARS_PER_LEAF as u64)
                .expect("scalar offset fits usize");
            let end = start + LEAF_CHUNK_SCALARS;
            assert_eq!(
                children.as_slice(),
                &scalars[start..end],
                "layer-0 chunk {index} is not the leaf scalars it covers"
            );
            continue;
        }

        // At layer >= 1 the children are the layer below's nodes.
        let below = &layers[usize::from(*layer) - 1];
        let width = chunk_width(*layer);
        let start = usize::try_from(*index).expect("index fits usize") * width;
        assert_eq!(
            children.as_slice(),
            &below[start..start + width],
            "layer-{layer} chunk {index} is not the canonical node slice"
        );
    }
}

/// A chunk is reported exactly once, and only when it is complete.
#[test]
fn a_chunk_folds_once_and_only_when_full() {
    const LEAVES: u64 = 700;
    let mut seen: Vec<(u8, u64)> = Vec::new();
    let mut f = Frontier::new();
    for i in 0..LEAVES {
        f.push_leaf_observed(&leaf(i), &mut |c| seen.push((c.layer, c.index)))
            .expect("advance");
    }

    let mut sorted = seen.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        seen.len(),
        "a chunk was reported twice: {seen:?}"
    );

    // Count against the schedule rather than a literal: a layer's chunks
    // are the complete multiples of its capacity.
    for layer in 0..=1u8 {
        let covered = u64::try_from(outputs_per_node(layer)).expect("node capacity fits u64");
        let expected = LEAVES / covered;
        let got = seen.iter().filter(|(l, _)| *l == layer).count() as u64;
        assert_eq!(
            got, expected,
            "layer {layer}: {got} chunks folded, {expected} are complete in {LEAVES} leaves"
        );
    }
}

/// `push_leaf` is `push_leaf_observed` with a no-op, so the two must leave
/// the frontier in the same state — otherwise the capturing path and the
/// production path would diverge silently.
#[test]
fn observing_does_not_change_the_frontier() {
    const LEAVES: u64 = 700;
    let mut plain = Frontier::new();
    let mut observed = Frontier::new();
    for i in 0..LEAVES {
        plain.push_leaf(&leaf(i)).expect("advance");
        observed
            .push_leaf_observed(&leaf(i), &mut |_| {})
            .expect("advance");
    }
    assert_eq!(
        plain.encode(),
        observed.encode(),
        "observing changed the frontier's state"
    );
    assert_eq!(plain.root().expect("root"), observed.root().expect("root"));
}
