// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;
use crate::corpus::min_leaves_for_depth;

// ── The verify round-trip red-bite ──────────────────────────────────────────
//
// The gate that makes the numbers mean anything: a harness whose artifacts do
// not verify prints garbage with confidence. Its scope is stated precisely --
// the round trip proves the PATH and the PROVER are coherent with each other.
// It does NOT prove the tree matches consensus; that is CT-2's
// reconstruct-root KAT's claim, against a real header root.

#[test]
fn a_dense_path_off_a_real_tree_proves_and_verifies() {
    let leaves = min_leaves_for_depth(3).expect("depth 3 has a floor");
    let corpus = build_corpus(leaves, 0x11);
    let layers = replay(&corpus);
    let path = read_off_path(&layers, corpus.spent_index);
    assert_eq!(
        usize::from(path.tree_depth),
        path.c1_layers.len() + path.c2_layers.len() + 1,
        "the C3 invariant: the leaf layer is the +1 and the root point is excluded"
    );

    let inputs = prove_inputs(&corpus, &path, 1);
    let result = prove_only(&inputs, &path, [0xAB; 32]).expect("prove");
    let images = [key_image(&corpus.chunk[corpus.spent_index])];
    let keys = [corpus.chunk[corpus.spent_index].pqc_key_scalar];
    let ok = shekyl_fcmp::proof::verify(
        &result.proof,
        &images,
        &result.pseudo_outs,
        &keys,
        &path.tree_root,
        path.tree_depth,
        [0xAB; 32],
    )
    .expect("verify");
    assert!(ok, "a path the harness measured must verify");
}

#[test]
fn a_synthesized_sparse_path_proves_and_verifies_at_the_same_depth() {
    // The escape from the 2.3 GB dense depth-6 corpus. The root here is a
    // genuine hash of the chain below it -- what makes the path synthetic is
    // only that no chain produced it, and nothing in the circuit depends on
    // that.
    let corpus = build_corpus(u64::try_from(SELENE_CHUNK_WIDTH).expect("width fits"), 0x22);
    let path = synth_sparse_path(&corpus, 3);
    assert_eq!(path.tree_depth, 3);
    assert_eq!(
        path.c1_layers.len() + path.c2_layers.len() + 1,
        3,
        "a synthesized path must satisfy the same C3 invariant"
    );
    for layer in path.c1_layers.iter().chain(path.c2_layers.iter()) {
        assert_eq!(layer.len(), 1, "sparse means one real child per layer");
    }

    let inputs = prove_inputs(&corpus, &path, 1);
    let result = prove_only(&inputs, &path, [0xCD; 32]).expect("prove");
    let images = [key_image(&corpus.chunk[corpus.spent_index])];
    let keys = [corpus.chunk[corpus.spent_index].pqc_key_scalar];
    let ok = shekyl_fcmp::proof::verify(
        &result.proof,
        &images,
        &result.pseudo_outs,
        &keys,
        &path.tree_root,
        path.tree_depth,
        [0xCD; 32],
    )
    .expect("verify");
    assert!(ok, "a sparse path is a real path: it must verify");
}

#[test]
fn a_proof_does_not_verify_against_a_different_root() {
    // The control on the two tests above: they would both pass against a
    // `verify` that ignored the root. This is what says they did not.
    let corpus = build_corpus(u64::try_from(SELENE_CHUNK_WIDTH).expect("width fits"), 0x33);
    let path = synth_sparse_path(&corpus, 3);
    let inputs = prove_inputs(&corpus, &path, 1);
    let result = prove_only(&inputs, &path, [0xEF; 32]).expect("prove");
    let images = [key_image(&corpus.chunk[corpus.spent_index])];
    let keys = [corpus.chunk[corpus.spent_index].pqc_key_scalar];
    let mut wrong_root = path.tree_root;
    wrong_root[0] ^= 0x01;
    let verdict = shekyl_fcmp::proof::verify(
        &result.proof,
        &images,
        &result.pseudo_outs,
        &keys,
        &wrong_root,
        path.tree_depth,
        [0xEF; 32],
    );
    assert!(
        !matches!(verdict, Ok(true)),
        "verify must not accept a proof against a root it was not built for"
    );
}

// ── Corpus shape ────────────────────────────────────────────────────────────

#[test]
fn the_corpus_holds_one_real_chunk_and_the_requested_leaf_count() {
    let corpus = build_corpus(1_000, 0x44);
    assert_eq!(corpus.chunk.len(), SELENE_CHUNK_WIDTH);
    assert_eq!(corpus.leaf_scalars.len(), 1_000 * SCALARS_PER_LEAF);
    // Repeating the real chunk's scalars is what keeps corpus construction from
    // consuming the measurement's budget; hash cost is identical for any valid
    // scalar, so the replay term is unaffected.
    assert_eq!(
        corpus.leaf_scalars[0],
        corpus.leaf_scalars[SELENE_CHUNK_WIDTH * SCALARS_PER_LEAF]
    );
}

#[test]
fn a_replayed_window_reaches_the_depth_the_ladder_predicts() {
    // Ties the replay proxy to the ladder: if the widths move, this fails here
    // rather than in a grading run.
    let leaves = min_leaves_for_depth(3).expect("depth 3 has a floor");
    let layers = replay(&build_corpus(leaves, 0x55));
    assert_eq!(layers.len(), 3);
}
