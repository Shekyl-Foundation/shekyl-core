// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CT-1 mixed-composition `build_upper_layers` KAT (frozen `R_k` + partial tail).
//!
//! Exercises the composition **mechanism** at layer `j = 0` (small `E` for CI
//! runtime). Production uses `SEGMENT_LAYER_J = 2`; Tier-A `store_kat` covers
//! the real leaf stream at mainnet scale.

use ciphersuite::{
    group::ff::{Field, PrimeField},
    Ciphersuite,
};
use helioselene::Selene;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use shekyl_curve_tree::segment::outputs_per_node;
use shekyl_curve_tree::store::mixed_composition_root;
use shekyl_fcmp::tree::{build_layers, build_upper_layers, SCALARS_PER_LEAF};

const TEST_LAYER_J: u8 = 0;

fn rand_leaves(rng: &mut ChaCha20Rng, n: usize) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(n * SCALARS_PER_LEAF);
    for _ in 0..n * SCALARS_PER_LEAF {
        out.push(<Selene as Ciphersuite>::F::random(&mut *rng).to_repr());
    }
    out
}

fn scalars_to_leaf_bytes(scalars: &[[u8; 32]]) -> Vec<[u8; 128]> {
    scalars
        .chunks(SCALARS_PER_LEAF)
        .map(|c| {
            let mut leaf = [0u8; 128];
            for (i, s) in c.iter().enumerate() {
                leaf[i * 32..(i + 1) * 32].copy_from_slice(s);
            }
            leaf
        })
        .collect()
}

fn mixed_at_j(
    leaf_count: u64,
    frozen_r: &[[u8; 32]],
    tail_leaf_bytes: &[[u8; 128]],
    j: u8,
) -> [u8; 32] {
    let e = outputs_per_node(j) as u64;
    let complete = leaf_count / e;
    let delta = usize::try_from(leaf_count % e).expect("tail delta fits usize");
    let complete_usize = usize::try_from(complete).expect("complete count fits usize");
    let mut initial = frozen_r[..complete_usize].to_vec();
    if delta > 0 {
        let tail_scalars: Vec<[u8; 32]> = tail_leaf_bytes
            .iter()
            .flat_map(|leaf| {
                (0..SCALARS_PER_LEAF).map(move |i| {
                    let mut s = [0u8; 32];
                    s.copy_from_slice(&leaf[i * 32..(i + 1) * 32]);
                    s
                })
            })
            .collect();
        let tail_layers = build_layers(&tail_scalars);
        initial.extend_from_slice(&tail_layers[usize::from(j)]);
    }
    build_upper_layers(initial, j).last().unwrap()[0]
}

#[test]
fn mixed_composition_matches_oracle_baseline() {
    let e = outputs_per_node(TEST_LAYER_J);
    let j = TEST_LAYER_J;
    let mut rng = ChaCha20Rng::from_seed([11u8; 32]);

    let cases = [
        ("baseline_one_segment", e),
        ("mixed_hot_path", e + e / 3),
        ("one_complete_plus_tail", 2 * e + e / 2),
    ];

    for (name, n) in cases {
        let scalars = rand_leaves(&mut rng, n);
        let oracle_root = build_layers(&scalars).last().unwrap()[0];
        let leaves = scalars_to_leaf_bytes(&scalars);
        let complete = n / e;
        let frozen: Vec<[u8; 32]> = (0..complete)
            .map(|k| {
                let seg = &scalars[k * e * SCALARS_PER_LEAF..(k + 1) * e * SCALARS_PER_LEAF];
                build_layers(seg)[usize::from(j)][0]
            })
            .collect();
        let tail = &leaves[complete * e..];
        let got_j0 = mixed_at_j(n as u64, &frozen, tail, j);
        assert_eq!(got_j0, oracle_root, "{name} inline j={j}");
        // `mixed_composition_root` is pinned to `SEGMENT_LAYER_J`; when testing
        // at j=0, only the inline helper is meaningful. For j=2, see `store_kat`.
        if j == shekyl_curve_tree::SEGMENT_LAYER_J {
            let got_prod = mixed_composition_root(n as u64, &frozen, tail).unwrap();
            assert_eq!(got_prod, oracle_root, "{name} production j");
        }
    }
}
