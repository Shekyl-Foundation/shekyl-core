// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Hot-path root composition: frozen `R_k` + partial tail + `build_upper_layers`.

use crate::segment::{extract_r_k, leaf_bytes_to_scalars, leaves_per_segment, SEGMENT_LAYER_J};
use shekyl_fcmp::tree::{build_layers, build_upper_layers, selene_hash_init};

/// Errors from the mixed-composition root path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MixedRootError {
    /// Layer stack from `build_upper_layers` was empty.
    EmptyUpperLayers,
    /// `frozen_r` is shorter than the number of complete segments required.
    InsufficientFrozenRoots,
    /// Partial tail has not yet built tree layer `SEGMENT_LAYER_J`.
    TailTooShortForLayerJ,
    /// `tail_leaf_bytes` length does not match `leaf_count` modulo segment size.
    TailLengthMismatch {
        /// Expected tail leaf count from `leaf_count`.
        expected: usize,
        /// Actual `tail_leaf_bytes` length supplied by the caller.
        got: usize,
    },
}

/// Root at `leaf_count` drained leaves via frozen `R_k` + tail composition.
///
/// `frozen_r` must contain `R_k` for every **complete** segment strictly before
/// the partial tail (segment ids `0..complete_segments`). When the tail is
/// empty (`leaf_count` is an exact multiple of `E`), all `leaf_count / E`
/// segment roots must be present.
pub fn mixed_composition_root(
    leaf_count: u64,
    frozen_r: &[[u8; 32]],
    tail_leaf_bytes: &[[u8; 128]],
) -> Result<[u8; 32], MixedRootError> {
    if leaf_count == 0 {
        return Ok(selene_hash_init());
    }

    let e = leaves_per_segment() as u64;
    let complete = leaf_count / e;
    let delta = usize::try_from(leaf_count % e).expect("segment tail fits usize");
    let expected_tail = if complete == 0 {
        usize::try_from(leaf_count).expect("leaf count fits usize")
    } else {
        delta
    };
    if tail_leaf_bytes.len() != expected_tail {
        return Err(MixedRootError::TailLengthMismatch {
            expected: expected_tail,
            got: tail_leaf_bytes.len(),
        });
    }
    // No complete segments yet — mixed composition does not apply.
    if complete == 0 {
        let scalars = leaf_bytes_to_scalars(tail_leaf_bytes);
        let layers = build_layers(&scalars);
        return layers
            .last()
            .map(|layer| layer[0])
            .ok_or(MixedRootError::EmptyUpperLayers);
    }

    let frozen_needed = usize::try_from(complete).expect("complete segment count fits usize");
    if frozen_r.len() < frozen_needed {
        return Err(MixedRootError::InsufficientFrozenRoots);
    }

    let mut initial_layer: Vec<[u8; 32]> = frozen_r[..frozen_needed].to_vec();

    if delta > 0 {
        initial_layer.extend_from_slice(&tail_layer_j_nodes(tail_leaf_bytes, SEGMENT_LAYER_J)?);
    }

    let upper = build_upper_layers(initial_layer, SEGMENT_LAYER_J);
    let root_layer = upper.last().ok_or(MixedRootError::EmptyUpperLayers)?;
    Ok(root_layer[0])
}

/// Full root from contiguous drained leaf bytes (recon oracle path).
#[must_use]
pub fn full_build_root(leaf_bytes: &[[u8; 128]]) -> [u8; 32] {
    if leaf_bytes.is_empty() {
        return selene_hash_init();
    }
    let scalars = leaf_bytes_to_scalars(leaf_bytes);
    build_layers(&scalars)
        .last()
        .map(|layer| layer[0])
        .unwrap_or(selene_hash_init())
}

/// Layer-`j` nodes contributed by a partial tail segment.
///
/// When the tail is too shallow for `build_layers` to reach absolute layer `j`
/// directly, promote from the tail's deepest built layer via `build_upper_layers`
/// so mixed composition can still combine frozen `R_k` with the tail's node at
/// the correct absolute depth (not treat the tail as an independent rooted tree
/// that must already be `j` layers deep).
fn tail_layer_j_nodes(
    tail_leaf_bytes: &[[u8; 128]],
    j: u8,
) -> Result<Vec<[u8; 32]>, MixedRootError> {
    let scalars = leaf_bytes_to_scalars(tail_leaf_bytes);
    if scalars.is_empty() {
        return Ok(Vec::new());
    }
    let layers = build_layers(&scalars);
    let j_idx = usize::from(j);
    if layers.len() > j_idx {
        return Ok(layers[j_idx].clone());
    }
    let deepest = layers.len().saturating_sub(1);
    if layers[deepest].is_empty() {
        return Err(MixedRootError::EmptyUpperLayers);
    }
    let upper = build_upper_layers(
        layers[deepest].clone(),
        u8::try_from(deepest).expect("tail tree depth fits u8"),
    );
    let offset = j_idx
        .checked_sub(deepest)
        .ok_or(MixedRootError::TailTooShortForLayerJ)?;
    upper
        .get(offset)
        .cloned()
        .ok_or(MixedRootError::TailTooShortForLayerJ)
}

/// Recompute `R_k` for segment `segment_id` from contiguous leaf bytes.
#[must_use]
pub fn recompute_segment_r_k(segment_leaf_bytes: &[[u8; 128]]) -> [u8; 32] {
    let scalars = leaf_bytes_to_scalars(segment_leaf_bytes);
    extract_r_k(&scalars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::outputs_per_node;
    use ciphersuite::{
        group::ff::{Field, PrimeField},
        Ciphersuite,
    };
    use helioselene::Selene;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use shekyl_fcmp::tree::SCALARS_PER_LEAF;

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

    #[test]
    fn mixed_composition_rejects_tail_length_mismatch() {
        let err = mixed_composition_root(5, &[], &[[0u8; 128]; 3]).unwrap_err();
        assert!(matches!(
            err,
            MixedRootError::TailLengthMismatch {
                expected: 5,
                got: 3
            }
        ));
    }

    #[test]
    fn tail_layer_j_promotion_matches_oracle_at_j0() {
        let j = 0u8;
        let e = outputs_per_node(j);
        let mut rng = ChaCha20Rng::from_seed([22u8; 32]);
        for delta in [1usize, e / 3, e - 1] {
            let seg0 = rand_leaves(&mut rng, e);
            let tail = rand_leaves(&mut rng, delta);
            let mut all = seg0.clone();
            all.extend_from_slice(&tail);
            let oracle = build_layers(&all);
            let frozen = vec![build_layers(&seg0)[usize::from(j)][0]];
            let tail_bytes = scalars_to_leaf_bytes(&tail);
            let promoted = tail_layer_j_nodes(&tail_bytes, j).expect("tail layer j");
            let mut initial = frozen;
            initial.extend_from_slice(&promoted);
            let got = build_upper_layers(initial, j).last().unwrap()[0];
            assert_eq!(got, oracle.last().unwrap()[0], "delta={delta} mixed root");
        }
    }
}
