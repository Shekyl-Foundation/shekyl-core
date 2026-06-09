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
    let j = usize::from(SEGMENT_LAYER_J);

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
        let tail_scalars = leaf_bytes_to_scalars(tail_leaf_bytes);
        let tail_layers = build_layers(&tail_scalars);
        if tail_layers.len() <= j {
            return Err(MixedRootError::TailTooShortForLayerJ);
        }
        initial_layer.extend_from_slice(&tail_layers[j]);
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

/// Recompute `R_k` for segment `segment_id` from contiguous leaf bytes.
#[must_use]
pub fn recompute_segment_r_k(segment_leaf_bytes: &[[u8; 128]]) -> [u8; 32] {
    let scalars = leaf_bytes_to_scalars(segment_leaf_bytes);
    extract_r_k(&scalars)
}
