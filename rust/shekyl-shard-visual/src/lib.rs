//! Deterministic shard identity visuals for the GUI wallet preview path.
//!
//! Implements the **candidate.v1** two-stage difference compositor documented in
//! `docs/V3_SHARD_VISUALIZATION.md`. Production archival shards will use the same
//! recipe once `ArchivalEngine` (Stage 5) lands; until then the wallet exposes
//! fixture aggregates on the Staking tab.

// Pixel compositing and feature normalization use intentional float/int casts;
// values are aesthetic scalars, not consensus amounts.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_lossless
)]

mod aggregate;
mod candidate;
mod compositor;
mod entropy;
mod features;
mod palette;
mod params;
mod render;

pub use aggregate::{hex_bytes, ShardAggregate};
pub use candidate::{recipe_from_params, render_candidate, CandidateRecipe};
pub use features::{features_from_aggregate, Features};
pub use params::{parameters_from_aggregate, parameters_with_hash_override, RenderParameters};

pub mod fixtures;

use image::ImageEncoder;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VisualError {
    #[error("invalid shard hash: {0}")]
    InvalidHash(String),
    #[error("invalid render size {size}: must be in {min}..={max}")]
    InvalidSize { size: u32, min: u32, max: u32 },
    #[error("PNG encode failed: {0}")]
    PngEncode(String),
}

/// Minimum accepted edge length for candidate.v1 renders.
///
/// `size == 0` underflows in several algorithms (`size - 1`) and must be
/// rejected rather than clamped (fail closed on untrusted preview input).
pub const MIN_RENDER_SIZE: u32 = 1;

/// Maximum accepted edge length for candidate.v1 renders.
///
/// Caps allocation at `size²` RGB pixels (~48 MiB at 4096) so a hostile
/// wire `size` cannot ask the preview path for a multi-gigabyte buffer.
/// The GUI clamps further (64..=512); explorers may use larger thumbs.
pub const MAX_RENDER_SIZE: u32 = 4096;

/// Reject a render `size` outside [`MIN_RENDER_SIZE`]..=[`MAX_RENDER_SIZE`].
pub fn check_render_size(size: u32) -> Result<(), VisualError> {
    if !(MIN_RENDER_SIZE..=MAX_RENDER_SIZE).contains(&size) {
        return Err(VisualError::InvalidSize {
            size,
            min: MIN_RENDER_SIZE,
            max: MAX_RENDER_SIZE,
        });
    }
    Ok(())
}

/// Render candidate.v1 for an aggregate at `size`×`size` and return PNG bytes.
pub fn render_candidate_png(agg: &ShardAggregate, size: u32) -> Result<Vec<u8>, VisualError> {
    let params = parameters_from_aggregate(agg);
    let image = render_candidate(&params, size)?;
    encode_png(&image)
}

/// Render from a 32-byte hash and feature vector (tweak / hash-override path).
pub fn render_candidate_png_from_features(
    shard_hash: &[u8; 32],
    features: Features,
    size: u32,
) -> Result<Vec<u8>, VisualError> {
    let params = params::parameters_from_synthetic(*shard_hash, features);
    let image = render_candidate(&params, size)?;
    encode_png(&image)
}

fn encode_png(image: &image::RgbImage) -> Result<Vec<u8>, VisualError> {
    let mut buf = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new(&mut buf);
    encoder
        .write_image(
            image.as_raw(),
            image.width(),
            image.height(),
            image::ExtendedColorType::Rgb8,
        )
        .map_err(|e| VisualError::PngEncode(e.to_string()))?;
    Ok(buf)
}
