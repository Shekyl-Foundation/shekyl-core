//! Deterministic shard identity visuals for the GUI wallet preview path.
//!
//! Implements the **candidate.v1** two-stage difference compositor documented in
//! `docs/V3_SHARD_VISUALIZATION.md`. Production archival shards will use the same
//! recipe once `ArchivalEngine` (Stage 5) lands; until then the wallet exposes
//! fixture aggregates on the Staking tab.

mod aggregate;
mod candidate;
mod compositor;
mod entropy;
mod features;
mod palette;
mod params;
mod render;

pub use aggregate::ShardAggregate;
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
    #[error("PNG encode failed: {0}")]
    PngEncode(String),
}

/// Render candidate.v1 for an aggregate at `size`×`size` and return PNG bytes.
pub fn render_candidate_png(agg: &ShardAggregate, size: u32) -> Result<Vec<u8>, VisualError> {
    let params = parameters_from_aggregate(agg);
    let image = render_candidate(&params, size);
    encode_png(&image)
}

/// Render from a 32-byte hash and feature vector (tweak / hash-override path).
pub fn render_candidate_png_from_features(
    shard_hash: &[u8; 32],
    features: Features,
    size: u32,
) -> Result<Vec<u8>, VisualError> {
    let params = params::parameters_from_synthetic(*shard_hash, features);
    let image = render_candidate(&params, size);
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
