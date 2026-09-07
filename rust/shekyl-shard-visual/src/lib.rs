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
pub use candidate::{recipe_from_params, CandidateRecipe};
// `render_candidate` (the raw `RgbImage` renderer) is deliberately NOT
// re-exported: a bare image can be encoded without its provenance chunks,
// bypassing the every-export-is-marked enforcement (review #617). All
// public rendering goes through the PNG entry points below.
use candidate::render_candidate;
pub use features::{features_from_aggregate, Features};
pub use params::{parameters_from_aggregate, parameters_with_hash_override, RenderParameters};

pub mod fixtures;

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

/// Pixel-derivation revision of this crate. Bump on ANY change that can
/// alter rendered bytes for the same parameters (a renderer draw, a
/// palette value, the compositor); consumers must include it in any
/// cache key for rendered images, or a cached PNG can pair with a recipe
/// the current code would not produce (review #617). Revision 1 was the
/// pre-ruling-A derivation. Once a spec version freezes, a revision bump
/// within it is a defect — pixel changes then require a new spec version.
pub const RENDER_REVISION: u32 = 2;

/// PNG `tEXt` keyword carrying [`CandidateRecipe::spec_version`].
pub const PNG_KEY_SPEC_VERSION: &str = "shekyl.spec_version";
/// PNG `tEXt` keyword carrying [`CandidateRecipe::canonical`].
pub const PNG_KEY_CANONICAL: &str = "shekyl.canonical";

/// Render candidate.v1 from a parameter bundle and return PNG bytes.
///
/// This is the one render entry point: the same `params` that produce
/// the pixels also stamp the PNG's provenance `tEXt` chunks
/// ([`PNG_KEY_SPEC_VERSION`], [`PNG_KEY_CANONICAL`]) and feed
/// [`recipe_from_params`], so bytes, chunks, and recipe cannot disagree.
/// The saved file stays self-describing even without its recipe
/// (ruling A: exports are visibly non-canonical).
pub fn render_candidate_png_from_params(
    params: &RenderParameters,
    size: u32,
) -> Result<Vec<u8>, VisualError> {
    let recipe = recipe_from_params(params);
    let image = render_candidate(params, size)?;
    encode_png(&image, &recipe)
}

/// Render candidate.v1 for an aggregate at `size`×`size` and return PNG bytes.
pub fn render_candidate_png(agg: &ShardAggregate, size: u32) -> Result<Vec<u8>, VisualError> {
    render_candidate_png_from_params(&parameters_from_aggregate(agg), size)
}

/// Render from a 32-byte hash and feature vector (tweak / synthetic path).
/// The output is non-canonical and its PNG chunks say so.
pub fn render_candidate_png_from_features(
    shard_hash: &[u8; 32],
    features: Features,
    size: u32,
) -> Result<Vec<u8>, VisualError> {
    let params = params::parameters_from_synthetic(*shard_hash, features);
    render_candidate_png_from_params(&params, size)
}

fn encode_png(image: &image::RgbImage, recipe: &CandidateRecipe) -> Result<Vec<u8>, VisualError> {
    let mut buf = Vec::new();
    let mut encoder = png::Encoder::new(&mut buf, image.width(), image.height());
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .add_text_chunk(PNG_KEY_SPEC_VERSION.into(), recipe.spec_version.clone())
        .map_err(|e| VisualError::PngEncode(e.to_string()))?;

    encoder
        .add_text_chunk(PNG_KEY_CANONICAL.into(), recipe.canonical.to_string())
        .map_err(|e| VisualError::PngEncode(e.to_string()))?;
    let mut writer = encoder
        .write_header()
        .map_err(|e| VisualError::PngEncode(e.to_string()))?;
    writer
        .write_image_data(image.as_raw())
        .map_err(|e| VisualError::PngEncode(e.to_string()))?;
    drop(writer);
    Ok(buf)
}
