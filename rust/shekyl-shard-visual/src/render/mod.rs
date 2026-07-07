mod aperiodic_tile;
mod crystalline;
mod phyllotaxis;
mod truchet;

use image::RgbImage;

use crate::params::RenderParameters;

/// The closed set of `candidate.v1` layer renderers.
///
/// Dispatch is over this enum rather than a string so the match below is
/// exhaustive: an unknown renderer is a compile error, not a runtime panic.
/// Adding a fifth renderer forces every `match` to be updated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    AperiodicTile,
    Phyllotaxis,
    Truchet,
    Crystalline,
}

impl Algorithm {
    /// Stable wire name used in the serialized `CandidateRecipe` and tests.
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::AperiodicTile => "aperiodic_tile",
            Algorithm::Phyllotaxis => "phyllotaxis",
            Algorithm::Truchet => "truchet",
            Algorithm::Crystalline => "crystalline",
        }
    }
}

pub fn render(params: &RenderParameters, algorithm: Algorithm, size: u32) -> RgbImage {
    match algorithm {
        Algorithm::AperiodicTile => aperiodic_tile::render(params, size),
        Algorithm::Phyllotaxis => phyllotaxis::render(params, size),
        Algorithm::Truchet => truchet::render(params, size),
        Algorithm::Crystalline => crystalline::render(params, size),
    }
}
