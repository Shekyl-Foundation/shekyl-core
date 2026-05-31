mod aperiodic_tile;
mod crystalline;
mod phyllotaxis;
mod truchet;

use image::RgbImage;

use crate::params::RenderParameters;

pub fn render(params: &RenderParameters, algorithm: &str, size: u32) -> RgbImage {
    match algorithm {
        "aperiodic_tile" => aperiodic_tile::render(params, size),
        "truchet" => truchet::render(params, size),
        "crystalline" => crystalline::render(params, size),
        _ => phyllotaxis::render(params, size),
    }
}
