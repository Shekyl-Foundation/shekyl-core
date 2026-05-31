use std::f64::consts::PI;

use image::RgbImage;
use serde::Serialize;

use crate::compositor::{composite, BlendMode};
use crate::entropy::EntropyStream;
use crate::palette::{palette_by_index, Palette};
use crate::params::RenderParameters;
use crate::render::{self, Algorithm};

const FG_TILE: Algorithm = Algorithm::AperiodicTile;
const FG_PHYLLOTAXIS: Algorithm = Algorithm::Phyllotaxis;
const BG_TRUCHET: Algorithm = Algorithm::Truchet;
const BG_CRYSTALLINE: Algorithm = Algorithm::Crystalline;
const CANDIDATE_BLEND: BlendMode = BlendMode::Difference;

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct CandidateRecipe {
    pub fg_tile: String,
    pub fg_phyllotaxis: String,
    pub fg_opacity: f64,
    pub fg_tile_palette: String,
    pub fg_phyllotaxis_palette: String,
    pub bg_truchet: String,
    pub bg_crystalline: String,
    pub bg_opacity: f64,
    pub bg_truchet_palette: String,
    pub bg_crystalline_palette: String,
    pub final_mode: String,
    pub final_opacity: f64,
}

fn palette_from_entropy(ent: &mut EntropyStream, idx: u32) -> Palette {
    palette_by_index(ent.uint32(idx) % 6)
}

fn gaussian_opacity(
    ent: &mut EntropyStream,
    u_idx: u32,
    v_idx: u32,
    mean: f64,
    sigma: f64,
    lo: f64,
    hi: f64,
) -> f64 {
    let u1 = ent.unit(u_idx).max(1e-9);
    let u2 = ent.unit(v_idx);
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * PI * u2).cos();
    let value = mean + sigma * z;
    let clipped = value.clamp(lo, hi);
    (clipped * 100.0).round() / 100.0
}

fn bell_opacity(ent: &mut EntropyStream, u_idx: u32, v_idx: u32) -> f64 {
    gaussian_opacity(ent, u_idx, v_idx, 0.5, 0.22, 0.25, 0.75)
}

fn final_opacity(ent: &mut EntropyStream, u_idx: u32, v_idx: u32) -> f64 {
    gaussian_opacity(ent, u_idx, v_idx, 0.80, 0.11, 0.58, 0.96)
}

fn opacity_from_params(
    params: &RenderParameters,
    namespace: &str,
    override_key: &str,
    u_idx: u32,
    v_idx: u32,
    sampler: fn(&mut EntropyStream, u32, u32) -> f64,
) -> f64 {
    if let Some(raw) = params.override_value(override_key) {
        if let Ok(v) = raw.parse::<f64>() {
            return (v.clamp(0.0, 1.0) * 100.0).round() / 100.0;
        }
    }
    let mut ent = params.entropy(namespace);
    sampler(&mut ent, u_idx, v_idx)
}

pub fn recipe_from_params(params: &RenderParameters) -> CandidateRecipe {
    let mut fg_ent = params.entropy("candidate.v1.fg");
    let mut bg_ent = params.entropy("candidate.v1.bg");

    let fg_tile_palette = palette_from_entropy(&mut fg_ent, 0);
    let fg_phyllotaxis_palette = palette_from_entropy(&mut fg_ent, 1);
    let bg_truchet_palette = palette_from_entropy(&mut bg_ent, 0);
    let bg_crystalline_palette = palette_from_entropy(&mut bg_ent, 1);

    let final_opacity = opacity_from_params(
        params,
        "candidate.v1.final.opacity",
        "candidate_final_opacity",
        0,
        1,
        final_opacity,
    );

    CandidateRecipe {
        fg_tile: FG_TILE.as_str().into(),
        fg_phyllotaxis: FG_PHYLLOTAXIS.as_str().into(),
        fg_opacity: opacity_from_params(
            params,
            "candidate.v1.fg.opacity",
            "candidate_fg_opacity",
            2,
            3,
            bell_opacity,
        ),
        fg_tile_palette: fg_tile_palette.name.into(),
        fg_phyllotaxis_palette: fg_phyllotaxis_palette.name.into(),
        bg_truchet: BG_TRUCHET.as_str().into(),
        bg_crystalline: BG_CRYSTALLINE.as_str().into(),
        bg_opacity: opacity_from_params(
            params,
            "candidate.v1.bg.opacity",
            "candidate_bg_opacity",
            2,
            3,
            bell_opacity,
        ),
        bg_truchet_palette: bg_truchet_palette.name.into(),
        bg_crystalline_palette: bg_crystalline_palette.name.into(),
        final_mode: "difference".into(),
        final_opacity,
    }
}

fn render_algorithm(
    params: &RenderParameters,
    algorithm: Algorithm,
    palette: Palette,
    size: u32,
) -> RgbImage {
    let layer = params.with_palette(palette);
    let image = render::render(&layer, algorithm, size);
    if image.width() != size || image.height() != size {
        return image::imageops::resize(&image, size, size, image::imageops::FilterType::Lanczos3);
    }
    image
}

fn render_foreground_composite(
    params: &RenderParameters,
    size: u32,
    recipe: &CandidateRecipe,
) -> RgbImage {
    let tile = render_algorithm(
        params,
        FG_TILE,
        crate::palette::palette_by_name(&recipe.fg_tile_palette),
        size,
    );
    let phyllotaxis = render_algorithm(
        params,
        FG_PHYLLOTAXIS,
        crate::palette::palette_by_name(&recipe.fg_phyllotaxis_palette),
        size,
    );
    composite(&tile, &phyllotaxis, CANDIDATE_BLEND, recipe.fg_opacity)
}

fn render_background_composite(
    params: &RenderParameters,
    size: u32,
    recipe: &CandidateRecipe,
) -> RgbImage {
    let truchet = render_algorithm(
        params,
        BG_TRUCHET,
        crate::palette::palette_by_name(&recipe.bg_truchet_palette),
        size,
    );
    let crystalline = render_algorithm(
        params,
        BG_CRYSTALLINE,
        crate::palette::palette_by_name(&recipe.bg_crystalline_palette),
        size,
    );
    composite(&truchet, &crystalline, CANDIDATE_BLEND, recipe.bg_opacity)
}

pub fn render_candidate(params: &RenderParameters, size: u32) -> RgbImage {
    let recipe = recipe_from_params(params);
    let bg = render_background_composite(params, size, &recipe);
    let fg = render_foreground_composite(params, size, &recipe);
    composite(&bg, &fg, CANDIDATE_BLEND, recipe.final_opacity)
}
