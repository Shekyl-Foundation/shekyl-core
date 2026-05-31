use image::{Rgb, RgbImage};
use imageproc::drawing::draw_filled_circle_mut;

use crate::params::RenderParameters;

const MIN_SEEDS: i32 = 220;
const MAX_SEEDS: i32 = 2_400;
const GOLDEN_DIVERGENCE: f64 = 137.507_764_084_4_f64.to_radians();

/// Per-algorithm SHAKE256 namespace (see `entropy.rs`). Each renderer draws
/// from its own independent stream so no two algorithms share hash words.
const NS: &str = "shard.v1.render.phyllotaxis";

pub fn render(params: &RenderParameters, size: u32) -> RgbImage {
    let f = params.features;
    let mut ent = params.entropy(NS);
    let n_seeds =
        (MIN_SEEDS as f64 + (MAX_SEEDS - MIN_SEEDS) as f64 * f.output_richness).round() as i32;

    let angle_perturbation = 0.06 * (ent.unit(0) - 0.5);
    let divergence = GOLDEN_DIVERGENCE + angle_perturbation;
    let c = (6.0 + 4.0 * ent.unit(1)).max(0.6);

    let bg_t = 0.05 + 0.10 * ent.unit(2);
    let bg_color = params.palette.sample(bg_t);
    let mut image = RgbImage::from_pixel(size, size, Rgb([bg_color.0, bg_color.1, bg_color.2]));

    let cx = size as f32 / 2.0;
    let cy = size as f32 / 2.0;

    let mut radii = Vec::with_capacity(n_seeds as usize);
    for i in 0..n_seeds {
        radii.push(c * (i as f64).sqrt());
    }
    let max_r = radii.last().copied().unwrap_or(1.0);
    let scale = (size as f64 * 0.45) / max_r.max(1e-6);
    let radii_pix: Vec<f64> = radii.iter().map(|r| r * scale).collect();

    let seed_radius_base = 1.5 + 4.5 * f.value_magnitude;
    let seed_radius_grow = 0.8 + 1.6 * f.tier_skew_high;

    let max_rp = radii_pix.last().copied().unwrap_or(1.0).max(1e-6);

    for (i, r_pix) in radii_pix.iter().enumerate() {
        let angle = i as f64 * divergence;
        let t_norm = i as f64 / (n_seeds - 1).max(1) as f64;
        let seed_r = (seed_radius_base + seed_radius_grow * t_norm).max(0.5) as i32;
        let color_t = *r_pix / max_rp;
        let color = params.palette.sample(color_t);
        let x = cx + (*r_pix * angle.cos()) as f32;
        let y = cy + (*r_pix * angle.sin()) as f32;
        draw_filled_circle_mut(
            &mut image,
            (x.round() as i32, y.round() as i32),
            seed_r,
            Rgb([color.0, color.1, color.2]),
        );
    }

    image
}
