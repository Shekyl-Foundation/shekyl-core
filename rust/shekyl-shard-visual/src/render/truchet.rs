use image::{Rgb, RgbImage};
use sha2::{Digest, Sha256};

use crate::params::RenderParameters;

const BASE_GRID: i32 = 8;

/// Per-algorithm SHAKE256 namespace (see `entropy.rs`). The per-cell `Sha256`
/// draws below are already domain-separated by the `"truchet"` tag and the
/// cell indices, so they stay; only the top-level foreground tone moves onto
/// this dedicated stream.
const NS: &str = "shard.v1.render.truchet";

pub fn render(params: &RenderParameters, size: u32) -> RgbImage {
    let f = params.features;
    let mut ent = params.entropy(NS);
    let max_depth = (1 + (2.0 * f.output_richness).round() as i32).clamp(1, 3);

    let bg_t = 0.04 + 0.18 * f.coinbase_ratio;
    let bg = params.palette.sample(bg_t);
    let fg_t = 0.65 + 0.30 * ent.unit(0);
    let fg = params.palette.sample(fg_t);

    let mut image = RgbImage::from_pixel(size, size, Rgb([bg.0, bg.1, bg.2]));
    let cells_per_side = BASE_GRID;
    let cell_size = size as f64 / cells_per_side as f64;
    let line_width_base =
        ((cell_size / 6.0 * (0.6 + 1.4 * f.tier_skew_high)).round() as i32).max(2);

    #[allow(clippy::too_many_arguments)]
    fn draw_cell(
        image: &mut RgbImage,
        params: &RenderParameters,
        x0: f64,
        y0: f64,
        w: f64,
        depth: i32,
        max_depth: i32,
        cell_size: f64,
        line_width_base: i32,
        fg: Rgb<u8>,
    ) {
        let cx_idx = (x0 / cell_size * (1 << depth) as f64) as u32;
        let cy_idx = (y0 / cell_size * (1 << depth) as f64) as u32;
        let mut h = Sha256::new();
        h.update(params.shard_hash);
        h.update(b"truchet");
        h.update(cx_idx.to_le_bytes());
        h.update(cy_idx.to_le_bytes());
        h.update([depth as u8]);
        let digest = h.finalize();
        let orientation = digest[0] & 1;
        let subdivide = depth < max_depth && (digest[1] & 1) == 1;

        if subdivide {
            let half = w / 2.0;
            for dx in 0..2 {
                for dy in 0..2 {
                    draw_cell(
                        image,
                        params,
                        x0 + dx as f64 * half,
                        y0 + dy as f64 * half,
                        half,
                        depth + 1,
                        max_depth,
                        cell_size,
                        line_width_base,
                        fg,
                    );
                }
            }
            return;
        }

        let line_w = ((line_width_base as f64 * 0.55_f64.powi(depth - 1)).round() as i32).max(1);
        let radius = w / 2.0;
        if orientation == 0 {
            draw_arc(image, x0, y0, radius, 0.0, 90.0, fg, line_w);
            draw_arc(
                image,
                x0 + w - radius,
                y0 + w - radius,
                radius,
                180.0,
                270.0,
                fg,
                line_w,
            );
        } else {
            draw_arc(
                image,
                x0 + w - radius,
                y0 - radius,
                radius,
                90.0,
                180.0,
                fg,
                line_w,
            );
            draw_arc(
                image,
                x0 - radius,
                y0 + w - radius,
                radius,
                270.0,
                360.0,
                fg,
                line_w,
            );
        }
    }

    for ix in 0..cells_per_side {
        for iy in 0..cells_per_side {
            draw_cell(
                &mut image,
                params,
                ix as f64 * cell_size,
                iy as f64 * cell_size,
                cell_size,
                1,
                max_depth,
                cell_size,
                line_width_base,
                Rgb([fg.0, fg.1, fg.2]),
            );
        }
    }

    image
}

#[allow(clippy::too_many_arguments)]
fn draw_arc(
    image: &mut RgbImage,
    cx: f64,
    cy: f64,
    radius: f64,
    start_deg: f64,
    end_deg: f64,
    color: Rgb<u8>,
    width: i32,
) {
    let steps = ((end_deg - start_deg).abs() * radius / 2.0).max(8.0) as i32;
    for s in 0..=steps {
        let t = s as f64 / steps as f64;
        let deg = start_deg + (end_deg - start_deg) * t;
        let rad = deg.to_radians();
        let x = (cx + radius * rad.cos()).round() as i32;
        let y = (cy + radius * rad.sin()).round() as i32;
        for dx in -width..=width {
            for dy in -width..=width {
                if dx * dx + dy * dy <= width * width {
                    let px = x + dx;
                    let py = y + dy;
                    if px >= 0
                        && py >= 0
                        && (px as u32) < image.width()
                        && (py as u32) < image.height()
                    {
                        image.put_pixel(px as u32, py as u32, color);
                    }
                }
            }
        }
    }
}
