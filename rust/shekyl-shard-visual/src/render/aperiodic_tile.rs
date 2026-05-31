use std::f64::consts::PI;

use image::{Rgb, RgbImage};
use imageproc::drawing::draw_polygon_mut;
use imageproc::point::Point;

use crate::params::RenderParameters;

const PHI: f64 = 1.618_033_988_749_895;
const BASE_DEPTH: i32 = 4;
const MAX_DEPTH: i32 = 6;

#[derive(Clone, Copy)]
struct Triangle {
    kind: u8,
    a: (f64, f64),
    b: (f64, f64),
    c: (f64, f64),
}

pub fn render(params: &RenderParameters, size: u32) -> RgbImage {
    let f = params.features;
    let depth = (BASE_DEPTH + (f.output_richness * (MAX_DEPTH - BASE_DEPTH) as f64).round() as i32)
        .clamp(BASE_DEPTH, MAX_DEPTH);

    let mut triangles = Vec::new();
    let n_rosette = 10;
    for i in 0..n_rosette {
        let angle1 = 2.0 * PI * (i as f64 - 0.5) / n_rosette as f64;
        let angle2 = 2.0 * PI * (i as f64 + 0.5) / n_rosette as f64;
        let (mut v1x, mut v1y) = (angle1.cos(), angle1.sin());
        let (mut v2x, mut v2y) = (angle2.cos(), angle2.sin());
        if i % 2 == 0 {
            std::mem::swap(&mut v1x, &mut v2x);
            std::mem::swap(&mut v1y, &mut v2y);
        }
        triangles.push(Triangle {
            kind: 0,
            a: (0.0, 0.0),
            b: (v1x, v1y),
            c: (v2x, v2y),
        });
    }

    for _ in 0..depth {
        triangles = deflate(&triangles);
    }

    let (x_lo, x_hi, y_lo, y_hi) = bounds(&triangles);
    let margin = 0.04;
    let scale = (size as f64 * (1.0 - 2.0 * margin)) / (x_hi - x_lo).max(y_hi - y_lo).max(1e-9);
    let cx_off = (size as f64 - (x_hi - x_lo) * scale) / 2.0 - x_lo * scale;
    let cy_off = (size as f64 - (y_hi - y_lo) * scale) / 2.0 - y_lo * scale;

    let spread = 0.4 + 0.5 * f.value_dispersion;
    let margin_t = (1.0 - spread) / 2.0;
    let sharp_t = margin_t;
    let robust_t = margin_t + spread;
    let sharp_color = params.palette.sample(sharp_t);
    let robust_color = params.palette.sample(robust_t);
    let edge_strength = 0.3 + 0.7 * f.tier_skew_high;
    let _edge_color = params.palette.sample(if (sharp_t + robust_t) / 2.0 < 0.5 {
        0.95
    } else {
        0.05
    });
    let _edge_width = (edge_strength * 1.5).round() as i32;

    let bg = params.palette.sample(0.04);
    let mut image = RgbImage::from_pixel(size, size, Rgb([bg.0, bg.1, bg.2]));

    for tri in triangles {
        let fill = if tri.kind == 0 {
            robust_color
        } else {
            sharp_color
        };
        let poly = [
            (
                (tri.a.0 * scale + cx_off).round() as i32,
                (tri.a.1 * scale + cy_off).round() as i32,
            ),
            (
                (tri.b.0 * scale + cx_off).round() as i32,
                (tri.b.1 * scale + cy_off).round() as i32,
            ),
            (
                (tri.c.0 * scale + cx_off).round() as i32,
                (tri.c.1 * scale + cy_off).round() as i32,
            ),
        ];
        if poly[0] == poly[1] || poly[1] == poly[2] || poly[0] == poly[2] {
            continue;
        }
        let points = vec![
            Point::new(poly[0].0, poly[0].1),
            Point::new(poly[1].0, poly[1].1),
            Point::new(poly[2].0, poly[2].1),
        ];
        draw_polygon_mut(&mut image, &points, Rgb([fill.0, fill.1, fill.2]));
    }

    image
}

fn bounds(tris: &[Triangle]) -> (f64, f64, f64, f64) {
    let mut x_lo = f64::INFINITY;
    let mut x_hi = f64::NEG_INFINITY;
    let mut y_lo = f64::INFINITY;
    let mut y_hi = f64::NEG_INFINITY;
    for t in tris {
        for (x, y) in [t.a, t.b, t.c] {
            x_lo = x_lo.min(x);
            x_hi = x_hi.max(x);
            y_lo = y_lo.min(y);
            y_hi = y_hi.max(y);
        }
    }
    (x_lo, x_hi, y_lo, y_hi)
}

fn deflate(tris: &[Triangle]) -> Vec<Triangle> {
    let inv_phi = 1.0 / PHI;
    let mut out = Vec::with_capacity(tris.len() * 2);
    for tri in tris {
        let (ax, ay) = tri.a;
        let (bx, by) = tri.b;
        let (cx, cy) = tri.c;
        if tri.kind == 0 {
            let px = ax + (bx - ax) * inv_phi;
            let py = ay + (by - ay) * inv_phi;
            let qx = ax + (cx - ax) * inv_phi;
            let qy = ay + (cy - ay) * inv_phi;
            out.push(Triangle {
                kind: 0,
                a: (cx, cy),
                b: (px, py),
                c: (bx, by),
            });
            out.push(Triangle {
                kind: 0,
                a: (qx, qy),
                b: (px, py),
                c: (ax, ay),
            });
            out.push(Triangle {
                kind: 1,
                a: (qx, qy),
                b: (px, py),
                c: (cx, cy),
            });
        } else {
            let rx = bx + (ax - bx) * inv_phi;
            let ry = by + (ay - by) * inv_phi;
            out.push(Triangle {
                kind: 1,
                a: (bx, by),
                b: (cx, cy),
                c: (rx, ry),
            });
            out.push(Triangle {
                kind: 0,
                a: (rx, ry),
                b: (cx, cy),
                c: (ax, ay),
            });
        }
    }
    out
}
