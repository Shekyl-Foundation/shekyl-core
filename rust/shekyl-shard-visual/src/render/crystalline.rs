use image::{Rgb, RgbImage};

use crate::params::RenderParameters;

const BASE_POINTS: usize = 6_000;
const TRANSIENT_ITERATIONS: usize = 200;

pub fn render(params: &RenderParameters, size: u32) -> RgbImage {
    let f = params.features;
    let omega = params.hash_unit(0);
    let k_base = 0.62 + 0.33 * params.hash_unit(1);
    let k_jitter = 0.20 * (f.value_dispersion - 0.5);
    let k = (k_base + k_jitter).clamp(0.0, 2.0);

    let plasma_freq = 6.0 + 8.0 * f.coinbase_ratio;
    let phase_shift = 2.0 * std::f64::consts::PI * params.hash_unit(2);

    let n_points = ((BASE_POINTS as f64) * (0.6 + 1.4 * f.activity_density)).round() as usize;

    let mut z_min = f64::INFINITY;
    let mut z_max = f64::NEG_INFINITY;
    let mut z_vals = vec![0.0; (size * size) as usize];

    for y in 0..size {
        for x in 0..size {
            let xf = x as f64 / size as f64;
            let yf = y as f64 / size as f64;
            let z = (2.0 * std::f64::consts::PI * (xf - 0.5) + phase_shift).sin()
                * yf.powf(1.8)
                + 0.3 * (plasma_freq * std::f64::consts::PI * xf + phase_shift).cos();
            z_min = z_min.min(z);
            z_max = z_max.max(z);
            z_vals[(y * size + x) as usize] = z;
        }
    }

    let span = (z_max - z_min).max(1e-9);
    let ts: Vec<f64> = z_vals.iter().map(|z| (z - z_min) / span).collect();
    let colors = params.palette.sample_array(&ts);

    let mut canvas: Vec<[u16; 3]> = colors
        .iter()
        .map(|c| [c.0 as u16, c.1 as u16, c.2 as u16])
        .collect();

    let seed = u64::from_le_bytes(params.shard_hash[..8].try_into().unwrap());
    let mut theta: Vec<f64> = (0..n_points)
        .map(|i| splitmix64(seed.wrapping_add(i as u64)) as f64 / u64::MAX as f64)
        .collect();

    for _ in 0..TRANSIENT_ITERATIONS {
        for t in &mut theta {
            *t = (*t + omega - (k / (2.0 * std::f64::consts::PI)) * (2.0 * std::f64::consts::PI * *t).sin())
                .rem_euclid(1.0);
        }
    }

    let ys = k / 2.0;
    for t in theta {
        let px = ((t * (size - 1) as f64).round() as u32).min(size - 1);
        let py = (((1.0 - ys) * (size - 1) as f64).round() as u32).min(size - 1);
        let idx = (py * size + px) as usize;
        for c in 0..3 {
            canvas[idx][c] = canvas[idx][c] / 4 + 255 * 3 / 4;
        }
    }

    let mut image = RgbImage::new(size, size);
    for y in 0..size {
        for x in 0..size {
            let idx = (y * size + x) as usize;
            image.put_pixel(
                x,
                y,
                Rgb([
                    canvas[idx][0].min(255) as u8,
                    canvas[idx][1].min(255) as u8,
                    canvas[idx][2].min(255) as u8,
                ]),
            );
        }
    }
    image
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
