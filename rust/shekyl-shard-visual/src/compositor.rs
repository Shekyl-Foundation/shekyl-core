use image::{Rgb, RgbImage};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlendMode {
    Difference,
}

fn blend_channel(bg: f64, fg: f64, mode: BlendMode) -> f64 {
    match mode {
        BlendMode::Difference => (bg - fg).abs(),
    }
}

/// Composite `fg` over `bg` with the given mode and opacity.
pub fn composite(bg: &RgbImage, fg: &RgbImage, mode: BlendMode, opacity: f64) -> RgbImage {
    let opacity = opacity.clamp(0.0, 1.0);
    let (w, h) = bg.dimensions();
    let mut out = RgbImage::new(w, h);

    for y in 0..h {
        for x in 0..w {
            let bg_px = bg.get_pixel(x, y);
            let fg_px = fg.get_pixel(x, y);
            let mut rgb = [0u8; 3];
            for i in 0..3 {
                let b = bg_px[i] as f64 / 255.0;
                let f = fg_px[i] as f64 / 255.0;
                let blended = blend_channel(b, f, mode);
                let v = b * (1.0 - opacity) + blended * opacity;
                rgb[i] = (v.clamp(0.0, 1.0) * 255.0).round() as u8;
            }
            out.put_pixel(x, y, Rgb(rgb));
        }
    }
    out
}
