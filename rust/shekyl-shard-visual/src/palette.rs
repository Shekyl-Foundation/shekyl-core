pub type Rgb = (u8, u8, u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Palette {
    pub name: &'static str,
    colors: &'static [Rgb],
}

impl Palette {
    pub fn sample(&self, t: f64) -> Rgb {
        if self.colors.is_empty() {
            return (0, 0, 0);
        }
        if self.colors.len() == 1 {
            return self.colors[0];
        }
        let t = t.clamp(0.0, 1.0);
        let scaled = t * (self.colors.len() - 1) as f64;
        let lo = scaled.floor() as usize;
        let hi = (lo + 1).min(self.colors.len() - 1);
        let frac = scaled - lo as f64;
        let c0 = self.colors[lo];
        let c1 = self.colors[hi];
        (
            ((c0.0 as f64) * (1.0 - frac) + (c1.0 as f64) * frac).round() as u8,
            ((c0.1 as f64) * (1.0 - frac) + (c1.1 as f64) * frac).round() as u8,
            ((c0.2 as f64) * (1.0 - frac) + (c1.2 as f64) * frac).round() as u8,
        )
    }

    pub fn sample_array(&self, ts: &[f64]) -> Vec<Rgb> {
        ts.iter().map(|&t| self.sample(t)).collect()
    }
}

pub const JEWEL: Palette = Palette {
    name: "jewel",
    colors: &[
        (24, 12, 56),
        (84, 24, 132),
        (190, 38, 122),
        (236, 132, 60),
        (252, 220, 96),
    ],
};

pub const PASTEL: Palette = Palette {
    name: "pastel",
    colors: &[
        (244, 232, 240),
        (210, 222, 240),
        (180, 222, 198),
        (240, 222, 168),
        (240, 192, 192),
    ],
};

pub const MONOCHROME: Palette = Palette {
    name: "monochrome",
    colors: &[
        (12, 14, 18),
        (60, 70, 90),
        (130, 144, 168),
        (200, 210, 226),
        (244, 248, 252),
    ],
};

pub const NEON: Palette = Palette {
    name: "neon",
    colors: &[
        (8, 8, 24),
        (48, 0, 168),
        (224, 16, 200),
        (32, 232, 200),
        (248, 248, 64),
    ],
};

pub const EARTH: Palette = Palette {
    name: "earth",
    colors: &[
        (40, 28, 20),
        (104, 64, 36),
        (168, 120, 64),
        (188, 168, 96),
        (104, 132, 84),
        (52, 80, 60),
    ],
};

pub const PRISMATIC: Palette = Palette {
    name: "prismatic",
    colors: &[
        (252, 64, 64),
        (252, 168, 48),
        (252, 232, 64),
        (96, 220, 96),
        (64, 168, 240),
        (132, 80, 240),
    ],
};

pub const PALETTES: &[Palette] = &[JEWEL, PASTEL, MONOCHROME, NEON, EARTH, PRISMATIC];

pub fn palette_by_name(name: &str) -> Palette {
    PALETTES
        .iter()
        .copied()
        .find(|p| p.name == name)
        .unwrap_or(JEWEL)
}

pub fn palette_by_index(idx: u32) -> Palette {
    PALETTES[(idx as usize) % PALETTES.len()]
}
