//! Banded piecewise-linear `Curve(work)` (float) — matches `reward_arithmetic` shape.

/// Provisional banded plateau-cap: slopes `[1.0, 0.5, 0.25, 0]` on work bands
/// `[0, cap/2, cap, 2·cap]` with plateau credited value `cap`.
#[must_use]
pub fn curve_banded(work: f64, plateau_value: f64) -> f64 {
    if work <= 0.0 || plateau_value <= 0.0 {
        return 0.0;
    }
    let plateau_work = plateau_value * 2.0;
    let b1 = plateau_work / 4.0;
    let b2 = plateau_work / 2.0;
    let b3 = plateau_work;

    if work >= b3 {
        return plateau_value;
    }

    let mut y = 0.0;

    let mut x = if work > b1 {
        y += b1;
        b1
    } else {
        return work;
    };

    if work > b2 {
        y += (b2 - x) * 0.5;
        x = b2;
    } else {
        return y + (work - x) * 0.5;
    }

    y + (work - x) * 0.25
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reaches_plateau_at_twice_cap_work() {
        assert!((curve_banded(16.0, 8.0) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn monotone_increasing() {
        let mut prev = 0.0;
        for i in 1..=160 {
            let w = i as f64 * 0.1;
            let c = curve_banded(w, 8.0);
            assert!(c >= prev - 1e-12);
            prev = c;
        }
    }
}
