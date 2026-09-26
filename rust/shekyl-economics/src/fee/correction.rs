// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Raw fee-correction scalar `C`, and the quantized instrument around it.
//!
//! [`FeeCorrection`] is the served multiplier. [`quantize_pow2_ceil`] /
//! [`hysteresis_step`] are the pow2 ceiling and §7 band: a wallet-cap bound
//! (`C_q ≥ C`) and the derivation instrument. They are not what the daemon
//! multiplies by.

use crate::params::{EconomicParams, SCALE};
use crate::release::calc_release_multiplier;
use crate::volume::TxVolume;

/// Raw fee-correction scalar `C = (1−σ)·M_r/(1−b)` in [`SCALE`] units.
///
/// Served multiplier for every rung and the relay floor. `C < 1` on a quiet
/// chain lowers the floor; `C > 1` raises it. No snap, no band, no rounding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FeeCorrection(u64);

impl FeeCorrection {
    /// `C = 1` in SCALE units.
    pub const UNITY: Self = Self(SCALE);

    /// Wrap a SCALE-unit value. Tests, FFI, and the wallet-cap bound (a
    /// number ≥ any reachable `C`) use this.
    #[must_use]
    pub const fn from_scaled(scaled: u64) -> Self {
        Self(scaled)
    }

    #[must_use]
    pub const fn as_scaled(self) -> u64 {
        self.0
    }
}

/// `C = (1−σ)·M_r/(1−b)` from the caller's already-computed `σ` and `b`
/// (the same `shekyl_calc_emission_share` / `shekyl_calc_burn_pct` values
/// the validation path uses at this state).
///
/// Total: `σ` and `b` are clamped below `SCALE`, so the divisor is at least
/// 1 and the quotient of two `u128`s built from `u64`s cannot exceed
/// `u64::MAX`.
#[must_use]
pub fn fee_correction(
    tx_volume: TxVolume,
    sigma_scaled: u64,
    burn_pct_scaled: u64,
    params: &EconomicParams,
) -> FeeCorrection {
    let m_r = calc_release_multiplier(
        tx_volume,
        params.tx_volume_baseline,
        params.release_min,
        params.release_max,
    );
    let sigma = sigma_scaled.min(SCALE - 1);
    let b = burn_pct_scaled.min(params.burn_cap).min(SCALE - 1);
    FeeCorrection(
        u64::try_from(u128::from(SCALE - sigma) * u128::from(m_r) / u128::from(SCALE - b))
            .expect("C fits u64: numerator <= SCALE * release_max, divisor >= 1"),
    )
}

/// Exact-integer `2^k ≤ c/s` (no float log2 — this feeds a
/// wallet-must-match-daemon derivation).
fn pow2_le(c: u128, s: u128, k: i32) -> bool {
    if k >= 0 {
        (s << k) <= c
    } else {
        s <= (c << (-k))
    }
}

/// Ceiling pow2 snap in `SCALE` fixed point: smallest exact power of two
/// `≥ c/SCALE`. Panics only if the snapped exponent leaves the range
/// `SCALE` can represent exactly (`2^-6 … 2^43`).
#[must_use]
pub fn quantize_pow2_ceil(c_scaled: u64) -> u64 {
    assert!(c_scaled > 0, "correction factor is structurally positive");
    let c = u128::from(c_scaled);
    let s = u128::from(SCALE);
    let mut kf: i32 = -40;
    while pow2_le(c, s, kf + 1) {
        kf += 1;
    }
    let exact = if kf >= 0 {
        (s << kf) == c
    } else {
        (c << (-kf)) == s
    };
    let k = if exact { kf } else { kf + 1 };
    assert!(
        (-6..=43).contains(&k),
        "2^{k} not exactly representable in SCALE units"
    );
    if k >= 0 {
        SCALE << k
    } else {
        SCALE >> (-k)
    }
}

/// Smallest exactly-representable raw `C`. [`hysteresis_step`] floors here
/// before snapping so a `C = 0` from a hostile FFI scalar cannot panic
/// across the ABI (rule 40).
const MIN_REPRESENTABLE_C: u64 = SCALE >> 6;

/// Pow2 ceiling of raw `C` behind the §7 hysteresis band.
///
/// `prev_cq_scaled = 0` means no history: the plain ceiling snap. With a
/// history, `C` must leave `[prev/2·(1−m), prev·(1+m)]` (`m` = 3%) before
/// the value moves.
///
/// Not the served scalar. Wallet cap uses the unseeded snap as a bound
/// (`C_q ≥ C`); the derivation instrument folds through this.
#[must_use]
pub fn hysteresis_step(c_scaled: u64, prev_cq_scaled: u64) -> u64 {
    const HYSTERESIS_MARGIN_MILLI: u128 = 30; // 3%
    let c = c_scaled.max(MIN_REPRESENTABLE_C);
    let cq = quantize_pow2_ceil(c);
    if prev_cq_scaled == 0 || cq == prev_cq_scaled {
        return cq;
    }
    let prev = u128::from(prev_cq_scaled);
    let c = u128::from(c);
    let upper = prev * (1000 + HYSTERESIS_MARGIN_MILLI) / 1000;
    let lower = (prev / 2) * (1000 - HYSTERESIS_MARGIN_MILLI) / 1000;
    if c > upper || c < lower {
        cq
    } else {
        prev_cq_scaled
    }
}

/// [`hysteresis_step`] wrapped around [`fee_correction`].
///
/// Not the served path. `prev_cq_scaled = 0` is the unseeded snap.
#[must_use]
pub fn fee_correction_quantized(
    tx_volume: TxVolume,
    sigma_scaled: u64,
    burn_pct_scaled: u64,
    prev_cq_scaled: u64,
    params: &EconomicParams,
) -> u64 {
    hysteresis_step(
        fee_correction(tx_volume, sigma_scaled, burn_pct_scaled, params).as_scaled(),
        prev_cq_scaled,
    )
}

/// The §7 band over a span of raw corrections, unseeded at the first cell.
/// `None` for an empty span.
#[must_use]
pub fn hysteresis_fold(cells_scaled: &[u64]) -> Option<u64> {
    let (first, rest) = cells_scaled.split_first()?;
    let mut cq = hysteresis_step(*first, 0);
    for &c in rest {
        cq = hysteresis_step(c, cq);
    }
    Some(cq)
}

/// True iff `⌈c⌉₂` is the band's state from every neighbour — computed
/// through [`hysteresis_step`], never a second copy of the margin.
#[must_use]
pub fn hysteresis_settled(c_scaled: u64) -> bool {
    let cq = hysteresis_step(c_scaled, 0);
    let lower_holds = cq / 2 >= MIN_REPRESENTABLE_C && hysteresis_step(c_scaled, cq / 2) != cq;
    let upper_holds = hysteresis_step(c_scaled, cq.saturating_mul(2)) != cq;
    !(lower_holds || upper_holds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantize_snap_is_exact_integer_ceiling() {
        for c in [500_000u64, 1_000_000, 2_000_000, 4_000_000] {
            assert_eq!(quantize_pow2_ceil(c), c);
        }
        assert_eq!(quantize_pow2_ceil(680_000), 1_000_000);
        assert_eq!(quantize_pow2_ceil(1_130_000), 2_000_000);
        assert_eq!(quantize_pow2_ceil(12_917_390), 16_000_000);
    }

    #[test]
    fn raw_correction_is_continuous_and_falls_below_one() {
        let p = EconomicParams::default();

        assert_eq!(
            fee_correction(TxVolume::per_block(50), 0, 0, &p),
            FeeCorrection::UNITY
        );

        let quiet = fee_correction(TxVolume::per_block(1), SCALE * 15 / 100, 0, &p);
        assert_eq!(quiet.as_scaled(), SCALE * 68 / 100);
        assert!(
            quiet < FeeCorrection::UNITY,
            "raw C must be able to LOWER the floor"
        );

        let a = fee_correction(TxVolume::window(50 * 720 + 1, 720), 0, 0, &p);
        let b = fee_correction(TxVolume::window(50 * 720 + 2, 720), 0, 0, &p);
        assert!(b >= a, "C is monotone in volume");
        assert!(
            b.as_scaled() - a.as_scaled() < SCALE / 1000,
            "one tx must move raw C by well under 0.1%, got {} in SCALE units",
            b.as_scaled() - a.as_scaled()
        );
    }

    #[test]
    fn quantized_correction_is_exactly_the_snap_of_the_raw_one() {
        let p = EconomicParams::default();
        let mut stepped = 0usize;
        for v in [1u64, 10, 40, 49, 50, 51, 65, 80, 200] {
            for sigma_pct in [0u64, 5, 15] {
                for burn_pct in [0u64, 10, 50] {
                    let sigma = SCALE * sigma_pct / 100;
                    let burn = SCALE * burn_pct / 100;
                    let raw = fee_correction(TxVolume::per_block(v), sigma, burn, &p);
                    assert_eq!(
                        fee_correction_quantized(TxVolume::per_block(v), sigma, burn, 0, &p),
                        hysteresis_step(raw.as_scaled(), 0),
                        "C_q must be the snap of raw C at v={v} sigma={sigma} b={burn}"
                    );
                    if hysteresis_step(raw.as_scaled(), 0) != raw.as_scaled() {
                        stepped += 1;
                    }
                }
            }
        }
        assert!(
            stepped > 0,
            "the sweep must include states the snap actually moves"
        );
    }

    #[test]
    fn fee_correction_quantized_is_total_at_hostile_scalars() {
        let p = EconomicParams::default();
        let cq = fee_correction_quantized(TxVolume::window(0, 0), SCALE - 1, 0, 0, &p);
        assert!(cq > 0, "a total path must still return a usable step");
        for (v, sigma, burn, prev) in [
            (0u64, SCALE - 1, 0u64, SCALE),
            (0, u64::MAX, 0, 0),
            (0, u64::MAX, u64::MAX, 0),
            (u64::MAX, u64::MAX, u64::MAX, u64::MAX),
            (u64::MAX, 0, u64::MAX, 0),
        ] {
            let out = fee_correction_quantized(TxVolume::window(v, 1), sigma, burn, prev, &p);
            assert!(
                out > 0,
                "unusable value at (v={v}, sigma={sigma}, burn={burn}, prev={prev})"
            );
        }
    }

    #[test]
    fn correction_hysteresis_holds_the_boundary() {
        let p = EconomicParams::default();
        assert_eq!(
            fee_correction_quantized(TxVolume::per_block(51), 0, 0, SCALE, &p),
            SCALE
        );
        assert_eq!(
            fee_correction_quantized(TxVolume::per_block(51), 0, 0, 0, &p),
            2 * SCALE
        );
        assert_eq!(
            fee_correction_quantized(TxVolume::per_block(65), 0, 0, SCALE, &p),
            2 * SCALE
        );
        assert_eq!(
            fee_correction_quantized(TxVolume::per_block(51), 0, 0, 2 * SCALE, &p),
            2 * SCALE
        );
    }

    #[test]
    fn hysteresis_fold_is_the_iterated_step() {
        assert_eq!(hysteresis_fold(&[]), None);
        for c in [0, SCALE >> 6, 680_000, SCALE, 1_020_000, 12_917_390] {
            assert_eq!(hysteresis_fold(&[c]), Some(hysteresis_step(c, 0)));
        }
        let span = [1_020_000, 1_020_000, 990_000, 1_010_000, 900_000];
        let mut cq = hysteresis_step(span[0], 0);
        assert_eq!(cq, 2 * SCALE);
        for (i, &c) in span.iter().enumerate().skip(1) {
            cq = hysteresis_step(c, cq);
            assert_eq!(hysteresis_fold(&span[..=i]), Some(cq));
        }
        assert_eq!(hysteresis_fold(&span[..4]), Some(2 * SCALE));
        assert_eq!(hysteresis_fold(&span), Some(SCALE));
    }

    fn boundary_biased_sequences() -> Vec<Vec<u64>> {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        (0..200)
            .map(|_| {
                let len = 8 + (next() % 40) as usize;
                (0..len)
                    .map(|_| {
                        let boundary = SCALE << (next() % 6);
                        let milli = next() % 121;
                        boundary / 1000 * (940 + milli)
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn hysteresis_fold_from_any_settled_index_is_the_full_fold() {
        let mut settled_seen = 0u32;
        let mut unsettled_seen = 0u32;
        for seq in boundary_biased_sequences() {
            let full = hysteresis_fold(&seq);
            for (j, &c) in seq.iter().enumerate() {
                let cq = hysteresis_step(c, 0);
                if hysteresis_settled(c) {
                    settled_seen += 1;
                    for prev in [0, cq / 4, cq / 2, cq, 2 * cq, 4 * cq, SCALE >> 6] {
                        assert_eq!(hysteresis_step(c, prev), cq, "c={c} prev={prev}");
                    }
                    assert_eq!(hysteresis_fold(&seq[j..]), full, "j={j} c={c}");
                } else {
                    unsettled_seen += 1;
                    let held = hysteresis_step(c, 2 * cq) != cq
                        || (cq / 2 >= (SCALE >> 6) && hysteresis_step(c, cq / 2) != cq);
                    assert!(held, "c={c} declared unsettled but no neighbour holds it");
                }
            }
        }
        assert!(
            settled_seen > 500 && unsettled_seen > 500,
            "{settled_seen}/{unsettled_seen}"
        );
    }

    #[test]
    fn banded_sequence_transitions_never_exceed_snap_transitions() {
        for seq in boundary_biased_sequences() {
            let mut snap_transitions = 0u32;
            let mut band_transitions = 0u32;
            let mut prev_snap = hysteresis_step(seq[0], 0);
            let mut prev_band = prev_snap;
            for &c in &seq[1..] {
                let snap = hysteresis_step(c, 0);
                let band = hysteresis_step(c, prev_band);
                snap_transitions += u32::from(snap != prev_snap);
                band_transitions += u32::from(band != prev_band);
                prev_snap = snap;
                prev_band = band;
            }
            assert!(
                band_transitions <= snap_transitions,
                "{band_transitions} > {snap_transitions}"
            );
        }
    }
}
