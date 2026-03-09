//! Economic system parameters — mirrors constants from cryptonote_config.h.

use serde::{Deserialize, Serialize};

pub const SCALE: u64 = 1_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicParams {
    pub release_min: u64,
    pub release_max: u64,
    pub tx_volume_baseline: u64,
    pub burn_base_rate: u64,
    pub burn_cap: u64,
    pub staker_pool_share: u64,
    pub money_supply: u64,
}

impl Default for EconomicParams {
    fn default() -> Self {
        Self {
            release_min: 800_000,           // 0.8x
            release_max: 1_300_000,         // 1.3x
            tx_volume_baseline: 100,
            burn_base_rate: 400_000,        // 40%
            burn_cap: 900_000,              // 90%
            staker_pool_share: 200_000,     // 20%
            money_supply: 4_294_967_296_000_000_000,
        }
    }
}

/// Clamp a value to [lo, hi].
#[inline]
pub fn clamp(value: u64, lo: u64, hi: u64) -> u64 {
    if value < lo {
        lo
    } else if value > hi {
        hi
    } else {
        value
    }
}

/// Multiply two u64 values and divide by SCALE, using u128 intermediary to avoid overflow.
#[inline]
pub fn mul_scale(a: u64, b: u64) -> u64 {
    let product = (a as u128) * (b as u128);
    (product / SCALE as u128) as u64
}

/// Integer square root via Newton's method (floor).
pub fn isqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clamp() {
        assert_eq!(clamp(500_000, 800_000, 1_300_000), 800_000);
        assert_eq!(clamp(1_000_000, 800_000, 1_300_000), 1_000_000);
        assert_eq!(clamp(2_000_000, 800_000, 1_300_000), 1_300_000);
    }

    #[test]
    fn test_mul_scale() {
        assert_eq!(mul_scale(2_000_000, 500_000), 1_000_000); // 2.0 * 0.5 = 1.0
        assert_eq!(mul_scale(1_000_000, 1_000_000), 1_000_000); // 1.0 * 1.0 = 1.0
        assert_eq!(mul_scale(1_300_000, 1_000_000), 1_300_000); // 1.3 * 1.0 = 1.3
    }

    #[test]
    fn test_mul_scale_no_overflow() {
        let big = u64::MAX;
        let result = mul_scale(big, SCALE);
        assert_eq!(result, big);
    }

    #[test]
    fn test_isqrt() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(4), 2);
        assert_eq!(isqrt(9), 3);
        assert_eq!(isqrt(10), 3);
        assert_eq!(isqrt(1_000_000), 1000);
    }
}
