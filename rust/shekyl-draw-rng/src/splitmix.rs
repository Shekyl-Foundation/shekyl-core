// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Seeded reference generator for measurement, simulation, and the golden
//! vector.
//!
//! This module compiles only under `cfg(any(test, feature = "splitmix"))`.
//! The `splitmix` feature is how another crate's tests, examples, and the
//! golden-vector generator name [`SplitMix64`]. A production build has no
//! such feature, so the type is not there to draw from.
//! `scripts/ci/check_test_only_features.py` holds the feature to
//! dev-dependency edges.

use super::RelayRng;

/// `2^64 / φ`. SplitMix64 adds this to its state on every draw
/// (Sebastiano Vigna's generator).
const GOLDEN_INCREMENT: u64 = 0x9E37_79B9_7F4A_7C15;

/// First multiplier of Stafford's mix finalizer.
const STAFFORD_MIX_1: u64 = 0xBF58_476D_1CE4_E5B9;

/// Second multiplier of Stafford's mix finalizer.
const STAFFORD_MIX_2: u64 = 0x94D0_49BB_1331_11EB;

/// Deterministic reference RNG.
///
/// The same generator `shekyl-standoff`'s harness uses. It is not a CSPRNG.
/// Any seed is valid, including zero. Two generators with the same seed
/// emit the same stream.
#[derive(Debug, Clone)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    /// Seed the generator.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }
}

impl RelayRng for SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        // Stafford's variant of Vigna's SplitMix64. The shifts are part of
        // that finalizer: 30, then 27, then 31.
        self.0 = self.0.wrapping_add(GOLDEN_INCREMENT);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(STAFFORD_MIX_1);
        z = (z ^ (z >> 27)).wrapping_mul(STAFFORD_MIX_2);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix64_is_deterministic_for_a_seed() {
        let a: Vec<u64> = (0..8)
            .scan(SplitMix64::new(42), |r, _| Some(r.next_u64()))
            .collect();
        let b: Vec<u64> = (0..8)
            .scan(SplitMix64::new(42), |r, _| Some(r.next_u64()))
            .collect();
        assert_eq!(a, b);
        // Distinct seeds must not collide on the first word.
        let mut c = SplitMix64::new(43);
        assert_ne!(a[0], c.next_u64());
    }
}
