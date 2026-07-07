//! Shared test RNG for the published KAT — a seeded `SplitMix64` implementing
//! [`shekyl_standoff::GapRng`]. This is *reference determinism* (a fixed seed
//! reproduces a fixed sequence so the vector is checkable), not a PRNG mandate:
//! a wallet grades on the draw property, not on emitting this exact stream.

use shekyl_standoff::GapRng;

/// Minimal seeded PRNG (SplitMix64). Identical recurrence to the one the
/// staking-sim uses, so the sim and the KAT exercise the same reference stream.
pub struct SplitMix64(pub u64);

impl GapRng for SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}
