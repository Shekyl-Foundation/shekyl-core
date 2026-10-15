// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The sim's one random generator: SplitMix64, deterministic across
//! platforms and with no dependency (rule 17). It stands in for what a
//! block that is never built would supply: dropout, a reveal lag, a seed,
//! a hash. Nothing the chain computes is drawn from it.

/// SplitMix64 over a `u64` state.
pub(crate) struct SplitMix64(u64);

impl SplitMix64 {
    /// The generator for run `seed`. Seeds are small integers; the multiply
    /// spreads them and the `+ 1` keeps seed 0 off the all-zero state.
    pub(crate) fn seeded(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9).wrapping_add(1))
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// 32 bytes of the stream, one [`Self::below`]`(256)` each: a seed or
    /// a hash for a block that is never built.
    pub(crate) fn bytes32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for byte in &mut out {
            *byte = u8::try_from(self.below(256)).expect("below 256 fits a byte");
        }
        out
    }

    /// Uniform draw in `[0, n)` by rejection (no modulo bias).
    /// `n` must be nonzero — an empty range has no uniform draw.
    pub(crate) fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "uniform draw from an empty range");
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let v = self.next();
            if v < zone {
                return v % n;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stream is a pinned function of the seed: every committed sim
    /// figure drawn from it moves if it does. The values were computed
    /// independently, from the SplitMix64 definition.
    #[test]
    fn the_stream_is_pinned() {
        let mut rng = SplitMix64::seeded(1);
        let draws: Vec<u64> = (0..5).map(|_| rng.below(1000)).collect();
        assert_eq!(draws, [191, 661, 971, 330, 55]);
        let mut rng = SplitMix64::seeded(7);
        let bytes = rng.bytes32();
        assert_eq!(bytes[..8], [0x48, 0xa1, 0x61, 0xe5, 0x85, 0x5c, 0x33, 0x17]);
    }

    #[test]
    #[should_panic(expected = "empty range")]
    fn an_empty_range_has_no_draw() {
        let _ = SplitMix64::seeded(1).below(0);
    }
}
