// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The harness's pseudo-random source. Operands only need to be
//! unpredictable to the code under test, not secret, so a small fast
//! generator seeded once from the OS is enough; and a [`Seed`] rebuilds the
//! same operand stream exactly, which is how a fixed operand set is
//! regenerated for every batch instead of being kept in a table.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

/// xorshift64* (Vigna, "An experimental exploration of Marsaglia's xorshift
/// generators, scrambled", 2016): shift triple A1 = (12, 25, 27) and the
/// multiplier M32.
const XORSHIFT_RIGHT_FIRST: u32 = 12;
const XORSHIFT_LEFT: u32 = 25;
const XORSHIFT_RIGHT_SECOND: u32 = 27;
const XORSHIFT_STAR_MULTIPLIER: u64 = 0x2545_F491_4F6C_DD1D;

/// Hashed under the OS-keyed `RandomState` to draw a run's seed: the key
/// carries the entropy, so any constant input serves.
const OS_SEED_INPUT: u64 = 0x5eed;

/// The starting point of a reproducible operand stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seed(u64);

pub struct Rng {
    state: u64,
}

impl Rng {
    /// A generator seeded from the OS, different on every run.
    pub fn from_os() -> Self {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u64(OS_SEED_INPUT);
        Self::from_seed(Seed(hasher.finish()))
    }

    /// The generator that `seed` names. xorshift's state must never be
    /// zero, so the low bit is forced: every seed is a valid one.
    pub fn from_seed(seed: Seed) -> Self {
        Rng { state: seed.0 | 1 }
    }

    /// A seed for a stream independent of this one's continuation.
    pub fn seed(&mut self) -> Seed {
        Seed(self.next_u64())
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state ^= self.state >> XORSHIFT_RIGHT_FIRST;
        self.state ^= self.state << XORSHIFT_LEFT;
        self.state ^= self.state >> XORSHIFT_RIGHT_SECOND;
        self.state.wrapping_mul(XORSHIFT_STAR_MULTIPLIER)
    }

    pub fn byte(&mut self) -> u8 {
        self.next_u64().to_le_bytes()[0]
    }

    /// `N` unrestricted bytes.
    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for chunk in out.chunks_mut(size_of::<u64>()) {
            let word = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        out
    }

    /// A value in `0..bound`. The modulo bias, at most `bound / 2^64`, is
    /// far below anything a timing run resolves.
    pub fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    /// Fisher–Yates.
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            items.swap(i, self.below(i + 1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_replays_its_stream() {
        let seed = Rng::from_os().seed();
        let (mut a, mut b) = (Rng::from_seed(seed), Rng::from_seed(seed));
        for _ in 0..64 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn the_zero_seed_does_not_stick_at_zero() {
        let mut rng = Rng::from_seed(Seed(0));
        assert_ne!(rng.next_u64(), 0);
    }

    #[test]
    fn bytes_fill_lengths_that_are_not_whole_words() {
        let mut rng = Rng::from_os();
        let odd: [u8; 13] = rng.bytes();
        assert!(odd.iter().any(|&b| b != 0));
    }

    #[test]
    fn a_shuffle_is_a_permutation() {
        let mut items: Vec<usize> = (0..100).collect();
        Rng::from_os().shuffle(&mut items);
        let mut sorted = items.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..100).collect::<Vec<_>>());
    }
}
