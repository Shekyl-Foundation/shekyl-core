// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one RNG a key is generated from when the key must be re-derivable.
//!
//! Every post-quantum key generator this crate calls takes an RNG, not a
//! seed. A key that has to come back from the wallet seed is therefore
//! generated from a deterministic stream over 32 seed bytes, and that stream
//! is part of the frozen derivation: ML-DSA-65 per-output and persona keys,
//! the ML-KEM-768 address key, and the FN-DSA-1024 receipt key are all the
//! bytes `rand_chacha::ChaCha20Rng::from_seed` gives. Each site used to
//! build that generator itself.
//!
//! `rand_chacha`'s generator does not wipe itself. It holds the seed as its
//! key and up to 256 bytes of buffered output, and it takes the seed by
//! value, so dropping it left both on the stack of whoever generated the
//! key. [`SeededRng`] produces the same stream and leaves nothing: it is the
//! RustCrypto ChaCha20 cipher with its `zeroize` feature, whose core and
//! output buffer are wiped on drop, keyed from a borrowed seed.
//!
//! # The stream, exactly
//!
//! ChaCha20, 20 rounds, the original layout: the seed is the 256-bit key,
//! the nonce is zero, the block counter starts at zero. Output is consumed
//! in whole little-endian 32-bit words, as `rand_core`'s block generator
//! consumes it:
//!
//! - `next_u32` is the next word;
//! - `next_u64` is the next two words, low then high;
//! - `fill_bytes` of `n` bytes takes `⌈n / 4⌉` words and writes the first
//!   `n` of their bytes. The rest of a partly used word is discarded, not
//!   kept for the next call.
//!
//! `matches_rand_chacha_on_every_call_shape` holds this against
//! `ChaCha20Rng` itself, and every pinned key vector in the crate holds it
//! against the bytes that were frozen. A change here that moves a vector is
//! a wrong change.
//!
//! The cipher counts blocks in 32 bits and stops at 256 GiB; `rand_chacha`
//! counts in 64. A key generator draws a few hundred bytes.

use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};
use chacha20::{ChaCha20Legacy, Key, LegacyNonce};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// A deterministic ChaCha20 stream over 32 seed bytes, wiped on drop.
///
/// For seeded key generation and for pinning a test vector or a bench.
/// Never a source of fresh randomness: the same seed is the same stream.
pub(crate) struct SeededRng {
    stream: ChaCha20Legacy,
}

impl SeededRng {
    /// The stream `rand_chacha::ChaCha20Rng::from_seed(*seed)` produces. The
    /// seed is borrowed and copied once, into the cipher's key schedule,
    /// which the cipher wipes.
    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        // A borrow reinterpreted as the cipher's key type, not a copy.
        let key: &Key = seed.into();
        Self {
            stream: ChaCha20Legacy::new(key, &LegacyNonce::default()),
        }
    }

    /// The next `N` keystream bytes, `N` a whole number of words.
    fn words<const N: usize>(&mut self) -> Zeroizing<[u8; N]> {
        let mut out = Zeroizing::new([0u8; N]);
        self.stream.apply_keystream(out.as_mut_slice());
        out
    }
}

impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(*self.words::<4>())
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(*self.words::<8>())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let whole = dest.len() - dest.len() % 4;
        let (words, tail) = dest.split_at_mut(whole);
        // The keystream is XORed into the buffer, so the buffer is zeroed
        // first: what a caller left in `dest` must not reach the output.
        words.fill(0);
        self.stream.apply_keystream(words);
        if !tail.is_empty() {
            let last = self.words::<4>();
            tail.copy_from_slice(&last[..tail.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// A seeded stream is as unpredictable as its seed, which is what the key
/// generators that require this marker need from it.
impl CryptoRng for SeededRng {}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::SeedableRng as _;
    use rand_chacha::ChaCha20Rng;

    /// What is wiped is the cipher's: its core and its wrapper's buffer are
    /// `ZeroizeOnDrop` only while the `zeroize` feature of `chacha20` is on.
    /// This fails to compile if that feature is ever dropped from the
    /// manifest, which is the only way the wipe can go away.
    #[test]
    fn the_stream_is_wiped_on_drop() {
        fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        wiped_on_drop::<ChaCha20Legacy>();
        wiped_on_drop::<chacha20::ChaCha20LegacyCore>();
    }

    /// One step of a call sequence against both generators.
    #[derive(Clone, Copy, Debug)]
    enum Call {
        U32,
        U64,
        Fill(usize),
    }

    fn agree(seed: [u8; 32], calls: &[Call]) {
        let mut ours = SeededRng::from_seed(&seed);
        let mut theirs = ChaCha20Rng::from_seed(seed);
        for (step, call) in calls.iter().enumerate() {
            match *call {
                Call::U32 => assert_eq!(ours.next_u32(), theirs.next_u32(), "{step}: {call:?}"),
                Call::U64 => assert_eq!(ours.next_u64(), theirs.next_u64(), "{step}: {call:?}"),
                Call::Fill(n) => {
                    // Different garbage in each buffer: the output must not
                    // depend on what the buffer held.
                    let mut a = vec![0xA5u8; n];
                    let mut b = vec![0x5Au8; n];
                    ours.fill_bytes(&mut a);
                    theirs.fill_bytes(&mut b);
                    assert_eq!(a, b, "{step}: {call:?}");
                }
            }
        }
    }

    /// The whole contract: the same bytes as `ChaCha20Rng::from_seed`, for
    /// every call a consumer can make, in any order — word-aligned fills
    /// (what the key generators draw), fills that end inside a word,
    /// single words and double words, and runs long enough to cross
    /// `rand_chacha`'s 256-byte buffer several times and at every offset.
    #[test]
    fn matches_rand_chacha_on_every_call_shape() {
        use Call::{Fill, U32, U64};
        let seeds = [[0u8; 32], [0xFFu8; 32], [0x11u8; 32], {
            let mut s = [0u8; 32];
            for (i, b) in s.iter_mut().enumerate() {
                *b = u8::try_from(i * 7 + 3).expect("fits");
            }
            s
        }];
        for seed in seeds {
            // What the generators draw: 32-byte fills.
            agree(seed, &[Fill(32), Fill(32), Fill(32), Fill(64), Fill(40)]);
            // Every length from empty past one buffer, back to back.
            let every: Vec<Call> = (0..=300).map(Fill).collect();
            agree(seed, &every);
            // Words and double words, across the buffer boundary at every
            // alignment: 63 words then a double word straddles it.
            for lead in 0..=65 {
                let mut calls = vec![U32; lead];
                calls.extend([U64, U32, U64, Fill(5), U64, Fill(3), U32, Fill(257), U64]);
                agree(seed, &calls);
            }
            // Odd fills interleaved with words.
            agree(
                seed,
                &[
                    Fill(1),
                    U32,
                    Fill(2),
                    U64,
                    Fill(3),
                    Fill(7),
                    U32,
                    Fill(255),
                    Fill(1),
                    U64,
                    Fill(1024),
                    Fill(9),
                ],
            );
        }
    }

    /// Two streams over one seed are one stream; over two seeds, two.
    #[test]
    fn the_stream_is_a_function_of_the_seed() {
        let mut a = [0u8; 96];
        let mut b = [0u8; 96];
        let mut c = [0u8; 96];
        SeededRng::from_seed(&[7; 32]).fill_bytes(&mut a);
        SeededRng::from_seed(&[7; 32]).fill_bytes(&mut b);
        SeededRng::from_seed(&[8; 32]).fill_bytes(&mut c);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
