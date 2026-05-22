// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`Blake2Generator`]: simple PRNG over Blake2b-512 per
//! [`specs.md`](../../external/randomx-v2/doc/specs.md) §3.5.
//!
//! The generator maintains a 64-byte internal state `S` and a byte
//! cursor `data_index` (offsets `0..=64`; `64` indicates "exhausted,
//! refill on next access"). On each request for `n` bytes
//! (`get_byte` ⇒ 1; `get_uint32` ⇒ 4) the generator checks whether
//! `n` bytes remain available in `S[data_index..]`. If not, it
//! refills by computing `S := Blake2b512(S)` in place and resets
//! `data_index = 0`. The initial state forces a refill on the very
//! first request: the constructor zero-fills `S`, copies up to 60
//! bytes of `seed` into `S[0..]`, writes the `nonce` as a little-
//! endian `u32` into `S[60..64]`, and sets `data_index = 64`. The
//! first observable byte is therefore byte 0 of `Blake2b512(initial
//! S)`, not byte 0 of the raw seed.
//!
//! # Spec / C reference
//!
//! - **Spec:** [`specs.md`](../../external/randomx-v2/doc/specs.md)
//!   §3.5 covers initialization and the refill rule. The spec does
//!   **not** describe a `nonce` parameter; the `nonce` extension at
//!   offset 60 is a C-reference implementation detail used by spec
//!   §7.2 to generate 8 distinct `SuperscalarHash` instances from
//!   the same key `K`. This spec-silence is a known item disposed
//!   by the audit table in `superscalar.rs` per
//!   `RANDOMX_V2_PHASE2B_PLAN.md` §5.5 (F5).
//! - **C reference:** `external/randomx-v2/src/blake2_generator.{hpp,cpp}`
//!   is the byte-for-byte target. The C uses `int nonce` and
//!   `store32(&data[60], nonce)`; the Rust port uses `u32` to be
//!   honest about the on-wire size and matches the same little-endian
//!   layout.
//!
//! # Test coverage
//!
//! Smoke tests in this module cover `(seed, nonce) →` stream
//! determinism, divergence under nonce variation, and the refill
//! boundary. Byte-for-byte spec-vector parity against the C
//! reference is exercised end-to-end by the `SuperscalarHash`
//! vectors in `superscalar.rs` (Layer A program-serialization +
//! Layer B execution-output + combined attestation tuple), since
//! `generate_superscalar` consumes `Blake2Generator` for every
//! opcode / register / immediate decision — a divergence in this
//! module would surface as a Layer A byte-diff against the
//! C-generated reference.

use blake2::{Blake2b512, Digest};

/// Maximum seed length consumed by [`Blake2Generator::new`]. Per
/// `external/randomx-v2/src/blake2_generator.cpp:36`. Seed bytes
/// beyond this length are silently truncated, matching the C
/// reference's `seedSize > maxSeedSize ? maxSeedSize : seedSize`
/// behavior. The 4-byte tail of the 64-byte state is reserved for
/// the `nonce` (offsets 60..64).
pub(crate) const MAX_SEED_SIZE: usize = 60;

/// Internal state size in bytes (Blake2b-512 output width). The
/// `data_index = STATE_SIZE` initial value forces a refill on the
/// first byte request.
const STATE_SIZE: usize = 64;

/// `(seed, nonce) → PRNG byte stream` per spec §3.5.
///
/// Consumed by [`generate_superscalar`](crate::superscalar::generate_superscalar)
/// to produce the 8 SuperscalarHash programs in
/// [`Cache::derive`](crate::Cache::derive) per spec §7.2.
pub(crate) struct Blake2Generator {
    /// Rolling 64-byte buffer; refilled by `S := Blake2b512(S)` when
    /// exhausted.
    data: [u8; STATE_SIZE],
    /// Cursor into `data`. Values in `0..=STATE_SIZE`; `STATE_SIZE`
    /// indicates "exhausted, refill on next access."
    data_index: usize,
}

impl Blake2Generator {
    /// Construct a generator from `seed` (truncated to
    /// [`MAX_SEED_SIZE`] bytes if longer) and `nonce` (written as
    /// little-endian `u32` at offset 60).
    ///
    /// The initial `data_index` is `STATE_SIZE`, which causes the
    /// first call to [`get_byte`] or [`get_uint32`] to refill the
    /// buffer via `Blake2b512(initial S)` before returning. This
    /// matches the C reference's `dataIndex(sizeof(data))`
    /// initialization at `blake2_generator.cpp:38`.
    ///
    /// [`get_byte`]: Blake2Generator::get_byte
    /// [`get_uint32`]: Blake2Generator::get_uint32
    pub(crate) fn new(seed: &[u8], nonce: u32) -> Self {
        let mut data = [0u8; STATE_SIZE];
        let copy_len = seed.len().min(MAX_SEED_SIZE);
        data[..copy_len].copy_from_slice(&seed[..copy_len]);
        data[MAX_SEED_SIZE..STATE_SIZE].copy_from_slice(&nonce.to_le_bytes());
        Self {
            data,
            data_index: STATE_SIZE,
        }
    }

    /// Return the next byte of the PRNG stream.
    pub(crate) fn get_byte(&mut self) -> u8 {
        self.check_data(1);
        let b = self.data[self.data_index];
        self.data_index += 1;
        b
    }

    /// Return the next 4 bytes of the PRNG stream interpreted as a
    /// little-endian `u32`.
    pub(crate) fn get_uint32(&mut self) -> u32 {
        self.check_data(4);
        let bytes: [u8; 4] = self.data[self.data_index..self.data_index + 4]
            .try_into()
            .expect("4-byte slice into 4-byte array cannot fail after check_data(4)");
        self.data_index += 4;
        u32::from_le_bytes(bytes)
    }

    /// Refill the buffer in place via `S := Blake2b512(S)` if fewer
    /// than `bytes_needed` bytes remain at `data[data_index..]`.
    /// Matches `blake2_generator.cpp:56`'s `checkData` exactly.
    fn check_data(&mut self, bytes_needed: usize) {
        if self.data_index + bytes_needed > STATE_SIZE {
            let mut hasher = Blake2b512::new();
            hasher.update(self.data);
            let out = hasher.finalize();
            self.data.copy_from_slice(&out);
            self.data_index = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The constructor sets `data_index = STATE_SIZE`, so the very
    /// first `get_byte` triggers a refill via `Blake2b512(initial S)`.
    /// Two generators with the same `(seed, nonce)` therefore produce
    /// identical streams from byte 0.
    #[test]
    fn same_seed_and_nonce_produce_identical_streams() {
        let mut g1 = Blake2Generator::new(b"shekyl-test-seed", 0);
        let mut g2 = Blake2Generator::new(b"shekyl-test-seed", 0);
        for _ in 0..200 {
            assert_eq!(g1.get_byte(), g2.get_byte());
        }
    }

    /// Distinct nonces with the same seed diverge at byte 0 (because
    /// the initial `S` differs at offsets 60..64, which Blake2b
    /// avalanches across the entire output). At least one of the
    /// first 64 bytes must differ; the probability of full
    /// collision is `2^-512`, so any flake here indicates a logic
    /// bug rather than chance.
    #[test]
    fn different_nonces_produce_different_streams() {
        let mut g0 = Blake2Generator::new(b"shekyl-test-seed", 0);
        let mut g1 = Blake2Generator::new(b"shekyl-test-seed", 1);
        let stream0: Vec<u8> = (0..64).map(|_| g0.get_byte()).collect();
        let stream1: Vec<u8> = (0..64).map(|_| g1.get_byte()).collect();
        assert_ne!(stream0, stream1);
    }

    /// Distinct seeds with the same nonce diverge similarly.
    #[test]
    fn different_seeds_produce_different_streams() {
        let mut ga = Blake2Generator::new(b"seed-a", 0);
        let mut gb = Blake2Generator::new(b"seed-b", 0);
        let stream_a: Vec<u8> = (0..64).map(|_| ga.get_byte()).collect();
        let stream_b: Vec<u8> = (0..64).map(|_| gb.get_byte()).collect();
        assert_ne!(stream_a, stream_b);
    }

    /// Refill boundary: drawing exactly 64 bytes consumes the first
    /// Blake2b output; the 65th byte triggers a second refill and
    /// differs from byte 0 of the first refill (with overwhelming
    /// probability).
    #[test]
    fn refill_boundary_at_64_bytes() {
        let mut g = Blake2Generator::new(b"refill-test", 0);
        let mut first_64 = [0u8; 64];
        for byte in &mut first_64 {
            *byte = g.get_byte();
        }
        let byte_65 = g.get_byte();
        // The 65th byte comes from a fresh Blake2b refill of the
        // first refill's output; it would equal first_64[0] only on
        // a 2^-8 chance. The test is statistically reliable; a true
        // refill bug would produce first_64[0] deterministically.
        assert_ne!(byte_65, first_64[0]);
    }

    /// `get_uint32` reads 4 little-endian bytes from the current
    /// buffer position. Compared against drawing 4 bytes from a
    /// twin generator, the u32 must equal the LE assembly of the
    /// four bytes.
    #[test]
    fn get_uint32_is_little_endian_of_get_byte_stream() {
        let mut g_u32 = Blake2Generator::new(b"endian-test", 7);
        let mut g_byte = Blake2Generator::new(b"endian-test", 7);
        let observed_u32 = g_u32.get_uint32();
        let b0 = g_byte.get_byte();
        let b1 = g_byte.get_byte();
        let b2 = g_byte.get_byte();
        let b3 = g_byte.get_byte();
        let expected = u32::from_le_bytes([b0, b1, b2, b3]);
        assert_eq!(observed_u32, expected);
    }

    /// Seed longer than [`MAX_SEED_SIZE`] is silently truncated, per
    /// the C reference. Two generators initialized with seeds
    /// agreeing on the first 60 bytes but differing afterward must
    /// produce identical streams.
    #[test]
    fn oversize_seed_truncated_at_max_seed_size() {
        let mut shared_prefix = vec![0u8; MAX_SEED_SIZE];
        for (i, byte) in shared_prefix.iter_mut().enumerate() {
            *byte = u8::try_from(i).expect("0..60 fits in u8");
        }
        let mut seed_a = shared_prefix.clone();
        seed_a.extend_from_slice(b"-tail-A");
        let mut seed_b = shared_prefix.clone();
        seed_b.extend_from_slice(b"-tail-B-with-more-bytes");
        let mut g_a = Blake2Generator::new(&seed_a, 0);
        let mut g_b = Blake2Generator::new(&seed_b, 0);
        for _ in 0..64 {
            assert_eq!(g_a.get_byte(), g_b.get_byte());
        }
    }
}
