// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! AES round primitives for RandomX v2's `AesGenerator1R`,
//! `AesGenerator4R`, and `AesHash1R` per
//! [`specs.md`](../../external/randomx-v2/doc/specs.md) §§3.2-3.4.
//!
//! This module is the thin wrapper layer over the `aes` crate's
//! [`hazmat::cipher_round`] and [`hazmat::equiv_inv_cipher_round`]
//! single-round primitives. The wrappers exist to:
//!
//! - Decouple Phase 2b consumers from the `aes` crate's `Block` type
//!   (an `Array<u8, U16>` from RustCrypto's `hybrid-array`); internal
//!   callers use plain `[u8; 16]` and the conversion happens exactly
//!   once at the wrapper boundary.
//! - Document the FIPS-197 / Intel AES-NI semantic alignment in one
//!   rustdoc paragraph rather than once per call site.
//!
//! The wrappers are zero-cost: both `aes` crate functions take
//! `&mut Block` / `&Block` and `hybrid-array` provides
//! `impl From<&mut [T; N]> for &mut Array<T, U>` (and the analogous
//! shared-ref form), so the conversion is a `cast_from_core_mut`
//! re-borrow with no allocation or copy.
//!
//! # Spec / C reference
//!
//! - **Spec:** [`specs.md`](../../external/randomx-v2/doc/specs.md)
//!   §§3.2-3.4. The generators are defined in terms of AES single-round
//!   operations matching `_mm_aesenc_si128` (encrypt) and
//!   `_mm_aesdec_si128` (equivalent-inverse decrypt).
//! - **C reference:** `external/randomx-v2/src/soft_aes.cpp`'s
//!   `soft_aesenc` and `soft_aesdec` are the byte-for-byte target.
//!   `aes-0.9.0`'s [`hazmat::cipher_round`] matches `soft_aesenc` and
//!   [`hazmat::equiv_inv_cipher_round`] matches `soft_aesdec` per the
//!   §5.6 verification record in
//!   [`RANDOMX_V2_PHASE2B_PLAN.md`](../../docs/design/RANDOMX_V2_PHASE2B_PLAN.md).
//!
//! # Safety posture
//!
//! Both wrappers are safe at their public surface; the underlying `aes`
//! crate routes through an `if_intrinsics_available!` macro (CPUID-gated
//! AES-NI on x86, NEON on aarch64) with an `unsafe { ... }` interior
//! that is verified internal to the `aes` crate. `#![deny(unsafe_code)]`
//! at the crate level survives.
//!
//! # Scope at this commit (Phase 2b commit 4)
//!
//! Round primitives (commit 1) plus the §3.2-3.4 composites
//! (commit 2): [`fill_aes_1r_x4`], [`fill_aes_4r_x4`],
//! [`hash_aes_1r_x4`]. The spec constants (initial state, generator
//! keys, extra-round keys) are ported as `const [u8; 16]` arrays via
//! [`pack_le_u32x4`] which reproduces `_mm_set_epi32(i3, i2, i1, i0)`'s
//! little-endian memory layout exactly.
//!
//! Commit 4 adds the byte-for-byte spec-vector parity tests against
//! the v2 fork's reference at pin `aaafe71`. The 8 reference vectors
//! live under [`tests/vectors/reference/aes/`] with `.meta.txt`
//! provenance headers; the C++ generator that produced them lives at
//! [`tests/vectors/reference/aes/_generator/`] and is reviewer-
//! runnable per its `README.md`. The Rust tests consume the
//! pre-committed `.bin` bytes via `include_bytes!`, so `cargo test`
//! has no dev-dep on the C library (Phase 2g's live differential
//! harness is the separate artifact).
//!
//! [`tests/vectors/reference/aes/`]: ../../tests/vectors/reference/aes/
//! [`tests/vectors/reference/aes/_generator/`]: ../../tests/vectors/reference/aes/_generator/
//!
//! [`hazmat::cipher_round`]: aes::hazmat::cipher_round
//! [`hazmat::equiv_inv_cipher_round`]: aes::hazmat::equiv_inv_cipher_round

use aes::{hazmat, Block};

/// AES encrypt single round (FIPS 197 Appendix C / `_mm_aesenc_si128`).
///
/// Applies `SubBytes → ShiftRows → MixColumns → AddRoundKey` to
/// `state` in place, using `round_key` as the round key. Byte-for-byte
/// equivalent to `external/randomx-v2/src/soft_aes.cpp`'s `soft_aesenc`.
pub(crate) fn cipher_round(state: &mut [u8; 16], round_key: &[u8; 16]) {
    let block: &mut Block = state.into();
    let round_key: &Block = round_key.into();
    hazmat::cipher_round(block, round_key);
}

/// AES equivalent-inverse-cipher single round (FIPS 197 Appendix C
/// equivalent-inverse form / `_mm_aesdec_si128`).
///
/// Applies `InvSubBytes → InvShiftRows → InvMixColumns → AddRoundKey`
/// (equivalent-inverse order; NOT FIPS 197 standard inverse order) to
/// `state` in place, using `round_key` as the round key. Byte-for-byte
/// equivalent to `external/randomx-v2/src/soft_aes.cpp`'s `soft_aesdec`.
///
/// The equivalent-inverse form is the only single-round inverse
/// primitive exposed by `aes-0.9.0::hazmat`; the FIPS 197 standard
/// inverse form is not exposed. This structurally precludes the
/// wrong-form selection failure mode per
/// [`RANDOMX_V2_PHASE2B_PLAN.md`](../../docs/design/RANDOMX_V2_PHASE2B_PLAN.md)
/// §4.1.
pub(crate) fn equiv_inv_cipher_round(state: &mut [u8; 16], round_key: &[u8; 16]) {
    let block: &mut Block = state.into();
    let round_key: &Block = round_key.into();
    hazmat::equiv_inv_cipher_round(block, round_key);
}

/// Pack four `u32` values into a 16-byte array matching the in-memory
/// layout of `_mm_set_epi32(i3, i2, i1, i0)` followed by `_mm_store_si128`
/// on a little-endian target.
///
/// `_mm_set_epi32(i3, i2, i1, i0)` places `i0` in the LOW 32 bits and
/// `i3` in the HIGH 32 bits of the 128-bit lane; on store the bytes
/// land at offsets `[0..4] = i0_LE, [4..8] = i1_LE, [8..12] = i2_LE,
/// [12..16] = i3_LE`. The C reference at
/// `external/randomx-v2/src/intrin_portable.h:158` defines
/// `rx_set_int_vec_i128` as exactly `_mm_set_epi32`; the soft fallback
/// at `intrin_portable.h:350` reproduces the same `{i0, i1, i2, i3}`
/// initialization order, so this packing is the platform-portable
/// canonical form of every `AES_*` spec constant in `aes_hash.cpp`.
const fn pack_le_u32x4(i3: u32, i2: u32, i1: u32, i0: u32) -> [u8; 16] {
    let i0 = i0.to_le_bytes();
    let i1 = i1.to_le_bytes();
    let i2 = i2.to_le_bytes();
    let i3 = i3.to_le_bytes();
    [
        i0[0], i0[1], i0[2], i0[3], i1[0], i1[1], i1[2], i1[3], i2[0], i2[1], i2[2], i2[3], i3[0],
        i3[1], i3[2], i3[3],
    ]
}

// -----------------------------------------------------------------------------
// AesGenerator1R spec constants (specs.md §3.2; aes_hash.cpp:134-139)
// -----------------------------------------------------------------------------
//
// "key0, key1, key2, key3 = Blake2b-512(\"RandomX AesGenerator1R keys\")"
// — `external/randomx-v2/src/aes_hash.cpp:134`. The 64-byte Blake2b
// output is partitioned into 4 × 16-byte round keys, each packed via
// `_mm_set_epi32` (high-to-low) and stored on a little-endian target.

const AES_GEN_1R_KEY0: [u8; 16] = pack_le_u32x4(0xb4f4_4917, 0xdbb5_552b, 0x6271_6609, 0x6dac_a553);
const AES_GEN_1R_KEY1: [u8; 16] = pack_le_u32x4(0x0da1_dc4e, 0x1725_d378, 0x846a_710d, 0x6d7c_af07);
const AES_GEN_1R_KEY2: [u8; 16] = pack_le_u32x4(0x3e20_e345, 0xf4c0_794f, 0x9f94_7ec6, 0x3f12_62f1);
const AES_GEN_1R_KEY3: [u8; 16] = pack_le_u32x4(0x4916_9154, 0x1631_4c88, 0xb1ba_317c, 0x6aef_8135);

// -----------------------------------------------------------------------------
// AesGenerator4R spec constants (specs.md §3.3; aes_hash.cpp:210-217)
// -----------------------------------------------------------------------------
//
// "key0..3 = Blake2b-512(\"RandomX AesGenerator4R keys 0-3\");
//  key4..7 = Blake2b-512(\"RandomX AesGenerator4R keys 4-7\")"
// — `external/randomx-v2/src/aes_hash.cpp:206-208`.

const AES_GEN_4R_KEY0: [u8; 16] = pack_le_u32x4(0x99e5_d23f, 0x2f54_6d2b, 0xd183_3ddb, 0x6421_aadd);
const AES_GEN_4R_KEY1: [u8; 16] = pack_le_u32x4(0xa5df_cde5, 0x06f7_9d53, 0xb691_3f55, 0xb20e_3450);
const AES_GEN_4R_KEY2: [u8; 16] = pack_le_u32x4(0x171c_02bf, 0x0aa4_679f, 0x515e_7baf, 0x5c3e_d904);
const AES_GEN_4R_KEY3: [u8; 16] = pack_le_u32x4(0xd8de_d291, 0xcd67_3785, 0xe78f_5d08, 0x8562_3763);
const AES_GEN_4R_KEY4: [u8; 16] = pack_le_u32x4(0x229e_ffb4, 0x3d51_8b6d, 0xe3d6_a7a6, 0xb582_6f73);
const AES_GEN_4R_KEY5: [u8; 16] = pack_le_u32x4(0xb272_b7d2, 0xe902_4d4e, 0x9c10_b3d9, 0xc756_6bf3);
const AES_GEN_4R_KEY6: [u8; 16] = pack_le_u32x4(0xf63b_efa7, 0x2ba9_660a, 0xf765_a38b, 0xf273_c9e7);
const AES_GEN_4R_KEY7: [u8; 16] = pack_le_u32x4(0xc0b0_762d, 0x0c06_d1fd, 0x9158_39de, 0x7a7c_d609);

// -----------------------------------------------------------------------------
// AesHash1R spec constants (specs.md §3.4; aes_hash.cpp:42-52)
// -----------------------------------------------------------------------------
//
// "state0..3 = Blake2b-512(\"RandomX AesHash1R state\");
//  xkey0, xkey1 = Blake2b-256(\"RandomX AesHash1R xkeys\")"
// — `external/randomx-v2/src/aes_hash.cpp:42-44`.

const AES_HASH_1R_STATE0: [u8; 16] =
    pack_le_u32x4(0xd798_3aad, 0xcc82_db47, 0x9fa8_56de, 0x92b5_2c0d);
const AES_HASH_1R_STATE1: [u8; 16] =
    pack_le_u32x4(0xace7_8057, 0xf59e_125a, 0x15c7_b798, 0x338d_996e);
const AES_HASH_1R_STATE2: [u8; 16] =
    pack_le_u32x4(0xe8a0_7ce4, 0x5079_506b, 0xae62_c7d0, 0x6a77_0017);
const AES_HASH_1R_STATE3: [u8; 16] =
    pack_le_u32x4(0x7e99_4948, 0x79a1_0005, 0x07ad_828d, 0x630a_240c);

const AES_HASH_1R_XKEY0: [u8; 16] =
    pack_le_u32x4(0x0689_0201, 0x90dc_56bf, 0x8b24_949f, 0xf6fa_8389);
const AES_HASH_1R_XKEY1: [u8; 16] =
    pack_le_u32x4(0xed18_f99b, 0xee10_43c6, 0x51f4_e03c, 0x61b2_63d1);

/// Split a 64-byte buffer into four 16-byte lane references (mutable).
///
/// The four `&mut [u8; 16]` references borrow `state` mutably for the
/// duration of the caller's scope, allowing the per-lane AES round
/// primitives to operate on each lane independently without copies.
fn split_into_4_lanes_mut(state: &mut [u8; 64]) -> [&mut [u8; 16]; 4] {
    let (l01, l23) = state.split_at_mut(32);
    let (l0, l1) = l01.split_at_mut(16);
    let (l2, l3) = l23.split_at_mut(16);
    [
        l0.try_into().expect("16-byte split"),
        l1.try_into().expect("16-byte split"),
        l2.try_into().expect("16-byte split"),
        l3.try_into().expect("16-byte split"),
    ]
}

/// Split a 64-byte buffer into four 16-byte lane references (shared).
fn split_into_4_lanes(state: &[u8; 64]) -> [&[u8; 16]; 4] {
    let (l01, l23) = state.split_at(32);
    let (l0, l1) = l01.split_at(16);
    let (l2, l3) = l23.split_at(16);
    [
        l0.try_into().expect("16-byte split"),
        l1.try_into().expect("16-byte split"),
        l2.try_into().expect("16-byte split"),
        l3.try_into().expect("16-byte split"),
    ]
}

/// `AesGenerator1R` per [`specs.md`] §3.2 / `aes_hash.cpp:152
/// fillAes1Rx4<softAes>`.
///
/// Fills `output` with PRNG bytes derived from `state` using a single
/// AES round per 16 bytes of output in four parallel lanes:
///
/// - Lane 0 (`state[0..16]`): `equiv_inv_cipher_round` keyed by
///   [`AES_GEN_1R_KEY0`].
/// - Lane 1 (`state[16..32]`): `cipher_round` keyed by
///   [`AES_GEN_1R_KEY1`].
/// - Lane 2 (`state[32..48]`): `equiv_inv_cipher_round` keyed by
///   [`AES_GEN_1R_KEY2`].
/// - Lane 3 (`state[48..64]`): `cipher_round` keyed by
///   [`AES_GEN_1R_KEY3`].
///
/// One iteration produces 64 bytes of output; the state mutated by
/// that iteration is the input for the next. After the loop, the
/// final state is written back to `state`, allowing chained calls per
/// `aes_hash.cpp:197-200`.
///
/// `output.len()` must be a non-zero multiple of 64; zero is permitted
/// (no-op leaving `state` untouched, matching the C semantics where
/// the loop body never executes for `outputSize == 0`).
///
/// [`specs.md`]: ../../external/randomx-v2/doc/specs.md
///
/// # Panics
///
/// Panics if `output.len() % 64 != 0`. The C reference asserts the
/// same precondition; the Rust port elevates it to an always-on
/// `assert_eq!` because the wrong size is a logic bug at the call
/// site, never recoverable.
///
/// # REMOVE WHEN PHASE 2c WIRES THIS:
///
/// Phase 2c lands `Vm::scratchpad_init` as the production caller per
/// `RANDOMX_V2_PHASE2B_PLAN.md` §5.1 F1 dissolution table. Until then
/// the only callers are tests; the `dead_code` lint is silenced
/// narrowly here per `21-reversion-clause-discipline.mdc`.
#[allow(dead_code)]
pub(crate) fn fill_aes_1r_x4(state: &mut [u8; 64], output: &mut [u8]) {
    assert_eq!(
        output.len() % 64,
        0,
        "fill_aes_1r_x4 requires output.len() to be a multiple of 64; got {len}",
        len = output.len(),
    );
    let [s0, s1, s2, s3] = split_into_4_lanes_mut(state);
    for chunk in output.chunks_exact_mut(64) {
        equiv_inv_cipher_round(s0, &AES_GEN_1R_KEY0);
        cipher_round(s1, &AES_GEN_1R_KEY1);
        equiv_inv_cipher_round(s2, &AES_GEN_1R_KEY2);
        cipher_round(s3, &AES_GEN_1R_KEY3);
        chunk[0..16].copy_from_slice(s0);
        chunk[16..32].copy_from_slice(s1);
        chunk[32..48].copy_from_slice(s2);
        chunk[48..64].copy_from_slice(s3);
    }
}

/// `AesGenerator4R` per [`specs.md`] §3.3 / `aes_hash.cpp:220
/// fillAes4Rx4<softAes>`.
///
/// Fills `output` with PRNG bytes derived from `state` using four AES
/// rounds per 64 bytes of output in four parallel lanes. Lane 0/1 use
/// keys 0..3; lane 2/3 use keys 4..7; lanes 0/2 apply
/// `equiv_inv_cipher_round` and lanes 1/3 apply `cipher_round`:
///
/// ```text
/// for each 64-byte chunk:
///     for round in 0..4:
///         lane0 = equiv_inv_cipher_round(lane0, key[round + 0])
///         lane1 = cipher_round(           lane1, key[round + 0])
///         lane2 = equiv_inv_cipher_round(lane2, key[round + 4])
///         lane3 = cipher_round(           lane3, key[round + 4])
///     emit (lane0, lane1, lane2, lane3) as the next 64 bytes
/// ```
///
/// Note: per the C reference at `aes_hash.cpp:282`, the final state is
/// **not** written back. The Rust signature reflects this by taking
/// `state: &[u8; 64]` (shared, not mutable) — calls that need the
/// per-iteration state mutated in-place use [`fill_aes_1r_x4`]
/// instead.
///
/// `output.len()` must be a non-zero multiple of 64; zero is permitted
/// (no-op, matching the C semantics).
///
/// [`specs.md`]: ../../external/randomx-v2/doc/specs.md
///
/// # Panics
///
/// Panics if `output.len() % 64 != 0`.
///
/// # REMOVE WHEN PHASE 2c WIRES THIS:
///
/// Phase 2c lands `Vm::program_init` as the production caller per
/// `RANDOMX_V2_PHASE2B_PLAN.md` §5.1 F1 dissolution table. Until
/// then dead by construction.
#[allow(dead_code)]
pub(crate) fn fill_aes_4r_x4(state: &[u8; 64], output: &mut [u8]) {
    assert_eq!(
        output.len() % 64,
        0,
        "fill_aes_4r_x4 requires output.len() to be a multiple of 64; got {len}",
        len = output.len(),
    );
    let [s0_init, s1_init, s2_init, s3_init] = split_into_4_lanes(state);
    let mut s0 = *s0_init;
    let mut s1 = *s1_init;
    let mut s2 = *s2_init;
    let mut s3 = *s3_init;
    for chunk in output.chunks_exact_mut(64) {
        equiv_inv_cipher_round(&mut s0, &AES_GEN_4R_KEY0);
        cipher_round(&mut s1, &AES_GEN_4R_KEY0);
        equiv_inv_cipher_round(&mut s2, &AES_GEN_4R_KEY4);
        cipher_round(&mut s3, &AES_GEN_4R_KEY4);

        equiv_inv_cipher_round(&mut s0, &AES_GEN_4R_KEY1);
        cipher_round(&mut s1, &AES_GEN_4R_KEY1);
        equiv_inv_cipher_round(&mut s2, &AES_GEN_4R_KEY5);
        cipher_round(&mut s3, &AES_GEN_4R_KEY5);

        equiv_inv_cipher_round(&mut s0, &AES_GEN_4R_KEY2);
        cipher_round(&mut s1, &AES_GEN_4R_KEY2);
        equiv_inv_cipher_round(&mut s2, &AES_GEN_4R_KEY6);
        cipher_round(&mut s3, &AES_GEN_4R_KEY6);

        equiv_inv_cipher_round(&mut s0, &AES_GEN_4R_KEY3);
        cipher_round(&mut s1, &AES_GEN_4R_KEY3);
        equiv_inv_cipher_round(&mut s2, &AES_GEN_4R_KEY7);
        cipher_round(&mut s3, &AES_GEN_4R_KEY7);

        chunk[0..16].copy_from_slice(&s0);
        chunk[16..32].copy_from_slice(&s1);
        chunk[32..48].copy_from_slice(&s2);
        chunk[48..64].copy_from_slice(&s3);
    }
}

/// `AesHash1R` per [`specs.md`] §3.4 / `aes_hash.cpp:67
/// hashAes1Rx4<softAes>`.
///
/// Computes a 64-byte hash of `input` by treating it as a stream of
/// round keys and absorbing them into four lanes initialized from the
/// [`AES_HASH_1R_STATE0`]..[`AES_HASH_1R_STATE3`] spec constants. Two
/// extra rounds with [`AES_HASH_1R_XKEY0`] and [`AES_HASH_1R_XKEY1`]
/// then finalize the lanes before they are concatenated into `hash`.
///
/// Per-64-byte-chunk per-lane operations:
///
/// - Lane 0 absorbs `input[0..16]` via `cipher_round`.
/// - Lane 1 absorbs `input[16..32]` via `equiv_inv_cipher_round`.
/// - Lane 2 absorbs `input[32..48]` via `cipher_round`.
/// - Lane 3 absorbs `input[48..64]` via `equiv_inv_cipher_round`.
///
/// Finalization (after absorbing every chunk): for each `xkey` in
/// [[`AES_HASH_1R_XKEY0`], [`AES_HASH_1R_XKEY1`]], apply
/// `cipher_round(state0, xkey)`, `equiv_inv_cipher_round(state1,
/// xkey)`, `cipher_round(state2, xkey)`, `equiv_inv_cipher_round(state3,
/// xkey)`.
///
/// `input.len()` must be a non-zero multiple of 64. Empty input is
/// permitted in the C reference (the loop body simply does not
/// execute); the Rust port preserves that semantic and the resulting
/// hash is the two-extra-rounds-from-initial-state value.
///
/// [`specs.md`]: ../../external/randomx-v2/doc/specs.md
///
/// # Panics
///
/// Panics if `input.len() % 64 != 0`.
///
/// # REMOVE WHEN PHASE 2c WIRES THIS:
///
/// Phase 2c lands `Vm::scratchpad_fingerprint` as the production
/// caller per `RANDOMX_V2_PHASE2B_PLAN.md` §5.1 F1 dissolution
/// table. Until then dead by construction.
#[allow(dead_code)]
pub(crate) fn hash_aes_1r_x4(input: &[u8], hash: &mut [u8; 64]) {
    assert_eq!(
        input.len() % 64,
        0,
        "hash_aes_1r_x4 requires input.len() to be a multiple of 64; got {len}",
        len = input.len(),
    );
    let mut s0 = AES_HASH_1R_STATE0;
    let mut s1 = AES_HASH_1R_STATE1;
    let mut s2 = AES_HASH_1R_STATE2;
    let mut s3 = AES_HASH_1R_STATE3;
    for chunk in input.chunks_exact(64) {
        let chunk: &[u8; 64] = chunk
            .try_into()
            .expect("64-byte chunk from chunks_exact(64)");
        let [in0, in1, in2, in3] = split_into_4_lanes(chunk);
        cipher_round(&mut s0, in0);
        equiv_inv_cipher_round(&mut s1, in1);
        cipher_round(&mut s2, in2);
        equiv_inv_cipher_round(&mut s3, in3);
    }

    // Two extra rounds with xkey0 then xkey1 to achieve full
    // diffusion across the 64-byte output (aes_hash.cpp:109-121).
    for xkey in [&AES_HASH_1R_XKEY0, &AES_HASH_1R_XKEY1] {
        cipher_round(&mut s0, xkey);
        equiv_inv_cipher_round(&mut s1, xkey);
        cipher_round(&mut s2, xkey);
        equiv_inv_cipher_round(&mut s3, xkey);
    }

    hash[0..16].copy_from_slice(&s0);
    hash[16..32].copy_from_slice(&s1);
    hash[32..48].copy_from_slice(&s2);
    hash[48..64].copy_from_slice(&s3);
}

#[cfg(test)]
mod tests {
    use super::*;

    // SubBytes(0x00) = 0x63 (AES S-box[0]); InvSubBytes(0x00) = 0x52
    // (AES inverse S-box[0]). For a uniform state and uniform round
    // key, ShiftRows / InvShiftRows are no-ops (each row is uniform)
    // and MixColumns / InvMixColumns of a uniform column [c, c, c, c]
    // produce [c, c, c, c] (the column-mix matrices have rows that
    // GF(2^8)-sum to 0x01). The single-round result is therefore the
    // post-SubBytes value XORed with the (uniform) round key.

    /// AES single round on all-zero state + all-zero round key:
    /// `SubBytes([0; 16])` = `[0x63; 16]`; `MixColumns` and
    /// `ShiftRows` are uniform-preserving; `AddRoundKey` with zero
    /// key leaves the state at `[0x63; 16]`.
    #[test]
    fn cipher_round_zero_state_zero_key_yields_sbox_zero() {
        let mut state = [0u8; 16];
        let key = [0u8; 16];
        cipher_round(&mut state, &key);
        assert_eq!(state, [0x63u8; 16]);
    }

    /// AES single round preserves the round-key argument (in-place
    /// only on the state).
    #[test]
    fn cipher_round_does_not_mutate_round_key() {
        let mut state = [0x42u8; 16];
        let key = [0x99u8; 16];
        let key_before = key;
        cipher_round(&mut state, &key);
        assert_eq!(key, key_before);
    }

    /// Equivalent-inverse-cipher single round on all-zero state +
    /// all-zero round key: `InvSubBytes([0; 16])` = `[0x52; 16]`;
    /// `InvShiftRows` and `InvMixColumns` are uniform-preserving;
    /// `AddRoundKey` with zero key leaves the state at `[0x52; 16]`.
    #[test]
    fn equiv_inv_cipher_round_zero_state_zero_key_yields_inv_sbox_zero() {
        let mut state = [0u8; 16];
        let key = [0u8; 16];
        equiv_inv_cipher_round(&mut state, &key);
        assert_eq!(state, [0x52u8; 16]);
    }

    /// Equivalent-inverse-cipher single round preserves the
    /// round-key argument.
    #[test]
    fn equiv_inv_cipher_round_does_not_mutate_round_key() {
        let mut state = [0x42u8; 16];
        let key = [0x99u8; 16];
        let key_before = key;
        equiv_inv_cipher_round(&mut state, &key);
        assert_eq!(key, key_before);
    }

    /// The two round primitives are distinct functions: on a chosen
    /// non-uniform state with a zero key, `cipher_round` and
    /// `equiv_inv_cipher_round` must produce different outputs. This
    /// catches a future implementation swap that would silently route
    /// both wrappers to the same underlying primitive.
    ///
    /// Note: on degenerate inputs (e.g., all-zero state + all-zero
    /// key) the single-round dec-of-enc *is* the identity by S-box
    /// inversion + uniform preservation under MixColumns; that's a
    /// property of the math, not a wiring bug. The non-uniform input
    /// here avoids the degeneracy.
    #[test]
    fn cipher_round_and_equiv_inv_cipher_round_are_distinct() {
        let non_uniform: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let key = [0u8; 16];
        let mut enc_state = non_uniform;
        cipher_round(&mut enc_state, &key);
        let mut dec_state = non_uniform;
        equiv_inv_cipher_round(&mut dec_state, &key);
        assert_ne!(enc_state, dec_state);
    }

    // -----------------------------------------------------------------
    // pack_le_u32x4 packing sanity (catches a future endianness flip
    // before it propagates into all 14 spec constants).
    // -----------------------------------------------------------------

    /// `pack_le_u32x4(0xd798_3aad, 0xcc82_db47, 0x9fa8_56de, 0x92b5_2c0d)`
    /// reproduces the in-memory layout of `_mm_set_epi32(i3, i2, i1, i0)`
    /// followed by `_mm_store_si128` on a little-endian target. The
    /// expected bytes are: `[i0_LE | i1_LE | i2_LE | i3_LE]`.
    #[test]
    fn pack_le_u32x4_matches_mm_set_epi32_le_store_layout() {
        let packed = pack_le_u32x4(0xd798_3aad, 0xcc82_db47, 0x9fa8_56de, 0x92b5_2c0d);
        let expected: [u8; 16] = [
            // i0 = 0x92b5_2c0d → LE bytes
            0x0d, 0x2c, 0xb5, 0x92, //
            // i1 = 0x9fa8_56de → LE bytes
            0xde, 0x56, 0xa8, 0x9f, //
            // i2 = 0xcc82_db47 → LE bytes
            0x47, 0xdb, 0x82, 0xcc, //
            // i3 = 0xd798_3aad → LE bytes
            0xad, 0x3a, 0x98, 0xd7,
        ];
        assert_eq!(packed, expected);
    }

    /// Sanity check on one ported spec constant: `AES_HASH_1R_STATE0`
    /// equals the same expected layout (catches a typo in any of the
    /// 4 hex constants supplied to `pack_le_u32x4`).
    #[test]
    fn aes_hash_1r_state0_matches_packed_constant() {
        let expected: [u8; 16] = [
            0x0d, 0x2c, 0xb5, 0x92, 0xde, 0x56, 0xa8, 0x9f, 0x47, 0xdb, 0x82, 0xcc, 0xad, 0x3a,
            0x98, 0xd7,
        ];
        assert_eq!(AES_HASH_1R_STATE0, expected);
    }

    // -----------------------------------------------------------------
    // fill_aes_1r_x4 per-iteration smoke tests
    // -----------------------------------------------------------------

    /// `fill_aes_1r_x4` chains: drawing 64 bytes then another 64
    /// produces the same final state and the same total output as a
    /// single 128-byte draw. Catches a regression where the state
    /// writeback (or split-lane lifetime) drops modifications between
    /// iterations.
    #[test]
    fn fill_aes_1r_x4_chained_two_iters_equals_single_two_iter_call() {
        let initial_state = [0x42u8; 64];

        let mut state_a = initial_state;
        let mut out_a = [0u8; 128];
        fill_aes_1r_x4(&mut state_a, &mut out_a);

        let mut state_b = initial_state;
        let mut out_b1 = [0u8; 64];
        let mut out_b2 = [0u8; 64];
        fill_aes_1r_x4(&mut state_b, &mut out_b1);
        fill_aes_1r_x4(&mut state_b, &mut out_b2);

        assert_eq!(out_a[0..64], out_b1);
        assert_eq!(out_a[64..128], out_b2);
        assert_eq!(state_a, state_b);
    }

    /// Zero-length output is a valid no-op (matches the C reference
    /// where the loop body never executes for `outputSize == 0`); the
    /// state must be unchanged.
    #[test]
    fn fill_aes_1r_x4_zero_output_is_noop() {
        let mut state = [0x77u8; 64];
        let state_before = state;
        let mut out: [u8; 0] = [];
        fill_aes_1r_x4(&mut state, &mut out);
        assert_eq!(state, state_before);
    }

    /// `output.len() % 64 != 0` panics with the documented message.
    #[test]
    #[should_panic(expected = "fill_aes_1r_x4 requires output.len()")]
    fn fill_aes_1r_x4_non_multiple_of_64_panics() {
        let mut state = [0u8; 64];
        let mut out = [0u8; 65];
        fill_aes_1r_x4(&mut state, &mut out);
    }

    // -----------------------------------------------------------------
    // fill_aes_4r_x4 per-iteration smoke tests
    // -----------------------------------------------------------------

    /// `fill_aes_4r_x4` does NOT write back state (matches the C
    /// reference at `aes_hash.cpp:282`). The Rust signature takes
    /// `state: &[u8; 64]` (shared), so the impossibility of mutation
    /// is type-enforced; this test pins the same property at runtime
    /// against a hypothetical future signature regression.
    #[test]
    fn fill_aes_4r_x4_chained_two_64byte_iters_produce_same_output_each_iter() {
        let state = [0x42u8; 64];
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        fill_aes_4r_x4(&state, &mut out1);
        fill_aes_4r_x4(&state, &mut out2);
        // Same state input → same output (the state-non-writeback
        // property is what makes this hold; if state were mutated
        // across iterations, the outputs would differ).
        assert_eq!(out1, out2);
    }

    /// A single 128-byte draw from `fill_aes_4r_x4` produces a 128-
    /// byte output where the first 64 bytes match a single 64-byte
    /// draw from the same state (the internal state mutates across
    /// the loop body even though the function doesn't write back to
    /// the caller's `state`).
    #[test]
    fn fill_aes_4r_x4_128byte_first_chunk_matches_64byte_draw_from_same_state() {
        let state = [0x33u8; 64];
        let mut out_128 = [0u8; 128];
        fill_aes_4r_x4(&state, &mut out_128);
        let mut out_64 = [0u8; 64];
        fill_aes_4r_x4(&state, &mut out_64);
        assert_eq!(out_128[0..64], out_64);
        // The second chunk must differ from the first (the internal
        // state mutates across iterations).
        assert_ne!(out_128[0..64], out_128[64..128]);
    }

    /// Zero-length output is a valid no-op.
    #[test]
    fn fill_aes_4r_x4_zero_output_is_noop() {
        let state = [0u8; 64];
        let mut out: [u8; 0] = [];
        fill_aes_4r_x4(&state, &mut out);
        // Type system gives us nothing observable here; the test
        // exists to confirm no panic on the empty-output path.
    }

    /// `output.len() % 64 != 0` panics.
    #[test]
    #[should_panic(expected = "fill_aes_4r_x4 requires output.len()")]
    fn fill_aes_4r_x4_non_multiple_of_64_panics() {
        let state = [0u8; 64];
        let mut out = [0u8; 63];
        fill_aes_4r_x4(&state, &mut out);
    }

    // -----------------------------------------------------------------
    // hash_aes_1r_x4 per-iteration smoke tests
    // -----------------------------------------------------------------

    /// `hash_aes_1r_x4` is deterministic on a fixed input.
    #[test]
    fn hash_aes_1r_x4_is_deterministic() {
        let input = [0x11u8; 128];
        let mut h1 = [0u8; 64];
        let mut h2 = [0u8; 64];
        hash_aes_1r_x4(&input, &mut h1);
        hash_aes_1r_x4(&input, &mut h2);
        assert_eq!(h1, h2);
    }

    /// `hash_aes_1r_x4` distinguishes inputs that differ in a single
    /// bit. The two extra finalization rounds with `xkey0`+`xkey1`
    /// guarantee full diffusion; the hash output must differ across
    /// virtually every byte. The test asserts strict inequality only.
    #[test]
    fn hash_aes_1r_x4_distinguishes_single_bit_flip() {
        let input_a = [0u8; 64];
        let mut input_b = [0u8; 64];
        input_b[37] = 0x01;
        let mut h_a = [0u8; 64];
        let mut h_b = [0u8; 64];
        hash_aes_1r_x4(&input_a, &mut h_a);
        hash_aes_1r_x4(&input_b, &mut h_b);
        assert_ne!(h_a, h_b);
    }

    /// Empty input is a valid no-op: the loop body never executes,
    /// and the resulting hash is the two-extra-rounds finalization of
    /// the initial state constants.
    #[test]
    fn hash_aes_1r_x4_empty_input_yields_finalization_of_initial_state() {
        let mut h_empty = [0u8; 64];
        hash_aes_1r_x4(&[], &mut h_empty);
        // Two distinct empty-input calls must agree (determinism +
        // no-op-on-empty composition).
        let mut h_empty_again = [0u8; 64];
        hash_aes_1r_x4(&[], &mut h_empty_again);
        assert_eq!(h_empty, h_empty_again);
        // The hash must NOT equal the raw concatenation of the
        // initial-state constants (the two finalization rounds
        // diffuse them).
        let mut raw_initial = [0u8; 64];
        raw_initial[0..16].copy_from_slice(&AES_HASH_1R_STATE0);
        raw_initial[16..32].copy_from_slice(&AES_HASH_1R_STATE1);
        raw_initial[32..48].copy_from_slice(&AES_HASH_1R_STATE2);
        raw_initial[48..64].copy_from_slice(&AES_HASH_1R_STATE3);
        assert_ne!(h_empty, raw_initial);
    }

    /// `input.len() % 64 != 0` panics.
    #[test]
    #[should_panic(expected = "hash_aes_1r_x4 requires input.len()")]
    fn hash_aes_1r_x4_non_multiple_of_64_panics() {
        let input = [0u8; 33];
        let mut h = [0u8; 64];
        hash_aes_1r_x4(&input, &mut h);
    }

    // -----------------------------------------------------------------
    // Spec-vector parity tests against the v2 fork's reference at pin
    // `aaafe71`. Vectors live under `tests/vectors/reference/aes/` and
    // were emitted by `tests/vectors/reference/aes/_generator/gen.cpp`
    // calling `soft_aesenc` / `soft_aesdec` (round primitives) and the
    // `<softAes=true>` template instantiations of `hashAes1Rx4` /
    // `fillAes1Rx4` / `fillAes4Rx4` (composites). See each vector's
    // `.meta.txt` for provenance + the spec section it attests to.
    //
    // The constants below MUST stay in sync with the
    // `ROUND_INPUT_STATES` / `ROUND_INPUT_KEYS` / `CHAIN_INPUT_STATE` /
    // `CHAIN_INPUT_KEY` tables in `gen.cpp`. A drift means the .bin's
    // committed bytes were produced from different inputs and the
    // parity assertion is meaningless; the integration is auditable by
    // grepping the Rust constants and the gen.cpp tables side by side.
    // -----------------------------------------------------------------

    /// Three round-primitive input tuples mirroring `gen.cpp`'s
    /// `ROUND_INPUT_STATES` / `ROUND_INPUT_KEYS`. Used by both the
    /// `round_enc` and `round_dec` vectors; the .bin layout is the
    /// concatenation of `cipher_round` / `equiv_inv_cipher_round`
    /// outputs in this order.
    const ROUND_INPUTS: [([u8; 16], [u8; 16]); 3] = [
        // T1: uniform-byte state + uniform-byte key.
        ([0x42; 16], [0x99; 16]),
        // T2: sequential state, zero key.
        (
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            [0x00; 16],
        ),
        // T3: sequential state, offset-sequential key (all bytes
        // distinct between state and key).
        (
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            [
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                0x1e, 0x1f,
            ],
        ),
    ];

    /// Chained-pair initial state and shared round key mirroring
    /// `gen.cpp`'s `CHAIN_INPUT_STATE` / `CHAIN_INPUT_KEY`.
    const CHAIN_INPUT_STATE: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const CHAIN_INPUT_KEY: [u8; 16] = [0xa5; 16];

    /// `cipher_round` byte-for-byte against `soft_aesenc` for 3
    /// non-degenerate input tuples.
    /// Provenance: see sibling `round_enc.meta.txt`.
    #[test]
    fn vector_round_enc() {
        let expected: &[u8] = include_bytes!("../tests/vectors/reference/aes/round_enc.bin");
        assert_eq!(expected.len(), 3 * 16, "round_enc.bin size");
        for (i, (state, key)) in ROUND_INPUTS.iter().enumerate() {
            let mut actual = *state;
            cipher_round(&mut actual, key);
            let expected_slice: &[u8; 16] = expected[i * 16..(i + 1) * 16]
                .try_into()
                .expect("16-byte vector segment");
            assert_eq!(
                &actual, expected_slice,
                "cipher_round tuple {i} mismatch (state={state:02x?}, key={key:02x?})",
            );
        }
    }

    /// `equiv_inv_cipher_round` byte-for-byte against `soft_aesdec`
    /// for the same 3 input tuples.
    /// Provenance: see sibling `round_dec.meta.txt`.
    #[test]
    fn vector_round_dec() {
        let expected: &[u8] = include_bytes!("../tests/vectors/reference/aes/round_dec.bin");
        assert_eq!(expected.len(), 3 * 16, "round_dec.bin size");
        for (i, (state, key)) in ROUND_INPUTS.iter().enumerate() {
            let mut actual = *state;
            equiv_inv_cipher_round(&mut actual, key);
            let expected_slice: &[u8; 16] = expected[i * 16..(i + 1) * 16]
                .try_into()
                .expect("16-byte vector segment");
            assert_eq!(
                &actual, expected_slice,
                "equiv_inv_cipher_round tuple {i} mismatch (state={state:02x?}, key={key:02x?})",
            );
        }
    }

    /// F6 supplement: 3 rounds of `cipher_round` chained against the
    /// same key; intermediate state pinned after each round. Catches
    /// the case where equivalent-inverse and FIPS-197 standard inverse
    /// forms happen to agree on degenerate inputs but diverge by
    /// round 2 (per `RANDOMX_V2_PHASE2B_PLAN.md` §5.6).
    /// Provenance: see sibling `chained_enc.meta.txt`.
    #[test]
    fn vector_chained_enc_3rounds() {
        let expected: &[u8] = include_bytes!("../tests/vectors/reference/aes/chained_enc.bin");
        assert_eq!(expected.len(), 3 * 16, "chained_enc.bin size");
        let mut state = CHAIN_INPUT_STATE;
        for round in 0..3 {
            cipher_round(&mut state, &CHAIN_INPUT_KEY);
            let expected_slice: &[u8; 16] = expected[round * 16..(round + 1) * 16]
                .try_into()
                .expect("16-byte chained-round segment");
            assert_eq!(
                &state, expected_slice,
                "cipher_round chained round {round} state mismatch",
            );
        }
    }

    /// F6 supplement: 3 rounds of `equiv_inv_cipher_round` chained.
    /// Provenance: see sibling `chained_dec.meta.txt`.
    #[test]
    fn vector_chained_dec_3rounds() {
        let expected: &[u8] = include_bytes!("../tests/vectors/reference/aes/chained_dec.bin");
        assert_eq!(expected.len(), 3 * 16, "chained_dec.bin size");
        let mut state = CHAIN_INPUT_STATE;
        for round in 0..3 {
            equiv_inv_cipher_round(&mut state, &CHAIN_INPUT_KEY);
            let expected_slice: &[u8; 16] = expected[round * 16..(round + 1) * 16]
                .try_into()
                .expect("16-byte chained-round segment");
            assert_eq!(
                &state, expected_slice,
                "equiv_inv_cipher_round chained round {round} state mismatch",
            );
        }
    }

    /// `fill_aes_1r_x4` byte-for-byte against
    /// `fillAes1Rx4<softAes=true>` at iters=4, initial state
    /// `[0x42; 64]`. Vector layout: `output[256]` ‖ `final_state[64]`,
    /// so this test asserts both the produced PRNG bytes *and* the
    /// state-writeback contract (`aes_hash.cpp:197-200`).
    /// Provenance: see sibling `gen_1r_state42_iters4.meta.txt`.
    #[test]
    fn vector_gen_1r_state42_iters4() {
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/aes/gen_1r_state42_iters4.bin");
        assert_eq!(expected.len(), 256 + 64, "gen_1r_state42_iters4.bin size");
        let mut state = [0x42u8; 64];
        let mut output = [0u8; 256];
        fill_aes_1r_x4(&mut state, &mut output);
        assert_eq!(
            output.as_slice(),
            &expected[0..256],
            "fill_aes_1r_x4 output bytes mismatch",
        );
        assert_eq!(
            &state,
            &expected[256..320],
            "fill_aes_1r_x4 final-state writeback mismatch",
        );
    }

    /// `fill_aes_4r_x4` byte-for-byte against
    /// `fillAes4Rx4<softAes=true>` at iters=4, initial state
    /// `[0x33; 64]`. No `final_state` segment — `fillAes4Rx4` does
    /// not write back state (`aes_hash.cpp:282`), and the Rust
    /// signature's `&[u8; 64]` (shared) parameter pins this at the
    /// type level.
    /// Provenance: see sibling `gen_4r_state33_iters4.meta.txt`.
    #[test]
    fn vector_gen_4r_state33_iters4() {
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/aes/gen_4r_state33_iters4.bin");
        assert_eq!(expected.len(), 256, "gen_4r_state33_iters4.bin size");
        let state = [0x33u8; 64];
        let mut output = [0u8; 256];
        fill_aes_4r_x4(&state, &mut output);
        assert_eq!(
            output.as_slice(),
            expected,
            "fill_aes_4r_x4 output bytes mismatch",
        );
    }

    /// `hash_aes_1r_x4` byte-for-byte against
    /// `hashAes1Rx4<softAes=true>` on a uniform 128-byte input.
    /// Exercises both the absorb-loop body (2 chunks) and the
    /// two-extra-rounds finalisation.
    /// Provenance: see sibling `hash_1r_uniform128.meta.txt`.
    #[test]
    fn vector_hash_1r_uniform128() {
        let expected: &[u8] =
            include_bytes!("../tests/vectors/reference/aes/hash_1r_uniform128.bin");
        assert_eq!(expected.len(), 64, "hash_1r_uniform128.bin size");
        let input = [0x11u8; 128];
        let mut hash = [0u8; 64];
        hash_aes_1r_x4(&input, &mut hash);
        assert_eq!(
            hash.as_slice(),
            expected,
            "hash_aes_1r_x4 uniform-input digest mismatch",
        );
    }

    /// `hash_aes_1r_x4` byte-for-byte against
    /// `hashAes1Rx4<softAes=true>` on the empty-input boundary case.
    /// The absorb loop body never executes; the digest is the
    /// finalisation of the initial-state spec constants alone. This
    /// pins the 6 spec constants (`AES_HASH_1R_STATE0..STATE3`,
    /// `AES_HASH_1R_XKEY0`, `AES_HASH_1R_XKEY1`) via their byte-level
    /// effect on the empty-input digest.
    /// Provenance: see sibling `hash_1r_empty.meta.txt`.
    #[test]
    fn vector_hash_1r_empty() {
        let expected: &[u8] = include_bytes!("../tests/vectors/reference/aes/hash_1r_empty.bin");
        assert_eq!(expected.len(), 64, "hash_1r_empty.bin size");
        let mut hash = [0u8; 64];
        hash_aes_1r_x4(&[], &mut hash);
        assert_eq!(
            hash.as_slice(),
            expected,
            "hash_aes_1r_x4 empty-input digest mismatch",
        );
    }
}
