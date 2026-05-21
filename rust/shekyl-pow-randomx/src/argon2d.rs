// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Argon2d "memory fill" primitive for `Cache::derive`.
//!
//! RandomX v2 Cache derivation per
//! [`external/randomx-v2/doc/specs.md`](../../../external/randomx-v2/doc/specs.md)
//! §7.1: a 256 MiB Argon2d run with the parameters in Table 7.1.1, where
//! "the finalizer and output calculation steps of Argon2 are omitted;
//! the output is the filled memory array." This file is the inside of
//! that step. Phase 2e's `Cache::derive` will own the buffer allocation
//! and call [`fill_cache`].
//!
//! # Dependency disposition (per `.cursor/rules/17-dependency-discipline.mdc`)
//!
//! - **Workspace state.** `argon2 = "0.5"` is already a workspace
//!   transitive via `shekyl-crypto-pq`'s wallet-file Argon2id usage. No
//!   new dependency added; the direct dep on this crate is declared with
//!   the same `(version, default-features, features)` shape so Cargo's
//!   feature unification produces a single argon2 build with
//!   `alloc + zeroize`.
//! - **API existence.** [`Argon2::fill_memory`] (argon2-0.5.3
//!   `src/lib.rs:268–318`) takes `(&self, pwd, salt, &mut impl
//!   AsMut<[Block]>)` and returns `Result<(), Error>`. Its rustdoc
//!   reads: "Use a password and associated parameters only to fill the
//!   given memory blocks. This method omits the calculation of a hash
//!   and can be used when only the filled memory is required." This is
//!   exactly the spec §7.1 omit-finalizer surface.
//! - **Property existence.** Internally, `fill_memory` calls
//!   `initial_hash(pwd, salt, &[])`; that function (argon2-0.5.3
//!   `src/lib.rs:498–540`) hashes the four `u32` parameters
//!   `(p_cost, output_len, m_cost, t_cost)` in little-endian, then
//!   `version | type | pwd_len | pwd | salt_len | salt | secret_len |
//!   secret | ad_len | ad` — with `output_len = 0` taken from the
//!   `Params { output_len: None, .. }` case (line 521–528). This
//!   reproduces `external/randomx-v2/src/dataset.cpp:76`'s
//!   `context.outlen = 0`, so the H0 prehash matches the C reference
//!   byte-for-byte. The hashing primitive itself is Blake2b-512 (RFC
//!   7693), matching the v2 fork's `blake2/blake2b.c`.
//! - **Feature-flag plumbing.** `alloc` is required by `fill_memory`
//!   (the function allocates an internal `Vec` for its working state;
//!   see `src/lib.rs:285`). `zeroize` activates `impl Zeroize for
//!   Block` (`src/block.rs:122–135`). Both are enabled in this crate's
//!   `Cargo.toml` direct dep and match `shekyl-crypto-pq`'s
//!   declaration; the unified feature set is `alloc + zeroize`
//!   regardless of which crate declares which.
//!
//! # Algorithm + version pinning
//!
//! - [`Algorithm::Argon2d`] = discriminant `0` (`src/algorithm.rs:54`),
//!   matching `external/randomx-v2/src/argon2.h:219` `Argon2_d = 0`.
//! - [`Version::V0x13`] = `0x13` (`src/version.rs`), matching
//!   `external/randomx-v2/src/argon2.h:228` `ARGON2_VERSION_NUMBER =
//!   ARGON2_VERSION_13`.
//!
//! # Threat-model note (per `.cursor/rules/35-secure-memory.mdc`)
//!
//! The Cache content is **public**: it is a deterministic function of
//! `key` (which is itself a block-header value, public by construction).
//! No constant-time discipline applies to this fill, and zeroization of
//! the filled `blocks` is defense-in-depth (not load-bearing) for our
//! threat model. The `zeroize` feature is enabled to keep the feature
//! union identical to `shekyl-crypto-pq`'s (avoiding a duplicate argon2
//! build), not because the cache itself requires wipe-on-drop.

use argon2::{Algorithm, Argon2, Block, Params, Version};

/// Number of 1 KiB Argon2 blocks in the RandomX Cache.
///
/// From `external/randomx-v2/doc/configuration.md` (pin `aaafe71`):
/// `RANDOMX_ARGON_MEMORY = 262144`. Mirrors
/// `external/randomx-v2/src/configuration.h` and is consumed by
/// `dataset.cpp:87` (`context.m_cost = RANDOMX_ARGON_MEMORY`).
pub(crate) const RANDOMX_ARGON_MEMORY: u32 = 262_144;

/// Number of Argon2d iteration passes for Cache initialization.
///
/// From configuration.md: `RANDOMX_ARGON_ITERATIONS = 3`.
pub(crate) const RANDOMX_ARGON_ITERATIONS: u32 = 3;

/// Number of parallel lanes for Cache initialization.
///
/// From configuration.md: `RANDOMX_ARGON_LANES = 1`.
pub(crate) const RANDOMX_ARGON_LANES: u32 = 1;

/// Argon2 salt used by Cache initialization.
///
/// From configuration.md: `RANDOMX_ARGON_SALT = "RandomX\x03"` (8
/// bytes — ASCII "RandomX" followed by the v2 salt-version byte
/// `0x03`). The salt-version byte distinguishes RandomX v1 (`0x02`)
/// from v2 (`0x03`); per `docs/design/RANDOMX_V2_PLAN.md` "Permanent
/// architectural decisions" §1, this crate accepts only the v2 salt.
pub(crate) const RANDOMX_ARGON_SALT: &[u8] = b"RandomX\x03";

/// Required `blocks` length for [`fill_cache`].
///
/// Equal to [`RANDOMX_ARGON_MEMORY`] in single-lane mode. Each
/// `argon2::Block` is `Block::SIZE = 1024` bytes, so the total
/// allocation is 256 MiB.
pub(crate) const RANDOMX_ARGON_BLOCKS: usize = RANDOMX_ARGON_MEMORY as usize;

/// Compile-time-validated Argon2 parameters for the RandomX Cache fill.
///
/// `argon2::Params::new` is `const fn`; if any of the `RANDOMX_ARGON_*`
/// constants above falls outside argon2 0.5.x valid ranges, this fails
/// to compile rather than panicking at runtime. Verified at source
/// against argon2-0.5.3 (`src/params.rs:107–155`):
/// `MIN_M_COST = 8 ≤ 262144 ≤ MAX_M_COST = u32::MAX`;
/// `MIN_T_COST = 1 ≤ 3 ≤ MAX_T_COST = u32::MAX`;
/// `MIN_P_COST = 1 ≤ 1 ≤ MAX_P_COST = 0xFFFFFF`;
/// `output_len = None` selects the omit-finalizer path.
const PARAMS: Params = match Params::new(
    RANDOMX_ARGON_MEMORY,
    RANDOMX_ARGON_ITERATIONS,
    RANDOMX_ARGON_LANES,
    None,
) {
    Ok(p) => p,
    Err(_) => panic!(
        "RANDOMX_ARGON_* constants out of range for argon2 0.5 \
         (verified at source; this branch is statically unreachable)",
    ),
};

/// Fill `blocks` with the RandomX v2 Cache content derived from `key`.
///
/// Wraps [`argon2::Argon2::fill_memory`] with the RandomX-specific
/// parameter set `(Argon2d, v0x13, m_cost = 262144, t_cost = 3,
/// p_cost = 1, salt = "RandomX\x03", output_len = None)` per
/// `external/randomx-v2/doc/specs.md` §7.1. The finalizer and
/// output-calculation steps of Argon2 are omitted; the output is the
/// filled memory array.
///
/// # Arguments
///
/// - `key`: the RandomX seedhash (a block-header value, up to ~64 bytes
///   in practice; argon2's `MAX_PWD_LEN = u32::MAX` is far larger than
///   anything RandomX produces).
/// - `blocks`: caller-allocated buffer; **must** have exactly
///   [`RANDOMX_ARGON_BLOCKS`] elements (262144 = 256 MiB). Wrong size
///   is a programmer error and panics.
///
/// # Panics
///
/// Panics if `blocks.len() != RANDOMX_ARGON_BLOCKS`. This is a logic
/// bug at the call site, not a recoverable error; the type system
/// would prevent it if Rust supported a `&mut [Block;
/// RANDOMX_ARGON_BLOCKS]` parameter without forcing the caller into
/// an awkward 256-MiB heap-allocation dance for the `[Block; N]`
/// type. Phase 2e's `Cache::derive` is the single production caller
/// and will allocate `vec![Block::default(); RANDOMX_ARGON_BLOCKS]`.
pub(crate) fn fill_cache(key: &[u8], blocks: &mut [Block]) {
    assert_eq!(
        blocks.len(),
        RANDOMX_ARGON_BLOCKS,
        "fill_cache requires exactly RANDOMX_ARGON_BLOCKS blocks \
         ({RANDOMX_ARGON_BLOCKS} = 256 MiB); got {actual}",
        actual = blocks.len(),
    );

    let argon2 = Argon2::new(Algorithm::Argon2d, Version::V0x13, PARAMS);
    argon2.fill_memory(key, RANDOMX_ARGON_SALT, blocks).expect(
        "Argon2::fill_memory cannot fail here: PARAMS validated at compile time; \
             blocks length matches m_cost * p_cost by assertion above; \
             key length is within argon2 0.5 valid range \
             (≤ MAX_PWD_LEN = u32::MAX); salt is 8 bytes \
             (≥ MIN_SALT_LEN = 8)",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constants must match the values published in
    /// `external/randomx-v2/doc/configuration.md` at pin `aaafe71`. A
    /// mismatch here means the spec moved and this crate's Cache
    /// derivation is out of sync with the consensus reference.
    #[test]
    fn constants_match_spec() {
        assert_eq!(RANDOMX_ARGON_MEMORY, 262_144);
        assert_eq!(RANDOMX_ARGON_ITERATIONS, 3);
        assert_eq!(RANDOMX_ARGON_LANES, 1);
        assert_eq!(RANDOMX_ARGON_SALT, b"RandomX\x03");
        assert_eq!(RANDOMX_ARGON_SALT.len(), 8);
        assert_eq!(RANDOMX_ARGON_BLOCKS, 262_144);
    }

    /// The compile-time-validated `PARAMS` instance must expose the
    /// spec values through its accessors. Sanity check that `Params`
    /// hasn't silently restructured between argon2 0.5 point releases
    /// in a way that loses parameter fidelity.
    #[test]
    fn params_match_spec() {
        assert_eq!(PARAMS.m_cost(), RANDOMX_ARGON_MEMORY);
        assert_eq!(PARAMS.t_cost(), RANDOMX_ARGON_ITERATIONS);
        assert_eq!(PARAMS.p_cost(), RANDOMX_ARGON_LANES);
        assert_eq!(PARAMS.output_len(), None);
        assert_eq!(PARAMS.block_count(), RANDOMX_ARGON_BLOCKS);
    }

    /// `fill_cache` must reject a wrong-sized buffer before reaching
    /// `argon2::fill_memory`. The assertion produces a clearer error
    /// message than argon2's internal `MismatchingBlocks` would.
    #[test]
    #[should_panic(expected = "fill_cache requires exactly RANDOMX_ARGON_BLOCKS blocks")]
    fn wrong_sized_blocks_panics() {
        // 64 blocks = 64 KiB; small enough that even if the assertion
        // didn't fire and argon2 tried to use it, allocation is cheap.
        let mut blocks: Vec<Block> = vec![Block::default(); 64];
        fill_cache(b"any key", &mut blocks);
    }
}
