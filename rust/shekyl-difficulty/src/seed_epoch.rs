// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RandomX seed-epoch schedule (CEN-D3): which block height's hash seeds
//! the cache used to verify a given height.
//!
//! Pure parameterized arithmetic, ported from the inherited C
//! `rx_seedheight`/`rx_seedheights` (formerly `src/crypto/rx-slow-hash.c`)
//! and hosted here — beside LWMA-1, the timestamp rule and `check_hash` —
//! because it is **consensus arithmetic the validator evaluates**, not
//! part of the hashing engine: `shekyl-chain-rules` derives the seed height
//! from the connecting height and reads the seed block's identity through
//! its `ChainView` (DRS-E6 slice 2, CEN-D3), and the engine crate
//! `shekyl-pow-randomx` never called it (it hosted the schedule for the FFI
//! until 2026-09-19). One implementation, in the crate whose job is
//! consensus arithmetic; this crate's zero-dependency posture holds.
//!
//! The `SEEDHASH_EPOCH_*` environment lever (the regtest/FAKECHAIN
//! fast-epoch override, with its C-`atoi` clamps) lives at the FFI
//! boundary in `shekyl-ffi::pow_randomx_ffi`, which reads the environment
//! once and passes the clamped parameters in. **The validator reads no
//! environment** (`CHAIN_RULES_SLICE_2.md` F5; the CEN-D3 pass condition in
//! `CONSENSUS_STORE_RECONCILIATION.md` §5.4.1): it calls [`seedheight`]
//! with the two constants below at every nettype.
//!
//! Overflow: `height + lag` in [`next_seedheight`] uses wrapping
//! arithmetic, matching C `uint64_t` wraparound (unreachable for real
//! chain heights; matters only for hostile values fed straight to the C
//! ABI).

/// Mainnet epoch length in blocks. Must equal
/// `BLOCKS_SYNCHRONIZING_MAX_COUNT` in `cryptonote_config.h` (a unit
/// test in `tests/unit_tests/seed_epoch.cpp` pins the two together across
/// the FFI).
pub const SEEDHASH_EPOCH_BLOCKS: u64 = 2048;

/// Mainnet seed lag in blocks.
pub const SEEDHASH_EPOCH_LAG: u64 = 64;

/// The height whose block hash seeds the cache for verifying `height`,
/// under an epoch schedule of `blocks` per epoch with `lag` blocks of
/// seed lag: `0` for `height ≤ blocks + lag`, else
/// `(height − lag − 1) & !(blocks − 1)`. The mainnet schedule is
/// ([`SEEDHASH_EPOCH_BLOCKS`], [`SEEDHASH_EPOCH_LAG`]); the FFI passes
/// clamped overrides on FAKECHAIN.
#[must_use]
pub const fn seedheight(height: u64, blocks: u64, lag: u64) -> u64 {
    if height <= blocks + lag {
        0
    } else {
        (height - lag - 1) & !(blocks - 1)
    }
}

/// The *upcoming* seed height: `seedheight(height + lag)`, for the
/// RPC next-seed pre-announce path (the second output of the retired
/// C `rx_seedheights`). Wrapping add matches C `uint64_t` overflow
/// (reachable only via hostile heights at the C ABI).
#[must_use]
pub const fn next_seedheight(height: u64, blocks: u64, lag: u64) -> u64 {
    seedheight(height.wrapping_add(lag), blocks, lag)
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: u64 = SEEDHASH_EPOCH_BLOCKS;
    const L: u64 = SEEDHASH_EPOCH_LAG;

    /// Pure re-statement of the C formula, used to cross-check the
    /// boundary sweep with explicit constants.
    fn c_formula(height: u64, blocks: u64, lag: u64) -> u64 {
        if height <= blocks + lag {
            0
        } else {
            (height - lag - 1) & !(blocks - 1)
        }
    }

    #[test]
    fn mainnet_schedule_matches_c_formula() {
        // Boundary sweep around the first three epochs plus large heights,
        // at the explicit mainnet constants.
        for h in (0..=3 * B + 130).chain([u64::MAX - 65, u64::MAX]) {
            assert_eq!(seedheight(h, B, L), c_formula(h, B, L), "height {h}");
        }
    }

    #[test]
    fn mainnet_pinned_values() {
        // Pinned expectations at the default 2048/64 schedule (KAT-style;
        // any change here is a consensus change).
        assert_eq!(seedheight(0, B, L), 0);
        assert_eq!(seedheight(2112, B, L), 0); // == blocks + lag: still genesis seed
        assert_eq!(seedheight(2113, B, L), 2048); // first rollover
        assert_eq!(seedheight(4160, B, L), 2048); // == 2*blocks + lag
        assert_eq!(seedheight(4161, B, L), 4096);
        assert_eq!(next_seedheight(2100, B, L), 2048); // lag window pre-announces
        assert_eq!(seedheight(2100, B, L), 0);
    }

    #[test]
    fn next_seedheight_wraps_like_c_uint64() {
        // C computed seedheight(height + lag) with uint64_t wraparound;
        // the port must not abort (workspace pins overflow-checks=true).
        assert_eq!(next_seedheight(u64::MAX, B, L), seedheight(L - 1, B, L));
        assert_eq!(next_seedheight(u64::MAX, B, L), 0);
        assert_eq!(
            next_seedheight(u64::MAX - L, B, L),
            seedheight(u64::MAX, B, L)
        );
    }
}
