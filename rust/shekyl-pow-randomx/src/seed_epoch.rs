// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RandomX seed-epoch schedule: which block height's hash seeds the
//! cache used to verify a given height.
//!
//! Ported from the inherited C `rx_seedheight`/`rx_seedheights`
//! (formerly `src/crypto/rx-slow-hash.c`). **This module is pure
//! parameterized arithmetic** — the crate's isolation charter (lib.rs
//! "Isolation invariants", enforced by
//! `scripts/ci/check_randomx_crate_invariants.sh`) bans ambient
//! runtime state here, so the `SEEDHASH_EPOCH_*` environment lever
//! (the regtest/FAKECHAIN fast-epoch override) lives at the FFI
//! boundary in `shekyl-ffi::pow_randomx_ffi`, which reads the
//! environment once and passes the clamped parameters in.
//!
//! # C-parity contract (precise, not "bit-for-bit")
//!
//! The schedule formula and the clamp *ranges* are byte-identical to
//! the retired C for every ASCII override value that fits in a C
//! `int`, and for all absent/garbage/negative values (both sides land
//! on the defaults). Three deliberate edge deltas from glibc `atoi`,
//! all regtest-lever-only and all measured against the C before
//! deletion:
//!
//! - values ≥ 2³²: glibc `atoi` is `(int)strtol` and truncates
//!   mod 2³² (measured: `atoi("4294967312") == 16`), so the old C
//!   *accepted* absurd wrapped overrides; this port parses the full
//!   number and clamps to the default instead.
//! - non-ASCII whitespace: C `isspace` skips ASCII only; this port
//!   does the same (`is_ascii_whitespace`), but note a plain
//!   `str::trim_start` would have accepted NBSP-prefixed values the
//!   C rejected — deliberately not used.
//! - non-UTF-8 env bytes: treated as absent (C parsed the raw byte
//!   prefix). The env read lives in `shekyl-ffi`; see there.
//!
//! Overflow: `height + lag` uses wrapping arithmetic, matching C
//! `uint64_t` wraparound (unreachable for real chain heights; matters
//! only for hostile values fed straight to the C ABI).

/// Mainnet epoch length in blocks. Must equal
/// `BLOCKS_SYNCHRONIZING_MAX_COUNT` in `cryptonote_config.h` (a unit
/// test in `tests/unit_tests/` pins the two together across the FFI).
pub const SEEDHASH_EPOCH_BLOCKS: u64 = 2048;
/// Mainnet seed lag in blocks.
pub const SEEDHASH_EPOCH_LAG: u64 = 64;

/// Clamp a raw `SEEDHASH_EPOCH_LAG` override exactly as the C `atoi`
/// path did for in-range values: absent → default; unparsable → 0 →
/// fails power-of-two → default; parsed but `> default` or not a
/// power of two → default.
#[must_use]
pub fn clamp_lag(raw: Option<&str>) -> u64 {
    match raw {
        None => SEEDHASH_EPOCH_LAG,
        Some(s) => {
            let lag = parse_atoi(s);
            if lag > SEEDHASH_EPOCH_LAG || !lag.is_power_of_two() {
                SEEDHASH_EPOCH_LAG
            } else {
                lag
            }
        }
    }
}

/// Clamp a raw `SEEDHASH_EPOCH_BLOCKS` override exactly as the C did:
/// `< 2`, `> default`, or not a power of two → default.
#[must_use]
pub fn clamp_blocks(raw: Option<&str>) -> u64 {
    match raw {
        None => SEEDHASH_EPOCH_BLOCKS,
        Some(s) => {
            let blocks = parse_atoi(s);
            if !(2..=SEEDHASH_EPOCH_BLOCKS).contains(&blocks) || !blocks.is_power_of_two() {
                SEEDHASH_EPOCH_BLOCKS
            } else {
                blocks
            }
        }
    }
}

/// C `atoi` semantics for the value range these knobs accept: ASCII
/// whitespace skipped (C-locale `isspace` — NOT Unicode whitespace),
/// optional sign, digits until the first non-digit; no digits → 0;
/// negative → 0 (no in-`int`-range negative wraps to an accepted
/// power of two, so outcomes match C on every branch). See the module
/// doc for the deliberate ≥2³² delta.
fn parse_atoi(s: &str) -> u64 {
    let t = s.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let t = t.strip_prefix('+').unwrap_or(t);
    if t.starts_with('-') {
        return 0;
    }
    let end = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    t[..end].parse::<u64>().unwrap_or(0)
}

/// The height whose block hash seeds the cache for verifying `height`,
/// under an epoch schedule of `blocks` per epoch with `lag` blocks of
/// seed lag. Callers pass parameters that have been through
/// [`clamp_blocks`]/[`clamp_lag`] (the FFI layer does this once per
/// process); the mainnet schedule is
/// ([`SEEDHASH_EPOCH_BLOCKS`], [`SEEDHASH_EPOCH_LAG`]).
#[must_use]
pub fn seedheight(height: u64, blocks: u64, lag: u64) -> u64 {
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
pub fn next_seedheight(height: u64, blocks: u64, lag: u64) -> u64 {
    seedheight(height.wrapping_add(lag), blocks, lag)
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: u64 = SEEDHASH_EPOCH_BLOCKS;
    const L: u64 = SEEDHASH_EPOCH_LAG;

    /// Pure re-statement of the C formula, used to cross-check the
    /// boundary sweep with explicit (non-env) constants.
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
        // at the explicit mainnet constants (env-independent).
        for h in (0..=3 * B + 130).chain([u64::MAX - 65, u64::MAX]) {
            assert_eq!(seedheight(h, B, L), c_formula(h, B, L), "height {h}");
        }
    }

    #[test]
    fn mainnet_pinned_values() {
        // Pinned expectations at the default 2048/64 schedule (KAT-style;
        // any change here is a consensus change). Env-independent: the
        // constants are passed explicitly.
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

    #[test]
    fn lag_clamp_matches_c_atoi_semantics() {
        assert_eq!(clamp_lag(None), 64);
        assert_eq!(clamp_lag(Some("16")), 16);
        assert_eq!(clamp_lag(Some("64")), 64);
        assert_eq!(clamp_lag(Some("128")), 64); // > default → default
        assert_eq!(clamp_lag(Some("3")), 64); // !pow2 → default
        assert_eq!(clamp_lag(Some("0")), 64); // 0 fails pow2
        assert_eq!(clamp_lag(Some("garbage")), 64); // atoi → 0 → default
        assert_eq!(clamp_lag(Some("-8")), 64);
        assert_eq!(clamp_lag(Some("  8tail")), 8); // ASCII-ws + prefix parse
        assert_eq!(clamp_lag(Some("+16")), 16);
        // Deliberate deltas from glibc atoi (module doc): mod-2^32 wrap
        // values are rejected to default rather than wrapped-accepted,
        // and non-ASCII whitespace is NOT skipped.
        assert_eq!(clamp_lag(Some("4294967312")), 64); // C accepted as 16
        assert_eq!(clamp_lag(Some("\u{00A0}16")), 64); // NBSP: C rejected too
        assert_eq!(clamp_lag(Some("99999999999999999999")), 64); // > u64: parse fails → default (C: LONG_MAX→(int)→-1→default)
    }

    #[test]
    fn blocks_clamp_matches_c_atoi_semantics() {
        assert_eq!(clamp_blocks(None), 2048);
        assert_eq!(clamp_blocks(Some("64")), 64);
        assert_eq!(clamp_blocks(Some("2")), 2);
        assert_eq!(clamp_blocks(Some("1")), 2048); // < 2 → default
        assert_eq!(clamp_blocks(Some("4096")), 2048); // > default → default
        assert_eq!(clamp_blocks(Some("1000")), 2048); // !pow2 → default
        assert_eq!(clamp_blocks(Some("x")), 2048);
    }
}
