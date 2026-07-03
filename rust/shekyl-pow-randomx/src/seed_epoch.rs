// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RandomX seed-epoch schedule: which block height's hash seeds the
//! cache used to verify a given height.
//!
//! Ported from the inherited C `rx_seedheight`/`rx_seedheights`
//! (formerly `src/crypto/rx-slow-hash.c`) with behavior preserved
//! bit-for-bit, including the `SEEDHASH_EPOCH_LAG` /
//! `SEEDHASH_EPOCH_BLOCKS` environment overrides — the regtest /
//! FAKECHAIN lever for fast epochs (`cryptonote_core.cpp` reads the
//! same variable for its own epoch bookkeeping, so both sides of the
//! FFI see one process environment). Like the C statics they replace,
//! the overrides are read **once** per process and cached.
//!
//! The consensus schedule (mainnet defaults): epoch length 2048
//! blocks, seed lag 64. `seedheight(h) = 0` for the first
//! `2048 + 64` blocks, then the last epoch boundary at least `lag+1`
//! blocks behind `h`. Overrides are clamped exactly as the C did:
//! non-power-of-two or out-of-range values fall back to the defaults
//! (`atoi` garbage parsed as 0, which fails the power-of-two check).

use std::sync::OnceLock;

/// Mainnet epoch length in blocks. Must equal
/// `BLOCKS_SYNCHRONIZING_MAX_COUNT` in `cryptonote_config.h`.
const SEEDHASH_EPOCH_BLOCKS: u64 = 2048;
/// Mainnet seed lag in blocks.
const SEEDHASH_EPOCH_LAG: u64 = 64;

fn is_power_of_2(n: u64) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

/// Clamp a raw `SEEDHASH_EPOCH_LAG` override exactly as the C `atoi`
/// path did: absent → default; unparsable → 0 → fails power-of-two →
/// default; parsed but `> default` or not a power of two → default.
fn clamp_lag(raw: Option<&str>) -> u64 {
    match raw {
        None => SEEDHASH_EPOCH_LAG,
        Some(s) => {
            let lag = parse_atoi(s);
            if lag > SEEDHASH_EPOCH_LAG || !is_power_of_2(lag) {
                SEEDHASH_EPOCH_LAG
            } else {
                lag
            }
        }
    }
}

/// Clamp a raw `SEEDHASH_EPOCH_BLOCKS` override exactly as the C did:
/// `< 2`, `> default`, or not a power of two → default.
fn clamp_blocks(raw: Option<&str>) -> u64 {
    match raw {
        None => SEEDHASH_EPOCH_BLOCKS,
        Some(s) => {
            let blocks = parse_atoi(s);
            if !(2..=SEEDHASH_EPOCH_BLOCKS).contains(&blocks) || !is_power_of_2(blocks) {
                SEEDHASH_EPOCH_BLOCKS
            } else {
                blocks
            }
        }
    }
}

/// C `atoi` semantics for the value range these knobs see: leading
/// whitespace skipped, optional sign, digits until the first
/// non-digit; no digits → 0. Negative values map to 0 (they would
/// wrap through C's int → unsigned comparison paths only for values
/// the clamps reject anyway; regtest uses small positive powers of
/// two).
fn parse_atoi(s: &str) -> u64 {
    let t = s.trim_start();
    let t = t.strip_prefix('+').unwrap_or(t);
    if t.starts_with('-') {
        return 0;
    }
    let digits: String = t.chars().take_while(char::is_ascii_digit).collect();
    digits.parse::<u64>().unwrap_or(0)
}

fn epoch_lag() -> u64 {
    static LAG: OnceLock<u64> = OnceLock::new();
    *LAG.get_or_init(|| clamp_lag(std::env::var("SEEDHASH_EPOCH_LAG").ok().as_deref()))
}

fn epoch_blocks() -> u64 {
    static BLOCKS: OnceLock<u64> = OnceLock::new();
    *BLOCKS.get_or_init(|| clamp_blocks(std::env::var("SEEDHASH_EPOCH_BLOCKS").ok().as_deref()))
}

/// The height whose block hash seeds the cache for verifying `height`.
#[must_use]
pub fn seedheight(height: u64) -> u64 {
    let lag = epoch_lag();
    let blocks = epoch_blocks();
    if height <= blocks + lag {
        0
    } else {
        (height - lag - 1) & !(blocks - 1)
    }
}

/// `(seedheight(height), seedheight(height + lag))` — the current
/// seed height and the upcoming one, for the RPC pre-announce path.
#[must_use]
pub fn seedheights(height: u64) -> (u64, u64) {
    (seedheight(height), seedheight(height + epoch_lag()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pure re-statement of the C formula at mainnet constants, used to
    /// cross-check `seedheight` without the env-cached accessors.
    fn c_formula(height: u64, blocks: u64, lag: u64) -> u64 {
        if height <= blocks + lag {
            0
        } else {
            (height - lag - 1) & !(blocks - 1)
        }
    }

    #[test]
    fn mainnet_schedule_matches_c_formula() {
        // Boundary sweep around the first three epochs plus large heights.
        for h in (0..=3 * 2048 + 130).chain([u64::MAX - 65, u64::MAX]) {
            assert_eq!(
                seedheight(h),
                c_formula(h, epoch_blocks(), epoch_lag()),
                "height {h}"
            );
        }
    }

    #[test]
    fn mainnet_pinned_values() {
        // Pinned expectations at the default 2048/64 schedule (KAT-style;
        // any change here is a consensus change).
        assert_eq!(seedheight(0), 0);
        assert_eq!(seedheight(2112), 0); // == blocks + lag: still genesis seed
        assert_eq!(seedheight(2113), 2048); // first rollover
        assert_eq!(seedheight(4160), 2048); // == 2*blocks + lag
        assert_eq!(seedheight(4161), 4096);
        let (s, n) = seedheights(2100);
        assert_eq!((s, n), (0, 2048)); // lag window pre-announces the next seed
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
        assert_eq!(clamp_lag(Some("  8tail")), 8); // atoi prefix parse
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
