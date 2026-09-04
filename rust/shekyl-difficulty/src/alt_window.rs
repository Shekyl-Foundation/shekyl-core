// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Alt-chain LWMA window selection (C2-R1b-Q1b / CEN-D5) — the stitch's
//! selection arithmetic, owned here so the rule has one implementation.
//!
//! The alt chain is conceptually `main[0..first_alt_height) ++ alt`, and
//! the LWMA-1 window for a candidate at `bei_height` is the last
//! `N + 1` entries ending at `bei_height - 1`. This function decides
//! **which entries fill the window** — the main-chain prefix range and
//! how many alt entries to take from the newest end — and enforces the
//! window invariant (`main + alt == min(N + 1, bei_height)`). The C++
//! side performs the DB fetches and the alt-list walk (rule 20: data
//! access is orchestration; a crossing that put LMDB reads behind the
//! FFI would be the anti-target).
//!
//! Both regimes live here — the short-alt stitch and the
//! alt-covers-the-window tail — so neither can drift against the other.

use crate::consts::N;
use crate::error::Error;

/// How to fill the LWMA window for an alt-chain candidate.
///
/// The main-chain prefix is the height range `[main_start, main_stop)`
/// (empty when `main_start == main_stop`); `alt_take_newest` entries are
/// then taken from the **newest** end of the alt chain, oldest-first, so
/// the assembled window ends at the candidate's parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AltWindowPlan {
    /// First main-chain height of the prefix (inclusive).
    pub main_start: u64,
    /// One past the last main-chain height of the prefix (exclusive).
    pub main_stop: u64,
    /// How many entries to take from the newest end of the alt chain.
    pub alt_take_newest: u64,
}

/// Plan the window for a candidate at `bei_height` whose stored alt
/// ancestry has `alt_len` blocks starting at `first_alt_height`
/// (`first_alt_height` is ignored when `alt_len == 0`: the parent is on
/// the main chain and the prefix ends at `bei_height`).
///
/// Errors:
/// * `Error::Window` — `bei_height == 0` (an alternative genesis is
///   structurally impossible; heights are >= 1 per C2-R3), or the alt
///   ancestry is not contiguous with the candidate
///   (`first_alt_height + alt_len != bei_height`) — the D5 linkage
///   precondition, failed closed instead of silently mis-windowed.
pub fn alt_window_plan(
    bei_height: u64,
    alt_len: u64,
    first_alt_height: u64,
) -> Result<AltWindowPlan, Error> {
    if bei_height == 0 {
        return Err(Error::Window);
    }
    if alt_len > 0
        && first_alt_height
            .checked_add(alt_len)
            .is_none_or(|end| end != bei_height)
    {
        return Err(Error::Window);
    }

    let window = N + 1;
    // Where the main-chain prefix ends: the first alt block, or the
    // candidate itself when its parent is on the main chain.
    let main_stop = if alt_len > 0 {
        first_alt_height
    } else {
        bei_height
    };

    if alt_len >= window {
        // The alt chain alone covers the window: newest N + 1 entries.
        return Ok(AltWindowPlan {
            main_start: 0,
            main_stop: 0,
            alt_take_newest: window,
        });
    }

    let main_count = core::cmp::min(window - alt_len, main_stop);
    let plan = AltWindowPlan {
        main_start: main_stop - main_count,
        main_stop,
        alt_take_newest: alt_len,
    };

    // The window invariant (round doc §4b Q1b): exactly N + 1 entries
    // above the genesis short-circuit threshold, `bei_height` below it.
    debug_assert_eq!(
        main_count + plan.alt_take_newest,
        core::cmp::min(window, bei_height)
    );
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: u64 = N + 1;

    fn total(p: &AltWindowPlan) -> u64 {
        (p.main_stop - p.main_start) + p.alt_take_newest
    }

    #[test]
    fn main_parent_short_chain_takes_whole_prefix() {
        // Candidate at height 5, parent on main: window is heights 0..5.
        let p = alt_window_plan(5, 0, 0).unwrap();
        assert_eq!((p.main_start, p.main_stop, p.alt_take_newest), (0, 5, 0));
        assert_eq!(total(&p), 5);
    }

    #[test]
    fn main_parent_tall_chain_takes_exactly_window() {
        let h = 10 * W;
        let p = alt_window_plan(h, 0, 0).unwrap();
        assert_eq!(total(&p), W);
        assert_eq!(p.main_stop, h);
        assert_eq!(p.main_start, h - W);
    }

    #[test]
    fn short_alt_stitches_main_prefix() {
        // 3 alt blocks on a tall chain: window - 3 main entries, then 3 alt.
        let first_alt = 10 * W;
        let p = alt_window_plan(first_alt + 3, 3, first_alt).unwrap();
        assert_eq!(p.alt_take_newest, 3);
        assert_eq!(p.main_stop, first_alt);
        assert_eq!(p.main_stop - p.main_start, W - 3);
        assert_eq!(total(&p), W);
    }

    #[test]
    fn alt_exactly_window_takes_no_main() {
        let first_alt = 10 * W;
        let p = alt_window_plan(first_alt + W, W, first_alt).unwrap();
        assert_eq!((p.main_start, p.main_stop, p.alt_take_newest), (0, 0, W));
    }

    #[test]
    fn long_alt_takes_newest_window() {
        let first_alt = 10 * W;
        let p = alt_window_plan(first_alt + 3 * W, 3 * W, first_alt).unwrap();
        assert_eq!((p.main_start, p.main_stop, p.alt_take_newest), (0, 0, W));
    }

    #[test]
    fn near_genesis_fork_stays_short() {
        // Fork at height 2 with 3 alt blocks: candidate at 5, total 5 (< W)
        // and the FFI genesis short-circuit governs above this layer.
        let p = alt_window_plan(5, 3, 2).unwrap();
        assert_eq!((p.main_start, p.main_stop, p.alt_take_newest), (0, 2, 3));
        assert_eq!(total(&p), 5);
    }

    #[test]
    fn height_zero_refused() {
        assert!(alt_window_plan(0, 0, 0).is_err());
    }

    #[test]
    fn discontiguous_ancestry_refused() {
        // first_alt + alt_len != bei_height: the D5 linkage precondition.
        assert!(alt_window_plan(100, 3, 90).is_err());
        // Overflowing ancestry is the same refusal, not a wrap.
        assert!(alt_window_plan(100, 3, u64::MAX - 1).is_err());
    }
}
