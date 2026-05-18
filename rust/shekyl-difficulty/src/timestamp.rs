//! Coupled timestamp validation predicates per
//! `docs/design/DAA_LWMA1.md` §5.5.
//!
//! These are predicates rather than value-producing transforms — per
//! §2.5, they live in `shekyl-difficulty` because the FTL and MTP
//! disposition is part of the LWMA-1 landing (FTL and MTP are
//! co-tuned consensus values that the algorithm depends on, not
//! free-floating chain parameters).
//!
//! Consumer responsibility: the predicates answer the question; the
//! consumer (block-header validator in Phase 4) decides what to do
//! with the answer. These functions are pure: no clock reads, no
//! side effects, no logging.

use crate::consts::{FTL_SECONDS, MTP_WINDOW_USIZE};

/// Returns `true` when `incoming` is acceptable under the Future-Time-
/// Limit rule: the incoming timestamp is at most `FTL_SECONDS` ahead
/// of the validator's local clock.
///
/// Formally: returns `incoming.saturating_sub(local_clock) <=
/// FTL_SECONDS`. The saturating subtraction is load-bearing because
/// the predicate must answer cleanly even when `incoming <
/// local_clock` (in which case the gap is zero or negative and the
/// answer is unconditionally `true`).
///
/// Per §5.5, FTL is `T*N/20 = 540` seconds and is co-tuned with the
/// algorithm-internal `6*T` solvetime clamp. Phase 4's block-header
/// validator consumes this predicate at the FTL check site that
/// inherited CryptoNote `BLOCK_FUTURE_TIME_LIMIT` previously
/// occupied.
#[must_use]
pub fn is_timestamp_below_ftl(incoming: u64, local_clock: u64) -> bool {
    incoming.saturating_sub(local_clock) <= FTL_SECONDS
}

/// Returns `true` when `incoming` is strictly greater than the median
/// of the preceding `MTP_WINDOW` timestamps (Median-Time-Past rule).
///
/// The `&[u64; MTP_WINDOW_USIZE]` const-sized-array reference is the
/// consensus-property-preserving baseline per §2.5: a window of
/// length other than `MTP_WINDOW` cannot satisfy the MTP rule, and
/// pushing that invariant into the type system catches off-by-one
/// errors at consumer call sites at compile time. Per §2.5, Phase 1
/// may revisit this signature if Phase 4 finds the const-sized
/// requirement ergonomically costly; the current shape is preserved
/// because it is the cheapest consensus property to defend.
///
/// `MTP_WINDOW` is `11` per §5.5; the array literal length below is
/// the `usize` mirror [`crate::consts::MTP_WINDOW_USIZE`], emitted
/// from `build.rs` and pinned against the `u64` const by the
/// const-eval `assert!` in `consts.rs`, so the array length cannot
/// drift from the JSON authority without a build failure.
#[must_use]
pub fn is_above_mtp(incoming: u64, previous_11: &[u64; MTP_WINDOW_USIZE]) -> bool {
    // Median of an odd-length sorted window is the middle element.
    // Copy because we cannot mutate the caller's window.
    let mut window = *previous_11;
    window.sort_unstable();
    // MTP_WINDOW is odd (== 11) per §5.5; the build asserts
    // MTP_WINDOW == 11 in `consts.rs`, so `MTP_WINDOW_USIZE / 2` is
    // the median index by construction.
    let median = window[MTP_WINDOW_USIZE / 2];
    incoming > median
}
