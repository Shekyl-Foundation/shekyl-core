//! Coupled timestamp validation predicates per
//! `docs/completed/DAA_LWMA1.md` §5.5.
//!
//! These are predicates rather than value-producing transforms — per
//! §2.5, they live in `shekyl-difficulty` because the FTL and MTP
//! disposition is part of the LWMA-1 landing (FTL and MTP are
//! co-tuned consensus values that the algorithm depends on, not
//! free-floating chain parameters).
//!
//! Consumer responsibility: the predicates answer the question; the
//! consumer decides what to do with the answer. These functions are
//! pure: no clock reads, no side effects, no logging.
//!
//! Consumer status (C2-R3, ratified 2026-09-01; crossing re-ratified
//! same day): [`check_timestamp_rule`] is the ONE implementation of the
//! ruled block-timestamp rule, exported to the C++ validator through
//! `shekyl-ffi`'s `shekyl_difficulty_check_timestamp_rule` — the C++
//! side is a marshaling shim per rule 20, and the shared vectors
//! `docs/test_vectors/MTP_BOUNDARY_V1.json` pin this crate natively and
//! the FFI boundary end-to-end. One implementation cannot drift from
//! itself; the earlier same-PR C++ twin was deleted with the crossing.

use crate::consts::{FTL_SECONDS, MTP_WINDOW_USIZE};

/// Verdict of the ruled block-timestamp rule (C2-R3,
/// `docs/completed/CONSENSUS_C2_R3_TIMESTAMPS.md` §4.3).
///
/// Discriminants are the wire-stable FFI codes returned by
/// `shekyl_difficulty_check_timestamp_rule`; renumbering is an FFI
/// break.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampRuleVerdict {
    /// The candidate satisfies both the FTL bound and the strict MTP
    /// bound.
    Ok = 0,
    /// The caller handed more than `MTP_WINDOW` timestamps — a caller
    /// bug (the newest-11 selection is order-dependent and therefore
    /// the caller's job, C2-R3-Q1 sub-a); refused loudly, never
    /// silently medianed.
    WindowTooWide = 1,
    /// The candidate exceeds `local_clock + FTL_SECONDS`.
    AboveFtl = 2,
    /// The candidate is not strictly greater than the window median.
    NotAboveMedian = 3,
}

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
/// algorithm-internal `6*T` solvetime clamp. The live FTL check IS this
/// predicate: [`check_timestamp_rule`] delegates its FTL half here, and
/// the C++ validator consumes it through the
/// `shekyl_difficulty_check_timestamp_rule` FFI (see the module-level
/// consumer-status note). The shared-vector u64-boundary rows pin the
/// saturating shape.
#[must_use]
pub fn is_timestamp_below_ftl(incoming: u64, local_clock: u64) -> bool {
    incoming.saturating_sub(local_clock) <= FTL_SECONDS
}

/// Returns `true` when `incoming` is strictly greater than the median
/// of the preceding `MTP_WINDOW` timestamps (Median-Time-Past rule).
///
/// The strict boundary is **ratified**, not incidental: C2-R3-Q1
/// (`docs/completed/CONSENSUS_C2_R3_TIMESTAMPS.md` §4, 2026-09-01)
/// re-derived the `>`-vs-`>=` question after §5.5's "preserved
/// unchanged" premise was refuted at the tree, and ruled strict. This
/// predicate is the future consensus rewrite's implementation of that
/// rule — aligned with the ruling and deliberately kept: zero
/// production callers is the designed state until the C3 cutover wires
/// the Rust validator (the live C++ validator implements the same ruled
/// sentence until then, pinned to this predicate by the shared vectors
/// in `docs/test_vectors/MTP_BOUNDARY_V1.json`). Window assembly —
/// newest-11 selection and genesis-timestamp padding (C2-R3-Q1 sub-a,
/// C2-R3-Q2) — is the caller's job; this predicate takes the assembled
/// 11-window.
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
pub fn is_above_mtp(incoming: u64, previous_window: &[u64; MTP_WINDOW_USIZE]) -> bool {
    // The strict `>` has exactly this one site; `mtp_median` owns the
    // median definition.
    incoming > mtp_median(previous_window)
}

/// The MTP window median: element index 5 (0-based) of the sorted
/// 11-element window (C2-R3-Q1 sub-c — stated by the ruling, not
/// inherited from any library's odd-window behavior).
#[must_use]
pub fn mtp_median(previous_window: &[u64; MTP_WINDOW_USIZE]) -> u64 {
    // Copy because we cannot mutate the caller's window.
    let mut window = *previous_window;
    window.sort_unstable();
    // MTP_WINDOW is odd (== 11) per §5.5; the build asserts
    // MTP_WINDOW == 11 in `consts.rs`, so `MTP_WINDOW_USIZE / 2` is
    // the median index by construction.
    window[MTP_WINDOW_USIZE / 2]
}

/// The single owner of the ruled block-timestamp rule
/// (`docs/completed/CONSENSUS_C2_R3_TIMESTAMPS.md` §4.3, ratified
/// 2026-09-01): a candidate timestamp is valid iff it is at most
/// `local_clock + FTL_SECONDS` AND strictly greater than
/// [`mtp_median`] of the 11 timestamps immediately preceding it on its
/// own chain, the window right-padded with the genesis timestamp when
/// fewer than 11 predecessors exist (C2-R3-Q2 — no bootstrap
/// carve-out).
///
/// `window` holds the ≤ 11 predecessor timestamps in any order;
/// callers with deeper history select the NEWEST 11 first (C2-R3-Q1
/// sub-a — the selection is order-dependent and therefore the
/// caller's job; a wider window is refused, never silently medianed).
/// The returned median is the padded window's [`mtp_median`] on every
/// arm except [`TimestampRuleVerdict::WindowTooWide`], where it is 0 —
/// callers (the miner-template floor) read it unconditionally.
///
/// Each comparison has exactly one site: the strict MTP bound lives in
/// [`is_above_mtp`], the saturating FTL bound in
/// [`is_timestamp_below_ftl`]. Verdict precedence: `WindowTooWide`,
/// then `AboveFtl`, then `NotAboveMedian`.
#[must_use]
pub fn check_timestamp_rule(
    candidate_ts: u64,
    window: &[u64],
    genesis_ts: u64,
    local_clock: u64,
) -> (TimestampRuleVerdict, u64) {
    if window.len() > MTP_WINDOW_USIZE {
        return (TimestampRuleVerdict::WindowTooWide, 0);
    }

    let mut padded = [genesis_ts; MTP_WINDOW_USIZE];
    padded[..window.len()].copy_from_slice(window);
    let median = mtp_median(&padded);

    if !is_timestamp_below_ftl(candidate_ts, local_clock) {
        return (TimestampRuleVerdict::AboveFtl, median);
    }
    if !is_above_mtp(candidate_ts, &padded) {
        return (TimestampRuleVerdict::NotAboveMedian, median);
    }
    (TimestampRuleVerdict::Ok, median)
}
