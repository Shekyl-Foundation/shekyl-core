// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Sliding-window **m-of-n** archival failure confirmation — the decision that
//! gates whether a failed baseline challenge is a *slashable* failure
//! ([`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md`](../../docs/completed/ARCHIVAL_FAILURE_CONFIRMATION_PIN.md) §1).
//!
//! Gate-2 §6 emits the per-epoch failure predicate `challenge_failed(P, s, E)`;
//! gate-4 §4.2 applies `slash(P, s)`. This module is the layer the pin inserts
//! between them: a single missed baseline is **not** a slashable failure. The
//! slash fires only when **m** misses fall within the last **n** baseline
//! *observations* for that `(P_id, shard)`.
//!
//! **Property enforced — "not-durably-absent"** (pin §1). Sustained absence
//! slashes; an isolated transient miss does not. This is deliberately *not* a
//! reachability SLA: mediocre uptime passes most baselines untested by design
//! (gate-2 §0).
//!
//! ## What this module is, and what it is not
//!
//! It is the **arithmetic and the window contract**. The C++ block-connect slash
//! scan (`db_lmdb.cpp`, `process_archival_slash_for_epoch`) owns the LMDB reads
//! that *gather* the observation sequence and calls this through
//! `shekyl-ffi`; it decides nothing (`20-rust-vs-cpp-policy`). The
//! interval-append the slash performs is unchanged — [`slash_open_interval_to_append`]
//! still produces exactly what the writer appends; only **whether** it fires
//! moves here.
//!
//! It is **not** a per-`P` confirmation FSM, and it schedules **no** post-miss
//! recheck. Both are pin §5 rejections, and the rejection is load-bearing rather
//! than stylistic: a predictable post-miss recheck *is* the gaming surface — a
//! mostly-offline `P` surfaces for the probe and evades (measured dodge-slash
//! ≈ 0 under escalation, ≈ 1 under this window). Anything that re-introduces
//! adaptive, predictable scrutiny after a miss re-opens that surface under a new
//! name (pin §3.2's "escape inherits the unpredictability prerequisite").
//!
//! ## Observations, not epochs — and why the distinction is load-bearing
//!
//! The window counts **baseline observations**: epochs at which a challenge was
//! actually posed to this `(P_id, shard)` and could have been answered. An epoch
//! in which the pair was bonded but *untested* is not an observation and
//! therefore not a miss. Without that filter, epochs a `P` could not have served
//! — before the shard's add-epoch, or across a stretch where the challenge is
//! unreconstructible — would accumulate as misses and slash an archiver that
//! never failed anything. (This is the pin §3.1 Round-2 confirmation concern
//! stated on the enforcement side: no alternate code path may count
//! bonded-but-uncredited epochs against a `P`.)
//!
//! ## The window is scoped to the record's *current* standing run
//!
//! Look-back stops at the boundary of the current continuous challengeable run
//! for the pair: the caller walks back from the decision epoch and halts at the
//! first epoch that is not an observation. Three consensus boundaries fall out
//! of that one rule, none of them special-cased:
//!
//! - **Before `E_join + 1`** — `good_through` is false, so the walk stops; a
//!   record cannot be charged for epochs predating its own join.
//! - **Before the shard's `E_add + 1`** — the as-of-`H_fire` holdings read is
//!   false, so the walk stops. The partial add epoch is forfeited in both
//!   directions (P2B-7 Pin 5: no credit earned in it, and no challenge fired in
//!   it can slash).
//! - **Across a closed bad interval (slash → `Rebond`)** — `good_through` is
//!   false inside the interval, so the walk stops at the reinstatement boundary.
//!
//! That third boundary is a **ruling, not an accident**, so it is stated
//! plainly: *a reinstated record starts the window clean*. The alternative —
//! carrying pre-slash misses across the `Rebond` — punishes one absence twice
//! and, worse, defeats the pin at exactly the point it matters: an archiver that
//! has already forfeited a `FLOOR` would then be one or two misses from the next
//! slash, i.e. back to the single-strike knife-edge this whole mechanism exists
//! to remove. Gate-4 §3.4 calls `Rebond` *reinstatement*, and §4.2 makes slash
//! forward-only; a clean window is the symmetric reading. The `Rebond` is not a
//! cheap window reset either — it is reachable only by having been slashed, and
//! the burned collateral is the price. Note the shard that *was* slashed gets
//! this for free through its add-epoch (a slash removes it; `Rebond` re-adds it
//! at `E_rebond`); the interval boundary is what extends the same treatment to a
//! **carried** shard the same sweep did not slash.
//!
//! ## Persistence: recomputed, never stored
//!
//! There is no miss-tally in persisted consensus state, and therefore no
//! `42-serialization-policy` version bump. The window is a pure function of the
//! per-`(P, s, E)` `serve_credit_bit` ledger and the bond record — both already
//! persisted, and both already reverted by `pop_block` (gate-2 §8, gate-4 §5).
//! Recomputing is what makes the mechanism reorg-safe for free: a rewound bit is
//! a rewound observation, with no second copy of the history to keep in sync.
//!
//! ## Numerics are provisional; the shape is frozen
//!
//! [`ARCHIVAL_FAILURE_WINDOW_M`] / [`ARCHIVAL_FAILURE_WINDOW_N`] come from
//! `config/consensus_constants.json` at the Round-1 provisional values (`m = 11`,
//! `n = 13` — `m` sized above the p99 single-outage span of ≈ 10 baselines). They
//! are **re-pinned at the Round-2 testnet stressnet** against the measured
//! outage-duration CDF, which must admit an `m` satisfying all four pin §3.2
//! criteria simultaneously (tail-robust, bond-resolution acceptable, crisis-tail
//! robust, deterrence-credible at the L17 ×0.25 crisis multiplier). The
//! *m-of-n shape* is genesis-frozen; the two integers are not — the
//! `bond_duration` precedent.

include!(concat!(
    env!("OUT_DIR"),
    "/archival_failure_window_generated.rs"
));

/// Round-1 provisional pin, restated as a compile-time sentinel so a re-pin of
/// the JSON authority is a deliberate two-file edit rather than a silent
/// numerics drift (the `bond_floor` idiom). Raising these is the Round-2
/// stressnet's job — see the module docs.
const _: () = assert!(
    ARCHIVAL_FAILURE_WINDOW_M == 11 && ARCHIVAL_FAILURE_WINDOW_N == 13,
    "archival failure-window m/n diverged from the Round-1 provisional pin \
     (ARCHIVAL_FAILURE_CONFIRMATION_PIN.md §1); re-pin is a Round-2 stressnet \
     decision, not a retune"
);

// Shape invariants. `build.rs` already refuses a JSON authority that breaks
// these; the const-assert is the Rust half of the pair, so a hand-edit of the
// generated file cannot slip past either.
const _: () = assert!(
    ARCHIVAL_FAILURE_WINDOW_M >= 1,
    "m = 0 would slash a P that never missed a baseline"
);
const _: () = assert!(
    ARCHIVAL_FAILURE_WINDOW_N >= ARCHIVAL_FAILURE_WINDOW_M,
    "n < m makes the miss threshold unreachable — a silently disabled slash"
);

/// One baseline observation for a `(P_id, shard)` pair: an epoch at which a
/// challenge was posed and could have been answered.
///
/// `served` is the epoch's `serve_credit_bit` — an **affirmative pass**, never
/// absence-of-failure (gate-2 §0.1). `!served` is the miss the window counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineObservation {
    /// The settlement epoch the baseline was observed in.
    pub settlement_epoch: u64,
    /// `serve_credit_bit(P_id, shard, settlement_epoch)`.
    pub served: bool,
}

impl BaselineObservation {
    /// A missed baseline at `settlement_epoch`.
    #[must_use]
    pub fn missed(settlement_epoch: u64) -> Self {
        Self {
            settlement_epoch,
            served: false,
        }
    }

    /// A passed baseline at `settlement_epoch`.
    #[must_use]
    pub fn served(settlement_epoch: u64) -> Self {
        Self {
            settlement_epoch,
            served: true,
        }
    }
}

/// Why an observation sequence could not be evaluated. Every arm is a **caller
/// marshal breach**, not a reachable consensus state — the C++ slash scan builds
/// the sequence itself, walking epochs strictly downward from the decision
/// epoch. The scan maps these to a FATAL abort (the gate-4 §4.3 connect-fold
/// posture): a slash decision taken over a malformed window would be a
/// consensus divergence, so it must be loud, never a soft skip in either
/// direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FailureWindowError {
    /// No observations at all. The decision epoch is itself an observation (the
    /// caller reaches this module only on a *missed* baseline), so an empty
    /// sequence means the caller dropped it.
    #[error("failure window is empty; the decision epoch is always an observation")]
    Empty,
    /// More than [`ARCHIVAL_FAILURE_WINDOW_N`] observations. The caller stops
    /// gathering at `n`; a longer sequence means it over-collected, and
    /// evaluating it would silently widen the window.
    #[error("failure window holds {len} observations; the window is {n}")]
    TooLong {
        /// Observations supplied.
        len: usize,
        /// [`ARCHIVAL_FAILURE_WINDOW_N`].
        n: usize,
    },
    /// Epochs are not strictly descending. The sequence is most-recent-first by
    /// contract; a repeat or an inversion means the same epoch was counted
    /// twice or the walk-back ran the wrong way — either way the miss count is
    /// not the window's.
    #[error("failure window epochs are not strictly descending at index {index}")]
    NotStrictlyDescending {
        /// Index of the first observation that did not fall below its
        /// predecessor.
        index: usize,
    },
    /// The most recent observation is a pass. The decision epoch is the head of
    /// the sequence and reaching this module means it was missed, so a served
    /// head is a caller that gathered the wrong epoch.
    ///
    /// This is not a lost decision: the miss count is monotone non-increasing
    /// across a passed baseline (a pass adds no miss and may evict one), so a
    /// window whose head is a pass can never be the *first* moment the
    /// threshold is crossed. Refusing it costs no slash and catches the bug.
    #[error("failure window head is a passed baseline, not the missed decision epoch")]
    HeadNotAMiss,
}

/// Miss threshold **m** — misses required inside the window to slash.
pub const FAILURE_WINDOW_M: u32 = ARCHIVAL_FAILURE_WINDOW_M;

/// Window width **n** — baseline observations the miss count is taken over.
pub const FAILURE_WINDOW_N: u32 = ARCHIVAL_FAILURE_WINDOW_N;

/// Passed baselines the window tolerates before the threshold becomes
/// unreachable (`n − m`).
///
/// The gathering caller uses this to stop reading LMDB early: the window holds
/// at most `n` observations, so once more than `n − m` of them have passed,
/// fewer than `m` misses remain possible no matter what the rest of the history
/// says. Exposed as a computed constant rather than left to the caller so the
/// arithmetic stays on this side of the FFI (`20-rust-vs-cpp-policy`).
///
/// At the Round-1 pin this is `2` — a healthy archiver's look-back ends after
/// three reads, not thirteen.
pub const FAILURE_WINDOW_SERVE_BUDGET: u32 = ARCHIVAL_FAILURE_WINDOW_N - ARCHIVAL_FAILURE_WINDOW_M;

/// Is this observation sequence a **slashable** failure?
///
/// `observations` is the trailing window for one `(P_id, shard)`, **most recent
/// first**, strictly descending in epoch, at most [`ARCHIVAL_FAILURE_WINDOW_N`]
/// long, with the head being the missed decision epoch. A shorter sequence is a
/// young or freshly-reinstated pair whose history simply does not reach `n`
/// observations yet — it is evaluated as-is, against the same `m`, which is the
/// conservative direction (fewer observations can only mean fewer misses).
///
/// Returns `true` iff at least `m` of them are misses.
pub fn failure_window_slashable(
    observations: &[BaselineObservation],
) -> Result<bool, FailureWindowError> {
    let n = ARCHIVAL_FAILURE_WINDOW_N as usize;
    if observations.is_empty() {
        return Err(FailureWindowError::Empty);
    }
    if observations.len() > n {
        return Err(FailureWindowError::TooLong {
            len: observations.len(),
            n,
        });
    }
    if observations[0].served {
        return Err(FailureWindowError::HeadNotAMiss);
    }
    for (index, pair) in observations.windows(2).enumerate() {
        if pair[1].settlement_epoch >= pair[0].settlement_epoch {
            return Err(FailureWindowError::NotStrictlyDescending { index: index + 1 });
        }
    }

    let misses = observations.iter().filter(|o| !o.served).count();
    Ok(misses >= ARCHIVAL_FAILURE_WINDOW_M as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a most-recent-first window from a most-recent-first miss pattern
    /// (`true` = missed), epochs descending from `head_epoch`.
    fn window(head_epoch: u64, missed: &[bool]) -> Vec<BaselineObservation> {
        missed
            .iter()
            .enumerate()
            .map(|(i, &m)| BaselineObservation {
                settlement_epoch: head_epoch - i as u64,
                served: !m,
            })
            .collect()
    }

    #[test]
    fn round1_provisional_params_are_the_pinned_pair() {
        // The JSON authority reaches the crate intact (pin §1 Round-1 table).
        assert_eq!(FAILURE_WINDOW_M, 11);
        assert_eq!(FAILURE_WINDOW_N, 13);
        assert_eq!(FAILURE_WINDOW_SERVE_BUDGET, 2);
    }

    #[test]
    fn single_transient_miss_does_not_slash() {
        // The property the pin exists for: an isolated miss inside an otherwise
        // clean history is absorbed, not punished.
        let mut missed = [false; 13];
        missed[0] = true; // the decision epoch
        assert_eq!(failure_window_slashable(&window(100, &missed)), Ok(false));
    }

    #[test]
    fn sustained_absence_slashes_at_exactly_m() {
        // m − 1 misses inside a full window: still absorbed.
        let mut missed = [false; 13];
        for m in missed.iter_mut().take(10) {
            *m = true;
        }
        assert_eq!(failure_window_slashable(&window(100, &missed)), Ok(false));

        // The m-th miss crosses the threshold.
        missed[10] = true;
        assert_eq!(failure_window_slashable(&window(100, &missed)), Ok(true));
    }

    #[test]
    fn misses_need_not_be_consecutive() {
        // "Sustained" is m-of-n, not a run: a P that answers every third
        // baseline is still durably absent.
        let missed: Vec<bool> = (0..13).map(|i| i % 3 != 2).collect();
        assert_eq!(missed.iter().filter(|m| **m).count(), 9);
        assert_eq!(failure_window_slashable(&window(100, &missed)), Ok(false));

        // Nine misses is under m; the pattern that reaches eleven does slash.
        let missed: Vec<bool> = (0..13).map(|i| i % 6 != 5).collect();
        assert_eq!(missed.iter().filter(|m| **m).count(), 11);
        assert_eq!(failure_window_slashable(&window(100, &missed)), Ok(true));
    }

    #[test]
    fn mostly_offline_p_slashes_dodge_slash_is_one() {
        // Pin §1: dodge slash = 1.000 — every baseline miss counts, and there
        // is no recheck surface to dodge (§5.5 contrast).
        let missed = [true; 13];
        assert_eq!(failure_window_slashable(&window(100, &missed)), Ok(true));
    }

    #[test]
    fn a_short_window_still_slashes_at_m() {
        // A pair whose standing run is younger than n: evaluated as-is. Eleven
        // misses is eleven misses whether or not two more observations exist.
        let missed = [true; 11];
        assert_eq!(failure_window_slashable(&window(100, &missed)), Ok(true));
        // And ten is not enough, however short the run.
        let missed = [true; 10];
        assert_eq!(failure_window_slashable(&window(100, &missed)), Ok(false));
    }

    #[test]
    fn a_single_observation_never_slashes_at_the_pinned_m() {
        // The single-strike behaviour this work replaces: one observed miss,
        // nothing else in the run. Today's code slashed here.
        assert_eq!(
            failure_window_slashable(&[BaselineObservation::missed(100)]),
            Ok(false)
        );
    }

    #[test]
    fn serve_budget_bounds_the_gather() {
        // The early-exit contract: more than SERVE_BUDGET passes inside a full
        // window makes m unreachable, whatever the unread history holds.
        let mut missed = [true; 13];
        for m in missed.iter_mut().skip(10) {
            *m = false; // three passes == SERVE_BUDGET + 1
        }
        assert_eq!(missed.iter().filter(|m| **m).count(), 10);
        assert_eq!(failure_window_slashable(&window(100, &missed)), Ok(false));

        // Exactly SERVE_BUDGET passes still reaches m.
        missed[10] = true;
        assert_eq!(failure_window_slashable(&window(100, &missed)), Ok(true));
    }

    #[test]
    fn epochs_may_skip_unobserved_gaps() {
        // Observations carry their own epochs precisely because the window is
        // not "the last n epochs": untested epochs are absent from the
        // sequence, and a gap changes no count.
        let obs = vec![
            BaselineObservation::missed(100),
            BaselineObservation::missed(80),
            BaselineObservation::missed(3),
        ];
        assert_eq!(failure_window_slashable(&obs), Ok(false));
    }

    #[test]
    fn marshal_breaches_are_typed_and_loud() {
        assert_eq!(
            failure_window_slashable(&[]),
            Err(FailureWindowError::Empty)
        );

        let too_long = window(100, &[true; 14]);
        assert_eq!(
            failure_window_slashable(&too_long),
            Err(FailureWindowError::TooLong { len: 14, n: 13 })
        );

        assert_eq!(
            failure_window_slashable(&[BaselineObservation::served(100)]),
            Err(FailureWindowError::HeadNotAMiss)
        );

        // Ascending order — the walk-back ran the wrong way.
        assert_eq!(
            failure_window_slashable(&[
                BaselineObservation::missed(100),
                BaselineObservation::missed(101),
            ]),
            Err(FailureWindowError::NotStrictlyDescending { index: 1 })
        );

        // A repeated epoch would double-count one observation.
        assert_eq!(
            failure_window_slashable(&[
                BaselineObservation::missed(100),
                BaselineObservation::missed(100),
            ]),
            Err(FailureWindowError::NotStrictlyDescending { index: 1 })
        );

        // The inversion is reported at its own index, not the head's.
        assert_eq!(
            failure_window_slashable(&[
                BaselineObservation::missed(100),
                BaselineObservation::missed(99),
                BaselineObservation::missed(99),
            ]),
            Err(FailureWindowError::NotStrictlyDescending { index: 2 })
        );
    }

    #[test]
    fn validation_precedes_the_count() {
        // A malformed window must not be answered "no slash" by accident — the
        // caller distinguishes a refusal from a verdict, and a soft skip here
        // would silently disable the slash.
        let mut too_long = window(100, &[true; 14]);
        too_long[0].served = true;
        // Head-not-a-miss AND too long: the length breach is reported first
        // (the window is not even the right shape to interpret).
        assert_eq!(
            failure_window_slashable(&too_long),
            Err(FailureWindowError::TooLong { len: 14, n: 13 })
        );
    }
}
