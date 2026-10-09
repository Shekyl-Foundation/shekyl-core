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
//! It is the **arithmetic**, the **window contract**, and the Rust slash
//! pass's gather ([`settlement_window_slashable`]). The C++ block-connect
//! slash scan (`db_lmdb.cpp`, `process_archival_slash_for_epoch`) still
//! gathers its own observation sequence from the serve-credit ledger and
//! calls [`failure_window_slashable`] through `shekyl-ffi`, until
//! `DEL-008`. It decides nothing (`20-rust-vs-cpp-policy`). The
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
//! ## Standing bounds both gathers
//!
//! Both gathers stop where the record's current continuous challengeable
//! run ends. [`good_through`] is false before `E_join + 1`, so a record
//! cannot be charged for epochs predating its own join, and it is false
//! across a closed bad interval (slash → `Reinstate`), so the walk stops
//! at the reinstatement boundary.
//!
//! That second boundary is a **ruling, not an accident**, so it is stated
//! plainly: *a reinstated record starts the window clean*. The alternative —
//! carrying pre-slash misses across the `Reinstate` — punishes one absence twice
//! and, worse, defeats the pin at exactly the point it matters: an archiver that
//! has already forfeited a `FLOOR` would then be one or two misses from the next
//! slash, i.e. back to the single-strike knife-edge this whole mechanism exists
//! to remove. Gate-4 §3.4 calls `Reinstate` *reinstatement*, and §4.2 makes slash
//! forward-only; a clean window is the symmetric reading. The `Reinstate` is not a
//! cheap window reset either — it is reachable only by having been slashed, and
//! the burned collateral is the price. Note the shard that *was* slashed gets
//! this for free through its add-epoch (a slash removes it; `Reinstate` re-adds it
//! at `E_reinstate`); the interval boundary is what extends the same treatment to a
//! **carried** shard the same sweep did not slash.
//!
//! The shard's add-epoch is not that same stop for both gathers. The partial
//! add epoch is forfeited in both directions (P2B-7 Pin 5: no credit earned
//! in it, and no challenge fired in it can slash), but each gather reaches
//! that fact its own way, below.
//!
//! ## The C++ gather (until `DEL-008`)
//!
//! `process_archival_slash_for_epoch` reads the serve-credit ledger and
//! halts at the first epoch that is not an observation. Before the shard's
//! `E_add + 1` the as-of-`H_fire` holdings read is false, so that halt is
//! also where the add-epoch stops this walk. Because it stops at the first
//! gap, the deepest epoch it can read is `n − 1` below the decision epoch.
//! The const-assert beside `SLASH_SETTLEMENT_TIP_LAG_EPOCHS` is **this**
//! walk's horizon: those `n − 1` epochs are still inside
//! `prune_archival_epochs_before`.
//!
//! ## The Rust gather ([`settlement_window_slashable`])
//!
//! The Rust slash pass reads settlement rows. By
//! `ARCHIVAL_SETTLEMENT_WRITER.md` `SO-D10b` it **passes over** an epoch
//! that is not an observation — a NonObservation row, or no row — and does
//! not stop there. Stopping would let a producer withhold one reveal, push
//! a non-server's pair below three issued draws in one epoch, and clear
//! its window. The walk stops where standing ends (`good_through` false),
//! at `FAILURE_WINDOW_N` observations, once passes exceed
//! [`FAILURE_WINDOW_SERVE_BUDGET`], and at [`settlement_retention_floor`].
//! Before the shard's `E_add + 1` the pair has no counted draw, so the
//! epoch is passed over and nothing accumulates: the add-epoch is not a
//! stop.
//!
//! A walk that passes over epochs is not bounded by `n − 1` epochs of
//! look-back, so the floor is the horizon the settlement rows' own prune
//! uses — one constant, [`SETTLEMENT_RETENTION_EPOCHS`] — ruled 2026-10-09
//! and in the rule from the first commit, so the prune is not a consensus
//! change when the Rust store gains one. The walk reads the floor and
//! nothing below it. It binds only in a degraded state. The window needs
//! `n` observations and the horizon leaves twice `n` epochs to find them
//! in, so the walk is cut short only when fewer than half a pair's epochs
//! are observed ([`WINDOW_MIN_OBSERVATION_PER_MILLE`]; the assert beside
//! it is that sentence in arithmetic). The simulated observation rate is
//! 0.96 or better, at which `n` observations span about fourteen epochs.
//! Below one half the network has larger problems than one unslashed pair.
//!
//! ## Persistence: recomputed, never stored
//!
//! There is no miss-tally in persisted consensus state, and therefore no
//! `42-serialization-policy` version bump. Each gather is a pure function of
//! the table it reads and the bond record. The C++ gather reads the
//! serve-credit ledger. The Rust gather reads settlement rows. Both tables
//! are already persisted, and both are reverted by `pop_block` (gate-2 §8,
//! gate-4 §5). Recomputing is what makes the mechanism reorg-safe for free:
//! a rewound row is a rewound observation, with no second copy of the
//! history to keep in sync.
//!
//! **The price of recomputing: each gather's depth is a retention
//! constraint.** `prune_archival_epochs_before` deletes every epoch-scoped
//! archival table below `tip_epoch − MAX_CLAIM_AGE_W`
//! (`prune_below_epoch_at_height`, `ARCHIVAL_CONSENSUS_STATE.md` §5), and a
//! pruned row is indistinguishable from one that was never written. What a
//! horizon breach *does* to the verdict depends on which table the gather
//! reads, and the two reads fail in **opposite directions**
//! (`ARCHIVAL_SETTLEMENT_WRITER.md` §8, `SO-D5`):
//!
//! - **`archival_serve_credit` — the C++ gather's read, until `DEL-008`**
//!   (an [`BaselineObservation`] is
//!   `archival_serve_credit_pass_count(...) > 0`). Absent means *no pass
//!   bit*, i.e. a **miss**. A breach reads *served* epochs as missed and
//!   **slashes an honest archiver** for history the node deleted.
//!   Loud-wrong: somebody's bond burns and they will say so. This walk
//!   stops at the first gap, so its deepest read is `n − 1` epochs back,
//!   and the const-assert on `SLASH_SETTLEMENT_TIP_LAG_EPOCHS` is the bound
//!   that keeps that read on disk.
//! - **`archival_settlement` — the Rust gather's read.** Absent means
//!   **non-observation** (`SO-D1`: never issued ⇒ not a miss), and the
//!   gather passes over it. A breach that treated a pruned row as absent
//!   would read fully-evidenced *failures* as unobserved epochs and
//!   silently **shrink the window's denominator**, so an archiver that
//!   should have been slashed is not. Quiet-wrong: nothing burns, nobody
//!   complains, the pin's deterrence erodes without a signal. The walk can
//!   pass over more than `n − 1` epochs, so the `n − 1` assert does not
//!   cover it. [`settlement_retention_floor`] does: the walk reads no epoch
//!   a store may delete, and [`WINDOW_MIN_OBSERVATION_PER_MILLE`] pins that
//!   the floor still leaves `n` observations while at least half a pair's
//!   epochs are observed.
//!
//! Both failures are consensus-deterministic (pruning is a function of tip
//! height, so every node deletes the same rows and reaches the same wrong
//! verdict — a false verdict, not a fork). They are stated together so that
//! a maintainer debugging a *missed* slash does not read "slashes honest
//! archivers" and conclude the retention bound is about somebody else's
//! problem. Raising `n` at Round-2 is the edit that would cross either
//! bound, and each bound is the assert for its own gather. Reorgs cannot
//! reach a prune boundary either (`ARCHIVAL_REORG_DEPTH_BLOCKS` ≪
//! `SETTLEMENT_EPOCH_BLOCKS`).
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

use shekyl_types::archival::SettlementOutcome;
use shekyl_types::SettlementEpoch;

use crate::bond_floor::MAX_CLAIM_AGE_W;
use crate::constants::SLASH_GRACE_EPOCHS;

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

/// Settlement epochs between a baseline epoch and the tip at which its slash
/// pass runs. Epoch `E` is settled by the first block above
/// `H_slash_deadline(E) = last_block(E + SLASH_GRACE_EPOCHS)`, which is the
/// first block of epoch `E + 1 + k`, and the scheduler settles each epoch at
/// that block (it advances its watermark on every connect, so it does not
/// drift behind the tip). `2` at `k = 1` — **on every schedule**, since the
/// grace is denominated in epochs.
const SLASH_SETTLEMENT_TIP_LAG_EPOCHS: u64 = 1 + SLASH_GRACE_EPOCHS;

/// **Prune-horizon coupling — the C++ gather may not out-reach the
/// serve-credit ledger's retention.** At the moment epoch `E` is settled
/// the tip is `E + LAG`, so rows below `E + LAG − MAX_CLAIM_AGE_W` are
/// already deleted, while that gather's look-back reaches `E − (n − 1)`
/// because it stops at the first gap. Requiring
/// `n − 1 ≤ MAX_CLAIM_AGE_W − LAG` keeps every epoch **that** walk can read
/// on disk. At the shipped values: `13 ≤ 26 − 2 + 1 = 25`, a 12-epoch margin.
///
/// This assert fires if Round-2 re-pins `n` upward past the retention
/// window, or if `MAX_CLAIM_AGE_W` is ever lowered. It is the C++ gather's
/// bound. The Rust gather passes over gaps and can read further;
/// [`settlement_retention_floor`] and the
/// [`WINDOW_MIN_OBSERVATION_PER_MILLE`] assert are its bound. Crossing
/// either does not fork the network (pruning is deterministic in tip
/// height) — it produces a wrong verdict whose *direction* depends on the
/// table read (module docs, `SO-D5`): against the serve-credit ledger a
/// pruned row is a **miss** and an honest archiver is slashed; against the
/// settlement table a pruned row is **non-observation** and a failed
/// archiver is not. Whichever constant moves, the fix is a decision about
/// both gathers, not a bump.
///
/// Holds on every schedule: `n`, `W` and the lag are all epoch-denominated, so
/// the FAKECHAIN-only `SHEKYL_SETTLEMENT_EPOCH_BLOCKS` lever moves none of the
/// three terms. (Until DRS-E4 commit 5 the grace was a block count that the
/// lever did not shorten, and a levered chain's real lag ran far past this
/// constant — a regtest chain was not a faithful model of the slash path. That
/// caveat is gone with the constant.)
const _: () = assert!(
    (ARCHIVAL_FAILURE_WINDOW_N as u64) + SLASH_SETTLEMENT_TIP_LAG_EPOCHS <= MAX_CLAIM_AGE_W + 1,
    "the C++ failure-window gather reaches further back than the epoch-scoped \
     archival tables are retained (prune_archival_epochs_before deletes below \
     tip - MAX_CLAIM_AGE_W). Against archival_serve_credit a pruned bit reads as \
     a MISS and honest archivers are slashed for epochs they served. The Rust \
     gather's bound is settlement_retention_floor: against archival_settlement \
     a pruned row reads as NON-OBSERVATION and a failed archiver escapes \
     (ARCHIVAL_SETTLEMENT_WRITER.md SO-D5)"
);

/// Epochs of settlement rows a store keeps below the tip's, and how far
/// the failure window's walk may read: **one constant for both**, so the
/// walk can never read a row a prune may have deleted (ruled 2026-10-09).
/// It is the claim window, because a settlement row is retained for as
/// long as its epoch can be cited.
pub const SETTLEMENT_RETENTION_EPOCHS: u64 = MAX_CLAIM_AGE_W;

/// The least share of a pair's epochs, in thousandths, that must be
/// observed for the retention horizon to leave the window its full `n`
/// observations. At or above it the horizon never shortens a walk. Below
/// it a slash can be missed, which is accepted: a network observing fewer
/// than half its pair-epochs is degraded past the point where one
/// unslashed pair matters.
pub const WINDOW_MIN_OBSERVATION_PER_MILLE: u64 = 500;

/// The epochs the walk can read at an on-time slash pass: the decision
/// epoch `E` and back to the floor. The pass for `E` connects in epoch
/// `E + LAG − 1`, so the floor is `E + LAG − 1 − RETENTION` and the span
/// from it through `E` is `RETENTION + 2 − LAG`.
const WINDOW_READABLE_EPOCHS: u64 =
    SETTLEMENT_RETENTION_EPOCHS + 2 - SLASH_SETTLEMENT_TIP_LAG_EPOCHS;

const _: () = assert!(
    WINDOW_MIN_OBSERVATION_PER_MILLE * WINDOW_READABLE_EPOCHS
        >= 1000 * (ARCHIVAL_FAILURE_WINDOW_N as u64),
    "at the stated minimum observation rate the retention horizon leaves the failure \
     window fewer than n observations: the walk would be cut short on a healthy network. \
     Re-pinning n upward, the retention downward or the slash grace upward crosses this, \
     and each is a decision about the others"
);

/// The lowest settlement epoch the failure window may read when the block
/// at `connecting` runs the slash pass: the horizon below which a store
/// may have deleted settlement rows. Zero while the chain is younger than
/// the retention.
#[must_use]
pub const fn settlement_retention_floor(
    schedule: crate::SettlementSchedule,
    connecting: shekyl_types::BlockHeight,
) -> shekyl_types::SettlementEpoch {
    let floor = match schedule
        .prune_below_epoch_at_height(connecting.to_raw(), SETTLEMENT_RETENTION_EPOCHS)
    {
        Some(floor) => floor,
        None => 0,
    };
    shekyl_types::SettlementEpoch::from_raw(floor)
}

/// **Connect-order coupling — the slash pass must read what the close wrote.**
/// At every connect the hooks run slash **then** close
/// (`blockchain_db.cpp`: `process_archival_slash_at_height` before
/// `process_archival_epoch_close_at_height`), so the height at which the
/// slash pass settles epoch `E` (the first block above
/// `H_slash_deadline(E) = (E+1)·SEB − 1 + k·SEB`, i.e. operand
/// `(E+1+k)·SEB`) must be **strictly** greater than the height at which
/// `E`'s close fires (operand `(E+1)·SEB`) — same-height is not enough,
/// because within one connect the slash arm runs first. The difference is
/// exactly `k·SEB`, so the coupling holds iff `k ≥ 1` (the epoch is nonzero
/// by its own assert).
///
/// This can fire on a real re-pin: a future `W`-window redesign that sets the
/// grace to zero ("settle immediately at close") silently inverts the order —
/// the slash pass would read settlement state the close has not written yet,
/// exactly the fold-before-read hazard the settlement design gates
/// structurally. Re-pinning `SLASH_GRACE_EPOCHS` to zero requires reordering
/// the connect hooks first, and that is a decision about both sides, not a
/// constant bump. The affine-shape coupling of the two derivations
/// (`epoch_close_height` and `settlement_epoch_slash_deadline_height`, both
/// in `consensus_state` since DRS-E4 commit 4 moved the geometry to its one
/// home) is asserted by test in `shekyl-ffi`'s schedule module, which
/// imports both.
const _: () = assert!(
    SLASH_GRACE_EPOCHS >= 1,
    "SLASH_GRACE_EPOCHS = 0 lands the slash pass for epoch E on the SAME \
     connect height as E's close, and the connect order runs slash before \
     close - the slash would read settlement state the close has not written \
     yet; reorder the connect hooks before re-pinning this to zero"
);

/// One baseline observation for a `(P_id, shard)` pair: an epoch at which a
/// challenge was posed and could have been answered.
///
/// `served` is the epoch's served state — an **affirmative pass**, never
/// absence-of-failure (gate-2 §0.1). `!served` is the miss the window counts.
///
/// **`PC-D4`: this is a per-EPOCH boolean, and deliberately not a count.** The
/// ledger is per-challenge now — a pair-epoch may hold several rows — and the
/// caller collapses them (`archival_serve_credit_pass_count(...) > 0`) before
/// marshaling. The row multiplicity therefore never reaches this module, which
/// is why widening the key needed no change here. Anything that wants to
/// distinguish two passes from three must take the count as a new input rather
/// than reinterpret this flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineObservation {
    /// The settlement epoch the baseline was observed in.
    pub settlement_epoch: u64,
    /// Whether `(P_id, shard, settlement_epoch)` has any affirmative pass —
    /// `archival_serve_credit_pass_count(...) > 0` on the C++ side. Under
    /// `PC-D4` that is a fold over rows, not a single stored bit.
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

/// The Rust slash pass's failure window, gathered from settlement rows.
///
/// `decision` is a Missed epoch: the caller enters only then, and this
/// function does not read it again. `in_standing` is the record's
/// challengeable run ([`crate::good_through`]). `row` is that epoch's
/// settlement outcome, or `None` when the pair has no row.
///
/// Served and Missed are observations. NonObservation and an absent row
/// are passed over. The walk stops where `in_standing` is false, at
/// [`FAILURE_WINDOW_N`] observations, once passes exceed
/// [`FAILURE_WINDOW_SERVE_BUDGET`], and at `floor`. `floor` is read; nothing
/// below it is. The decision epoch is the first observation, so a walk that
/// never steps back is the decision alone.
///
/// # Errors
///
/// A `row` error is returned as it stands. The fold's own refusals are not
/// reachable from a walk this function built: the sequence holds the
/// decision epoch and at most [`FAILURE_WINDOW_N`] observations, strictly
/// descending, headed by a miss.
pub fn settlement_window_slashable<E>(
    decision: SettlementEpoch,
    floor: SettlementEpoch,
    mut in_standing: impl FnMut(SettlementEpoch) -> bool,
    mut row: impl FnMut(SettlementEpoch) -> Result<Option<SettlementOutcome>, E>,
) -> Result<bool, E> {
    let window = usize::try_from(FAILURE_WINDOW_N).expect("the window width fits a usize");
    let mut observations = Vec::with_capacity(window);
    observations.push(BaselineObservation::missed(decision.to_raw()));
    let mut passes_seen = 0u32;
    let mut earlier = decision;
    while observations.len() < window {
        let Some(candidate) = earlier
            .to_raw()
            .checked_sub(1)
            .map(SettlementEpoch::from_raw)
        else {
            break;
        };
        if candidate < floor {
            break;
        }
        earlier = candidate;
        if !in_standing(earlier) {
            break;
        }
        match row(earlier)? {
            Some(SettlementOutcome::Served) => {
                observations.push(BaselineObservation::served(earlier.to_raw()));
                passes_seen += 1;
                if passes_seen > FAILURE_WINDOW_SERVE_BUDGET {
                    break;
                }
            }
            Some(SettlementOutcome::Missed) => {
                observations.push(BaselineObservation::missed(earlier.to_raw()));
            }
            Some(SettlementOutcome::NonObservation) | None => {}
        }
    }
    Ok(failure_window_slashable(&observations).expect(
        "the gathered window holds the decision epoch and at most FAILURE_WINDOW_N observations",
    ))
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
    fn the_window_fits_inside_the_archival_retention_horizon() {
        // The C++ gather's bound (module docs, *The C++ gather*): it stops
        // at the first gap, so its deepest read is `n − 1` below the
        // decision epoch. The Rust gather passes over gaps; its bound is
        // [`settlement_retention_floor`], tested on
        // [`settlement_window_slashable`]. Both tables prune at one horizon
        // (`prune_archival_epochs_before`), and a breach fails in the
        // direction of the table read (SO-D5).
        let deepest_epoch_read = u64::from(FAILURE_WINDOW_N) - 1; // n - 1 below the decision epoch
        let oldest_epoch_retained = MAX_CLAIM_AGE_W - SLASH_SETTLEMENT_TIP_LAG_EPOCHS;
        assert!(
            deepest_epoch_read <= oldest_epoch_retained,
            "window reaches {deepest_epoch_read} epochs back; only \
             {oldest_epoch_retained} are retained at slash time"
        );
        assert_eq!(SLASH_SETTLEMENT_TIP_LAG_EPOCHS, 2);
        // Headroom for the Round-2 re-pin, at the genesis schedule.
        assert_eq!(oldest_epoch_retained - deepest_epoch_read, 12);
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

    fn epoch(raw: u64) -> SettlementEpoch {
        SettlementEpoch::from_raw(raw)
    }

    /// The epochs `row` was asked for, and whether the window slashes.
    fn walk<R>(
        decision: u64,
        floor: u64,
        in_standing: impl FnMut(SettlementEpoch) -> bool,
        row: R,
    ) -> (bool, Vec<u64>)
    where
        R: FnMut(SettlementEpoch) -> Result<Option<SettlementOutcome>, &'static str>,
    {
        let mut asked = Vec::new();
        let mut row = row;
        let slash = settlement_window_slashable(epoch(decision), epoch(floor), in_standing, |e| {
            asked.push(e.to_raw());
            row(e)
        })
        .expect("the row read succeeds");
        (slash, asked)
    }

    #[test]
    fn the_decision_epoch_is_the_first_observation_and_is_not_reread() {
        let (slash, asked) = walk(8, 0, |_| true, |_| Ok(Some(SettlementOutcome::Missed)));
        assert!(
            !asked.contains(&8),
            "the caller already knows the decision is a miss"
        );
        assert_eq!(asked.first().copied(), Some(7));
        // The decision plus the eight epochs below it is nine misses, under m.
        assert!(!slash);
        assert_eq!(asked.last().copied(), Some(0));
    }

    #[test]
    fn an_unobserved_epoch_is_passed_over() {
        let (slash, asked) = walk(
            12,
            0,
            |_| true,
            |epoch| {
                let outcome = match epoch.to_raw() {
                    11 => Some(SettlementOutcome::NonObservation),
                    9 => None,
                    _ => Some(SettlementOutcome::Missed),
                };
                Ok(outcome)
            },
        );
        // A stop at the NonObservation would leave the decision alone.
        // Passing over 11 and 9 gathers the decision plus the ten misses
        // at 10, 8, 7, …, 0: m, so the pair is slashed.
        assert!(slash);
        assert!(asked.contains(&11) && asked.contains(&9) && asked.contains(&0));
    }

    #[test]
    fn the_walk_stops_where_standing_ends_and_does_not_read_past_it() {
        let (slash, asked) = walk(
            20,
            0,
            |epoch| epoch.to_raw() >= 15,
            |_| Ok(Some(SettlementOutcome::Missed)),
        );
        assert!(!slash, "five misses inside the run are under m");
        assert_eq!(asked, (15..=19).rev().collect::<Vec<_>>());
    }

    #[test]
    fn three_served_epochs_end_the_walk_short_of_a_slash() {
        let (slash, asked) = walk(
            20,
            0,
            |_| true,
            |epoch| {
                let outcome = if epoch.to_raw() >= 17 {
                    SettlementOutcome::Served
                } else {
                    SettlementOutcome::Missed
                };
                Ok(Some(outcome))
            },
        );
        assert!(!slash);
        // The third serve is the one past the budget. The misses below it
        // would have reached m had the walk continued.
        assert_eq!(asked, vec![19, 18, 17]);
    }

    #[test]
    fn the_retention_floor_is_read_and_nothing_below_it_is() {
        // The chain case in miniature (ruled 2026-10-09): decision 28, floor
        // 3. Misses at 1..=10 leave epochs 1 and 2 below the floor, so the
        // eight inside it plus the decision are nine, under m.
        let (slash, asked) = walk(
            28,
            3,
            |_| true,
            |epoch| {
                let raw = epoch.to_raw();
                Ok((1..=10).contains(&raw).then_some(SettlementOutcome::Missed))
            },
        );
        assert!(!slash, "two of the ten misses sit below the floor");
        assert!(!asked.contains(&28));
        assert!(asked.contains(&3) && asked.contains(&10));
        assert!(!asked.contains(&2) && !asked.contains(&1));

        // The same gap, with the ten misses moved up onto the floor: 3..=12
        // plus the decision is m, and the pair is slashed.
        let (slash, asked) = walk(
            28,
            3,
            |_| true,
            |epoch| {
                let raw = epoch.to_raw();
                Ok((3..=12).contains(&raw).then_some(SettlementOutcome::Missed))
            },
        );
        assert!(slash, "eleven misses at or above the floor");
        assert!(asked.contains(&3));
        assert!(!asked.contains(&2));
    }

    #[test]
    fn a_row_read_that_fails_is_the_walks_error() {
        let err = settlement_window_slashable(
            epoch(4),
            epoch(0),
            |_| true,
            |epoch| {
                if epoch.to_raw() == 2 {
                    Err("hole")
                } else {
                    Ok(Some(SettlementOutcome::Missed))
                }
            },
        );
        assert_eq!(err, Err("hole"));
    }
}
