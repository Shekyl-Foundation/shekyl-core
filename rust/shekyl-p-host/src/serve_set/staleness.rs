// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Whether a host's serve-set is still tracking its bond record.

/// How many blocks of local ingest a serve-set may lag the record it was
/// derived from before the host is considered stale.
///
/// **Injectable, and deliberately not pinned here.** The tolerable lag is
/// "how long can a newly-connected shard go unpinned before a challenge can
/// ask for it", which is a function of the assignment schedule and
/// drawability — fork-2-adjacent territory, and the same class of number the
/// round refuses to guess for W₂ (`ARCHIVAL_CHALLENGE_MECHANISM.md` §7 fork
/// 5: deriving it first would be picking a number and back-filling the
/// justification). Injected rather than constant, on the `ScanSchedule`
/// precedent: the loop takes its cadence as a parameter so a later round can
/// pin it without touching the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StalenessBound(u64);

impl StalenessBound {
    /// A bound of `blocks` of local ingest.
    #[must_use]
    pub const fn blocks(blocks: u64) -> Self {
        Self(blocks)
    }

    /// The bound in blocks.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Whether a host's serve-set is still tracking its bond record.
///
/// # One clock read twice, and two drivers
///
/// The lag is [`ServingReader::sync_tip_height`](shekyl_curve_tree::ServingReader::sync_tip_height)
/// now, minus the same value stamped when the witness was minted. That is
/// deliberately *one* quantity: a difference of two different quantities is
/// only a lag when they happen to agree, and the two available here do not
/// — the record's [`ServeSet::as_of_height`](super::ServeSet::as_of_height)
/// is the daemon's tip over RPC, and a wallet catching up sits thousands of
/// blocks below it. Subtracting those would read `Current { lag: 0 }` for
/// the whole catch-up, which is exactly the window in which holdings move
/// and a gained shard goes unpinned.
///
/// What makes one clock a *liveness* signal is that the reader and the
/// writer of the stamp are different: the stamp is taken by the persona-side
/// P-scan refresh, and the value it stamps is advanced by the principal's
/// block scan. Stop the refresh and the stamp freezes while ingest keeps
/// climbing. A quantity the same driver moved on both sides would read
/// `Current` forever, which is the failure this exists to catch.
///
/// # What it cannot see
///
/// A wallet where the block scan **and** the refresh have both stopped —
/// most concretely a curve-tree actor that fail-stopped and could not be
/// resumed — freezes ingest and the stamp together, and the lag stays
/// constant. [`Self::RefreshFailing`] is the arm that covers it, and it is
/// host state rather than store state precisely so that a common-mode store
/// fault cannot silence it: a refresh that keeps being *attempted* and keeps
/// failing is evidence no store reading can supply.
///
/// The residual, stated rather than left implicit: if the refresh loop is
/// itself gone *and* ingest is stopped, nothing is attempted and nothing
/// advances, so there is no local evidence at all. That is a wallet in which
/// no task is running, and it is out of reach of any signal this host can
/// produce from inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Staleness {
    /// Within the bound.
    Current {
        /// Blocks ingested since the serve-set was last derived.
        lag: u64,
    },
    /// Past the bound: the serve-set has stopped tracking the bond record.
    ///
    /// **This is the shape the refresh's own failure takes, and it needs no
    /// adversary.** The refresh is periodic and lives *outside* the host, so
    /// anything that stops it stops it silently from here: the task is
    /// cancelled and nothing restarts it, the task was never started, it
    /// panics, or every sweep fails and retries forever against a daemon
    /// that is simply unreachable. A host whose refresh has stopped keeps
    /// serving a frozen serve-set, and a shard connected after the freeze is
    /// unpinned and prunable — the same ordinary steady-state hazard
    /// [`crate::PersonaServingHost::refresh`] exists to close, re-entering
    /// through the trigger rather than through the pins.
    ///
    /// A periodic job that has stopped is invisible to whatever depends on
    /// it; that is the whole of the argument, and it holds under every
    /// posture and every threat model. This is the only local evidence.
    Stale {
        /// Blocks ingested since the serve-set was last derived.
        lag: u64,
        /// The bound that was exceeded.
        bound: u64,
    },
    /// The store's ingest tip is **below** where it was when this witness
    /// was minted: the tree rolled back beneath these pins.
    ///
    /// Its own arm rather than a saturating zero, and rather than folding
    /// into [`Self::Stale`], because the diagnosis differs completely even
    /// though the next action is the same. `Stale` says the refresh
    /// machinery has stopped and should be investigated; this says a reorg
    /// happened, nothing is broken, and the next refresh tick re-pins and
    /// re-stamps. Sending an operator to debug a healthy refresh loop is a
    /// false alarm, and false alarms are how a tripwire gets ignored.
    ///
    /// **This arm does not answer the pin question, and must not be read as
    /// if it did.** It is a statement about the tip only. An earlier version
    /// of this doc said a rollback means "during this window the witness names
    /// pins the store no longer holds" — true, and the trap is the phrase
    /// *this window*: the tip is not monotonic, so re-ingest lifts it back
    /// above the stamp and closes the window while the deleted pin rows stay
    /// deleted. Whether pins are actually gone is measured by
    /// [`Self::PinsDropped`], which is checked first and has no window.
    RolledBack {
        /// The ingest tip stamped when the witness was minted.
        minted_at_tip: u64,
        /// The ingest tip now — below `minted_at_tip`.
        tip: u64,
    },
    /// Members this witness claims are pinned **are no longer pinned in the
    /// store**, so `prune_frozen` is free to discard their bytes.
    ///
    /// The most serious **list-arm** reading, and the only one that reports
    /// an exposure that has already happened rather than a signal that one
    /// might be developing.
    ///
    /// **Measured, not inferred, and that is the whole point.** Pins are
    /// deleted by `truncate_from_tree_position` / `rollback_to_fork` (the F9
    /// pinned-segment rollback) and **nothing recreates them but a re-pin** —
    /// block ingest does not. [`Self::RolledBack`] can only see the window
    /// where the tip is still below the stamp, and the tip is not monotonic:
    /// once the principal re-ingests past that height the subtraction goes
    /// positive again and every tip-derived arm reports `Current` while the
    /// pins stay gone. A host whose refresh trigger is the failed component
    /// would return to an affirmative healthy reading while serving shards
    /// nothing retains. Asking the pin table directly has no such window.
    ///
    /// **It cannot self-clear.** The condition is re-read from the store on
    /// every call, so it persists until a refresh actually re-pins — which
    /// mints a new witness. That is the latch, and it is structural rather
    /// than a flag someone has to remember to reset.
    /// A ratio rather than the id list, so this stays `Copy` like every other
    /// arm — it is polled beside the tor posture and folded into one operator
    /// alarm, and a status value that allocates would be the odd one out.
    /// `dropped` against `claimed` also separates the two cases that differ in
    /// remedy: a partial loss is a reorg above some members, while
    /// `dropped == claimed` is a store-wide event. The ids themselves are a
    /// diagnostic rather than a status, and live on
    /// [`PinnedServeSet::dropped_pins`](super::PinnedServeSet::dropped_pins).
    ///
    /// **Prefix witnesses never produce this arm.** They have no pin rows.
    /// A missing prune-disabled declaration is [`Self::PostureLost`].
    PinsDropped {
        /// Claimed members with no pin row.
        dropped: u32,
        /// Members this witness claims are pinned — the denominator.
        claimed: u32,
    },
    /// The CompleteTree prefix's prune-disabled declaration is **gone**.
    ///
    /// The prefix arm's pin is the one-way posture flag, not a pin table.
    /// A `false` after a successful acquire is corruption or tampering —
    /// every production surface is one-way — and `prune_frozen` is then
    /// free to discard the whole corpus. Re-declaring the flag (the
    /// production pinner does so idempotently on every refresh) restores
    /// the refusal, **not** any bytes already pruned in the window.
    ///
    /// Its own arm rather than [`Self::PinsDropped`]: that one means pin
    /// rows deleted by rollback, bytes still present, next refresh
    /// re-pins. None of that is true here. The operator who sees this
    /// should not be sent to debug a pin table this arm never wrote.
    PostureLost {
        /// The prefix length this witness claimed when the declaration
        /// vanished — the scope now unprotected.
        frozen_count: u64,
    },
    /// The last refresh attempt **failed**, and this many have failed in a
    /// row since the last success.
    ///
    /// Produced by [`crate::PersonaServingHost::staleness`], never by
    /// [`PinnedServeSet::staleness`](super::PinnedServeSet::staleness): it
    /// is a fact about attempts, not about the store, and that is what
    /// makes it the one arm a store-wide fault cannot suppress. When ingest
    /// and the refresh stop together — the fail-stopped curve-tree actor —
    /// the lag arms freeze and this one keeps counting.
    ///
    /// **No threshold, deliberately.** Reporting the first failure is not a
    /// verdict that the host is broken; it is the fact that the last attempt
    /// did not succeed, and `consecutive` is what separates a transient RPC
    /// blip from a refresh that has been failing for four hundred ticks.
    /// Inventing a "how many failures is too many" constant here would be
    /// the number-first, justification-after move this round refuses
    /// elsewhere — and unlike [`StalenessBound`], there is no injection site
    /// that would make it anyone else's to choose yet.
    RefreshFailing {
        /// Failed refresh attempts since the last successful one; at least 1.
        consecutive: u32,
    },
}

impl Staleness {
    /// Whether the serve-set is **not** known to be tracking the record.
    ///
    /// True for every arm but [`Self::Current`]. Note that a single failed
    /// refresh already reads stale: the arms report what is known, and what
    /// is known after a failed attempt is that the set was not re-derived.
    /// A caller that wants to tolerate a blip should match
    /// [`Self::RefreshFailing`] and read `consecutive` rather than ask this
    /// question.
    #[must_use]
    pub fn is_stale(self) -> bool {
        !matches!(self, Self::Current { .. })
    }

    /// Blocks ingested since the serve-set was last derived, where that is a
    /// meaningful number.
    ///
    /// `None` for [`Self::RolledBack`] (the store un-ingested; the
    /// difference is not a lag), [`Self::RefreshFailing`] (no store
    /// reading was taken), [`Self::PinsDropped`] and [`Self::PostureLost`]
    /// (an exposure, not a lag). Returning `0` for those would be the same
    /// false all-clear this reading exists to avoid, one layer up.
    #[must_use]
    pub fn lag(self) -> Option<u64> {
        match self {
            Self::Current { lag } | Self::Stale { lag, .. } => Some(lag),
            Self::RolledBack { .. }
            | Self::RefreshFailing { .. }
            | Self::PinsDropped { .. }
            | Self::PostureLost { .. } => None,
        }
    }
}

impl std::fmt::Display for Staleness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Current { lag } => write!(f, "serve-set current ({lag} blocks behind ingest)"),
            Self::Stale { lag, bound } => write!(
                f,
                "serve-set has not been re-derived for {lag} blocks of ingest (bound {bound}): \
                 a shard connected since then is unpinned and can be pruned before it is \
                 served — check that refresh is still succeeding"
            ),
            Self::RolledBack { minted_at_tip, tip } => write!(
                f,
                "the curve-tree store rolled back beneath this serve-set (ingest tip {tip}, \
                 pinned at {minted_at_tip}): a rollback drops pinned-segment rows above the \
                 fork, so these shards may no longer be pinned. The next refresh re-pins them; \
                 no action is needed unless this persists"
            ),
            Self::RefreshFailing { consecutive } => write!(
                f,
                "the serve-set refresh has failed {consecutive} time(s) in a row: the \
                 obligation is not being re-derived, so a shard connected since the last \
                 success is unpinned and can be pruned before it is served — check the \
                 persona's daemon transport and the curve-tree actor"
            ),
            Self::PinsDropped { dropped, claimed } => write!(
                f,
                "{dropped} of {claimed} serve-set members are no longer pinned in the store: \
                 their bytes can be pruned now, and this persona would fail a challenge on \
                 them. A rollback drops pinned rows and block ingest does not restore them, \
                 so this clears only when a refresh re-pins — check that refresh is still \
                 succeeding"
            ),
            Self::PostureLost { frozen_count } => write!(
                f,
                "the CompleteTree prune-disabled declaration is gone, so prune_frozen can \
                 discard the whole frozen corpus (prefix length {frozen_count}). Re-declaring \
                 the flag restores the refusal, not any bytes already pruned in the window. \
                 This is corruption or tampering — every production surface is one-way — \
                 check the store and that refresh is still succeeding"
            ),
        }
    }
}
