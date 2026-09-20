// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serve-set departure ledger and the chain view its observations are
//! admissible against (`WALLET_SIDE_STORE.md` `WSS-Q8` / `WSS-25`).
//!
//! # Why this is a module and not two checks in the pinner
//!
//! The release gate is the one piece of the serving design that destroys
//! data: after the `WSS-13` unwind a release erases bytes an honest archiver
//! is still obliged to serve. Everything here exists to make the *evidence*
//! that gate acts on impossible to forge by accident.
//!
//! That evidence is not a map of heights. It is a map of heights **plus the
//! claim that they were all observed on one unbroken timeline** — because the
//! gate's question is "has this shard been absent across two consecutive
//! epoch opens", and "consecutive" is a statement about the observer, not
//! about the chain. Two things break the timeline, and neither is visible in
//! the map:
//!
//! 1. **A sync gap.** While the daemon reports syncing the wallet observes
//!    nothing (`R-B`). A shard that was absent before the gap, re-added
//!    during it, and departed again after it carries a pre-gap timestamp that
//!    describes an absence which *ended*. Clocking from it can release
//!    immediately.
//! 2. **A rollback.** The daemon's `synchronized` flag is **sticky** — the
//!    inherited C++ sets it `false → true` exactly once
//!    (`cryptonote_protocol_handler.inl:2465`, the only mutation; the
//!    constructor at `:219` is the only other write) and never clears it on a
//!    pop or reorg. So a rollback between the sync read and the record read
//!    leaves a witness whose height is *above* the record's, and reading the
//!    ledger's clock off the witness counts epoch opens the current record
//!    never crossed.
//!
//! Hazard 2 is why *reading the sync witness first is not sufficient*, and
//! the correction is worth stating plainly because the ordering argument
//! sounds like it covers this and does not: ordering fixes which read is
//! older in wall-clock time, and the hazard is about which height is larger.
//! Those are different claims, and a sticky flag severs them.
//!
//! So the observation height is not a number the caller picks. It is
//! [`CoherentChainView`], which two mutually-corroborating reads have to
//! agree on, and the ledger accepts observations against nothing else.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS;

use crate::engine::daemon::synced_chain_facts::{CoherentChainView, TimelineBreak};

/// Consecutive epoch opens a shard must be absent across before its pin may
/// be released.
///
/// Two rather than one because one is too tight: absent at only the current
/// epoch's open makes the *previous* epoch the last one the pair was drawable
/// in, and a challenge issued in its final block still has to resolve. The
/// extra epoch is that resolution slack.
///
/// **`W₂` is deliberately not an operand.** The challenge-resolution window
/// has no landed constant — it is the rig's output
/// (`ARCHIVAL_CHALLENGE_MECHANISM.md` §9.7 item 6, still UNDERIVED) — so a
/// gate naming it could not be written yet. This one does not need it: a full
/// epoch of slack covers any `W₂` shorter than one `SETTLEMENT_EPOCH_BLOCKS`,
/// which at ~14 days against a window measured in minutes-to-hours is not a
/// close call. **Reopening criterion (rule 21):** if the rig ever derives a
/// `W₂` at or above one epoch, this gate is wrong and must take `W₂` as an
/// operand.
pub(crate) const EPOCHS_BEFORE_PIN_RELEASE: u64 = 2;

/// Shards pinned in the store but absent from the connected record, and the
/// coherent height at which each was **first** observed absent.
///
/// # In memory, per session, deliberately
///
/// A restart forgets the clock and restarts it, so a wallet that reopens
/// repeatedly reclaims disk more slowly — but it never releases *early*,
/// which is the only direction that costs anything irreversible. Persisting
/// it would buy faster reclamation of a recoverable resource at the price of
/// a schema version and a migration, for a decision `§9.7` item 5 already
/// rules should fail toward retention.
///
/// A broken timeline is handled the same way and for the same reason: the
/// ledger forgets, rather than trying to reason about what it did not see.
#[derive(Debug, Default)]
pub(crate) struct DepartureLedger {
    absent_since: BTreeMap<u64, CoherentChainView>,
    /// The view of the last admitted observation, for detecting a chain that
    /// moved backwards *between* refreshes — the same hazard
    /// [`CoherentChainView`] closes *within* one.
    last_observed: Option<CoherentChainView>,
}

impl DepartureLedger {
    /// Fold one refresh's observation in, and return the shards whose pins
    /// are now releasable.
    ///
    /// `owed` is what the connected record says this persona must serve;
    /// `pinned` is what the store is actually retaining. The difference is
    /// retained-but-not-owed — the leak `§9.7` item 5 prices at ~13.6 GB
    /// against a rule-76 Pi-4 floor, since nothing else removes a pin.
    ///
    /// # The gate is epoch-shaped, not reorg-shaped, and that is the point
    ///
    /// The obvious gate is a reorg depth — wait until the departure has
    /// settled. **That is the wrong quantity, and using it here would turn a
    /// disk leak into a slash risk.** §4 quantizes drawability to epoch
    /// boundaries: *"a pair is drawable in E iff it held the shard at E's
    /// open"*, evaluated at that fixed pre-challenge height on purpose — the
    /// WS-1 constraint, *"no tip-holdings read that would let P drop the
    /// shard after the fire and escape"*. A mid-epoch drop does **not** end
    /// the obligation for E; the pair stays drawable, and challengeable,
    /// through E's close.
    ///
    /// That matters here and not one layer up because
    /// [`StoreShardProvider`](shekyl_p_serve::StoreShardProvider) is
    /// serve-set-blind: it answers for any shard whose bytes are present. A
    /// dropped-but-still-pinned shard is therefore still *served*, which is
    /// why today's leak happens to keep the obligation met. Release the pin
    /// early and the prune reclaims the bytes while the pair is still
    /// drawable — a miss, then a slash, for disk.
    ///
    /// A shard that reappears in the record clears its entry, so a departure
    /// that reverses inside the window costs nothing and leaves no trace.
    pub(crate) fn observe(
        &mut self,
        view: CoherentChainView,
        owed: &BTreeSet<u64>,
        pinned: &[u64],
    ) -> Vec<u64> {
        // The chain moved backwards between refreshes. Prior entries were
        // clocked against heights this view cannot be compared to, so they
        // are not evidence any more — the same judgement the sync gap gets,
        // for the same reason. Deliberately a *reset*, not a saturating
        // subtraction: saturating kept stale entries alive and merely
        // declined to elapse them, which is the shape that let a pre-gap
        // timestamp survive into a post-gap decision.
        if self.last_observed.is_some_and(|last| view.at() < last.at()) {
            self.absent_since.clear();
        }
        self.last_observed = Some(view);

        // A shard back in the record is not departed at all: drop its entry
        // so its clock restarts if it leaves again.
        self.absent_since
            .retain(|shard_id, _| !owed.contains(shard_id));

        let now_epoch = view.at().to_raw() / SETTLEMENT_EPOCH_BLOCKS;
        let mut releasable = Vec::new();
        for &shard_id in pinned {
            if owed.contains(&shard_id) {
                continue;
            }
            let first_absent = *self.absent_since.entry(shard_id).or_insert(view);
            let absent_epoch = first_absent.at().to_raw() / SETTLEMENT_EPOCH_BLOCKS;
            if now_epoch.saturating_sub(absent_epoch) >= EPOCHS_BEFORE_PIN_RELEASE {
                releasable.push(shard_id);
            }
        }
        // Released pins stop being pinned, so their entries are spent.
        for shard_id in &releasable {
            self.absent_since.remove(shard_id);
        }
        releasable
    }

    /// Record that the wallet could not observe, and forget what it knew.
    ///
    /// Called on every refresh that cannot mint a [`SyncedChainFacts`]. The
    /// entries are dropped rather than frozen because a frozen entry is a
    /// claim about an interval nobody watched: a shard absent before the
    /// break, re-added during it, and departed again after it would otherwise
    /// resume a clock that had already been satisfied and could release at
    /// once.
    ///
    /// Forgetting costs a full re-observation — at worst two more epochs of
    /// retained disk. That is the recoverable direction, and it is the same
    /// trade the restart case already takes.
    pub(crate) fn break_timeline(&mut self, _why: TimelineBreak) {
        self.absent_since.clear();
        self.last_observed = None;
    }

    /// How many shards are currently under observation as departed.
    ///
    /// The ledger's only read surface: the release decision is
    /// [`Self::observe`]'s return value, so nothing outside needs the map.
    #[cfg(test)]
    pub(crate) fn observed_absences(&self) -> usize {
        self.absent_since.len()
    }
}

#[cfg(test)]
#[path = "departure_ledger_tests.rs"]
mod tests;
