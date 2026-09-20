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
//! 3. **A reorg that catches back up.** A branch can rewind across an epoch
//!    open and be *above* the last observed height by the next refresh. If
//!    the replacement branch restored a shard at that open and dropped it
//!    again, the surviving entry releases a shard that was held when it
//!    mattered. Height monotonicity — the check hazard 2 first got — cannot
//!    see this at all: two branches share every height below their fork.
//!    Only the identity of the block at the observed height can, so the
//!    ledger rests on a [`ChainAnchor`] and refuses to carry an observation
//!    across a refresh whose anchor the chain no longer reports.
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

use shekyl_types::BlockHash;

use shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS;

use crate::engine::daemon::synced_chain_facts::{ChainAnchor, CoherentChainView, TimelineBreak};

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

/// What the chain reports now at the anchor the ledger last rested on.
///
/// Supplied by the caller — the ledger is a pure type and cannot ask the
/// daemon — but the **verdict** is the ledger's, not the caller's: it
/// compares the hash itself and forgets on anything but an exact match. A
/// caller cannot get this wrong in a way that helps it. Supplying the wrong
/// hash, or `Unverifiable`, both forget, which is the safe direction; the
/// only way to *carry* an observation is to hand back the very hash the
/// chain reported, at the height the ledger named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Continuity {
    /// The ledger rests on nothing yet, so there is nothing to verify.
    /// Only meaningful when [`DepartureLedger::resting_on`] is `None`; if it
    /// is `Some`, this is treated as unverifiable.
    FirstObservation,
    /// The block the chain reports now at the anchor's height.
    Verified { canonical_now: BlockHash },
    /// The anchor could not be re-read: the daemon was unreachable, or the
    /// height no longer exists on its chain. Either way, not comparable.
    Unverifiable,
}

/// What the connected record says this persona owes, in the shape the record
/// states it.
///
/// Two shapes because the record has two (`HoldingsKind`), and the ledger
/// must hear about both: a `CompleteTree` record owes the whole corpus **by
/// wire rule** — it carries no shard list, and reading its empty list as
/// "owes nothing" would mark every pinned shard absent. Handing the ledger
/// an honest "everything" instead lets a `CompleteTree` epoch do what any
/// other observation does: a shard that is owed is not departed, so its
/// clock is dropped and restarts if it leaves again.
///
/// The alternative — not observing a `CompleteTree` refresh at all — is
/// the defect this type replaces: an absence clock started under a compact
/// record survived an epoch in which the shard was owed and drawable, and
/// released on the next compact refresh as though that epoch had never
/// happened. Every vouched observation passes through
/// [`DepartureLedger::observe`]; the holdings kind chooses the input, not
/// whether the call is made.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Obligation<'a> {
    /// Every shard, by wire rule (`HoldingsKind::CompleteTree`).
    Everything,
    /// Exactly this list (`HoldingsKind::ShardSetCompact`), or nothing at all
    /// for a persona with no record.
    Exactly(&'a BTreeSet<u64>),
}

impl Obligation<'_> {
    fn owes(self, shard_id: u64) -> bool {
        match self {
            Self::Everything => true,
            Self::Exactly(set) => set.contains(&shard_id),
        }
    }
}

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
    /// The chain identity the current observations were taken against.
    /// Before the next observation is carried, the caller re-reads the block
    /// at this height and the ledger checks it is still this block.
    resting_on: Option<ChainAnchor>,
}

impl DepartureLedger {
    /// Fold one refresh's observation in, and return the shards whose pins
    /// are now releasable.
    ///
    /// `obligation` is what the connected record says this persona must
    /// serve, in the record's own shape ([`Obligation`]); `pinned` is what
    /// the store is actually retaining. The difference is
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
        continuity: Continuity,
        obligation: Obligation<'_>,
        pinned: &[u64],
    ) -> Vec<u64> {
        // Carry the prior observations only if the chain still reports the
        // block they were anchored to. Anything else — a different hash, an
        // unreadable anchor, `FirstObservation` claimed while resting on
        // something — forgets. This replaces a height-monotonicity check,
        // which a reorg-and-catch-up passes and this refuses: the heights
        // agree, the blocks do not.
        let carried = match (self.resting_on, continuity) {
            (None, _) => true,
            (Some(prior), Continuity::Verified { canonical_now }) => canonical_now == prior.hash,
            (Some(_), _) => false,
        };
        if !carried {
            self.absent_since.clear();
        }
        // A view with no coherent anchor (the reads disagreed in the
        // rollback direction) must not become the thing the NEXT refresh
        // rests on; the caller breaks the timeline on that path before
        // reaching here, so this is belt to that braces.
        match view.anchor() {
            Some(anchor) => self.resting_on = Some(anchor),
            None => {
                self.absent_since.clear();
                self.resting_on = None;
            }
        }

        // A shard back in the record is not departed at all: drop its entry
        // so its clock restarts if it leaves again.
        self.absent_since
            .retain(|&shard_id, _| !obligation.owes(shard_id));

        let now_epoch = view.at().to_raw() / SETTLEMENT_EPOCH_BLOCKS;
        let mut releasable = Vec::new();
        for &shard_id in pinned {
            if obligation.owes(shard_id) {
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
        self.resting_on = None;
    }

    /// The anchor the current observations rest on — what the caller must
    /// re-read from the chain and hand back as [`Continuity`] before the
    /// next observation, or `None` if there is nothing to carry.
    pub(crate) fn resting_on(&self) -> Option<ChainAnchor> {
        self.resting_on
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
