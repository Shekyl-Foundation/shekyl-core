// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Driving the zone: what runs when a deadline elapses, and what the caller
//! must do about it.
//!
//! This decides *when*; it does not sleep. The caller arms its existing timer
//! against [`Driver::next_wake`] and calls [`Driver::poll`] when that elapses —
//! so RP-3a adds no reactor to the p2p path, and `shekyl-relay-privacy`'s
//! reason-2 seal (*"the existing timer stays in charge"*) holds rather than
//! breaks. Ownership is still single: the driver owns the zone, and the only
//! things crossing the boundary are commands inward and [`Effect`]s outward.
//!
//! # Two disciplines this module exists to hold
//!
//! **Hold the mechanism, derive the fact.** There is deliberately no
//! `armed_deadline` field. The next wake time is a *derived* read of the
//! schedulers ([`Driver::next_wake`]), never a cached copy — because the
//! schedulers already own their deadlines, and a second copy desyncs exactly
//! when re-arming races a fresh draw. That is the `PeerFluff::flush_at` bug one
//! layer up, and the same fix applies before it happens. A driver may legitimately
//! hold an OS timer *handle* — that is the mechanism, "a timer is pending" — but
//! never the deadline *value*, which is the fact the scheduler owns.
//!
//! **The map never crosses, in either direction.** C++ is never given a way to
//! read the stem map on its own schedule: with the zone strand gone, a
//! caller-initiated read would race this driver's mutations, which is precisely
//! the hazard the seal named (§18.5 finding 3). The carrier, in its own task,
//! is handed a copy of the slots and the covered sessions
//! ([`Relay::carrier_view`]) when they change, never a reference. Commands
//! (`update_stems`, connection events) mutate and return nothing; every
//! effect leaves through [`Driver::poll`] or a force hook.

use shekyl_draw_rng::RelayRng;
use shekyl_relay_privacy::schedule::Millis;
use shekyl_relay_privacy::stem_map::ConnectionId;

use crate::graph::{Relay, TxBlob};

/// Work the driver produced that the caller must perform.
///
/// The zone decides; transport acts. Blobs are opaque — framing, padding and
/// the socket stay C++ — so an effect names a destination and bytes, never a
/// message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Release this peer's batch. The caller frames and sends.
    Fluff {
        /// Where the batch goes.
        peer: ConnectionId,
        /// The batched transaction blobs (shared handles; content-sorted).
        blobs: Vec<TxBlob>,
    },
    /// Stem this transaction to `peer`: an embargo's reshape to the
    /// alternate (§12.2), or a held origin's first send (RX-2).
    ///
    /// [`carrier`](Effect::Stem::carrier) is the zone's decision. The caller
    /// sends as it says and records the stem when the write lands. The bytes
    /// are the transaction's own; no relay or retry state rides them (§12.2
    /// item 5).
    Stem {
        /// The successor.
        peer: ConnectionId,
        /// The transaction, by hash.
        tx: crate::TxId,
        /// Its bytes.
        blob: TxBlob,
        /// The session it arrived on; `None` for this node's own.
        source: Option<ConnectionId>,
        /// How the stem leaves.
        carrier: crate::RelayCarrier,
    },
    /// The zone fluffed these relayed transactions when their stem phase
    /// ended at an embargo: the pool's shown bit is set for each
    /// (criterion 2, Q9).
    Published {
        /// The transactions, by hash.
        txs: Vec<crate::TxId>,
    },
}

/// Owns a zone and runs its scheduled steps.
///
/// Sync by construction: nothing here spawns, sleeps or awaits. A production
/// task sleeps until [`Driver::next_wake`] and calls [`Driver::poll`]; a test
/// calls `poll` directly. Both run the same code, which is what keeps the
/// daemon's force-step hooks honest rather than a test-only shortcut.
#[derive(Debug)]
pub struct Driver {
    zone: Relay,
}

impl Driver {
    /// Take ownership of a zone.
    pub fn new(zone: Relay) -> Self {
        Self { zone }
    }

    /// The zone, for commands that arrive from outside (connection events,
    /// transactions offered for relay).
    pub fn zone_mut(&mut self) -> &mut Relay {
        &mut self.zone
    }

    /// The zone, for reads.
    pub fn zone(&self) -> &Relay {
        &self.zone
    }

    /// When the driver next has work — the earliest of the epoch boundary,
    /// any pending fluff batch, any noise channel, any in-flight stem
    /// observation (each one an embargo), and any held origin's next plan.
    ///
    /// **Derived on every call, never cached.** A stored copy would be a second
    /// owner of a fact the schedulers already hold, and it would go stale the
    /// moment a newly queued batch draws an earlier deadline than the one last
    /// armed. `next_wake_follows_a_newly_queued_batch_without_re_arming` is the
    /// test that fails if someone adds that cache.
    pub fn next_wake(&self) -> Millis {
        // The sources, folded into one answer: the epoch always has a
        // deadline; fluff has one only with a batch pending; stem
        // observations have one while anything is in flight (§38 — silence
        // resolves on this clock); held origins have one while any is held. Per-tx deadlines live in their owners; this only
        // folds the min. The carrier's channels keep their own schedule in
        // their own task (`crate::carrier`, `CVR-R6`).
        let mut wake = self.zone.epoch_deadline();
        if let Some(fluff) = self.zone.fluff_deadline() {
            wake = wake.min(fluff);
        }
        if let Some(stem) = self.zone.stem_observation_deadline() {
            wake = wake.min(stem);
        }
        if let Some(unsent) = self.zone.unsent_deadline() {
            wake = wake.min(unsent);
        }
        wake
    }

    /// Run every step due at `now` and return the resulting work.
    ///
    /// The stem set at an epoch boundary is the zone's established outbound
    /// sessions. A fluff-release wake does not rebuild it. The branch that
    /// decides this is the zone's own `epoch_deadline`, evaluated exactly
    /// here: the caller never holds a copy of it to decide for itself.
    pub fn poll<R: RelayRng + ?Sized>(&mut self, now: Millis, rng: &mut R) -> Vec<Effect> {
        let mut effects = Vec::new();

        // Epoch first: a rollover re-draws the role and the stem set from
        // the session registry, and the fluff release below should observe
        // the new epoch, not the old one.
        if now >= self.zone.epoch_deadline() {
            self.zone.start_epoch(now, rng);
            self.zone.rebuild_stems(rng);
        }

        // Stem observations resolve here: a deadline passed with no re-arrival
        // is a silence (§38). After the epoch block, so a rollover's fresh map
        // cannot retroactively change who an in-flight observation was charged
        // to. The earliest pending deadline is folded into `next_wake`, so the
        // asio timer actually fires for these — not only when fluff/epoch
        // happen to wake first.
        // A silence is an embargo that fired: the zone re-stems to the
        // alternate or ends the stem phase (§12.2, §14.7; `CVR-R6`). Then every held origin that is
        // due is planned again (RX-2). The tallies the silences also feed are
        // §12.11's, whose selection consumer is not built.
        let fired = self.zone.fire_embargoes(now, rng);
        let unsent = self.zone.due_unsent(now, rng);
        for stem in fired.stems.into_iter().chain(unsent.stems) {
            effects.push(Effect::Stem {
                peer: stem.peer,
                tx: stem.tx,
                blob: stem.blob,
                source: stem.source,
                carrier: stem.carrier,
            });
        }
        if !fired.published.is_empty() {
            effects.push(Effect::Published {
                txs: fired.published,
            });
        }

        for (peer, blobs) in self.zone.flush_fluff(now, false) {
            effects.push(Effect::Fluff { peer, blobs });
        }

        effects
    }

    /// Release every pending fluff batch regardless of deadline.
    ///
    /// What the daemon's `run_fluff()` hook drives. It runs the same release
    /// path as [`Driver::poll`]; only which batches count as due differs.
    pub fn force_fluff(&mut self, now: Millis) -> Vec<Effect> {
        self.zone
            .flush_fluff(now, true)
            .into_iter()
            .map(|(peer, blobs)| Effect::Fluff { peer, blobs })
            .collect()
    }

    /// Start a new epoch immediately — what `run_epoch()` drives.
    pub fn force_epoch<R: RelayRng + ?Sized>(&mut self, now: Millis, rng: &mut R) {
        self.zone.start_epoch(now, rng);
        self.zone.rebuild_stems(rng);
    }
}

#[cfg(test)]
mod tests;
