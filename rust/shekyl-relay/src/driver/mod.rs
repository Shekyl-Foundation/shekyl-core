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
//! the hazard the seal named (§18.5 finding 3). Nor is it pushed an array to
//! decode: a covert binding travels with each [`Effect::NoiseSend`], and a
//! channel whose slot is unbound is told so at its own cadence by
//! [`Effect::NoiseUnbind`] — decisions leave, never the inputs to them
//! (§20.3). Commands (`update_stems`, connection events) mutate and return
//! nothing; every effect leaves through [`Driver::poll`] or a force hook.

use shekyl_relay_privacy::rng::RelayRng;
use shekyl_relay_privacy::schedule::Millis;
use shekyl_relay_privacy::stem_map::ConnectionId;

#[cfg(test)]
use crate::zone::FluffReach;
use crate::zone::{TxBlob, Zone};

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
    /// Covert channel `channel` is due: send on it now.
    ///
    /// **Carries no payload discriminant, and that is CV-4** (§20.2). Whether
    /// this send is a dummy or drains a queued real fragment is a *queue*
    /// question, and the queue is C++. Rust decides **when** and **who**; C++
    /// decides **what**.
    ///
    /// The omission is structural, not stylistic. Handing the scheduler a
    /// `DUMMY | REAL` tag would let the cadence react to having something real
    /// to say — and the breaking change would look like an optimisation
    /// (*"a real fragment is pending, drain it sooner"*), which is a
    /// covert-channel leak wearing a latency improvement's costume. Constant-rate
    /// cover works precisely because the schedule cannot know. With no
    /// discriminant here, Rust is not *trusted* to ignore the queue — it is
    /// structurally unable to consult it.
    NoiseSend {
        /// Channel index. Positional: channel `i` is bound to stem slot `i`.
        channel: usize,
        /// The peer stem slot `channel` is bound to — **the inversion** (§20.3).
        /// Rust no longer pushes an ordered slot array for C++ to bind
        /// positionally; it hands over the decision itself, already made
        /// against the map it owns. An unbound slot emits nothing (CV-2), so
        /// this is never nil.
        peer: ConnectionId,
    },
    /// Covert channel `channel` is due but its stem slot is unbound: clear it.
    ///
    /// **The other half of the deleted slot array** (§20.3, amended at the
    /// deletion). The array carried two facts per slot: *who* a bound channel
    /// sends to — which now travels with each [`Effect::NoiseSend`] — and
    /// *that* an unbound channel stopped. The second fact cannot ride a send,
    /// because an unbound channel emits none (CV-2); without it, the C++
    /// enqueue guard (`queue_covert_notify`'s nil check) reads a stale binding
    /// forever, and a dormant channel accumulates queued messages without
    /// bound — a node holding fewer peers than the channel width is a
    /// *permanent* instance of that state, not a transient one.
    ///
    /// **Derived per due tick, not pushed per transition.** This occupies the
    /// cadence slot a send would have: each due channel emits exactly one
    /// effect, send or unbind by the binding's current state, read from
    /// `stem_slots()` at the poll. A transition-shaped emission was rejected
    /// twice over: it needs the driver to remember what the binding was last
    /// poll — a shadow copy of a fact the map owns, the duplicate-fact class
    /// `PeerFluff::flush_at` named and `live_stems` was designed out of — and
    /// it is one-shot, so a clear that fails to take effect (a swallowed
    /// exception, a dropped post) leaves the guard stale *permanently*, which
    /// is the exact failure this effect exists to prevent. Per-tick derivation
    /// caches nothing and self-heals: a lost clear repeats one covert interval
    /// later, and the receiver (`clear_channel`) is idempotent, so repetition
    /// is free.
    ///
    /// Still a decision, not an input: one channel index, no array, no width
    /// for C++ to reconcile. The receiver restores the inherited nil-repoint
    /// semantics — nil the binding, discard buffers — on the channel's strand.
    /// A rebind never emits this: the new binding travels with the next send,
    /// where the in-flight remainder is discarded (CV-1).
    NoiseUnbind {
        /// Channel index. Positional: channel `i` follows stem slot `i`.
        channel: usize,
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
    zone: Zone,
}

impl Driver {
    /// Take ownership of a zone.
    pub fn new(zone: Zone) -> Self {
        Self { zone }
    }

    /// The zone, for commands that arrive from outside (connection events,
    /// transactions offered for relay).
    pub fn zone_mut(&mut self) -> &mut Zone {
        &mut self.zone
    }

    /// The zone, for reads.
    pub fn zone(&self) -> &Zone {
        &self.zone
    }

    /// When the driver next has work — the earliest of the epoch boundary,
    /// any pending fluff batch, any covert channel, and any in-flight stem
    /// observation.
    ///
    /// **Derived on every call, never cached.** A stored copy would be a second
    /// owner of a fact the schedulers already hold, and it would go stale the
    /// moment a newly queued batch draws an earlier deadline than the one last
    /// armed. `next_wake_follows_a_newly_queued_batch_without_re_arming` is the
    /// test that fails if someone adds that cache.
    pub fn next_wake(&self) -> Millis {
        // Four sources, folded into one answer: the epoch always has a
        // deadline; fluff has one only with a batch pending; covert has one
        // only when the zone runs covert channels; stem observations have one
        // while anything is in flight (§38 — silence resolves on this clock).
        //
        // **Folding the sleep is not folding the schedule** (§20.2a). Each
        // covert channel keeps its own deadline in the zone; this only asks
        // which is earliest. That distinction is the whole of CV-3: the shared
        // wake is what makes a resample-on-foreign-wake bug *reachable*, so the
        // re-arm stays in `Zone::due_noise_channel`, which touches only the
        // single channel that actually fired. Stem observation is the same
        // shape: per-tx deadlines live in `StemWatch`; this only folds the min.
        let mut wake = self.zone.epoch_deadline();
        if let Some(fluff) = self.zone.fluff_deadline() {
            wake = wake.min(fluff);
        }
        if let Some(covert) = self.zone.noise_deadline() {
            wake = wake.min(covert);
        }
        if let Some(stem) = self.zone.stem_observation_deadline() {
            wake = wake.min(stem);
        }
        wake
    }

    /// Run every step due at `now` and return the resulting work.
    ///
    /// `gather_outbound` yields the caller's current outbound connection set —
    /// the driver does not reach for it, because the p2p connection table is
    /// asio's to own (§18.5). It is a **thunk, not a slice**, because the set is
    /// needed *only* at an epoch boundary, where the stem map is rebuilt; a plain
    /// fluff-release wake — the common case — must not pay to gather it. So the
    /// closure is called at most once, and only inside the epoch branch below.
    /// The branch that decides this is the zone's own `epoch_deadline`, evaluated
    /// exactly here: the caller never holds a copy of it to decide for itself.
    pub fn poll<R: RelayRng + ?Sized>(
        &mut self,
        now: Millis,
        gather_outbound: impl FnOnce() -> Vec<ConnectionId>,
        rng: &mut R,
    ) -> Vec<Effect> {
        let mut effects = Vec::new();

        // Epoch first: a rollover re-draws the role and the stem set, and the
        // fluff release below should observe the new epoch, not the old one.
        // Only here is `gather_outbound` invoked — a fluff-only wake skips it.
        if now >= self.zone.epoch_deadline() {
            self.zone.start_epoch(now, rng);
            self.zone.rebuild_stems(gather_outbound(), rng);
        }

        // Stem observations resolve here: a deadline passed with no re-arrival
        // is a silence (§38). After the epoch block, so a rollover's fresh map
        // cannot retroactively change who an in-flight observation was charged
        // to. The earliest pending deadline is folded into `next_wake`, so the
        // asio timer actually fires for these — not only when fluff/epoch
        // happen to wake first.
        // The count is discarded **intentionally, pending a consumer** — the
        // selection tier that reads these tallies is §12.11 and is not built.
        // Said here because a production call with a dropped return is
        // otherwise indistinguishable from rot at the next census, which is
        // the same note the covert machinery carries.
        let _resolved = self.zone.expire_stem_observations(now);

        for (peer, blobs) in self.zone.flush_fluff(now, false) {
            effects.push(Effect::Fluff { peer, blobs });
        }

        // Covert steps last, and after the epoch block on purpose: a rollover
        // rebuilds the stem slots, and channel `i` follows slot `i`, so
        // emitting before the rebuild would name a channel against the slots it
        // is about to stop being bound to.
        //
        // At most one covert effect per poll (`due_noise_channel`): a late
        // strand that finds several deadlines past must not emit them as a
        // synchronized multi-channel burst. Remaining due channels surface on
        // the next wake (immediate if their deadlines are still in the past).
        // Nothing here consults a queue or a payload — CV-4 by construction.
        // The binding is resolved HERE, against the map the zone owns: send or
        // unbind by the binding's current state. An unbound slot produces no
        // covert SEND at its index and shifts no other (CV-2); its due tick
        // carries the clear instead — see [`Effect::NoiseUnbind`].
        if let Some(channel) = self.zone.due_noise_channel(now, rng) {
            match self.zone.stem_slots().get(channel).copied().flatten() {
                Some(peer) => effects.push(Effect::NoiseSend { channel, peer }),
                None => effects.push(Effect::NoiseUnbind { channel }),
            }
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
    pub fn force_epoch<R: RelayRng + ?Sized>(
        &mut self,
        now: Millis,
        outbound: &[ConnectionId],
        rng: &mut R,
    ) {
        self.zone.start_epoch(now, rng);
        self.zone.rebuild_stems(outbound.to_vec(), rng);
    }
}

#[cfg(test)]
mod tests;
