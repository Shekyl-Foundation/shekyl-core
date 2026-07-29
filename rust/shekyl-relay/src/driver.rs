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
//! **Push, never pull.** Stem-slot changes leave as [`Effect::StemSlots`]. C++
//! is never given a way to read the map on its own schedule: with the zone
//! strand gone, a caller-initiated read would race this driver's mutations,
//! which is precisely the hazard the seal named (§18.5 finding 3).

use shekyl_relay_privacy::rng::RelayRng;
use shekyl_relay_privacy::schedule::Millis;
use shekyl_relay_privacy::stem_map::{ConnectionId, StemSetChange};

#[cfg(test)]
use crate::zone::FluffReach;
use crate::zone::{RelayPlan, TxBlob, Zone};

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
    /// The stem slots changed; re-point anything bound to them positionally.
    ///
    /// **Pushed, never pulled.** Slot order is meaningful and nils are kept in
    /// position, because the consumer indexes by slot (§16.1 contract 3).
    StemSlots(Vec<Option<ConnectionId>>),
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
    CovertSend {
        /// Channel index. Positional: channel `i` is bound to stem slot `i`.
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

    /// When the driver next has work — the earliest of the epoch boundary and
    /// any pending fluff batch.
    ///
    /// **Derived on every call, never cached.** A stored copy would be a second
    /// owner of a fact the schedulers already hold, and it would go stale the
    /// moment a newly queued batch draws an earlier deadline than the one last
    /// armed. `next_wake_follows_a_newly_queued_batch_without_re_arming` is the
    /// test that fails if someone adds that cache.
    pub fn next_wake(&self) -> Millis {
        // Three sources now, folded into one answer: the epoch always has a
        // deadline; fluff has one only with a batch pending; covert has one
        // only when the zone runs covert channels.
        //
        // **Folding the sleep is not folding the schedule** (§20.2a). Each
        // covert channel keeps its own deadline in the zone; this only asks
        // which is earliest. That distinction is the whole of CV-3: the shared
        // wake is what makes a resample-on-foreign-wake bug *reachable*, so the
        // re-arm stays in `Zone::due_covert_channels`, which touches only the
        // channels that actually fired.
        let mut wake = self.zone.epoch_deadline();
        if let Some(fluff) = self.zone.fluff_deadline() {
            wake = wake.min(fluff);
        }
        if let Some(covert) = self.zone.covert_deadline() {
            wake = wake.min(covert);
        }
        wake
    }

    /// Merge the caller's current outbound set into the stem map, pushing the
    /// new slots outward if the set changed.
    ///
    /// This is the inherited `update_channels::run` — a *mid-epoch* refresh,
    /// distinct from the rollover below. The daemon needs it on three paths: a
    /// new outbound connection, a covert send that failed, and the forced
    /// refresh after a stem send failure in `dandelionpp_notify`. First-time
    /// population of an empty public-zone map is handled by
    /// [`Driver::plan_relay_with_refresh`] instead.
    pub fn update_stems<R: RelayRng + ?Sized>(
        &mut self,
        outbound: &[ConnectionId],
        rng: &mut R,
    ) -> Vec<Effect> {
        let change = self.zone.update_stems(outbound.to_vec(), rng);
        self.slots_if_changed(change)
    }

    /// Plan a relay; on [`RelayPlan::NoRoute`], refresh from `outbound` once
    /// and re-plan, pushing slots if the refresh changed them.
    ///
    /// See [`Zone::plan_relay_with_refresh`]. Returns the plan plus any
    /// [`Effect::StemSlots`] the mid-call refresh produced.
    pub fn plan_relay_with_refresh<R: RelayRng + ?Sized>(
        &mut self,
        source: Option<ConnectionId>,
        local_origin: bool,
        outbound: &[ConnectionId],
        rng: &mut R,
    ) -> (RelayPlan, Vec<Effect>) {
        let (plan, change) =
            self.zone
                .plan_relay_with_refresh(source, local_origin, outbound.to_vec(), rng);
        (plan, self.slots_if_changed(change))
    }

    /// Re-draw the whole stem set — what an epoch rollover does.
    ///
    /// See [`crate::Zone::rebuild_stems`] for why this is not the merge above.
    fn rebuild_stems<R: RelayRng + ?Sized>(
        &mut self,
        outbound: &[ConnectionId],
        rng: &mut R,
    ) -> Vec<Effect> {
        let change = self.zone.rebuild_stems(outbound.to_vec(), rng);
        self.slots_if_changed(change)
    }

    /// The one place "changed ⇒ push the slots" is implemented. A second copy
    /// of that rule is a second place for the push to be forgotten, and a
    /// forgotten push is silent: the slots simply stay stale.
    fn slots_if_changed(&self, change: StemSetChange) -> Vec<Effect> {
        if change.needs_rearm() {
            vec![Effect::StemSlots(self.zone.stem_slots().to_vec())]
        } else {
            Vec::new()
        }
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
            effects.extend(self.rebuild_stems(&gather_outbound(), rng));
        }

        for (peer, blobs) in self.zone.flush_fluff(now, false) {
            effects.push(Effect::Fluff { peer, blobs });
        }

        // Covert sends last, and after the epoch block on purpose: a rollover
        // rebuilds the stem slots, and channel `i` is bound to slot `i`, so
        // emitting before the rebuild would name a channel against the slots it
        // is about to stop being bound to.
        //
        // `due_covert_channels` re-arms only what fired (CV-3). Nothing here
        // consults a queue or a payload — the effect carries an index and
        // nothing else, which is CV-4 by construction.
        for channel in self.zone.due_covert_channels(now, rng) {
            effects.push(Effect::CovertSend { channel });
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
    ) -> Vec<Effect> {
        self.zone.start_epoch(now, rng);
        self.rebuild_stems(outbound, rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_relay_privacy::params::DandelionParams;
    use shekyl_relay_privacy::rng::SplitMix64;
    use shekyl_relay_privacy::schedule::PeerDirection;

    fn id(byte: u8) -> ConnectionId {
        let mut b = [0u8; 16];
        b[0] = byte;
        ConnectionId::from_bytes(b)
    }

    /// A `gather_outbound` thunk that must never run. Passed to [`Driver::poll`]
    /// on wakes that do not cross an epoch boundary, so it doubles as the witness
    /// that a fluff-only wake never pays for the outbound scan — poll invoking it
    /// off an epoch boundary would fail here rather than pass quietly.
    fn no_gather() -> Vec<ConnectionId> {
        unreachable!("a fluff-only wake must not gather the outbound set")
    }

    fn driver(rng: &mut SplitMix64) -> Driver {
        Driver::new(Zone::new(
            DandelionParams::inherited(),
            2,
            FluffReach::EveryPeer,
            false,
            0,
            rng,
        ))
    }

    #[test]
    fn next_wake_follows_a_newly_queued_batch_without_re_arming() {
        // The duplicate-fact guard, and the reason there is no `armed_deadline`
        // field. A cached wake time would still hold the epoch boundary here,
        // because nothing told it to re-arm — and the fluff would fire late, or
        // not until the epoch rolled. Deriving the fact makes that
        // unrepresentable rather than merely unlikely.
        let mut rng = SplitMix64::new(40);
        let mut d = driver(&mut rng);
        let epoch_wake = d.next_wake();
        assert_eq!(
            epoch_wake,
            d.zone().epoch_deadline(),
            "with no batch pending, the epoch boundary is the only wake"
        );

        d.zone_mut()
            .on_handshake_complete(id(1), PeerDirection::Outbound);
        d.zone_mut().queue_fluff(&[vec![1]], None, 0, &mut rng);
        let fluff = d.zone().fluff_deadline().expect("a batch is in flight");
        assert!(fluff < epoch_wake, "fixture: the fluff must be the sooner");

        assert_eq!(
            d.next_wake(),
            fluff,
            "next_wake must follow a fresh draw with no explicit re-arm — if this \
             fails, look for a cached armed-deadline that went stale"
        );
    }

    #[test]
    fn polling_releases_a_batch_at_its_deadline_and_not_before() {
        let mut rng = SplitMix64::new(41);
        let mut d = driver(&mut rng);
        d.zone_mut()
            .on_handshake_complete(id(1), PeerDirection::Inbound);
        d.zone_mut().queue_fluff(&[vec![7]], None, 0, &mut rng);
        let due = d.zone().fluff_deadline().unwrap();

        if due > 0 {
            assert!(
                d.poll(due - 1, no_gather, &mut rng).is_empty(),
                "not due yet"
            );
        }
        assert_eq!(
            d.poll(due, no_gather, &mut rng),
            vec![Effect::Fluff {
                peer: id(1),
                blobs: vec![TxBlob::from([7u8].as_slice())]
            }]
        );
    }

    #[test]
    fn an_epoch_rollover_pushes_the_new_slots_outward() {
        // Push, not pull (§18.5 finding 3): the caller learns the slots changed
        // because the driver hands them over, never because it reached in.
        let mut rng = SplitMix64::new(42);
        let mut d = driver(&mut rng);
        let outbound = vec![id(1), id(2), id(3)];

        let effects = d.poll(d.zone().epoch_deadline(), || outbound.clone(), &mut rng);
        let slots = effects
            .iter()
            .find_map(|e| match e {
                Effect::StemSlots(s) => Some(s.clone()),
                Effect::Fluff { .. } | Effect::CovertSend { .. } => None,
            })
            .expect("a rollover re-draws the stem set");
        assert_eq!(slots.len(), 2, "two slots at the configured width");
        assert!(slots.iter().flatten().all(|p| outbound.contains(p)));
    }

    #[test]
    fn a_mid_epoch_refresh_pushes_slots_without_rolling_the_epoch() {
        // The path the public zone actually depends on. `notify` is constructed
        // before any peer connects, so the map is empty until the first relay
        // attempt refreshes it — without this, every transaction would fluff on
        // a node that is perfectly able to stem.
        let mut rng = SplitMix64::new(45);
        let mut d = driver(&mut rng);
        let deadline = d.zone().epoch_deadline();
        assert_eq!(d.zone().live_stems(), 0, "fixture: no peers yet");

        let effects = d.update_stems(&[id(1), id(2), id(3)], &mut rng);
        assert!(
            matches!(effects.as_slice(), [Effect::StemSlots(s)] if s.len() == 2),
            "a first population is a change, so the slots must be pushed"
        );
        assert_eq!(d.zone().live_stems(), 2);
        assert_eq!(
            d.zone().epoch_deadline(),
            deadline,
            "a refresh is not a rollover — the role and its deadline stand"
        );

        assert!(
            d.update_stems(&[id(1), id(2), id(3)], &mut rng).is_empty(),
            "an unchanged set must push nothing, or every relay attempt would \
             re-point the covert channels bound to these slots"
        );
    }

    #[test]
    fn polling_before_the_epoch_boundary_changes_nothing() {
        let mut rng = SplitMix64::new(43);
        let mut d = driver(&mut rng);
        let deadline = d.zone().epoch_deadline();
        assert!(d.poll(deadline - 1, no_gather, &mut rng).is_empty());
        assert_eq!(d.zone().epoch_deadline(), deadline, "epoch untouched");
    }

    #[test]
    fn forcing_runs_the_same_paths_as_the_deadline() {
        // The force-step hooks drive production code, not a shortcut — the
        // property the whole round's oracle rests on.
        let mut rng = SplitMix64::new(44);
        let mut d = driver(&mut rng);
        d.zone_mut()
            .on_handshake_complete(id(1), PeerDirection::Inbound);
        d.zone_mut().queue_fluff(&[vec![9]], None, 0, &mut rng);
        let due = d.zone().fluff_deadline().unwrap();
        if due > 0 {
            assert!(d.poll(0, no_gather, &mut rng).is_empty(), "not due at t=0");
        }
        assert_eq!(
            d.force_fluff(0),
            vec![Effect::Fluff {
                peer: id(1),
                blobs: vec![TxBlob::from([9u8].as_slice())]
            }],
            "force releases the same batch the deadline would have"
        );

        let before = d.zone().epoch_deadline();
        let _ = d.force_epoch(0, &[id(1), id(2)], &mut rng);
        assert_ne!(d.zone().epoch_deadline(), before, "a new epoch was drawn");
    }

    /// Covert channels emit **independently**: one `CovertSend` per advance.
    ///
    /// **This is a soundness property, not an implementation preference.**
    /// Constant-rate cover works because the aggregate rate is constant. Two
    /// channels firing together produce a 2×fragment burst against otherwise
    /// empty intervals, making aggregate emission bursty and periodic — exactly
    /// the shape the mechanism exists to deny an observer. So synchronization
    /// is not merely different, it is a defect.
    ///
    /// **Why it lives here and not in the `levin_notify` gtests.** The C++
    /// covert path draws deadlines from `SecureRelayRng` (`OsRng`), which has no
    /// seam — so a per-advance count assertion there flakes whenever two draws
    /// collide (~1 in 5,000 over a 5 s band at ms granularity). Making it
    /// deterministic would need a test-only seeding hook, which is precisely the
    /// test-drive divergence RP-3b removed everywhere else. Here the RNG is a
    /// **generic parameter**, not a branch: production instantiates with
    /// `SecureRelayRng`, this with `SplitMix64`, and the logic is byte-identical.
    /// A parameter is not a test-only channel; a branch is. Same for `now`.
    ///
    /// The gtests keep what §20.5 says that oracle is for — counts, status,
    /// payload identity — and assert them collision-robustly. Cadence is
    /// asserted here, exactly, where it can be.
    ///
    /// **Negative-controlled per leg, because synchronization has two entry
    /// points and one injection cannot reach both.** A construction-time
    /// injection (all channels share one initial deadline) trips the *fixture*
    /// assertion — proving the precondition is sound, not that the count
    /// assertion bites. An emission-time injection (the due predicate broken so
    /// every channel fires on every wake, deadlines left distinct) trips the
    /// *count* assertion with `[0, 1]`. Both were run and observed to fail. A
    /// control that only reaches the precondition would be the
    /// asserted-a-constant-against-itself shape at one remove.
    #[test]
    fn covert_channels_emit_one_per_advance_not_synchronized() {
        let mut rng = SplitMix64::new(11);
        let mut d = Driver::new(Zone::new(
            DandelionParams::inherited(),
            2,
            FluffReach::EveryPeer,
            true,
            0,
            &mut rng,
        ));

        // Fixture requirement: distinct deadlines, or "one per advance" could
        // hold by coincidence rather than by independence.
        let (a, b) = (
            d.zone().covert_deadline_at(0).expect("ch0 armed"),
            d.zone().covert_deadline_at(1).expect("ch1 armed"),
        );
        assert_ne!(a, b, "the two channels must be armed independently");

        // Advance to the earliest deadline: exactly one channel is due.
        let first = d.next_wake();
        let covert: Vec<usize> = d
            .poll(first, Vec::new, &mut rng)
            .into_iter()
            .filter_map(|e| match e {
                Effect::CovertSend { channel } => Some(channel),
                _ => None,
            })
            .collect();
        assert_eq!(
            covert.len(),
            1,
            "one advance fires one channel; {covert:?} means the channels are              synchronized, which makes aggregate emission bursty"
        );
        let firstc = covert[0];

        // Advance again: the other channel, and only it.
        let second = d.next_wake();
        assert!(second > first, "the next wake is strictly later");
        let covert2: Vec<usize> = d
            .poll(second, Vec::new, &mut rng)
            .into_iter()
            .filter_map(|e| match e {
                Effect::CovertSend { channel } => Some(channel),
                _ => None,
            })
            .collect();
        assert_eq!(covert2.len(), 1, "second advance also fires exactly one");
        assert_ne!(
            covert2[0], firstc,
            "the second advance fires the OTHER channel — liveness, so a              scheduler that only ever serves channel 0 cannot pass"
        );
    }
}
