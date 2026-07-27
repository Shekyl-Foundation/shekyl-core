// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Driving the zone: what runs when a deadline elapses, and what the caller
//! must do about it.
//!
//! This is the piece that *is* the second reactor (§18.5). Asio keeps sockets
//! and the p2p path; this drives relay timing. The seal `lib.rs` broke was
//! against a second reactor **racing** the p2p path, and the reason it does not
//! race is that ownership is single: the driver owns the zone, and the only
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
use shekyl_relay_privacy::stem_map::ConnectionId;

use crate::zone::Zone;

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
        /// The batched transaction blobs, in acceptance order.
        blobs: Vec<Vec<u8>>,
    },
    /// The stem slots changed; re-point anything bound to them positionally.
    ///
    /// **Pushed, never pulled.** Slot order is meaningful and nils are kept in
    /// position, because the consumer indexes by slot (§16.1 contract 3).
    StemSlots(Vec<Option<ConnectionId>>),
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
        match self.zone.fluff_deadline() {
            Some(fluff) => fluff.min(self.zone.epoch_deadline()),
            None => self.zone.epoch_deadline(),
        }
    }

    /// Run every step due at `now` and return the resulting work.
    ///
    /// `outbound` is the caller's current outbound connection set — the driver
    /// does not reach for it, because the p2p connection table is asio's to own
    /// (§18.5). It is needed at an epoch boundary, where the stem map is rebuilt.
    pub fn poll<R: RelayRng + ?Sized>(
        &mut self,
        now: Millis,
        outbound: &[ConnectionId],
        rng: &mut R,
    ) -> Vec<Effect> {
        let mut effects = Vec::new();

        // Epoch first: a rollover re-draws the role and the stem set, and the
        // fluff release below should observe the new epoch, not the old one.
        if now >= self.zone.epoch_deadline() {
            self.zone.start_epoch(now, rng);
            if self.zone.update_stems(outbound.to_vec(), rng).needs_rearm() {
                effects.push(Effect::StemSlots(self.zone.stem_slots().to_vec()));
            }
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
    pub fn force_epoch<R: RelayRng + ?Sized>(
        &mut self,
        now: Millis,
        outbound: &[ConnectionId],
        rng: &mut R,
    ) -> Vec<Effect> {
        self.zone.start_epoch(now, rng);
        if self.zone.update_stems(outbound.to_vec(), rng).needs_rearm() {
            vec![Effect::StemSlots(self.zone.stem_slots().to_vec())]
        } else {
            Vec::new()
        }
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

    fn driver(rng: &mut SplitMix64) -> Driver {
        Driver::new(Zone::new(DandelionParams::inherited(), 2, 0, rng))
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
        let fluff = d
            .zone_mut()
            .queue_fluff(&[vec![1]], None, 0, &mut rng)
            .expect("a batch is in flight");
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
        let due = d
            .zone_mut()
            .queue_fluff(&[vec![7]], None, 0, &mut rng)
            .unwrap();

        if due > 0 {
            assert!(d.poll(due - 1, &[], &mut rng).is_empty(), "not due yet");
        }
        assert_eq!(
            d.poll(due, &[], &mut rng),
            vec![Effect::Fluff {
                peer: id(1),
                blobs: vec![vec![7]]
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

        let effects = d.poll(d.zone().epoch_deadline(), &outbound, &mut rng);
        let slots = effects
            .iter()
            .find_map(|e| match e {
                Effect::StemSlots(s) => Some(s.clone()),
                Effect::Fluff { .. } => None,
            })
            .expect("a rollover re-draws the stem set");
        assert_eq!(slots.len(), 2, "two slots at the configured width");
        assert!(slots.iter().flatten().all(|p| outbound.contains(p)));
    }

    #[test]
    fn polling_before_the_epoch_boundary_changes_nothing() {
        let mut rng = SplitMix64::new(43);
        let mut d = driver(&mut rng);
        let deadline = d.zone().epoch_deadline();
        assert!(d.poll(deadline - 1, &[id(1)], &mut rng).is_empty());
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
        let due = d
            .zone_mut()
            .queue_fluff(&[vec![9]], None, 0, &mut rng)
            .unwrap();
        if due > 0 {
            assert!(d.poll(0, &[], &mut rng).is_empty(), "not due at t=0");
        }
        assert_eq!(
            d.force_fluff(0),
            vec![Effect::Fluff {
                peer: id(1),
                blobs: vec![vec![9]]
            }],
            "force releases the same batch the deadline would have"
        );

        let before = d.zone().epoch_deadline();
        let _ = d.force_epoch(0, &[id(1), id(2)], &mut rng);
        assert_ne!(d.zone().epoch_deadline(), before, "a new epoch was drawn");
    }
}
