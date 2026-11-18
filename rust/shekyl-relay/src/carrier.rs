// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The carrier's schedule: when each channel sends, and to whom.
//!
//! **Apart from the relay's work** (`CVR-R6`; Rick, 2026-11-18). The
//! emission tick must not wait on relay work: on 2026-11-05 a relay owner
//! blocked behind the pool's commit for 28 s and 32 s, and both channels
//! went silent for as long, an observable event on the cover link. So the
//! schedule, each channel's binding and the queue run in their own task
//! (`owner::carrier`), and a busy relay owner delays what it hands the
//! carrier, never a window. This type is that task's schedule: plain
//! `&mut self` steps returning deadlines, like the zone, so a test drives
//! it directly.
//!
//! **What it is told, and nothing else.** The relay owner, which alone
//! owns the stem map and the session registry, hands it a [`CarrierView`]
//! whenever either changes — each channel's stem slot, and which sessions
//! carry cover — and says when an epoch begins. It never reads the queue
//! (CV-4): which window is real is decided after it has said who is due.
//!
//! **CV-3 lives in how deadlines are mutated.** Each entry is drawn once and
//! re-drawn only when *that* channel fires. A wake caused by anything else
//! leaves every other entry untouched. Re-drawing on a foreign wake and
//! keeping the earlier deadline takes the minimum of two draws, which biases
//! the effective interval **short** — a privacy defect no count assertion
//! and no goodness-of-fit grade can see (§20.2a).

use std::collections::BTreeSet;

use shekyl_draw_rng::RelayRng;
use shekyl_relay_privacy::params::carrier;
use shekyl_relay_privacy::schedule::{Millis, NoiseCadence};
use shekyl_relay_privacy::stem_map::ConnectionId;

use crate::noise_queue::Starts;

/// What the relay owner tells the carrier about its sessions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CarrierView {
    /// The session in each stem slot, in slot order: channel `i` follows
    /// slot `i` (§20.3).
    pub slots: Vec<Option<ConnectionId>>,
    /// The established sessions that carry cover: encrypted, on a
    /// connector whose timing an observer at this node's end can see
    /// (`CVR-R3`).
    pub covered: BTreeSet<ConnectionId>,
}

/// The peer one channel sends to, and the windows left in its epoch tail.
///
/// Outside a tail the binding follows the channel's stem slot at each due
/// window. At an epoch boundary it keeps the peer it last sent to for
/// [`carrier::EPOCH_TAIL_WINDOWS`] more windows, during which no message
/// starts, then takes the slot's new peer (`CVR-R4`; Rick, 2026-11-18). The
/// tail is set whatever the queue holds: the schedule does not see the
/// queue (CV-4), so the switch comes after the same count of windows
/// whether or not a message was in flight.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ChannelBinding {
    /// The peer the channel last sent to. `None` before its first send and
    /// after its slot went empty or uncovered.
    peer: Option<ConnectionId>,
    /// Windows still owed to `peer` after the last epoch boundary.
    tail_left: u32,
}

/// What a channel's due window does ([`Carrier::due`]).
///
/// **Carries no payload discriminant, and that is CV-4** (§20.2). Whether a
/// send is a dummy or drains a queued real fragment is a queue question. The
/// schedule decides **when** and **who**; the queue decides **what**. A
/// `DUMMY | REAL` tag would let the cadence react to having something real
/// to say — a noise-channel leak wearing a latency improvement's costume.
/// [`Starts`] is not that tag: it comes from the epoch tail, not the queue.
///
/// **An empty slot unbinds at every due tick, not once per transition.** A
/// transition-shaped clear needs a remembered last binding and is one-shot,
/// so a clear that fails to take effect leaves the queue stale for good; a
/// per-tick clear self-heals one interval later, and unbinding is
/// idempotent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseDue {
    /// Send one window to `peer`; [`Starts`] says whether a new message may
    /// begin in it.
    Send {
        /// The channel, which is its stem slot.
        channel: usize,
        /// The session the window goes to.
        peer: ConnectionId,
        /// Closed during the channel's epoch tail.
        starts: Starts,
    },
    /// The channel's slot holds no peer: drop what the channel held.
    Unbind {
        /// The channel.
        channel: usize,
    },
}

/// The carrier's schedule and bindings.
#[derive(Debug)]
pub struct Carrier {
    cadence: NoiseCadence,
    /// Next send deadline per channel, indexed by channel.
    deadlines: Vec<Millis>,
    /// Who each channel sends to, and how much of its tail is left.
    bindings: Vec<ChannelBinding>,
    /// The relay owner's last word on the slots and the covered sessions.
    view: CarrierView,
}

impl Carrier {
    /// A schedule for `channels` channels, each armed from `now`.
    pub fn new<R: RelayRng + ?Sized>(channels: usize, now: Millis, rng: &mut R) -> Self {
        let cadence = NoiseCadence::shipped();
        let deadlines = (0..channels).map(|_| cadence.next_send(now, rng)).collect();
        Self {
            cadence,
            deadlines,
            bindings: vec![ChannelBinding::default(); channels],
            view: CarrierView::default(),
        }
    }

    /// How many channels.
    #[must_use]
    pub fn channels(&self) -> usize {
        self.deadlines.len()
    }

    /// The relay owner's view of the slots and the covered sessions.
    pub fn set_view(&mut self, view: CarrierView) {
        self.view = view;
    }

    /// An epoch boundary: every channel that has a peer owes it the tail.
    /// Unconditional — the queue is not consulted (CV-4).
    pub fn begin_tails(&mut self) {
        for binding in self
            .bindings
            .iter_mut()
            .filter(|binding| binding.peer.is_some())
        {
            binding.tail_left = carrier::EPOCH_TAIL_WINDOWS;
        }
    }

    /// The earliest channel deadline.
    #[must_use]
    pub fn deadline(&self) -> Option<Millis> {
        self.deadlines.iter().copied().min()
    }

    /// A channel's armed deadline, for CV-3's witness.
    #[cfg(test)]
    pub(crate) fn deadline_at(&self, channel: usize) -> Option<Millis> {
        self.deadlines.get(channel).copied()
    }

    /// The single earliest channel due at `now`, re-armed from **`now`**.
    ///
    /// At most one channel per call: several channels emitting in one wake
    /// is a synchronized burst — the soundness defect constant-rate cover
    /// exists to deny. A late wake that finds several deadlines past still
    /// surfaces them one call at a time.
    ///
    /// Re-armed from `now`, not the old deadline: arming from a past
    /// deadline catch-up-bursts after a stall; arming from `now` preserves
    /// inter-send spacing under load (phase may lag; rate does not). Only
    /// the fired entry is touched — CV-3.
    pub fn due_channel<R: RelayRng + ?Sized>(&mut self, now: Millis, rng: &mut R) -> Option<usize> {
        let (idx, _) = self
            .deadlines
            .iter()
            .copied()
            .enumerate()
            .filter(|&(_, d)| d <= now)
            .min_by_key(|&(_, d)| d)?;
        self.deadlines[idx] = self.cadence.next_send(now, rng);
        Some(idx)
    }

    /// What the single earliest channel due at `now` does, re-armed from
    /// `now` like [`Self::due_channel`].
    ///
    /// During the channel's epoch tail the window goes to the peer it last
    /// sent to, with [`Starts::Closed`], while that session still carries
    /// cover; a lost peer ends the tail at once, and the half-sent message
    /// restarts on the next peer (CV-1). Outside the tail the window goes to
    /// the peer in the channel's stem slot with [`Starts::Open`]. A slot
    /// whose session carries no cover sends nothing, and the channel stays
    /// armed for a later covered occupant. An empty slot unbinds.
    pub fn due<R: RelayRng + ?Sized>(&mut self, now: Millis, rng: &mut R) -> Option<NoiseDue> {
        let channel = self.due_channel(now, rng)?;
        let slot = self.view.slots.get(channel).copied().flatten();
        let covered = |peer: &ConnectionId| self.view.covered.contains(peer);
        let binding = self.bindings[channel];
        if binding.tail_left > 0 {
            if let Some(old) = binding.peer.filter(covered) {
                self.bindings[channel].tail_left -= 1;
                return Some(NoiseDue::Send {
                    channel,
                    peer: old,
                    starts: Starts::Closed,
                });
            }
        }
        let next = match slot {
            Some(peer) if covered(&peer) => Some(NoiseDue::Send {
                channel,
                peer,
                starts: Starts::Open,
            }),
            // Nothing is sent: the channel is bound to no one, so the next
            // boundary owes no tail to a peer it left.
            Some(_) => None,
            None => Some(NoiseDue::Unbind { channel }),
        };
        self.bindings[channel] = ChannelBinding {
            peer: match next {
                Some(NoiseDue::Send { peer, .. }) => Some(peer),
                _ => None,
            },
            tail_left: 0,
        };
        next
    }
}

/// The zone's driver and the carrier's schedule on one test clock, stepped
/// as the relay owner and the carrier task run them: the owner polls the
/// zone and hands the carrier its view, and the carrier answers who is due.
#[cfg(test)]
pub(crate) mod pair {
    use shekyl_draw_rng::RelayRng;
    use shekyl_relay_privacy::schedule::Millis;
    use shekyl_relay_privacy::stem_map::ConnectionId;

    use super::{Carrier, NoiseDue};
    use crate::driver::{Driver, Effect};
    use crate::graph::Relay;
    use crate::noise_queue::Starts;

    /// What one step produced, in one stream.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum Step {
        /// The zone's work.
        Zone(Effect),
        /// A carrier window.
        NoiseSend {
            channel: usize,
            peer: ConnectionId,
            starts: Starts,
        },
        /// A carrier unbind.
        NoiseUnbind { channel: usize },
    }

    pub(crate) struct Pair {
        pub(crate) driver: Driver,
        pub(crate) carrier: Option<Carrier>,
        epochs: u64,
    }

    impl Pair {
        pub(crate) fn new<R: RelayRng + ?Sized>(driver: Driver, rng: &mut R) -> Self {
            let carrier = driver
                .zone()
                .noise_enabled()
                .then(|| Carrier::new(driver.zone().stem_width(), 0, rng));
            let epochs = driver.zone().epochs_started();
            let mut pair = Self {
                driver,
                carrier,
                epochs,
            };
            pair.sync();
            pair
        }

        pub(crate) fn zone(&self) -> &Relay {
            self.driver.zone()
        }

        pub(crate) fn zone_mut(&mut self) -> &mut Relay {
            self.driver.zone_mut()
        }

        /// The carrier's earliest deadline.
        pub(crate) fn carrier_deadline(&self) -> Option<Millis> {
            self.carrier.as_ref().and_then(Carrier::deadline)
        }

        /// The earlier of the two tasks' wakes.
        pub(crate) fn next_wake(&self) -> Millis {
            let zone = self.driver.next_wake();
            self.carrier_deadline()
                .map_or(zone, |carrier| carrier.min(zone))
        }

        /// Hand the carrier the zone's view, and begin tails when an epoch
        /// began since the last.
        pub(crate) fn sync(&mut self) {
            let Some(carrier) = self.carrier.as_mut() else {
                return;
            };
            carrier.set_view(self.driver.zone().carrier_view());
            let epochs = self.driver.zone().epochs_started();
            if epochs != self.epochs {
                carrier.begin_tails();
                self.epochs = epochs;
            }
        }

        /// One wake of each task at `now`: the zone first, then the
        /// carrier's one due channel.
        pub(crate) fn poll<R: RelayRng + ?Sized>(&mut self, now: Millis, rng: &mut R) -> Vec<Step> {
            let mut out: Vec<Step> = self
                .driver
                .poll(now, rng)
                .into_iter()
                .map(Step::Zone)
                .collect();
            self.sync();
            if let Some(carrier) = self.carrier.as_mut() {
                match carrier.due(now, rng) {
                    Some(NoiseDue::Send {
                        channel,
                        peer,
                        starts,
                    }) => out.push(Step::NoiseSend {
                        channel,
                        peer,
                        starts,
                    }),
                    Some(NoiseDue::Unbind { channel }) => out.push(Step::NoiseUnbind { channel }),
                    None => {}
                }
            }
            out
        }
    }
}
