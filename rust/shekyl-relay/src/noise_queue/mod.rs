// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-channel noise fragment queues — the **executor** half of the noise
//! path, deliberately separated from the scheduler.
//!
//! Step 2 of the relay-logic cutover (`COVER_TRAFFIC_RESTORATION.md` §2.9):
//! the Rust port of C++'s `send_noise` / `queue_covert_notify` /
//! `clear_channel`.
//!
//! # CV-4: why this is its own module and not a field of [`crate::Zone`]
//!
//! **The noise schedule must carry no information about whether real traffic
//! is pending** (§20.2). A cadence that reacts to queue depth is a timing
//! channel, and constant-rate cover exists to defeat exactly that. The
//! scheduler decides *when* and *who*; this decides *what*.
//!
//! Before the cutover that separation was enforced by an accident of the
//! C++/Rust split — the queue lived in `levin_notify.cpp` and Rust had no
//! handle to it. **That was never the mechanism**, only friction: `Zone`
//! already owns the *fluff* queue, so the rule is narrower — *the noise
//! scheduler does not see the noise queue* — and once both halves are Rust it
//! has to hold in types. `cv4_the_cadence_does_not_depend_on_queue_depth` is
//! what replaces the friction.
//!
//! # Length is the invariant, and it has ONE owner
//!
//! **Every emission is exactly [`NoiseQueues::window`] bytes — real fragment
//! and dummy alike.** Length is the one thing a noise channel holds constant,
//! so anything that can make a real send a different size from a dummy is a
//! leak, not a degradation.
//!
//! The window is `dummy.len()` and nothing else. There is no exported
//! constant to disagree with it: the dummy is built by
//! `shekyl_levin::noise_notify(n)`, which produces exactly `n` bytes, and a
//! caller that needs the window reads [`NoiseQueues::window`]. A second
//! readable source would be the `transit_for` literal one layer up — a
//! duplicate that drifts.

use std::collections::VecDeque;

use shekyl_relay_privacy::params::carrier;
use shekyl_relay_privacy::stem_map::ConnectionId;

/// A caller-minted handle for one enqueued message.
///
/// # Opaque ON PURPOSE — the queue must not be able to read it
///
/// This is deliberately **not** a transaction hash. [`NoiseQueues`] holds
/// framed bytes it cannot parse, and that is what keeps §2.9b enforceable and
/// the queue format-agnostic: the size bound is the enforcement point
/// precisely because the carrier has no way to interpret what it is handed.
/// A queue that held a `crypto::hash` would have a reason to look inside, and
/// the next change would give it one.
///
/// So the caller mints a value, the queue stores and returns it, and only the
/// caller knows what it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CarrierToken(pub u64);

/// What became of an enqueued message. Reported once, terminally.
///
/// # What [`Self::Sent`] means, and what it does not
///
/// Every window was **accepted by the transport** — not acknowledged by the
/// peer. This type reports what its caller's send returned, and for the C++
/// producer that is `connections::send`, which places bytes on a connection's
/// asynchronous write queue. A socket that fails after accepting them never
/// comes back, so relay recording and the F-10 observation are charged on
/// acceptance.
///
/// The name mirrors what `send` means throughout this tree rather than
/// overstating it; strengthening it needs a completion signal the transport
/// does not offer, which is a `docs/FOLLOWUPS.md` item against the daemon
/// transport cutover.
///
/// # Both arms exist, and the failure arm is the load-bearing one
///
/// A completion signal alone is not enough. [`NoiseQueues::unbind`] clears a
/// channel's pending messages, so a message can leave the queue having never
/// been offered to the transport at all — and a caller waiting only for
/// [`Self::Sent`] would wait
/// forever on a record that will never fire. That is the unresolved-token
/// shape [`NoiseSend`]'s non-destructive take was designed against, one layer
/// up, and it is why discard reports too.
///
/// The consumer must treat [`Self::Discarded`] as **not relayed** rather than
/// as silence: the pool's `relayed` bit drives an origin's backoff, and an
/// origin given the long wait for a message that was discarded waits ~1148 s
/// for a transaction that was never sent and will not be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierOutcome {
    /// Every window was accepted by the transport for `peer` — see the type
    /// doc above for why that is acceptance and not receipt.
    ///
    /// **The peer is reported because the enqueuer cannot know it.** A channel
    /// binds to whatever its stem slot holds at each send, and an epoch
    /// rebuild or a mid-epoch rebind moves that. Recording the peer chosen at
    /// enqueue time would charge an F-10 observation to a node the message was
    /// never sent to at all — a wrong entry in the tallies, not a missing
    /// one.
    ///
    /// It is unambiguous for a COMPLETED message precisely because of CV-1: a
    /// rebind restarts the run rather than resuming it, so every window of a
    /// message that finished was accepted for ONE peer, and this is that
    /// peer.
    Sent {
        token: CarrierToken,
        peer: ConnectionId,
    },
    /// The message left the queue without being fully sent. No peer: a
    /// discarded message has no successor to charge.
    Discarded(CarrierToken),
}

impl CarrierOutcome {
    /// The peer every window was accepted for, or `None` for a discard.
    ///
    /// Not proof of receipt — see [`CarrierOutcome`].
    #[must_use]
    pub fn peer(self) -> Option<ConnectionId> {
        match self {
            Self::Sent { peer, .. } => Some(peer),
            Self::Discarded(_) => None,
        }
    }
}

impl CarrierOutcome {
    /// The token this outcome is about.
    #[must_use]
    pub fn token(self) -> CarrierToken {
        match self {
            Self::Sent { token, .. } | Self::Discarded(token) => token,
        }
    }

    /// Whether every window was accepted by the transport — see
    /// [`CarrierOutcome`] for what that does and does not guarantee.
    #[must_use]
    pub fn was_sent(self) -> bool {
        matches!(self, Self::Sent { .. })
    }
}

/// A framed message and the handle its enqueuer will recognise it by.
#[derive(Debug)]
struct PendingMessage {
    bytes: Vec<u8>,
    token: CarrierToken,
}

/// One channel's pending work.
#[derive(Debug, Default)]
struct ChannelQueue {
    /// Framed messages waiting for this channel's due ticks. Each is a whole
    /// multiple of the window (enforced at [`NoiseQueues::enqueue`]).
    pending: VecDeque<PendingMessage>,
    /// How far into `pending.front()` the send has got. `None` when no message
    /// is mid-flight.
    offset: Option<usize>,
    /// The peer this channel was bound to when the in-flight run started.
    bound: Option<ConnectionId>,
    /// Invalidates outstanding [`NoiseSend`] tokens. Bumped on take, on
    /// [`NoiseSend::failed`], and on [`NoiseQueues::unbind`] — the three
    /// events that mean a previously taken fragment is no longer the live
    /// send. `sent`/`failed` apply only when this still matches the token.
    epoch: u64,
}

impl ChannelQueue {
    fn bump(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
    }
}

/// A fragment taken for exactly one send, awaiting its outcome.
///
/// # Dropping this is a FAILURE, and that is correct without any `Drop` code
///
/// [`NoiseQueues::take_for_send`] is **non-destructive**: it computes the
/// fragment without advancing anything. Only [`NoiseSend::sent`] advances.
/// So a token that is dropped, forgotten, or lost to an early return leaves the
/// queue exactly as it was, and the next take on that channel produces the same
/// fragment — a restart, which is the CV-1 behaviour anyway.
///
/// This is deliberate rather than incidental. A `Drop` that had to *restore*
/// state would need a handle back into the queue, which would make this a
/// borrow — and a borrow cannot span the send, because the transport
/// (`shekyl-tor`) is async even though the relay logic is not. Non-destructive
/// take is what lets the token cross an await and still be correct when it is
/// dropped.
///
/// # A stale resolve is a no-op
///
/// The token carries the channel's epoch at take. A later take, `failed`, or
/// `unbind` bumps that epoch, so resolving the old token cannot advance a
/// different message — take → unbind → enqueue → `sent()` would otherwise
/// walk into the successor. The type exists to cross an await; without the
/// epoch it would only be safe to drop, not to resolve late.
#[must_use = "a noise send must be resolved with `sent()` or `failed()`; \
              dropping it restarts the fragment on the next take"]
#[derive(Debug)]
pub struct NoiseSend {
    channel: usize,
    bytes: Vec<u8>,
    /// False for a dummy: there is nothing to advance on success.
    real: bool,
    epoch: u64,
}

impl NoiseSend {
    fn live<'a>(&self, queues: &'a mut NoiseQueues) -> Option<&'a mut ChannelQueue> {
        let q = queues.channels.get_mut(self.channel)?;
        (q.epoch == self.epoch).then_some(q)
    }

    /// The send succeeded: advance past this fragment.
    ///
    /// The only thing that consumes queue state. A message whose last window
    /// just went out leaves the queue.
    ///
    /// Takes `self` — the token is single-use, so a caller cannot resolve one
    /// twice — and takes the queue as an argument rather than holding a
    /// reference, which is what lets the token cross an await. A stale token
    /// (epoch moved on) is a no-op rather than a mutation of a later send.
    pub fn sent(self, queues: &mut NoiseQueues) {
        if !self.real {
            return; // A dummy advances nothing.
        }
        let window = queues.window();
        let Some(q) = self.live(queues) else {
            return;
        };
        let Some(message) = q.pending.front() else {
            return;
        };

        let next = q
            .offset
            .unwrap_or(0)
            .checked_add(window)
            .expect("noise offset + window");
        if next >= message.bytes.len() {
            q.offset = None;
            // Every window of the message has now been accepted by the
            // transport. This is the ONLY point at which that becomes true,
            // which is why the completion is reported from here rather than
            // from the caller's send: the caller knows a FRAGMENT was
            // accepted, not a message.
            // The peer this run was bound to IS the successor: CV-1 restarts
            // on rebind, so a message that completed went entirely to it.
            let done = q.pending.pop_front().map(|m| m.token).zip(q.bound);
            if let Some((token, peer)) = done {
                queues.resolved.push(CarrierOutcome::Sent { token, peer });
            }
        } else {
            q.offset = Some(next);
        }
    }

    /// The send failed: drop the in-flight run and unbind.
    ///
    /// Mirrors C++ `send_noise`'s failure arm, which clears `active` and nils
    /// the connection so the caller can refresh stems. The message is **not**
    /// dropped — it restarts on the next take, so a failed send costs a
    /// fragment rather than a transaction. A stale token is a no-op: it must
    /// not unbind a later binding.
    pub fn failed(self, queues: &mut NoiseQueues) {
        let Some(q) = self.live(queues) else {
            return;
        };
        q.offset = None;
        q.bound = None;
        q.bump();
    }

    /// The bytes to put on the wire — always exactly the window.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Which channel this belongs to.
    #[must_use]
    pub fn channel(&self) -> usize {
        self.channel
    }
}

/// Per-channel noise queues, indexed by channel — which **is** the stem slot
/// (§20.3).
///
/// Holds no schedule and no clock. It cannot advance time, and nothing here is
/// reachable from [`crate::Driver::poll`].
#[derive(Debug)]
pub struct NoiseQueues {
    channels: Vec<ChannelQueue>,
    /// The dummy payload. **Its length is the fragment window** — one value, so
    /// a real fragment and a dummy cannot disagree about length.
    dummy: Vec<u8>,
    /// Windows one channel may hold pending, in total.
    ///
    /// **The drain rate is fixed and the input rate is not**, which is the
    /// whole reason this exists. A channel emits ONE window per due tick
    /// whether or not anything is queued, so a node stemming faster than the
    /// cadence would grow `pending` — and C++'s token map with it — without
    /// bound. Refusing at the door instead sends the overflow by the ordinary
    /// wire, which is where it would have gone anyway.
    ///
    /// **This is the ONLY bound on growth, and nothing else drains a queue.**
    /// An epoch roll rebuilds the stem slots and does not touch `NoiseQueues`:
    /// pending messages survive it. The single drain is [`NoiseQueues::unbind`],
    /// which fires only when a channel's slot resolves to no peer at its due
    /// tick, and reports [`CarrierOutcome::Discarded`] for everything it
    /// clears. CV-1 restarts an in-flight run when its peer changes; it drops
    /// nothing from `pending`. So the surplus is not something a roll would
    /// have thrown away — without this cap it simply accumulates.
    ///
    /// Set to one epoch's worth of deliverable windows
    /// ([`carrier::noise_windows_in_epoch`], counted at the SLOWEST cadence so
    /// the figure cannot overstate what a channel drains). That is a backlog
    /// bound, not a delivery promise: a channel may not fall more than about
    /// one epoch behind. What it admits is queueing delay — a message accepted
    /// behind a full budget waits up to roughly an epoch for the wire. One
    /// consequence is already handled by the producer rather than owed: the
    /// pool re-offers a `local` entry at `MIN_RELAY_TIME` (300 s), inside a
    /// backlog that may run to a full epoch (600 s), so `dandelionpp_notify`
    /// dedups by txid instead of enqueueing the same transaction twice. What
    /// remains for the owed re-derivation round is the timing derivation
    /// itself, not that hazard.
    window_budget: usize,
    /// Terminal outcomes awaiting collection by [`NoiseQueues::take_resolved`].
    resolved: Vec<CarrierOutcome>,
}

impl NoiseQueues {
    /// `None` when `dummy` is empty: a zero window would make every emission
    /// zero-length, which is not cover.
    #[must_use]
    /// `window_budget` is how many windows ONE channel may hold pending; see
    /// the field. `None` when it is zero, for the same reason an empty dummy
    /// is refused: a queue that can accept nothing is not a carrier.
    pub fn new(channels: usize, dummy: Vec<u8>, window_budget: usize) -> Option<Self> {
        if dummy.is_empty() || window_budget == 0 {
            return None;
        }
        Some(Self {
            channels: (0..channels).map(|_| ChannelQueue::default()).collect(),
            dummy,
            resolved: Vec::new(),
            window_budget,
        })
    }

    /// Windows one channel may hold pending, in total.
    #[must_use]
    pub fn window_budget(&self) -> usize {
        self.window_budget
    }

    /// The fragment window, in bytes — **the only definition**.
    #[must_use]
    pub fn window(&self) -> usize {
        self.dummy.len()
    }

    /// Channel count — the stem width, not a queue depth.
    #[must_use]
    pub fn channels(&self) -> usize {
        self.channels.len()
    }

    /// Offer a framed message to `channel`.
    ///
    /// Refused when the channel is out of range, the message is empty, or its
    /// length is **not a whole multiple of [`Self::window`]**.
    ///
    /// # Why a non-multiple is refused rather than padded
    ///
    /// A message that is not a multiple ends in a short fragment, and a short
    /// send is distinguishable from a dummy — the leak this channel exists to
    /// prevent. Padding here would make the queue format-aware (it would have
    /// to know that trailing bytes are safe, which is true for levin but is not
    /// this type's business). Refusing keeps the queue format-agnostic while
    /// leaving one owner for the number: the caller cannot pad to a window it
    /// invented, because [`Self::window`] is the only place to read one.
    /// `token` is the caller's handle for this message: opaque to the queue,
    /// returned verbatim in the [`CarrierOutcome`] that resolves it.
    pub fn enqueue(&mut self, channel: usize, message: Vec<u8>, token: CarrierToken) -> bool {
        // Refusal travels in the return value, not a `debug_assert!` — the
        // out-of-range arm signals that way, a debug-only panic would make the
        // guard untestable, and `false` survives into release where a caller
        // bug is no less a bug.
        if message.is_empty() || !message.len().is_multiple_of(self.window()) {
            return false;
        }
        // CV-1's cap, enforced where work is ACCEPTED rather than only where a
        // zone is CONSTRUCTED.
        //
        // `Zone::new` checks that an epoch affords `MAX_FRAGMENTS` windows, so
        // a configuration is validated against that many worst-case sends. But
        // nothing stopped a longer message being enqueued into it: the length
        // check above admits any whole multiple of the window, so a six-window
        // message entered a zone validated for five and could never finish:
        // it cannot complete within one epoch, and any roll that hands its
        // slot to a different peer restarts it from the first fragment (CV-1)
        // — silently, since a restart is not reported. Refusing here makes the
        // accepted work match the checked invariant.
        //
        // This is also what bounds a BATCH. `NOTIFY_NEW_TRANSACTIONS` carries a
        // vector (`make_tx_message` takes `std::vector<blobdata>`), so a
        // notification is not one transaction by construction — two maximum
        // transactions are ~196 KB, ten windows, double the cap. The carrier
        // has no way to parse what it is handed, so the size bound is the
        // enforcement point: an oversized batch is refused here rather than
        // truncated later.
        if message.len() / self.window() > carrier::MAX_FRAGMENTS as usize {
            return false;
        }
        // The CHANNEL's budget, not just this message's size. A per-message cap
        // bounds one transaction; nothing bounded how many. The drain is one
        // window per due tick, so without this a node stemming faster than the
        // cadence grows the queue — and the caller's identity map with it —
        // until memory runs out. Nothing else would clear it: a roll does not
        // touch this queue. See `window_budget` for why that makes this arm
        // the only bound rather than a tidier-up after one.
        let window = self.window();
        match self.channels.get_mut(channel) {
            Some(q)
                if (q.pending.iter().map(|m| m.bytes.len()).sum::<usize>() + message.len())
                    / window
                    > self.window_budget =>
            {
                false
            }
            Some(q) => {
                q.pending.push_back(PendingMessage {
                    bytes: message,
                    token,
                });
                true
            }
            None => false,
        }
    }

    /// Take what `channel` should put on the wire for `peer` — **always
    /// exactly [`Self::window`] bytes**, real or cover.
    ///
    /// `None` means *no such channel*, a caller bug. It never means "nothing to
    /// send": a bound noise channel always sends, which is what constant-rate
    /// cover is. An unbound slot emits nothing, but that is the scheduler's
    /// call — it yields `Effect::NoiseUnbind` rather than asking here.
    ///
    /// **CV-1: a rebind discards the in-flight remainder.** If `peer` differs
    /// from the binding the run started under, the offset is dropped and the
    /// message restarts from its first fragment. Resuming would make this send
    /// the tail of a run rather than a whole window — and length is the one
    /// thing held constant (§20.5).
    ///
    /// Non-destructive: see [`NoiseSend`].
    pub fn take_for_send(&mut self, channel: usize, peer: ConnectionId) -> Option<NoiseSend> {
        let window = self.window();
        let q = self.channels.get_mut(channel)?;

        if q.bound != Some(peer) {
            q.bound = Some(peer);
            q.offset = None; // CV-1: restart, never resume.
        }
        q.bump();
        let epoch = q.epoch;

        if q.pending.is_empty() {
            return Some(NoiseSend {
                channel,
                bytes: self.dummy.clone(),
                real: false,
                epoch,
            });
        }

        let offset = q.offset.unwrap_or(0);
        let end = offset.checked_add(window).expect("noise offset + window");
        // A short slice would PUBLISH — length is the invariant. Enqueue
        // proved the message is a whole number of windows, and `sent` only
        // advances by one window, so this is unreachable except as a bug.
        // Panic rather than emit a distinguishable send, and rather than
        // dummy-without-pop (the empty-head wedge this type already knows).
        let Some(bytes) = q.pending.front().and_then(|m| m.bytes.get(offset..end)) else {
            panic!(
                "noise fragment [{offset}, {end}) is not a slice of a message \
                 that enqueue proved to be a whole number of windows"
            );
        };
        Some(NoiseSend {
            channel,
            bytes: bytes.to_vec(),
            real: true,
            epoch,
        })
    }

    /// The channel's stem slot went unbound: drop everything it held.
    ///
    /// **Every dropped message reports [`CarrierOutcome::Discarded`].** This is
    /// the failure counterpart to the completion signal, and it is not
    /// optional: a message cleared here left the queue without reaching the
    /// wire, and a consumer waiting only for `Sent` would wait forever on a
    /// record that will never fire.
    pub fn unbind(&mut self, channel: usize) {
        if let Some(q) = self.channels.get_mut(channel) {
            let dropped: Vec<CarrierToken> = q.pending.drain(..).map(|m| m.token).collect();
            q.offset = None;
            q.bound = None;
            q.bump();
            self.resolved
                .extend(dropped.into_iter().map(CarrierOutcome::Discarded));
        }
    }

    /// Take every outcome resolved since the last call.
    ///
    /// # CV-4: this is an OUTPUT, not a channel back into the scheduler
    ///
    /// The barrier is that the cadence decides *when* to emit and *to whom*.
    /// These outcomes report what the cadence already did, after it did it —
    /// the same shape as [`NoiseSend::sent`] and [`NoiseSend::failed`], which
    /// resolve a send the scheduler had already chosen. Nothing here is
    /// readable by the schedule, and `cv4_the_cadence_does_not_depend_on_queue_depth`
    /// remains the gate on that.
    ///
    /// Drains, so an outcome is delivered once. A caller that drops the result
    /// loses it, which is the same trade as the send token and correct for the
    /// same reason: the alternative is unbounded retention of records nobody
    /// consumed.
    pub fn take_resolved(&mut self) -> Vec<CarrierOutcome> {
        std::mem::take(&mut self.resolved)
    }
}

#[cfg(test)]
mod tests;
