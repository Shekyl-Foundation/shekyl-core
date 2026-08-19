// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-channel covert fragment queues — the **executor** half of the covert
//! path, deliberately separated from the scheduler.
//!
//! Step 2 of the relay-logic cutover (`COVER_TRAFFIC_RESTORATION.md` §2.9):
//! the Rust port of C++'s `send_noise` / `queue_covert_notify` /
//! `clear_channel`.
//!
//! # CV-4: why this is its own module and not a field of [`crate::Zone`]
//!
//! **The covert schedule must carry no information about whether real traffic
//! is pending** (§20.2). A cadence that reacts to queue depth is a timing
//! channel, and constant-rate cover exists to defeat exactly that. The
//! scheduler decides *when* and *who*; this decides *what*.
//!
//! Before the cutover that separation was enforced by an accident of the
//! C++/Rust split — the queue lived in `levin_notify.cpp` and Rust had no
//! handle to it. **That was never the mechanism**, only friction: `Zone`
//! already owns the *fluff* queue, so the rule is narrower — *the covert
//! scheduler does not see the covert queue* — and once both halves are Rust it
//! has to hold in types. `cv4_the_cadence_does_not_depend_on_queue_depth` is
//! what replaces the friction.
//!
//! # Length is the invariant, and it has ONE owner
//!
//! **Every emission is exactly [`NoiseQueues::window`] bytes — real fragment
//! and dummy alike.** Length is the one thing a covert channel holds constant,
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

use shekyl_relay_privacy::stem_map::ConnectionId;

/// One channel's pending work.
#[derive(Debug, Default)]
struct ChannelQueue {
    /// Framed messages waiting for this channel's due ticks. Each is a whole
    /// multiple of the window (enforced at [`NoiseQueues::enqueue`]).
    pending: VecDeque<Vec<u8>>,
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
#[must_use = "a covert send must be resolved with `sent()` or `failed()`; \
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
            .expect("covert offset + window");
        if next >= message.len() {
            q.offset = None;
            let _ = q.pending.pop_front();
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

/// Per-channel covert queues, indexed by channel — which **is** the stem slot
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
}

impl NoiseQueues {
    /// `None` when `dummy` is empty: a zero window would make every emission
    /// zero-length, which is not cover.
    #[must_use]
    pub fn new(channels: usize, dummy: Vec<u8>) -> Option<Self> {
        if dummy.is_empty() {
            return None;
        }
        Some(Self {
            channels: (0..channels).map(|_| ChannelQueue::default()).collect(),
            dummy,
        })
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
    pub fn enqueue(&mut self, channel: usize, message: Vec<u8>) -> bool {
        // Refusal travels in the return value, not a `debug_assert!` — the
        // out-of-range arm signals that way, a debug-only panic would make the
        // guard untestable, and `false` survives into release where a caller
        // bug is no less a bug.
        if message.is_empty() || !message.len().is_multiple_of(self.window()) {
            return false;
        }
        match self.channels.get_mut(channel) {
            Some(q) => {
                q.pending.push_back(message);
                true
            }
            None => false,
        }
    }

    /// Take what `channel` should put on the wire for `peer` — **always
    /// exactly [`Self::window`] bytes**, real or cover.
    ///
    /// `None` means *no such channel*, a caller bug. It never means "nothing to
    /// send": a bound covert channel always sends, which is what constant-rate
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
        let end = offset.checked_add(window).expect("covert offset + window");
        // A short slice would PUBLISH — length is the invariant. Enqueue
        // proved the message is a whole number of windows, and `sent` only
        // advances by one window, so this is unreachable except as a bug.
        // Panic rather than emit a distinguishable send, and rather than
        // dummy-without-pop (the empty-head wedge this type already knows).
        let Some(bytes) = q.pending.front().and_then(|m| m.get(offset..end)) else {
            panic!(
                "covert fragment [{offset}, {end}) is not a slice of a message \
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
    pub fn unbind(&mut self, channel: usize) {
        if let Some(q) = self.channels.get_mut(channel) {
            q.pending.clear();
            q.offset = None;
            q.bound = None;
            q.bump();
        }
    }
}

#[cfg(test)]
mod tests;
