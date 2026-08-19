// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-channel covert fragment queues — the **executor** half of the covert
//! path, deliberately separated from the scheduler.
//!
//! # Why this is its own module and not a field of [`crate::Zone`]
//!
//! **CV-4 (`DAEMON_RELAY_PRIVACY.md` §20.2): the covert schedule must carry no
//! information about whether real traffic is pending.** A cadence that reacts
//! to queue depth is a timing channel, and constant-rate cover exists to defeat
//! exactly that. So the scheduler decides *when* and *who*; this decides
//! *what*.
//!
//! Until the daemon Rust cutover that separation was enforced by an accident of
//! the C++/Rust split — the queue lived in `levin_notify.cpp` and Rust had no
//! handle to it. **That was never the mechanism**, only a strong incidental
//! barrier: `Zone` already owns the *fluff* queue (`contexts`), so there is no
//! rule that queues live in C++. The rule is narrower — *the covert scheduler
//! does not see the covert queue* — and once both halves are Rust, the barrier
//! has to be rebuilt in types rather than inherited from the language boundary.
//!
//! What the boundary supplied was **friction**: wiring queue depth into the
//! schedule meant a `#[repr(C)]` field or a new FFI entry point, loud in
//! review. In one crate the same violation is `if q.has_pending() { … }` — one
//! line that reads as a latency improvement. That is §20.2's named failure
//! mode, and `cv4_the_cadence_does_not_depend_on_queue_depth` is what replaces
//! the friction.
//!
//! This type does **not** expose a depth query. A `len` / `is_empty` /
//! `has_pending` method would be the API the leak writes itself against.

use std::collections::VecDeque;

use shekyl_relay_privacy::stem_map::ConnectionId;

/// One channel's pending work, matching `noise_channel` (`levin_notify.cpp`).
///
/// `pending` holds the original framed messages. `active` is the unsent
/// remainder of the message currently being sliced. The original stays in
/// `pending` until every fragment has gone, so a CV-1 rebind can *restart*
/// the same message rather than resume a mid-message remainder (length is
/// the leak) or drop the payload (liveness).
#[derive(Debug, Default)]
struct ChannelQueue {
    pending: VecDeque<Vec<u8>>,
    /// Unsent tail of the current message. `None` / empty means the next
    /// take clones `pending.front()` and starts from the beginning.
    active: Option<Vec<u8>>,
    bound: Option<ConnectionId>,
}

/// Per-channel covert queues, indexed by channel — which **is** the stem slot
/// (§20.3).
///
/// Holds no schedule and no clock. It cannot advance time, and nothing here is
/// reachable from [`crate::Driver::poll`].
#[derive(Debug)]
pub struct CovertQueues {
    channels: Vec<ChannelQueue>,
}

impl CovertQueues {
    /// One queue per channel, sized to the stem width.
    #[must_use]
    pub fn new(channels: usize) -> Self {
        Self {
            channels: (0..channels).map(|_| ChannelQueue::default()).collect(),
        }
    }

    /// Channel count — the stem width, not a queue depth.
    #[must_use]
    pub fn channels(&self) -> usize {
        self.channels.len()
    }

    /// Offer a framed message to `channel`.
    ///
    /// Refused when the channel index is out of range, **or when `message` is
    /// empty**. Not refused on an unbound channel: binding is the scheduler's
    /// fact and travels with each send, so the discard happens at
    /// [`Self::take_for_send`] where the current binding is known (CV-1)
    /// rather than against a copy kept here.
    ///
    /// # Why empty is refused at the boundary
    ///
    /// A framed levin notify always carries a header, so an empty message is a
    /// caller bug rather than a state the wire can produce. Refusing it here —
    /// the queue's only insertion point — establishes the invariant
    /// *`pending` never holds an empty message*, which
    /// [`Self::take_for_send`] depends on to make progress.
    ///
    /// **Without it the channel wedges silently and permanently.** An empty
    /// head is reloaded on every take and never popped, so every later message
    /// on that channel is blocked forever — and the failure is *invisible by
    /// construction*: a wedged channel keeps emitting dummies, which is
    /// precisely what a healthy idle channel looks like. Constant-rate cover
    /// means nothing observable changes when the queue stops draining.
    pub fn enqueue(&mut self, channel: usize, message: Vec<u8>) -> bool {
        // Refusal travels in the return value, not a `debug_assert!`. The
        // out-of-range arm below already signals that way, and a debug-only
        // panic would both break the symmetry and make the guard untestable —
        // any test exercising the refusal would abort instead of observing it.
        // A `false` return is also the stronger signal: it survives into
        // release, where a caller bug is no less a bug.
        if message.is_empty() {
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

    /// Take the next `fragment_len` bytes `channel` should put on the wire
    /// for `peer`.
    ///
    /// `None` means **send a dummy** — the common case, not an error.
    /// `fragment_len` is the covert fragment window (`CRYPTONOTE_NOISE_BYTES`
    /// in production). A zero window is a caller bug: nothing is consumed.
    ///
    /// **CV-1: a rebind discards the in-flight remainder and restarts.** If
    /// `peer` differs from the binding the active tail was taken under, that
    /// tail is dropped and the next take clones `pending.front()` from the
    /// start. Resuming would let the extra send time leak that this node was
    /// pushing something real (§20.5). Restarting keeps the payload live
    /// (the C++ `send_noise` shape) without the length leak.
    pub fn take_for_send(
        &mut self,
        channel: usize,
        peer: ConnectionId,
        fragment_len: usize,
    ) -> Option<Vec<u8>> {
        if fragment_len == 0 {
            debug_assert!(false, "covert fragment window must be non-zero");
            return None;
        }
        let q = self.channels.get_mut(channel)?;
        if q.bound != Some(peer) {
            q.active = None;
            q.bound = Some(peer);
        }
        if q.active.as_ref().is_none_or(Vec::is_empty) {
            q.active = q.pending.front().cloned();
        }
        let active = q.active.as_mut()?;
        if active.is_empty() {
            /* Unreachable: `enqueue` refuses empty messages, so `pending`
            cannot hold one. Handled anyway, and **by discarding rather than
            returning early**, because the early return is what wedges the
            channel: the empty head would be reloaded on every subsequent
            take and never popped, blocking the queue permanently while the
            channel went on emitting dummies — indistinguishable from idle.

            Discarding costs one dummy tick and the channel recovers. */
            debug_assert!(false, "covert queue holds an empty message");
            q.active = None;
            let _ = q.pending.pop_front();
            return None;
        }
        let n = fragment_len.min(active.len());
        let fragment: Vec<u8> = active.drain(..n).collect();
        if active.is_empty() {
            q.active = None;
            let _ = q.pending.pop_front();
        }
        Some(fragment)
    }

    /// The channel's stem slot went unbound: drop everything it held.
    pub fn unbind(&mut self, channel: usize) {
        if let Some(q) = self.channels.get_mut(channel) {
            q.pending.clear();
            q.active = None;
            q.bound = None;
        }
    }
}

#[cfg(test)]
mod tests;
