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

use std::collections::VecDeque;

use shekyl_relay_privacy::stem_map::ConnectionId;

/// One channel's pending work.
#[derive(Debug, Default)]
struct ChannelQueue {
    /// Framed messages waiting for this channel's next due tick.
    pending: VecDeque<Vec<u8>>,
    /// The message currently mid-flight, if any.
    active: Option<Vec<u8>>,
    /// The peer this channel was bound to when `active` was taken.
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
    /// Refused when the channel index is out of range. **Not** refused on an
    /// unbound channel here: binding is the scheduler's fact and travels with
    /// each send, so the discard happens at [`Self::take_for_send`] where the
    /// current binding is known (CV-1) rather than against a copy kept here.
    pub fn enqueue(&mut self, channel: usize, message: Vec<u8>) -> bool {
        match self.channels.get_mut(channel) {
            Some(q) => {
                q.pending.push_back(message);
                true
            }
            None => false,
        }
    }

    /// Take what `channel` should put on the wire for `peer`.
    ///
    /// `None` means **send a dummy** — which is the common case and is not an
    /// error.
    ///
    /// **CV-1: a rebind discards the in-flight remainder.** If `peer` differs
    /// from the binding the active message was taken under, that message is
    /// dropped rather than resumed: resuming would let the extra send time leak
    /// that this node was pushing something real (§20.5). The discard is here,
    /// at the one site that learns the new binding.
    pub fn take_for_send(&mut self, channel: usize, peer: ConnectionId) -> Option<Vec<u8>> {
        let q = self.channels.get_mut(channel)?;
        if q.bound != Some(peer) {
            // Rebind (or first bind): whatever was mid-flight belongs to the
            // previous peer and does not travel.
            q.active = None;
            q.bound = Some(peer);
        }
        if q.active.is_none() {
            q.active = q.pending.pop_front();
        }
        q.active.take()
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
