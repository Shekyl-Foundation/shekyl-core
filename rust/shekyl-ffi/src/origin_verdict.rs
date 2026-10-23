// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The relay's hop-0 verdict for a local origin, published process-wide.
//!
//! One `levin::notify` holds every connector registry, so one relay decides
//! whether a transaction this node originates leaves on an address-hiding
//! session now, and one cell holds that fact (`GS-Q3`). The writer is the
//! production zone's publish in [`crate::relay_zone_ffi`]; the readers are
//! the managed-Tor supervisor in `shekyl-daemon`, which projects it as
//! `OwnTx` and Health (`TOR_SUPERVISOR.md` posture table), and the RPC
//! `health` boolean (`TSR-Q4`). Both parts are `false` until the zone
//! exists, and under every `tor` setting: with `tor = off` the relay has
//! no address-hiding class and the verdict is simply false.
//!
//! The verdict has two parts, split by `RPC_CHANNEL.md` §6.1's test.
//! [`OriginVerdict::connected`] is the class part, "an outbound session
//! hides this node's address now": transient, saying nothing lasting about
//! the node, so it is the `health` grant's boolean. [`OriginVerdict::routable`]
//! adds the pin part, "this epoch's frozen own-edge candidates are not all
//! gone": it moves exactly when the node's own-edge peers disconnect, so
//! it is the `status` grant's, through `OwnTx`. A peer who held `health`
//! and was the own edge could otherwise watch the boolean flip on its own
//! disconnect.
//!
//! The link being usable is neither part. After a Tor boot the link is
//! usable before any address-hiding peer has handshaken, and the relay
//! holds a local origin until one has (`GS-F3`).

use std::sync::LazyLock;

use tokio::sync::watch;

/// The relay's hop-0 verdict for a local origin, in its two parts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OriginVerdict {
    /// An outbound session hides this node's address now. The `health`
    /// grant's boolean.
    pub connected: bool,
    /// A transaction this node originates leaves on such a session now:
    /// `connected`, and the epoch's origin pin is not exhausted. `OwnTx`'s
    /// fact, under the `status` grant. Implies `connected`.
    pub routable: bool,
}

static VERDICT: LazyLock<watch::Sender<OriginVerdict>> =
    LazyLock::new(|| watch::channel(OriginVerdict::default()).0);

/// A receiver of the verdict. `changed()` wakes on a change and `borrow()`
/// reads the value now. The sender is process-static, so the channel never
/// closes.
#[must_use]
pub fn watch() -> watch::Receiver<OriginVerdict> {
    VERDICT.subscribe()
}

/// The verdict now.
#[must_use]
pub fn current() -> OriginVerdict {
    *VERDICT.borrow()
}

/// Publish the verdict. A repeat of the current value wakes nobody.
pub(crate) fn publish(verdict: OriginVerdict) {
    VERDICT.send_if_modified(|held| {
        if *held == verdict {
            return false;
        }
        *held = verdict;
        true
    });
}
