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
//! Health boolean (`TSR-Q4`). `false` until the zone exists.
//!
//! The link being usable is not this fact. After a Tor boot the link is
//! usable before any address-hiding peer has handshaken, and the relay
//! holds a local origin until one has (`GS-F3`).

use std::sync::LazyLock;

use tokio::sync::watch;

static VERDICT: LazyLock<watch::Sender<bool>> = LazyLock::new(|| watch::channel(false).0);

/// A receiver of the verdict. `changed()` wakes on a flip and `borrow()`
/// reads the value now. The sender is process-static, so the channel never
/// closes.
#[must_use]
pub fn watch() -> watch::Receiver<bool> {
    VERDICT.subscribe()
}

/// The verdict now.
#[must_use]
pub fn current() -> bool {
    *VERDICT.borrow()
}

/// Publish the verdict. A repeat of the current value wakes nobody.
pub(crate) fn publish(routable: bool) {
    VERDICT.send_if_modified(|held| {
        if *held == routable {
            return false;
        }
        *held = routable;
        true
    });
}
