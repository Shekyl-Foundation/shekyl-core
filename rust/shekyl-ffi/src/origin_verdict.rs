// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The relay's hop-0 verdict for a local origin, published process-wide.
//!
//! One `levin::notify` holds every connector registry, so one relay decides
//! and one cell holds that fact (`GS-Q3`). The writer is the production
//! zone's publish in [`crate::relay_zone_ffi`]; the readers are the
//! managed-Tor supervisor in `shekyl-daemon` and the RPC `health` boolean
//! (`TSR-Q4`). The cell is [`OriginVerdict::Absent`] until the zone exists.
//!
//! [`OriginVerdict`] is the relay's type. Health is
//! [`OriginVerdict::hides_address`]. `OwnTx` reads
//! [`OriginVerdict::origin_leaves`]. The link being usable is neither.

use std::sync::{Arc, LazyLock};

use tokio::sync::watch;

pub use shekyl_relay::OriginVerdict;

/// The writing end of a verdict channel. The process has one, held by the
/// production zone; a test zone holds one of its own, so no test touches
/// the process cell.
pub type OriginPublisher = Arc<watch::Sender<OriginVerdict>>;

static VERDICT: LazyLock<OriginPublisher> =
    LazyLock::new(|| Arc::new(watch::channel(OriginVerdict::default()).0));

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

/// The process cell's publisher, for the one production zone.
#[must_use]
pub(crate) fn process_publisher() -> OriginPublisher {
    Arc::clone(&VERDICT)
}

/// Publish `verdict` through `publisher`. A repeat of the current value wakes
/// nobody.
pub(crate) fn publish_to(publisher: &OriginPublisher, verdict: OriginVerdict) {
    publisher.send_if_modified(|held| {
        if *held == verdict {
            return false;
        }
        *held = verdict;
        true
    });
}
