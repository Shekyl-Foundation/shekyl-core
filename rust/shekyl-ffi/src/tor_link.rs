// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What this node's own Tor dials show, one cell for the process
//! (`TOR_SUPERVISOR.md` §4.2, "every Tor dial's outcome"). Display only,
//! never a verdict on the link (`TSR-Q14`).
//!
//! The one dialer writes it through its `sink`; the managed-Tor supervisor in
//! `shekyl-daemon` reads it. The cell holds the default tally until the
//! dialer exists. The tally is counts only: no address, no reply code.

use std::sync::{Arc, LazyLock};

use tokio::sync::watch;

pub use shekyl_dialer::TorLinkTally;

/// The deadline every Tor dial runs under (`TOR_DIAL_WITHIN_NANOS`). The
/// managed Tor's `SocksTimeout` sits below it, so Tor's own reply ends a dial
/// it cannot attach before this deadline does (`TOR_SUPERVISOR.md` §4.2).
pub const TOR_DIAL_WITHIN: std::time::Duration =
    std::time::Duration::from_nanos(shekyl_transport_layer::spans::TOR_DIAL_WITHIN_NANOS);

/// The managed Tor's `SocksTimeout`: it answers a SOCKS request it cannot
/// attach just inside [`TOR_DIAL_WITHIN`], so a blocked link is Tor's reply,
/// never a race with that deadline (`TOR_SUPERVISOR.md` §4.2). The one
/// constant: the daemon launches its Tor with it, and the dialer reads its
/// [`SocksTimeout::window`] as the window a Tor attempt can use, so an
/// attempt that fails at or after it is final within its test (the dialer
/// in-flight bound, revision 4, Rick 2026-10-26).
pub const TOR_SOCKS_TIMEOUT: shekyl_tor_control_client::control::SocksTimeout =
    shekyl_tor_control_client::control::SocksTimeout::Below {
        dial_deadline: TOR_DIAL_WITHIN,
    };

static TALLY: LazyLock<watch::Sender<TorLinkTally>> =
    LazyLock::new(|| watch::channel(TorLinkTally::default()).0);

/// A receiver of the tally. `changed()` wakes on a change. The sender is
/// process-static, so the channel never closes.
#[must_use]
pub fn watch() -> watch::Receiver<TorLinkTally> {
    TALLY.subscribe()
}

/// The dialer's sink into the process cell. It runs under the dialer's lock;
/// a `watch` send does not block. A repeat of the current tally wakes nobody.
#[must_use]
pub(crate) fn sink() -> shekyl_dialer::TallySink {
    Arc::new(|tally| {
        TALLY.send_if_modified(|held| {
            if *held == tally {
                return false;
            }
            *held = tally;
            true
        });
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dialer's sink reaches the supervisor's receiver, and a repeat of
    /// the same tally does not wake it. The only test of the process cell.
    #[test]
    fn the_dialers_sink_reaches_the_supervisor_and_a_repeat_wakes_nobody() {
        let mut receiver = watch();
        receiver.borrow_and_update();
        let tally = TorLinkTally {
            opened: 0,
            unopened: 3,
            held: 0,
        };
        let sink = sink();
        sink(tally);
        assert!(receiver.has_changed().expect("process-static"));
        assert_eq!(*receiver.borrow_and_update(), tally);
        sink(tally);
        assert!(!receiver.has_changed().expect("process-static"));
    }
}
