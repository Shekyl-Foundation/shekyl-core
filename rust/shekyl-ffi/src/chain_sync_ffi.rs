// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain sync's two process-wide entries (CS-5): the slot the node leaves
//! its chain-sync owner in for the seam's bind (§2), and the state the
//! shell's `core::is_synchronized` reads (§3).
//!
//! The handler's sync reads that lived here went with the handler's sync
//! half: chain sync is the Rust owner's, and nothing in C++ reads the chain
//! for sync. The one handshake tip is the dialer's
//! (`crate::dialer_ffi::shekyl_p2p_handshake_tip`).

use std::sync::{Arc, Mutex, PoisonError};

use shekyl_chain_sync::SyncState;
use shekyl_chain_sync_runtime::router::Routed;
use shekyl_seam::Hub;
use tokio::sync::{mpsc, oneshot, watch};

/// What the node leaves for the seam's bind (CS-5 §2): the sender its
/// chain-sync owner reads routed messages from, and the one-shot the owner
/// waits on for the hub.
struct Attach {
    router: mpsc::UnboundedSender<Routed>,
    hub: oneshot::Sender<Arc<Hub>>,
}

static ATTACH: Mutex<Option<Attach>> = Mutex::new(None);

/// Chain sync's published state, as the node holds it.
static STATE: Mutex<Option<watch::Receiver<SyncState>>> = Mutex::new(None);

/// Leave the node's chain-sync owner for the seam's bind
/// ([`crate::seam_ffi::shekyl_seam_bind`]), which attaches the Levin router
/// to `router` and sends the hub it mints down `hub`, and install the
/// node's sync state for [`shekyl_node_is_synchronized`]. A second install
/// replaces the first, whose owner then sees its hub sender dropped.
///
/// # Deleter
///
/// Slice 4, with the bind, when the hub becomes the node's: the node then
/// hands its owner the hub directly (CS-Q9's slice-4 table). The state
/// goes with [`shekyl_node_is_synchronized`]'s reader.
pub fn install(
    router: mpsc::UnboundedSender<Routed>,
    hub: oneshot::Sender<Arc<Hub>>,
    state: watch::Receiver<SyncState>,
) {
    *ATTACH.lock().unwrap_or_else(PoisonError::into_inner) = Some(Attach { router, hub });
    *STATE.lock().unwrap_or_else(PoisonError::into_inner) = Some(state);
}

/// Clear what [`install`] left. A slot no bind took drops the owner's hub
/// sender, so an owner still waiting for its hub ends, and the state reads
/// as not synchronized.
pub fn uninstall() {
    ATTACH.lock().unwrap_or_else(PoisonError::into_inner).take();
    STATE.lock().unwrap_or_else(PoisonError::into_inner).take();
}

/// 1 when chain sync reads `Synced`, 0 otherwise (CS-5 §3): what the
/// shell's `core::is_synchronized` answers for the transaction relay.
///
/// `Following` is not synchronized for relay's purposes (CS-Q2 step 8): a
/// node following a chain it cannot verify does not fluff into it. No
/// node, and a node whose state watch has closed, read 0.
///
/// # Deleter
///
/// RD, with `levin_notify` and the shell's `i_core_events`.
#[no_mangle]
pub extern "C" fn shekyl_node_is_synchronized() -> u8 {
    let state = STATE.lock().unwrap_or_else(PoisonError::into_inner);
    let synced = state
        .as_ref()
        .is_some_and(|state| state.has_changed().is_ok() && *state.borrow() == SyncState::Synced);
    u8::from(synced)
}

/// Take what the node left, once. The production seam is bound once per
/// process (`zone_server.h`'s `bind_seam`). A later bind, such as a test's
/// rebind after a clear, finds nothing and builds a pass-through router.
pub(crate) fn take() -> Option<(mpsc::UnboundedSender<Routed>, oneshot::Sender<Arc<Hub>>)> {
    ATTACH
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .map(|attach| (attach.router, attach.hub))
}

#[cfg(test)]
mod state_tests {
    use super::*;
    use shekyl_types::{BlockHeight, ChainCount};

    /// The export answers 1 for `Synced` only: `Following` is not
    /// synchronized for relay's purposes, and neither is a node that is
    /// behind or has no view. No node installed, and a node uninstalled,
    /// read 0.
    #[test]
    fn the_node_is_synchronized_only_while_chain_sync_reads_synced() {
        let _seam = crate::seam_ffi::seam_bind_lock().lock();
        uninstall();
        assert_eq!(shekyl_node_is_synchronized(), 0, "no node");
        let (state_tx, state) = watch::channel(SyncState::NoView);
        let (router, _routed) = mpsc::unbounded_channel();
        let (hub, _hub) = oneshot::channel();
        install(router, hub, state);
        let cases = [
            (SyncState::NoView, 0),
            (
                SyncState::Behind {
                    have: shekyl_difficulty::CumulativeDifficulty::from_raw(1),
                    best: shekyl_difficulty::CumulativeDifficulty::from_raw(2),
                    target: ChainCount::from_raw(2),
                },
                0,
            ),
            (
                SyncState::Following {
                    verified_to: BlockHeight::from_raw(1),
                },
                0,
            ),
            (SyncState::Synced, 1),
        ];
        for (published, expected) in cases {
            state_tx.send_replace(published);
            assert_eq!(shekyl_node_is_synchronized(), expected, "{published:?}");
        }
        uninstall();
        assert_eq!(shekyl_node_is_synchronized(), 0, "uninstalled");
    }
}
