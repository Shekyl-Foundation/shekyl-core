// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain sync's two process-wide entries (CS-5): the owners the node leaves
//! for the seam's bind (§2), and the state the shell's `core::is_synchronized`
//! reads (§3). The bind takes the latest owner still waiting. Each node
//! keeps the lease for its own hub sender.
//!
//! The handler's sync reads that lived here went with the handler's sync
//! half: chain sync is the Rust owner's, and nothing in C++ reads the chain
//! for sync. The one handshake tip is the dialer's
//! (`crate::dialer_ffi::shekyl_p2p_handshake_tip`).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use shekyl_chain_sync::SyncState;
use shekyl_chain_sync_runtime::router::Routed;
use shekyl_seam::Hub;
use tokio::sync::{mpsc, oneshot, watch};

/// One installed owner's router sender and hub sender.
struct Live {
    router: mpsc::UnboundedSender<Routed>,
    hub: oneshot::Sender<Arc<Hub>>,
}

/// Which owner. The counter is the process's; an id is not reused while a
/// [`OwnerLease`] for it can still drop.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct OwnerId(u64);

/// The owners this process has installed, and which of them the bind takes.
///
/// A node's tests open more than one node in this process. Each owner
/// publishes only on its own watch, and releasing one does not end another.
struct Owners {
    next: OwnerId,
    live: BTreeMap<OwnerId, Live>,
    /// The owner [`take`] hands the seam. Absent when none is waiting.
    waiting: Option<OwnerId>,
    /// The owner the seam's bind took. A later bind is [`Refused::SecondBind`].
    taken: Option<OwnerId>,
    /// Whose state [`shekyl_node_is_synchronized`] reads. The latest install.
    published: Option<OwnerId>,
}

impl Owners {
    const EMPTY: Self = Self {
        next: OwnerId(0),
        live: BTreeMap::new(),
        waiting: None,
        taken: None,
        published: None,
    };

    fn alloc(&mut self) -> OwnerId {
        let id = self.next;
        self.next = OwnerId(
            id.0.checked_add(1)
                .expect("a process installs fewer owners than u64::MAX"),
        );
        id
    }
}

static OWNERS: Mutex<Owners> = Mutex::new(Owners::EMPTY);

/// The node's hold on the owner it installed.
///
/// Dropping it releases that owner alone: its hub sender goes, if the seam
/// has not already taken it, and a node still waiting on the hub ends. A
/// later install does not drop this. The bind takes the latest owner still
/// waiting; it does not take one whose lease has gone.
#[must_use = "dropping the lease ends this chain-sync owner"]
pub struct OwnerLease {
    id: OwnerId,
}

impl Drop for OwnerLease {
    fn drop(&mut self) {
        release(self.id);
    }
}

/// Why a bind found no owner to attach the router to. Either way the seam
/// would run without chain sync, so the bind is refused and the daemon
/// does not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// No node installed its owner before the bind.
    NoOwner,
    /// The daemon's bind already took the node's owner.
    SecondBind,
}

impl Refused {
    /// The cause, as the bind logs it.
    #[must_use]
    pub const fn cause(self) -> &'static str {
        match self {
            Self::NoOwner => "the seam was bound before the node installed its chain-sync owner",
            Self::SecondBind => {
                "the seam was bound a second time after chain sync attached to the first binding"
            }
        }
    }
}

/// Chain sync's published state, as the node holds it.
static STATE: Mutex<Option<watch::Receiver<SyncState>>> = Mutex::new(None);

/// Leave the node's chain-sync owner for the seam's bind
/// ([`crate::seam_ffi::shekyl_seam_bind`]), which attaches the Levin router
/// to `router` and sends the hub it mints down `hub`, and install the
/// node's sync state for [`shekyl_node_is_synchronized`].
///
/// The returned lease is that owner's. A later install does not drop this
/// hub sender: the earlier owner keeps publishing on its own watch until
/// its lease drops. The bind takes the latest owner still waiting. After a
/// bind has taken one, a later install stays out of the bind; the seam is
/// bound once.
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
) -> OwnerLease {
    let mut owners = OWNERS.lock().unwrap_or_else(PoisonError::into_inner);
    let id = owners.alloc();
    owners.live.insert(id, Live { router, hub });
    // A bind already taken stays taken. The new owner waits on its own hub
    // until its node releases it; it is not a second owner for this seam.
    if owners.taken.is_none() {
        owners.waiting = Some(id);
    }
    owners.published = Some(id);
    drop(owners);
    *STATE.lock().unwrap_or_else(PoisonError::into_inner) = Some(state);
    OwnerLease { id }
}

/// Release one owner. The seam's bind, if it already took this owner, is
/// not given another: the slot goes empty, and the next bind is
/// [`Refused::NoOwner`] until a node installs again.
fn release(id: OwnerId) {
    let mut owners = OWNERS.lock().unwrap_or_else(PoisonError::into_inner);
    owners.live.remove(&id);
    if owners.waiting == Some(id) {
        owners.waiting = None;
    }
    if owners.taken == Some(id) {
        owners.taken = None;
    }
    if owners.published == Some(id) {
        owners.published = None;
        drop(owners);
        STATE.lock().unwrap_or_else(PoisonError::into_inner).take();
    }
}

/// Clear every owner [`install`] left, taken or not. Each hub sender still
/// held drops, so an owner still waiting for its hub ends, and the state
/// reads as not synchronized. A lease that drops afterwards finds nothing
/// of its own. The next id is not reused.
pub fn uninstall() {
    let mut owners = OWNERS.lock().unwrap_or_else(PoisonError::into_inner);
    let next = owners.next;
    *owners = Owners::EMPTY;
    owners.next = next;
    drop(owners);
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

/// The owner's ends a test's stand-in keeps, so the router it binds stays
/// attached: the router's receiver and the hub one-shot's receiver. Held,
/// not read.
#[cfg(test)]
pub(crate) struct TestOwner {
    _routed: mpsc::UnboundedReceiver<Routed>,
    _hub: oneshot::Receiver<Arc<Hub>>,
    _lease: OwnerLease,
}

/// For this crate's tests that bind the seam: install a stand-in for the
/// node's owner the way the node does ([`install`]), so the bind builds
/// the production router, attached. Any slot left by an earlier test is
/// emptied first. Test-only: the shipped archive has no way to install an
/// owner but the node's.
#[cfg(test)]
pub(crate) fn install_test_owner() -> TestOwner {
    uninstall();
    let (router, routed) = mpsc::unbounded_channel();
    let (hub_tx, hub) = oneshot::channel();
    let lease = install(router, hub_tx, watch::channel(SyncState::NoView).1);
    TestOwner {
        _routed: routed,
        _hub: hub,
        _lease: lease,
    }
}

/// What a bind takes from the slot: the owner's router sender and its hub
/// one-shot.
pub(crate) type Taken = (mpsc::UnboundedSender<Routed>, oneshot::Sender<Arc<Hub>>);

/// Take what the node left, once. The production seam is bound once per
/// process (`zone_server.h`'s `bind_seam`), after the node installed its
/// owner. With no owner, or with the owner already taken, the seam would
/// run without chain sync: [`Refused`].
pub(crate) fn take() -> Result<Taken, Refused> {
    let mut owners = OWNERS.lock().unwrap_or_else(PoisonError::into_inner);
    if owners.taken.is_some() {
        return Err(Refused::SecondBind);
    }
    let Some(id) = owners.waiting.take() else {
        return Err(Refused::NoOwner);
    };
    let live = owners
        .live
        .remove(&id)
        .expect("the waiting owner is installed");
    owners.taken = Some(id);
    Ok((live.router, live.hub))
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
        let _owner = install(router, hub, state);
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

    /// A second install used to drop the first owner's hub sender, and that
    /// owner then published `NoView` and stopped. The first node is still
    /// open: its hub stays until its own lease drops, and the bind takes
    /// the later owner.
    #[test]
    fn a_later_install_keeps_an_earlier_owners_hub() {
        use tokio::sync::oneshot::error::TryRecvError;

        let _seam = crate::seam_ffi::seam_bind_lock().lock();
        uninstall();
        let (router_a, _routed_a) = mpsc::unbounded_channel();
        let (hub_a, mut wait_a) = oneshot::channel();
        let first = install(router_a, hub_a, watch::channel(SyncState::NoView).1);
        let (router_b, _routed_b) = mpsc::unbounded_channel();
        let (hub_b, mut wait_b) = oneshot::channel();
        let second = install(router_b, hub_b, watch::channel(SyncState::NoView).1);

        assert_eq!(wait_a.try_recv().err(), Some(TryRecvError::Empty));
        assert_eq!(wait_b.try_recv().err(), Some(TryRecvError::Empty));

        drop(first);
        assert_eq!(
            wait_a.try_recv().err(),
            Some(TryRecvError::Closed),
            "the first owner's hub ends with its lease"
        );
        assert_eq!(
            wait_b.try_recv().err(),
            Some(TryRecvError::Empty),
            "the later owner is still waiting"
        );

        let (_router, hub) = take().expect("the later owner is the one waiting");
        assert_eq!(take().err(), Some(Refused::SecondBind));
        drop(hub);
        assert_eq!(wait_b.try_recv().err(), Some(TryRecvError::Closed));

        drop(second);
        assert_eq!(take().err(), Some(Refused::NoOwner));
    }
}
