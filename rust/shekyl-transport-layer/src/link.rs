// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The link under each connector (`TOR_SUPERVISOR.md` §4.1, `TSR-F1`).
//!
//! A link is the route a dial takes and whether this node can open streams
//! through it. It is published by whoever owns the connector's route and read
//! by everyone else: the connector reads the route at each dial, and the
//! dialer's plan reads the outbound facet before it draws. Clearnet's route is
//! direct or the operator's SOCKS proxy. Tor's is the SOCKS address of the Tor
//! it dials through.
//!
//! One [`Links`] holds every connector's link. A reader takes a copy with
//! [`Links::get`]; a reader that waits for a change registers a watcher with
//! [`Links::subscribe`], which is called after every change.
//!
//! The inbound facet (whether peers can reach this node's address through the
//! link) arrives with the supervisor, which is its one source; there is no
//! slot for it until then.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use shekyl_timing_engine::Tick;

use crate::ConnectorId;

/// How a connector's dials leave this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// A plain TCP connect to the peer.
    Direct,
    /// Through the SOCKS5 proxy at this address.
    Socks(SocketAddr),
}

/// Why a link went down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownCause {
    /// The managed Tor's process ended: its SOCKS port is gone with it.
    ProcessExited,
}

/// Can this node open streams through the link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outbound {
    /// Nothing has said yet: no route has been installed.
    Unknown,
    /// Dials can leave through the route, since `since`.
    Usable { since: Tick },
    /// Dials cannot leave, since `since`, for `cause`.
    Down { cause: DownCause, since: Tick },
}

/// One connector's link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    /// Bumps on every new route, and when a route is withdrawn. A `Down` for
    /// an earlier incarnation is stale and changes nothing.
    pub incarnation: u64,
    /// `None` while there is no route.
    pub route: Option<Route>,
    /// The outbound facet.
    pub outbound: Outbound,
}

impl Link {
    const UNKNOWN: Self = Self {
        incarnation: 0,
        route: None,
        outbound: Outbound::Unknown,
    };

    /// Whether dials can leave through this link now.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        matches!(self.outbound, Outbound::Usable { .. })
    }
}

/// Called after a connector's link changes, with that connector. It must not
/// publish to the same [`Links`]: it runs on the publisher's thread.
pub type Watcher = Arc<dyn Fn(ConnectorId) + Send + Sync>;

/// Every connector's link, and who is told when one changes.
pub struct Links {
    links: Mutex<[Link; ConnectorId::COUNT]>,
    watchers: Mutex<Vec<Watcher>>,
}

impl Default for Links {
    fn default() -> Self {
        Self::new()
    }
}

impl Links {
    /// Every link unknown, with no route.
    #[must_use]
    pub fn new() -> Self {
        Self {
            links: Mutex::new([Link::UNKNOWN; ConnectorId::COUNT]),
            watchers: Mutex::new(Vec::new()),
        }
    }

    /// A copy of `connector`'s link as it stands.
    #[must_use]
    pub fn get(&self, connector: ConnectorId) -> Link {
        self.links.lock().expect("links")[connector.index()]
    }

    /// Install `route` for `connector`, usable from `now`. Returns the new
    /// incarnation, which a later [`Self::publish_down`] names.
    pub fn publish_usable(&self, connector: ConnectorId, route: Route, now: Tick) -> u64 {
        self.change(connector, |link| {
            link.incarnation = link.incarnation.wrapping_add(1);
            link.route = Some(route);
            link.outbound = Outbound::Usable { since: now };
        })
    }

    /// The route of `incarnation` went down at `now`. Returns whether the
    /// link changed: a newer route has replaced that incarnation, or it was
    /// already down, and then nothing changes. The route stays recorded, so a
    /// reader can say which route fell.
    pub fn publish_down(
        &self,
        connector: ConnectorId,
        incarnation: u64,
        cause: DownCause,
        now: Tick,
    ) -> bool {
        let changed = {
            let mut links = self.links.lock().expect("links");
            let link = &mut links[connector.index()];
            if link.incarnation != incarnation || !link.is_usable() {
                false
            } else {
                link.outbound = Outbound::Down { cause, since: now };
                true
            }
        };
        if changed {
            self.notify(connector);
        }
        changed
    }

    /// Withdraw `connector`'s route: unknown, with none. The zone host does
    /// this at its shutdown, so a host built later starts from nothing.
    pub fn withdraw(&self, connector: ConnectorId) {
        self.change(connector, |link| {
            link.incarnation = link.incarnation.wrapping_add(1);
            link.route = None;
            link.outbound = Outbound::Unknown;
        });
    }

    /// Call `watcher` after every change to any connector's link.
    pub fn subscribe(&self, watcher: Watcher) {
        self.watchers.lock().expect("link watchers").push(watcher);
    }

    fn change(&self, connector: ConnectorId, edit: impl FnOnce(&mut Link)) -> u64 {
        let incarnation = {
            let mut links = self.links.lock().expect("links");
            let link = &mut links[connector.index()];
            edit(link);
            link.incarnation
        };
        self.notify(connector);
        incarnation
    }

    /// The watchers run with neither lock held.
    fn notify(&self, connector: ConnectorId) {
        let watchers: Vec<Watcher> = self.watchers.lock().expect("link watchers").clone();
        for watcher in watchers {
            watcher(connector);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn socks(port: u16) -> Route {
        Route::Socks(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
    }

    #[test]
    fn a_link_starts_unknown_with_no_route() {
        let links = Links::new();
        let link = links.get(ConnectorId::Tor);
        assert_eq!(link.route, None);
        assert_eq!(link.outbound, Outbound::Unknown);
        assert!(!link.is_usable());
    }

    #[test]
    fn a_route_is_usable_and_its_death_is_down() {
        let links = Links::new();
        let incarnation = links.publish_usable(ConnectorId::Tor, socks(9050), Tick::new(5));
        assert!(links.get(ConnectorId::Tor).is_usable());
        assert!(links.publish_down(
            ConnectorId::Tor,
            incarnation,
            DownCause::ProcessExited,
            Tick::new(9)
        ));
        let link = links.get(ConnectorId::Tor);
        assert_eq!(
            link.outbound,
            Outbound::Down {
                cause: DownCause::ProcessExited,
                since: Tick::new(9)
            }
        );
        assert_eq!(link.route, Some(socks(9050)), "the fallen route is kept");
        assert!(
            links.get(ConnectorId::Clearnet).route.is_none(),
            "one connector's link is its own"
        );
    }

    /// A death reported for a route that has since been replaced does not
    /// take the new route down.
    #[test]
    fn a_stale_down_changes_nothing() {
        let links = Links::new();
        let first = links.publish_usable(ConnectorId::Tor, socks(9050), Tick::new(1));
        let second = links.publish_usable(ConnectorId::Tor, socks(9150), Tick::new(2));
        assert_ne!(first, second);
        assert!(!links.publish_down(
            ConnectorId::Tor,
            first,
            DownCause::ProcessExited,
            Tick::new(3)
        ));
        assert!(links.get(ConnectorId::Tor).is_usable());
        links.withdraw(ConnectorId::Tor);
        assert!(!links.publish_down(
            ConnectorId::Tor,
            second,
            DownCause::ProcessExited,
            Tick::new(4)
        ));
        assert_eq!(links.get(ConnectorId::Tor).outbound, Outbound::Unknown);
    }

    #[test]
    fn a_watcher_hears_every_change_and_nothing_else() {
        let links = Links::new();
        let heard = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&heard);
        links.subscribe(Arc::new(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
        }));
        let incarnation = links.publish_usable(ConnectorId::Clearnet, Route::Direct, Tick::new(1));
        assert!(links.publish_down(
            ConnectorId::Clearnet,
            incarnation,
            DownCause::ProcessExited,
            Tick::new(2)
        ));
        assert!(!links.publish_down(
            ConnectorId::Clearnet,
            incarnation,
            DownCause::ProcessExited,
            Tick::new(3)
        ));
        links.withdraw(ConnectorId::Clearnet);
        assert_eq!(heard.load(Ordering::SeqCst), 3, "usable, down, withdrawn");
    }
}
