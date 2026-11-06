// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What this node's own Tor shows the managed-Tor supervisor, and what the
//! supervisor tells the network: the dial tally (`TOR_SUPERVISOR.md` §4.2,
//! display only, never a verdict on the link, `TSR-Q14`), the probe's
//! arrivals (§4.5), and the managed route's incarnation.
//!
//! One instance per network, held by [`crate::Network`]. The supervisor in
//! `shekyl-daemon` reads the two watches and publishes the route through
//! the network's verbs.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use shekyl_dialer::{TallySink, TorLinkTally};
use shekyl_p2p_session::{ProbeArrival, ProbeSink};
use shekyl_socks::{Proxy, SocksUsername};
use shekyl_tor_control_client::control::SocksTimeout;
use shekyl_transport_layer::{spans, ConnectorId, Links, Route};
use tokio::sync::watch;

/// The deadline every Tor dial runs under (`TOR_DIAL_WITHIN_NANOS`). The
/// managed Tor's `SocksTimeout` sits below it, so Tor's own reply ends a
/// dial it cannot attach before this deadline does (`TOR_SUPERVISOR.md`
/// §4.2).
pub const TOR_DIAL_WITHIN: Duration = Duration::from_nanos(spans::TOR_DIAL_WITHIN_NANOS);

/// The managed Tor's `SocksTimeout`: it answers a SOCKS request it cannot
/// attach just inside [`TOR_DIAL_WITHIN`], so a blocked link is Tor's reply,
/// never a race with that deadline. The one constant: the daemon launches
/// its managed Tor with it, and when that Tor's route is published the
/// dialer reads its [`SocksTimeout::earliest_expiry`] as its window. An
/// operator's Tor has its own, which this node does not know, and gives the
/// dialer no window.
pub const TOR_SOCKS_TIMEOUT: SocksTimeout = SocksTimeout::Below {
    dial_deadline: TOR_DIAL_WITHIN,
};

/// The managed route as published: the incarnation the link gave it and
/// the SOCKS address. Read back by [`TorLink::managed_socks`] against the
/// link, so a route that fell since is not reported.
#[derive(Clone, Copy)]
struct ManagedRoute {
    incarnation: u64,
    at: SocketAddr,
}

/// The Tor link's cells.
pub(crate) struct TorLink {
    probe: watch::Sender<Option<ProbeArrival>>,
    tally: watch::Sender<TorLinkTally>,
    managed: Mutex<Option<ManagedRoute>>,
}

impl TorLink {
    pub(crate) fn new() -> Self {
        Self {
            probe: watch::channel(None).0,
            tally: watch::channel(TorLinkTally::default()).0,
            managed: Mutex::new(None),
        }
    }

    /// The probe that last arrived; `None` until one does.
    pub(crate) fn probe_arrivals(&self) -> watch::Receiver<Option<ProbeArrival>> {
        self.probe.subscribe()
    }

    /// The dial tally as it changes.
    pub(crate) fn tally(&self) -> watch::Receiver<TorLinkTally> {
        self.tally.subscribe()
    }

    /// The sink the dialer reports the tally through. A repeat of the held
    /// tally wakes nobody.
    pub(crate) fn sink(self: &Arc<Self>) -> TallySink {
        let link = Arc::clone(self);
        Arc::new(move |tally| {
            link.tally.send_if_modified(|held| {
                if *held == tally {
                    return false;
                }
                *held = tally;
                true
            });
        })
    }

    /// Record the managed route as published, and return its incarnation.
    pub(crate) fn record_managed(&self, incarnation: u64, at: SocketAddr) {
        *self.managed.lock().expect("managed route") = Some(ManagedRoute { incarnation, at });
    }

    /// The managed Tor's SOCKS address, while the link this node dials
    /// through is that route: `None` before the daemon publishes one, after
    /// it is withdrawn, or when the link now points elsewhere.
    pub(crate) fn managed_socks(&self, links: &Links) -> Option<SocketAddr> {
        let ManagedRoute { incarnation, at } = (*self.managed.lock().expect("managed route"))?;
        let link = links.get(ConnectorId::Tor);
        (link.is_usable()
            && link.incarnation == incarnation
            && link.route == Some(Route::Socks(at)))
        .then_some(at)
    }

    /// The managed route with `isolation` as its SOCKS pair: the daemon's
    /// own dials through its Tor (the producer, the probe) use a pair the
    /// peers' dials do not, so Tor keeps their circuits apart.
    pub(crate) fn managed_route(
        &self,
        links: &Links,
        isolation: &Arc<SocksUsername>,
    ) -> Option<Proxy> {
        self.managed_socks(links)
            .map(|at| Proxy::authenticated_shared(at, Arc::clone(isolation)))
    }
}

impl ProbeSink for TorLink {
    fn probe_arrived(&self, arrival: ProbeArrival) {
        self.probe.send_replace(Some(arrival));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dialers_sink_reaches_the_supervisor_and_a_repeat_wakes_nobody() {
        let link = Arc::new(TorLink::new());
        let mut receiver = link.tally();
        receiver.borrow_and_update();
        let tally = TorLinkTally {
            opened: 0,
            unopened: 3,
            held: 0,
            last_sign_of_life: None,
            last_unopened_at: None,
        };
        let sink = link.sink();
        sink(tally);
        assert!(receiver.has_changed().expect("link held"));
        assert_eq!(*receiver.borrow_and_update(), tally);
        sink(tally);
        assert!(!receiver.has_changed().expect("link held"));
    }

    #[test]
    fn a_managed_route_is_reported_only_while_the_link_is_that_route() {
        use shekyl_timing_engine::Tick;
        let link = TorLink::new();
        let links = Links::new();
        let at: SocketAddr = ([127, 0, 0, 1], 9050).into();
        assert_eq!(link.managed_socks(&links), None);
        let published = links.publish_usable(ConnectorId::Tor, Route::Socks(at), Tick::new(1));
        link.record_managed(published.incarnation(), at);
        assert_eq!(link.managed_socks(&links), Some(at));
        links.withdraw(ConnectorId::Tor);
        assert_eq!(link.managed_socks(&links), None);
    }
}
