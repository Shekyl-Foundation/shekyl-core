// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the network tells the managed-Tor supervisor, and what the
//! supervisor tells the network.
//!
//! The supervisor in `shekyl-daemon` hands the network its [`SupervisorFeeds`]
//! at start (`TOR_SUPERVISOR.md` §5): the network's producers publish into
//! them and never wait on the supervisor. The supervisor publishes the route
//! through the network's verbs, and [`TorLink`] keeps the managed route's
//! incarnation, one instance per network, held by [`crate::Network`].

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use shekyl_dialer::TallySink;
use shekyl_p2p_session::{ProbeSink, SessionsSink};
use shekyl_relay::owner::VerdictSink;
use shekyl_socks::{Proxy, SocksUsername};
use shekyl_tor_control_client::control::SocksTimeout;
use shekyl_transport_layer::{spans, ConnectorId, Links, Route};

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

/// What the managed-Tor supervisor hears from the network. Each is called
/// by its producer and must not block (`TOR_SUPERVISOR.md` §5).
pub struct SupervisorFeeds {
    /// The dialer's tally of this node's Tor dials (§4.2): the value at
    /// start, then each change. Display only (`TSR-Q14`).
    pub tally: TallySink,
    /// Each probe of this node's onion that arrived (§4.5).
    pub probes: Arc<dyn ProbeSink>,
    /// The relay's hop-0 verdict for a local origin (`GS-Q3`): the value at
    /// start, then each change.
    pub verdict: VerdictSink,
    /// The sessions each connector holds (`TSR-Q12`): the count at start,
    /// then each change.
    pub sessions: SessionsSink,
}

/// The managed route as published: the incarnation the link gave it and
/// the SOCKS address. Read back by [`TorLink::managed_socks`] against the
/// link, so a route that fell since is not reported.
#[derive(Clone, Copy)]
struct ManagedRoute {
    incarnation: u64,
    at: SocketAddr,
}

/// The managed route's incarnation, as the supervisor last published it.
pub(crate) struct TorLink {
    managed: Mutex<Option<ManagedRoute>>,
}

impl TorLink {
    pub(crate) fn new() -> Self {
        Self {
            managed: Mutex::new(None),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

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
