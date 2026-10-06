// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The sort that `Connection` is built from.
//!
//! C++ keeps `p2p_connection_context` through this step. Nothing here
//! changes a session. The hub stores a [`Connection`] beside the
//! endpoint it already published.
//!
//! The test for each member is who asserted it
//! (`LV3_CONNECTION_OBJECT.md`, the step-a table).
//!
//! # Observed, write-once at adoption
//!
//! `m_connection_id`, the connected address, the direction, the
//! connector, and `m_started`. The seam measured these when the row was
//! adopted. They do not change. Eviction, admission, the protection set,
//! and the operator view read only this bin.
//!
//! The byte counters (`m_last_recv`, `m_last_send`, the counts, the
//! speeds) are observed too, and they advance. They are not write-once,
//! and they are not this step's fields. The socket is what moves them.
//! A claim does not.
//!
//! # Claimed
//!
//! `m_last_known_hash`, `support_flags`, and the handshake's advertised
//! address. The peer asserted them. `Claimed<T>` is the type so a reader
//! cannot treat one as a measurement. Sync may use a claim as a
//! hypothesis. Nothing that decides who stays connected may.
//!
//! A height the peer sent is claimed. A height raised from a block this
//! node accepted is observed chain length. The two do not share a
//! representation. The label that names which message wrote it stays on
//! the C++ context with the rest of the sync bookkeeping.
//!
//! # The one promotion
//!
//! The advertised address stays claimed. A re-dial that answers is a new
//! `Observed` endpoint, and it is outbound: an inbound socket is not a
//! dial this node placed. The observation does not write the claim. That
//! is the gray-to-white rule on this object: the claim and the
//! observation do not share a representation.
//!
//! # Local
//!
//! The sync driver's bookkeeping: `m_state`, the three lists this node
//! built, the request timers, `m_in_timedsync`, `sent_addresses`, and
//! `m_remote_height_source`. They stay on the C++ context until that
//! driver moves. This step does not copy them into a second store.
//!
//! # Not fields
//!
//! `m_ssl` is not a field. p2p SSL was deleted in #909. It comes back
//! only if that protocol does.
//!
//! `m_score` is not a field. §2.7.2: a score a peer can improve by what
//! it asserts is the self-selection trap. The C++ field stays where it
//! is; deleting it would change who gets dropped, and this step changes
//! no behavior. A later round may add a counter whose inputs are
//! measurements this node made — idle time, a check it ran — and not
//! the peer's claims. A claim is not that measurement.

use shekyl_onion_v3::v3_pubkey;
use shekyl_timing_engine::Tick;
use shekyl_transport_layer::{Direction, SocketId};

use crate::endpoint::Endpoint;

/// A value the peer asserted.
///
/// The read is [`Self::claim`]. There is no other way out, so a call
/// site cannot treat the value as a measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claimed<T> {
    value: T,
}

impl<T> Claimed<T> {
    /// `value` is what the peer said.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self { value }
    }

    /// What the peer asserted. Not a measurement.
    #[must_use]
    pub const fn claim(&self) -> &T {
        &self.value
    }
}

/// A value this node measured, fixed where it was constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observed<T> {
    value: T,
}

impl<T> Observed<T> {
    /// `value` is what this node measured.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self { value }
    }

    /// The measurement.
    #[must_use]
    pub const fn get(&self) -> &T {
        &self.value
    }
}

/// The address the handshake advertised.
///
/// This is not the endpoint the socket connected to. The connected
/// address is [`Endpoint`], observed at adoption.
///
/// A clearnet handshake carries a host the receiver does not keep: the
/// wire zeros it, and the port is combined with the host already
/// observed on the socket. Storing that host would make a reader treat
/// a discarded value as an address. An overlay handshake carries the
/// service the peer named, and that service is the claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvertisedEndpoint {
    /// The port the public-zone handshake named.
    Clearnet {
        /// The advertised port.
        port: u16,
    },
    /// The v3 service the overlay handshake named, and its port.
    Tor {
        /// The service key.
        key: [u8; 32],
        /// The advertised port.
        port: u16,
    },
}

impl AdvertisedEndpoint {
    /// `port` is the port the public-zone handshake named.
    #[must_use]
    pub const fn clearnet(port: u16) -> Self {
        Self::Clearnet { port }
    }

    /// The overlay service `host` names, or `None` when `host` is not a
    /// v3 onion.
    #[must_use]
    pub fn tor(host: &str, port: u16) -> Option<Self> {
        Some(Self::Tor {
            key: v3_pubkey(host)?,
            port,
        })
    }

    /// The advertised port.
    #[must_use]
    pub const fn port(self) -> u16 {
        match self {
            Self::Clearnet { port } | Self::Tor { port, .. } => port,
        }
    }
}

/// A re-dial that answered.
///
/// The claim is the handshake's advertisement. The observation is the
/// endpoint the re-dial connected to. Constructing this does not write
/// the claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Redial {
    claimed: Claimed<AdvertisedEndpoint>,
    observed: Observed<Endpoint>,
}

impl Redial {
    /// Hold the claim beside the endpoint the re-dial connected to.
    ///
    /// `None` when `observed` is inbound. A re-dial is a socket this
    /// node opened.
    #[must_use]
    pub const fn new(claimed: Claimed<AdvertisedEndpoint>, observed: Endpoint) -> Option<Self> {
        if !matches!(observed.direction(), Direction::Outbound) {
            return None;
        }
        Some(Self {
            claimed,
            observed: Observed::new(observed),
        })
    }

    /// The handshake's advertisement, unchanged.
    #[must_use]
    pub const fn claimed(&self) -> &Claimed<AdvertisedEndpoint> {
        &self.claimed
    }

    /// The endpoint the re-dial connected to.
    #[must_use]
    pub const fn observed(&self) -> &Observed<Endpoint> {
        &self.observed
    }
}

/// A recorded chain length, with the provenance of the write.
///
/// A height the peer sent is a claim. The chain length of a block this
/// node accepted is a measurement. The message label
/// (`remote_height_source`) stays on the C++ context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteHeight {
    /// The peer asserted this height.
    Claim(Claimed<u64>),
    /// Chain length of a block this node accepted.
    AcceptedBlock(Observed<u64>),
}

/// One adopted session.
///
/// The endpoint and the start time are write-once. Claims are recorded
/// later and do not replace the endpoint. There is no score and no SSL
/// flag: those are not fields of this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connection {
    id: SocketId,
    endpoint: Observed<Endpoint>,
    started: Tick,
    remote_height: Option<RemoteHeight>,
    last_known_hash: Option<Claimed<[u8; 32]>>,
    support_flags: Option<Claimed<u32>>,
    advertised: Option<Claimed<AdvertisedEndpoint>>,
}

impl Connection {
    /// The identity observed at adoption.
    #[must_use]
    pub const fn open(id: SocketId, endpoint: Endpoint, started: Tick) -> Self {
        Self {
            id,
            endpoint: Observed::new(endpoint),
            started,
            remote_height: None,
            last_known_hash: None,
            support_flags: None,
            advertised: None,
        }
    }

    /// The admission id.
    #[must_use]
    pub const fn id(self) -> SocketId {
        self.id
    }

    /// The endpoint observed at adoption.
    #[must_use]
    pub const fn endpoint(&self) -> &Observed<Endpoint> {
        &self.endpoint
    }

    /// When the row was adopted.
    #[must_use]
    pub const fn started(self) -> Tick {
        self.started
    }

    /// The recorded height, claimed or observed.
    #[must_use]
    pub const fn remote_height(&self) -> Option<&RemoteHeight> {
        self.remote_height.as_ref()
    }

    /// Record a height the peer sent. A later claim replaces an earlier
    /// one, including one raised from an accepted block. The endpoint
    /// stays.
    pub fn note_claimed_height(&mut self, height: u64) {
        self.remote_height = Some(RemoteHeight::Claim(Claimed::new(height)));
    }

    /// Raise the recorded chain length from a block this node accepted.
    ///
    /// A delivered block never lowers the record. A later claim still
    /// replaces it, through [`Self::note_claimed_height`].
    pub fn raise_from_accepted_block(&mut self, chain_length: u64) {
        if chain_length <= self.recorded_height() {
            return;
        }
        self.remote_height = Some(RemoteHeight::AcceptedBlock(Observed::new(chain_length)));
    }

    fn recorded_height(&self) -> u64 {
        match &self.remote_height {
            Some(RemoteHeight::Claim(height)) => *height.claim(),
            Some(RemoteHeight::AcceptedBlock(height)) => *height.get(),
            None => 0,
        }
    }

    /// The hash the peer asserted.
    #[must_use]
    pub const fn last_known_hash(&self) -> Option<&Claimed<[u8; 32]>> {
        self.last_known_hash.as_ref()
    }

    /// Record the hash the peer asserted. The endpoint stays.
    pub fn note_last_known_hash(&mut self, hash: [u8; 32]) {
        self.last_known_hash = Some(Claimed::new(hash));
    }

    /// The support flags the peer asserted.
    #[must_use]
    pub const fn support_flags(&self) -> Option<&Claimed<u32>> {
        self.support_flags.as_ref()
    }

    /// Record the support flags the peer asserted. The endpoint stays.
    pub fn note_support_flags(&mut self, flags: u32) {
        self.support_flags = Some(Claimed::new(flags));
    }

    /// The endpoint the handshake advertised.
    #[must_use]
    pub const fn advertised(&self) -> Option<&Claimed<AdvertisedEndpoint>> {
        self.advertised.as_ref()
    }

    /// Record the advertised port. It does not replace the observed endpoint.
    pub fn note_advertised(&mut self, advertised: AdvertisedEndpoint) {
        self.advertised = Some(Claimed::new(advertised));
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use shekyl_transport_layer::{Direction, SocketId};

    use super::*;

    fn endpoint(port: u16) -> Endpoint {
        Endpoint::Clearnet {
            ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            port,
            direction: Direction::Outbound,
        }
    }

    #[test]
    fn adoption_fixes_the_endpoint() {
        let id = SocketId::from_ffi(1).expect("id");
        let started = Tick::new(9);
        let mut connection = Connection::open(id, endpoint(18080), started);
        connection.note_advertised(AdvertisedEndpoint::clearnet(22021));
        connection.note_claimed_height(4);
        connection.note_last_known_hash([9; 32]);
        connection.note_support_flags(7);
        assert_eq!(
            connection.endpoint().get().clearnet_ip(),
            endpoint(18080).clearnet_ip()
        );
        assert_eq!(connection.id(), id);
        assert_eq!(connection.started(), started);
        assert_eq!(
            connection.advertised().expect("claim").claim().port(),
            22021
        );
        assert_eq!(
            connection.remote_height().expect("height"),
            &RemoteHeight::Claim(Claimed::new(4))
        );
        assert_eq!(
            *connection.last_known_hash().expect("hash").claim(),
            [9; 32]
        );
        assert_eq!(*connection.support_flags().expect("flags").claim(), 7);
    }

    #[test]
    fn a_redial_keeps_the_claim() {
        let claimed = Claimed::new(AdvertisedEndpoint::clearnet(22021));
        let redial = Redial::new(claimed, endpoint(18080)).expect("outbound");
        assert_eq!(redial.claimed().claim().port(), 22021);
        let port = match *redial.observed().get() {
            Endpoint::Clearnet { port, .. } => port,
            Endpoint::TorInbound | Endpoint::Tor { .. } => unreachable!("clearnet dial"),
        };
        assert_eq!(port, 18080);
        assert_eq!(claimed.claim().port(), 22021);
    }

    #[test]
    fn an_overlay_claim_keeps_the_service() {
        let key = [0x11u8; 32];
        let host = shekyl_onion_v3::v3_onion_hostname(&key);
        let advertised = AdvertisedEndpoint::tor(&host, 18081).expect("v3");
        assert_eq!(advertised, AdvertisedEndpoint::Tor { key, port: 18081 });
        assert!(AdvertisedEndpoint::tor("not-an-onion", 1).is_none());
    }

    #[test]
    fn a_redial_refuses_an_inbound_socket() {
        let claimed = Claimed::new(AdvertisedEndpoint::clearnet(18080));
        assert!(Redial::new(claimed, Endpoint::TorInbound).is_none());
    }

    #[test]
    fn an_accepted_block_raises_and_a_claim_replaces() {
        let id = SocketId::from_ffi(1).expect("id");
        let mut connection = Connection::open(id, endpoint(18080), Tick::new(1));
        connection.raise_from_accepted_block(4);
        connection.raise_from_accepted_block(3);
        assert_eq!(
            connection.remote_height().expect("height"),
            &RemoteHeight::AcceptedBlock(Observed::new(4))
        );
        connection.note_claimed_height(2);
        assert_eq!(
            connection.remote_height().expect("height"),
            &RemoteHeight::Claim(Claimed::new(2))
        );
    }
}
