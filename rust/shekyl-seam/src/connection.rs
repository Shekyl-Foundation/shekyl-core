// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One adopted session.
//!
//! The hub row is this value. Adoption fixes the id, the endpoint, and
//! the start time. A later claim does not replace that endpoint.
//!
//! A fact the peer asserted is [`Claimed`]. A chain length this node
//! measured is [`ChainLength`]. They are different fields. A claim does
//! not erase a measurement, and a delivered block does not lower the
//! length.
//!
//! The handshake's advertisement is not the connected address. Clearnet
//! keeps the port: the wire zeros the host. An overlay keeps the v3
//! service. Port 0 is not a port. A re-dial is a new outbound session,
//! admitted only when that observation is the advertisement. The claim
//! stays on the origin.

use std::num::NonZeroU16;

use shekyl_onion_v3::v3_pubkey;
use shekyl_timing_engine::Tick;
use shekyl_transport_layer::{Direction, SocketId};

use crate::endpoint::Endpoint;

/// A value the peer asserted.
///
/// [`Self::claim`] is the only read.
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

    /// What the peer asserted.
    #[must_use]
    pub const fn claim(&self) -> &T {
        &self.value
    }
}

/// Which message carried a height the peer asserted.
///
/// The label is this node's. The number is the peer's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeightMessage {
    /// The handshake's current height.
    Handshake,
    /// A timed sync.
    TimedSync,
    /// A get-objects reply.
    GetObjects,
    /// A chain entry.
    ChainEntry,
}

/// A height the peer asserted, and the message that carried it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeightClaim {
    height: u64,
    message: HeightMessage,
}

impl HeightClaim {
    /// The height the peer asserted.
    #[must_use]
    pub const fn height(self) -> u64 {
        self.height
    }

    /// The message that carried [`Self::height`].
    #[must_use]
    pub const fn message(self) -> HeightMessage {
        self.message
    }
}

/// Chain length of a block this node accepted.
///
/// The length is one past the coinbase height. A coinbase height with no
/// successor is not a length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChainLength(u64);

impl ChainLength {
    /// `coinbase_height` is the height written in the block.
    #[must_use]
    pub const fn from_coinbase_height(coinbase_height: u64) -> Option<Self> {
        match coinbase_height.checked_add(1) {
            Some(length) => Some(Self(length)),
            None => None,
        }
    }

    /// The length.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The address the handshake advertised.
///
/// This is not the endpoint the socket connected to. The connected
/// address is [`Endpoint`], fixed at adoption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvertisedEndpoint {
    /// The port the public-zone handshake named.
    Clearnet {
        /// The advertised port. Never zero.
        port: NonZeroU16,
    },
    /// The v3 service the overlay handshake named, and its port.
    Tor {
        /// The service key.
        key: [u8; 32],
        /// The advertised port. Never zero.
        port: NonZeroU16,
    },
}

impl AdvertisedEndpoint {
    /// `port` is the port the public-zone handshake named.
    ///
    /// `None` when `port` is zero.
    #[must_use]
    pub const fn clearnet(port: u16) -> Option<Self> {
        match NonZeroU16::new(port) {
            Some(port) => Some(Self::Clearnet { port }),
            None => None,
        }
    }

    /// The overlay service `host` names.
    ///
    /// `None` when `host` is not a v3 onion, or when `port` is zero.
    #[must_use]
    pub fn tor(host: &str, port: u16) -> Option<Self> {
        let port = NonZeroU16::new(port)?;
        Some(Self::Tor {
            key: v3_pubkey(host)?,
            port,
        })
    }

    /// The advertised port.
    #[must_use]
    pub const fn port(self) -> NonZeroU16 {
        match self {
            Self::Clearnet { port } | Self::Tor { port, .. } => port,
        }
    }
}

/// Why [`crate::Hub::adopt_redial`] did not admit the new socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedialRefusal {
    /// The origin is gone, closed, or has no advertisement this observation matches.
    NotThisClaim,
    /// The new admission id is already a row.
    AlreadyAdmitted,
}

/// A re-dial that observed the origin's advertisement.
///
/// The claim stays the origin's. [`Self::session`] is the new outbound
/// session, and its endpoint is the observation. Constructing this does
/// not write the claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redial {
    origin: SocketId,
    claim: Claimed<AdvertisedEndpoint>,
    session: Connection,
}

impl Redial {
    /// The session whose advertisement was dialed.
    #[must_use]
    pub const fn origin(&self) -> SocketId {
        self.origin
    }

    /// The handshake's advertisement, unchanged.
    #[must_use]
    pub const fn claim(&self) -> &Claimed<AdvertisedEndpoint> {
        &self.claim
    }

    /// The outbound session the dial observed.
    #[must_use]
    pub const fn session(&self) -> &Connection {
        &self.session
    }

    /// The outbound session, for the hub to store.
    #[must_use]
    pub fn into_session(self) -> Connection {
        self.session
    }
}

/// One adopted session.
///
/// Not [`Copy`]: recording on a clone does not record on the hub row.
/// The hub writes the row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connection {
    id: SocketId,
    endpoint: Endpoint,
    started: Tick,
    claimed_height: Option<HeightClaim>,
    accepted_chain_length: Option<ChainLength>,
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
            endpoint,
            started,
            claimed_height: None,
            accepted_chain_length: None,
            last_known_hash: None,
            support_flags: None,
            advertised: None,
        }
    }

    /// The admission id.
    #[must_use]
    pub const fn id(&self) -> SocketId {
        self.id
    }

    /// The endpoint observed at adoption.
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// When the row was adopted.
    #[must_use]
    pub const fn started(&self) -> Tick {
        self.started
    }

    /// The height the peer asserted, if any message has.
    #[must_use]
    pub const fn claimed_height(&self) -> Option<HeightClaim> {
        self.claimed_height
    }

    /// Record a height the peer sent.
    ///
    /// A later claim replaces an earlier claim. The accepted chain length
    /// stays.
    pub(crate) fn note_claimed_height(&mut self, height: u64, message: HeightMessage) {
        self.claimed_height = Some(HeightClaim { height, message });
    }

    /// The chain length of a block this node accepted, if one has been raised.
    #[must_use]
    pub const fn accepted_chain_length(&self) -> Option<ChainLength> {
        self.accepted_chain_length
    }

    /// Raise the accepted chain length.
    ///
    /// A shorter length does not replace a longer one. The claimed height
    /// stays.
    pub(crate) fn raise_accepted_chain_length(&mut self, length: ChainLength) {
        if self
            .accepted_chain_length
            .is_some_and(|have| length.get() <= have.get())
        {
            return;
        }
        self.accepted_chain_length = Some(length);
    }

    /// The hash the peer asserted.
    #[must_use]
    pub const fn last_known_hash(&self) -> Option<&Claimed<[u8; 32]>> {
        self.last_known_hash.as_ref()
    }

    /// Record the hash the peer asserted.
    pub(crate) fn note_last_known_hash(&mut self, hash: [u8; 32]) {
        self.last_known_hash = Some(Claimed::new(hash));
    }

    /// The support flags the peer asserted.
    #[must_use]
    pub const fn support_flags(&self) -> Option<&Claimed<u32>> {
        self.support_flags.as_ref()
    }

    /// Record the support flags the peer asserted.
    pub(crate) fn note_support_flags(&mut self, flags: u32) {
        self.support_flags = Some(Claimed::new(flags));
    }

    /// The endpoint the handshake advertised.
    #[must_use]
    pub const fn advertised(&self) -> Option<&Claimed<AdvertisedEndpoint>> {
        self.advertised.as_ref()
    }

    /// Record the advertised endpoint. The observed endpoint stays.
    pub(crate) fn note_advertised(&mut self, advertised: AdvertisedEndpoint) {
        self.advertised = Some(Claimed::new(advertised));
    }

    /// The outbound session a dial of this advertisement observed.
    ///
    /// `None` when this session has no advertisement, or `observed` is not
    /// that advertisement. A clearnet dial uses this session's observed
    /// host and the claimed port. An overlay dial is that v3 key and port.
    /// This session is not modified.
    #[must_use]
    pub fn redial(&self, id: SocketId, observed: Endpoint, started: Tick) -> Option<Redial> {
        let claim = *self.advertised()?;
        if !observes(self.endpoint(), claim.claim(), &observed) {
            return None;
        }
        Some(Redial {
            origin: self.id,
            claim,
            session: Self::open(id, observed, started),
        })
    }
}

/// `observed` is a dial of `claim` from `origin`.
fn observes(origin: &Endpoint, claim: &AdvertisedEndpoint, observed: &Endpoint) -> bool {
    match (claim, origin, observed) {
        (
            AdvertisedEndpoint::Clearnet { port },
            Endpoint::Clearnet { ip: origin_ip, .. },
            Endpoint::Clearnet {
                ip,
                port: observed_port,
                direction: Direction::Outbound,
            },
        ) => ip == origin_ip && *observed_port == port.get(),
        (
            AdvertisedEndpoint::Tor { key, port },
            _,
            Endpoint::Tor {
                key: observed_key,
                port: observed_port,
            },
        ) => observed_key == key && *observed_port == port.get(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use shekyl_transport_layer::{Direction, SocketId};

    use super::*;

    fn endpoint(port: u16, direction: Direction) -> Endpoint {
        Endpoint::Clearnet {
            ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            port,
            direction,
        }
    }

    fn open() -> Connection {
        Connection::open(
            SocketId::from_ffi(1).expect("id"),
            endpoint(18080, Direction::Inbound),
            Tick::new(9),
        )
    }

    #[test]
    fn adoption_fixes_the_endpoint() {
        let mut connection = open();
        let advertised = AdvertisedEndpoint::clearnet(22021).expect("port");
        connection.note_advertised(advertised);
        connection.note_claimed_height(4, HeightMessage::Handshake);
        connection.note_last_known_hash([9; 32]);
        connection.note_support_flags(7);
        assert_eq!(connection.endpoint(), &endpoint(18080, Direction::Inbound));
        assert_eq!(
            connection.advertised().expect("claim").claim().port().get(),
            22021
        );
        let height = connection.claimed_height().expect("height");
        assert_eq!(height.height(), 4);
        assert_eq!(height.message(), HeightMessage::Handshake);
        assert_eq!(
            *connection.last_known_hash().expect("hash").claim(),
            [9; 32]
        );
        assert_eq!(*connection.support_flags().expect("flags").claim(), 7);
    }

    #[test]
    fn a_claim_does_not_erase_an_accepted_length() {
        let mut connection = open();
        let four = ChainLength::from_coinbase_height(3).expect("length");
        let three = ChainLength::from_coinbase_height(2).expect("length");
        let five = ChainLength::from_coinbase_height(4).expect("length");
        assert_eq!(four.get(), 4);
        assert!(ChainLength::from_coinbase_height(u64::MAX).is_none());
        connection.raise_accepted_chain_length(four);
        connection.raise_accepted_chain_length(three);
        connection.note_claimed_height(2, HeightMessage::TimedSync);
        assert_eq!(connection.accepted_chain_length(), Some(four));
        assert_eq!(
            connection.claimed_height().expect("claim").message(),
            HeightMessage::TimedSync
        );
        connection.raise_accepted_chain_length(five);
        assert_eq!(connection.accepted_chain_length(), Some(five));
        assert_eq!(connection.claimed_height().expect("claim").height(), 2);
    }

    #[test]
    fn a_zero_port_is_not_an_advertisement() {
        assert!(AdvertisedEndpoint::clearnet(0).is_none());
        let key = [0x11u8; 32];
        let host = shekyl_onion_v3::v3_onion_hostname(&key);
        assert!(AdvertisedEndpoint::tor(&host, 0).is_none());
        assert!(AdvertisedEndpoint::tor("not-an-onion", 1).is_none());
    }

    #[test]
    fn a_redial_observes_the_claim_and_leaves_the_origin() {
        let mut origin = open();
        let before = origin.clone();
        let advertised = AdvertisedEndpoint::clearnet(22021).expect("port");
        origin.note_advertised(advertised);
        let observed = endpoint(22021, Direction::Outbound);
        let redial = origin
            .redial(SocketId::from_ffi(2).expect("id"), observed, Tick::new(11))
            .expect("dial");
        assert_eq!(redial.origin(), origin.id());
        assert_eq!(redial.claim().claim(), &advertised);
        assert_eq!(redial.session().endpoint(), &observed);
        assert!(redial.session().advertised().is_none());
        assert_eq!(origin.endpoint(), before.endpoint());
        assert_eq!(origin.advertised().expect("claim").claim(), &advertised);
        assert!(origin
            .redial(
                SocketId::from_ffi(3).expect("id"),
                endpoint(18080, Direction::Outbound),
                Tick::new(11),
            )
            .is_none());
        assert!(origin
            .redial(
                SocketId::from_ffi(3).expect("id"),
                endpoint(22021, Direction::Inbound),
                Tick::new(11),
            )
            .is_none());
        let other_host = Endpoint::Clearnet {
            ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)),
            port: 22021,
            direction: Direction::Outbound,
        };
        assert!(origin
            .redial(
                SocketId::from_ffi(3).expect("id"),
                other_host,
                Tick::new(11)
            )
            .is_none());
    }

    #[test]
    fn an_overlay_redial_keeps_the_service() {
        let key = [0x11u8; 32];
        let host = shekyl_onion_v3::v3_onion_hostname(&key);
        let advertised = AdvertisedEndpoint::tor(&host, 18081).expect("v3");
        let mut origin = open();
        origin.note_advertised(advertised);
        let observed = Endpoint::Tor { key, port: 18081 };
        let redial = origin
            .redial(SocketId::from_ffi(4).expect("id"), observed, Tick::new(1))
            .expect("dial");
        assert_eq!(redial.session().endpoint(), &observed);
        assert!(origin
            .redial(
                SocketId::from_ffi(5).expect("id"),
                Endpoint::Tor {
                    key: [0x22; 32],
                    port: 18081,
                },
                Tick::new(1),
            )
            .is_none());
        assert!(origin
            .redial(
                SocketId::from_ffi(5).expect("id"),
                Endpoint::TorInbound,
                Tick::new(1),
            )
            .is_none());
    }
}
