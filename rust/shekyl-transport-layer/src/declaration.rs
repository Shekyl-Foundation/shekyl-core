// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! D7. Each connector declares what its network provides. A cell nobody
//! has assessed reads "not assessed". It does not inherit another network's
//! answer.

use crate::address::PeerAddress;

/// A connector that is built. I2P is a column in the table and is not
/// one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectorId {
    /// Clearnet.
    Clearnet,
    /// Tor.
    Tor,
}

/// A column of the declaration table, including the column that has no
/// connector yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkColumn {
    /// Clearnet.
    Clearnet,
    /// Tor.
    Tor,
    /// Present so a third network has a shape. No connector is built.
    I2p,
}

/// An assessed value, or a cell nobody has assessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Assessment<T> {
    /// Someone has written down what this network does.
    Assessed(T),
    /// Nobody has assessed this cell.
    NotAssessed,
}

/// The words a cell reads as.
pub trait CellText {
    /// The cell's text. "not assessed" is [`Assessment::NotAssessed`], not
    /// a value of this trait.
    fn cell_text(self) -> &'static str;
}

impl<T: CellText> Assessment<T> {
    /// What the cell reads as.
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Self::NotAssessed => "not assessed",
            Self::Assessed(value) => value.cell_text(),
        }
    }
}

/// How peers are named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Addressing {
    /// IPv4 or IPv6, plus a port.
    Ip,
    /// Onion v3. The connector dials those hostnames only.
    OnionV3,
    /// A `.b32.i2p` host.
    B32I2p,
}

impl CellText for Addressing {
    fn cell_text(self) -> &'static str {
        match self {
            Self::Ip => "ipv4/ipv6",
            Self::OnionV3 => "onion v3",
            Self::B32I2p => "b32.i2p",
        }
    }
}

/// Encryption of the byte stream against the network observer. Native to
/// the network. A layer added on top is not this cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeEncryption {
    /// Nothing native. The Noise layer is added because of this cell.
    NoneNative,
    /// End to end to the peer's onion service, classical only.
    Classical,
}

impl CellText for NativeEncryption {
    fn cell_text(self) -> &'static str {
        match self {
            Self::NoneNative => "none native",
            Self::Classical => "native, classical only",
        }
    }
}

/// Whether the destination is authenticated to the dialer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestinationAuth {
    /// Noise NN does not authenticate the peer.
    No,
    /// An onion address is the service's public key, one way.
    OneWay,
}

impl CellText for DestinationAuth {
    fn cell_text(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::OneWay => "one way",
        }
    }
}

/// A yes or no that has been assessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YesNo {
    /// The property holds.
    Yes,
    /// The property does not hold.
    No,
}

impl CellText for YesNo {
    fn cell_text(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
        }
    }
}

/// Correlation, or the origin of a relayed transaction. The assessed
/// answer on the networks where it has been written down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotProvided;

impl CellText for NotProvided {
    fn cell_text(self) -> &'static str {
        "not provided"
    }
}

/// What an observer at this node's end can see of the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalVisibility {
    /// The connection's existence, timing, volume, and sizes.
    Visible,
    /// The same facts, as Tor traffic.
    VisibleAsTor,
}

impl CellText for LocalVisibility {
    fn cell_text(self) -> &'static str {
        match self {
            Self::Visible => "visible",
            Self::VisibleAsTor => "visible as tor traffic",
        }
    }
}

/// Whether an inbound peer has an address a ban can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BannableInbound {
    /// The socket address.
    Yes,
    /// This zone, no address.
    NoAddress,
}

impl CellText for BannableInbound {
    fn cell_text(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::NoAddress => "no address",
        }
    }
}

/// What a connection is a stream of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamKind {
    /// TCP.
    Tcp,
    /// A Tor stream.
    Tor,
}

impl CellText for StreamKind {
    fn cell_text(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Tor => "tor stream",
        }
    }
}

/// The observed identity of an inbound peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundIdentity {
    /// The socket address.
    SocketAddress,
    /// This zone, no address.
    ZoneNoAddress,
}

impl CellText for InboundIdentity {
    fn cell_text(self) -> &'static str {
        match self {
            Self::SocketAddress => "socket address",
            Self::ZoneNoAddress => "zone, no address",
        }
    }
}

/// Where a connector's deadlines come from. No duration is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeadlineInput {
    /// Measured on that connector. The number is not written yet.
    MeasuredPerConnector,
    /// There is no connector to measure.
    WhenAConnectorExists,
}

impl CellText for DeadlineInput {
    fn cell_text(self) -> &'static str {
        match self {
            Self::MeasuredPerConnector => "measured per connector",
            Self::WhenAConnectorExists => "when a connector exists",
        }
    }
}

/// Rendezvous arrival priced by onion-service proof of work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rendezvous {
    /// Clearnet has no rendezvous.
    NotApplicable,
    /// Enabled. Flood resistance is a separate cell.
    Enabled,
}

impl CellText for Rendezvous {
    fn cell_text(self) -> &'static str {
        match self {
            Self::NotApplicable => "not applicable",
            Self::Enabled => "enabled",
        }
    }
}

/// Flood resistance of streams inside an established circuit. The only
/// value today is that nobody has assessed it. A result from the Tor
/// flood test is what would add another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloodResistance {
    /// The Tor flood test has not been run.
    NotAssessed,
}

impl FloodResistance {
    /// What the cell reads as.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::NotAssessed => "not assessed",
        }
    }
}

/// One column of the D7 table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Declaration {
    addressing: Assessment<Addressing>,
    encryption: Assessment<NativeEncryption>,
    destination_authenticated: Assessment<DestinationAuth>,
    address_hidden_from_peer: Assessment<YesNo>,
    destination_hidden_from_local_observer: Assessment<YesNo>,
    address_hidden_from_remote_observer: Assessment<YesNo>,
    correlation: Assessment<NotProvided>,
    local_observer_visibility: Assessment<LocalVisibility>,
    relay_origin: Assessment<NotProvided>,
    bannable_inbound: Assessment<BannableInbound>,
    stream: Assessment<StreamKind>,
    inbound_identity: Assessment<InboundIdentity>,
    deadline_inputs: Assessment<DeadlineInput>,
    rendezvous: Assessment<Rendezvous>,
    flood_resistance: Option<FloodResistance>,
}

impl Declaration {
    /// Addressing.
    #[must_use]
    pub const fn addressing(self) -> Assessment<Addressing> {
        self.addressing
    }
    /// Native encryption against the network observer.
    #[must_use]
    pub const fn encryption(self) -> Assessment<NativeEncryption> {
        self.encryption
    }
    /// Destination authenticated to the dialer.
    #[must_use]
    pub const fn destination_authenticated(self) -> Assessment<DestinationAuth> {
        self.destination_authenticated
    }
    /// This node's address hidden from the peer.
    #[must_use]
    pub const fn address_hidden_from_peer(self) -> Assessment<YesNo> {
        self.address_hidden_from_peer
    }
    /// Destination hidden from an observer at this node's end.
    #[must_use]
    pub const fn destination_hidden_from_local_observer(self) -> Assessment<YesNo> {
        self.destination_hidden_from_local_observer
    }
    /// This node's address hidden from an observer at the peer's end.
    #[must_use]
    pub const fn address_hidden_from_remote_observer(self) -> Assessment<YesNo> {
        self.address_hidden_from_remote_observer
    }
    /// Correlation by an observer at both ends.
    #[must_use]
    pub const fn correlation(self) -> Assessment<NotProvided> {
        self.correlation
    }
    /// Connection existence, timing, volume, and sizes at this node's end.
    #[must_use]
    pub const fn local_observer_visibility(self) -> Assessment<LocalVisibility> {
        self.local_observer_visibility
    }
    /// Origin of relayed transactions, against peers.
    #[must_use]
    pub const fn relay_origin(self) -> Assessment<NotProvided> {
        self.relay_origin
    }
    /// Whether an inbound peer has a bannable address.
    #[must_use]
    pub const fn bannable_inbound(self) -> Assessment<BannableInbound> {
        self.bannable_inbound
    }
    /// Stream semantics.
    #[must_use]
    pub const fn stream(self) -> Assessment<StreamKind> {
        self.stream
    }
    /// Observed identity of an inbound peer.
    #[must_use]
    pub const fn inbound_identity(self) -> Assessment<InboundIdentity> {
        self.inbound_identity
    }
    /// Deadline inputs. No duration.
    #[must_use]
    pub const fn deadline_inputs(self) -> Assessment<DeadlineInput> {
        self.deadline_inputs
    }
    /// Rendezvous arrival priced by proof of work.
    #[must_use]
    pub const fn rendezvous(self) -> Assessment<Rendezvous> {
        self.rendezvous
    }
    /// Flood resistance, when this column has that residual.
    #[must_use]
    pub const fn flood_resistance(self) -> Option<FloodResistance> {
        self.flood_resistance
    }

    /// Every cell's text, including the flood residual when this column has one.
    #[must_use]
    pub fn texts(self) -> Vec<&'static str> {
        let mut out = vec![
            self.addressing.text(),
            self.encryption.text(),
            self.destination_authenticated.text(),
            self.address_hidden_from_peer.text(),
            self.destination_hidden_from_local_observer.text(),
            self.address_hidden_from_remote_observer.text(),
            self.correlation.text(),
            self.local_observer_visibility.text(),
            self.relay_origin.text(),
            self.bannable_inbound.text(),
            self.stream.text(),
            self.inbound_identity.text(),
            self.deadline_inputs.text(),
            self.rendezvous.text(),
        ];
        if let Some(flood) = self.flood_resistance {
            out.push(flood.text());
        }
        out
    }
}

/// The column for `which`.
#[must_use]
pub const fn declaration(which: NetworkColumn) -> Declaration {
    match which {
        NetworkColumn::Clearnet => Declaration {
            addressing: Assessment::Assessed(Addressing::Ip),
            encryption: Assessment::Assessed(NativeEncryption::NoneNative),
            destination_authenticated: Assessment::Assessed(DestinationAuth::No),
            address_hidden_from_peer: Assessment::Assessed(YesNo::No),
            destination_hidden_from_local_observer: Assessment::Assessed(YesNo::No),
            address_hidden_from_remote_observer: Assessment::Assessed(YesNo::No),
            correlation: Assessment::Assessed(NotProvided),
            local_observer_visibility: Assessment::Assessed(LocalVisibility::Visible),
            relay_origin: Assessment::Assessed(NotProvided),
            bannable_inbound: Assessment::Assessed(BannableInbound::Yes),
            stream: Assessment::Assessed(StreamKind::Tcp),
            inbound_identity: Assessment::Assessed(InboundIdentity::SocketAddress),
            deadline_inputs: Assessment::Assessed(DeadlineInput::MeasuredPerConnector),
            rendezvous: Assessment::Assessed(Rendezvous::NotApplicable),
            flood_resistance: None,
        },
        NetworkColumn::Tor => Declaration {
            addressing: Assessment::Assessed(Addressing::OnionV3),
            encryption: Assessment::Assessed(NativeEncryption::Classical),
            destination_authenticated: Assessment::Assessed(DestinationAuth::OneWay),
            address_hidden_from_peer: Assessment::Assessed(YesNo::Yes),
            destination_hidden_from_local_observer: Assessment::Assessed(YesNo::Yes),
            address_hidden_from_remote_observer: Assessment::Assessed(YesNo::Yes),
            correlation: Assessment::Assessed(NotProvided),
            local_observer_visibility: Assessment::Assessed(LocalVisibility::VisibleAsTor),
            relay_origin: Assessment::Assessed(NotProvided),
            bannable_inbound: Assessment::Assessed(BannableInbound::NoAddress),
            stream: Assessment::Assessed(StreamKind::Tor),
            inbound_identity: Assessment::Assessed(InboundIdentity::ZoneNoAddress),
            deadline_inputs: Assessment::Assessed(DeadlineInput::MeasuredPerConnector),
            rendezvous: Assessment::Assessed(Rendezvous::Enabled),
            flood_resistance: Some(FloodResistance::NotAssessed),
        },
        NetworkColumn::I2p => Declaration {
            addressing: Assessment::Assessed(Addressing::B32I2p),
            encryption: Assessment::NotAssessed,
            destination_authenticated: Assessment::NotAssessed,
            address_hidden_from_peer: Assessment::NotAssessed,
            destination_hidden_from_local_observer: Assessment::NotAssessed,
            address_hidden_from_remote_observer: Assessment::NotAssessed,
            correlation: Assessment::NotAssessed,
            local_observer_visibility: Assessment::NotAssessed,
            relay_origin: Assessment::Assessed(NotProvided),
            bannable_inbound: Assessment::NotAssessed,
            stream: Assessment::NotAssessed,
            inbound_identity: Assessment::NotAssessed,
            deadline_inputs: Assessment::Assessed(DeadlineInput::WhenAConnectorExists),
            rendezvous: Assessment::NotAssessed,
            flood_resistance: None,
        },
    }
}

/// The connector an address selects. I2P selects none.
#[must_use]
pub const fn connector_for(address: &PeerAddress) -> Option<ConnectorId> {
    match address {
        PeerAddress::Ipv4 { .. } | PeerAddress::Ipv6 { .. } => Some(ConnectorId::Clearnet),
        PeerAddress::Tor { .. } => Some(ConnectorId::Tor),
        PeerAddress::I2p { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        connector_for, declaration, Assessment, BannableInbound, ConnectorId, DeadlineInput,
        FloodResistance, NativeEncryption, NetworkColumn, NotProvided, Rendezvous,
    };
    use crate::address::PeerAddress;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn an_unassessed_cell_reads_not_assessed() {
        let i2p = declaration(NetworkColumn::I2p);
        assert_eq!(i2p.encryption().text(), "not assessed");
        assert_eq!(
            i2p.texts()
                .iter()
                .filter(|text| **text == "not assessed")
                .count(),
            11
        );
        let tor = declaration(NetworkColumn::Tor);
        assert_eq!(tor.flood_resistance(), Some(FloodResistance::NotAssessed));
        assert_eq!(
            tor.texts()
                .iter()
                .filter(|text| **text == "not assessed")
                .count(),
            1
        );
        assert_eq!(
            declaration(NetworkColumn::Clearnet)
                .texts()
                .iter()
                .filter(|text| **text == "not assessed")
                .count(),
            0
        );
    }

    #[test]
    fn no_cell_uses_a_reputation_word() {
        for column in [
            NetworkColumn::Clearnet,
            NetworkColumn::Tor,
            NetworkColumn::I2p,
        ] {
            for text in declaration(column).texts() {
                let lower = text.to_ascii_lowercase();
                assert!(!lower.contains("protected"), "{text}");
                assert!(!lower.contains("secure"), "{text}");
                assert!(!lower.contains("anonymous"), "{text}");
            }
        }
    }

    #[test]
    fn the_assessed_clearnet_and_tor_cells_match_the_table() {
        let clearnet = declaration(NetworkColumn::Clearnet);
        assert_eq!(
            clearnet.encryption(),
            Assessment::Assessed(NativeEncryption::NoneNative)
        );
        assert_eq!(
            clearnet.bannable_inbound(),
            Assessment::Assessed(BannableInbound::Yes)
        );
        assert_eq!(
            clearnet.rendezvous(),
            Assessment::Assessed(Rendezvous::NotApplicable)
        );
        assert_eq!(clearnet.relay_origin(), Assessment::Assessed(NotProvided));
        let tor = declaration(NetworkColumn::Tor);
        assert_eq!(
            tor.bannable_inbound(),
            Assessment::Assessed(BannableInbound::NoAddress)
        );
        assert_eq!(tor.rendezvous(), Assessment::Assessed(Rendezvous::Enabled));
        let i2p = declaration(NetworkColumn::I2p);
        assert_eq!(i2p.relay_origin(), Assessment::Assessed(NotProvided));
        assert_eq!(
            i2p.deadline_inputs(),
            Assessment::Assessed(DeadlineInput::WhenAConnectorExists)
        );
    }

    #[test]
    fn the_address_type_selects_one_connector() {
        assert_eq!(
            connector_for(&PeerAddress::Ipv4 {
                ip: Ipv4Addr::LOCALHOST,
                port: 18080,
            }),
            Some(ConnectorId::Clearnet)
        );
        assert_eq!(
            connector_for(&PeerAddress::Ipv6 {
                ip: Ipv6Addr::LOCALHOST,
                port: 18080,
            }),
            Some(ConnectorId::Clearnet)
        );
        assert_eq!(
            connector_for(&PeerAddress::Tor {
                host: "example.onion".to_owned(),
                port: 18080,
            }),
            Some(ConnectorId::Tor)
        );
        assert_eq!(
            connector_for(&PeerAddress::I2p {
                host: "example.b32.i2p".to_owned(),
                port: 0,
            }),
            None
        );
    }
}
