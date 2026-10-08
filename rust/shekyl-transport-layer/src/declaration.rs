// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! D7. Each connector declares what its network provides. A cell nobody
//! has assessed reads "not assessed". It does not inherit another network's
//! answer.
//!
//! [`connector_for`] reads the addressing cell, so two connectors cannot
//! claim one family. [`stack_plan`] reads the encryption cell: a network
//! with no native encryption gets the Noise layer, and the session above
//! that plan does not match on the connector.

use shekyl_net_address::NetworkAddress;
use shekyl_relay_privacy::verify_cost::{
    ADOPTED_TRANSIT_ASSUMPTION_MS, ANON_ZONE_TRANSIT_ASSUMPTION_MS,
};

/// A transit assumption that is a whole number of milliseconds.
///
/// The declaration stores `u32`. The assumption is `f64` because the
/// embargo math is. The assert is the cast being exact.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    clippy::float_cmp
)]
const fn whole_ms(ms: f64) -> u32 {
    let whole = ms as u32;
    assert!(ms == whole as f64);
    whole
}

/// A column of the declaration table, including the column that has no
/// connector yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkColumn {
    /// Clearnet.
    Clearnet,
    /// Tor.
    Tor,
}

macro_rules! connectors {
    (
        $(#[$enum_meta:meta])*
        enum ConnectorId {
            $($(#[$meta:meta])* $name:ident => $column:ident),+ $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[repr(u8)]
        pub enum ConnectorId {
            $($(#[$meta])* $name,)+
        }

        impl ConnectorId {
            /// Every built connector, in declaration order.
            ///
            /// The occupancy table and the process-wide inbound sum both
            /// walk this list. A connector that is not here is not counted.
            pub const ALL: &'static [Self] = &[$(Self::$name,)+];

            /// Rows in the occupancy table. One per connector.
            pub const COUNT: usize = Self::ALL.len();

            /// Index into the occupancy table. Dense from zero, in [`Self::ALL`] order.
            #[must_use]
            pub const fn index(self) -> usize {
                match self {
                    $(Self::$name => Self::$name as usize,)+
                }
            }

            /// The declaration column for this connector.
            #[must_use]
            pub const fn column(self) -> NetworkColumn {
                match self {
                    $(Self::$name => NetworkColumn::$column,)+
                }
            }
        }

        const _: () = {
            // `index` is the discriminant, and the macro emits the variants
            // in order with no explicit values, so the discriminants are
            // 0..COUNT. A hole would write one connector's occupancy into
            // another's row.
            let mut position = 0usize;
            $(
                assert!(ConnectorId::$name.index() == position);
                position += 1;
            )+
            assert!(position == ConnectorId::COUNT);
        };
    };
}

connectors! {
    /// A connector that is built.
    enum ConnectorId {
        /// Clearnet.
        Clearnet => Clearnet,
        /// Tor.
        Tor => Tor,
    }
}

/// An assessed value, or a cell nobody has assessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Assessment<T> {
    /// Someone has written down what this network does.
    Assessed(T),
    /// Nobody has assessed this cell.
    NotAssessed,
}

/// How peers are named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Addressing {
    /// IPv4 or IPv6, plus a port.
    Ip,
    /// Onion v3. The connector dials those hostnames only.
    OnionV3,
}

/// The addressing family an address presents.
///
/// IPv4 and IPv6 are one family. This is the variant, not a check that
/// the hostname is well formed. The dial rule does that check.
#[must_use]
pub const fn addressing_of(address: &NetworkAddress) -> Addressing {
    match address {
        NetworkAddress::Ipv4 { .. } | NetworkAddress::Ipv6 { .. } => Addressing::Ip,
        NetworkAddress::Tor { .. } => Addressing::OnionV3,
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

/// A layer the transport adds because the connector's network does not
/// provide a property the session contract requires.
///
/// The session reads the byte stream above this list. It does not match
/// on [`ConnectorId`], and it does not know which layer supplied encryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddedLayer {
    /// The Noise NNhfs handshake and record layer in `shekyl-p2p-transport`.
    ///
    /// Added when native encryption is [`NativeEncryption::NoneNative`].
    Noise,
}

/// Whether a column can be built, and which layers the transport adds
/// under the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackPlan {
    /// `layers` is what the transport adds. Empty means the network
    /// already meets the encryption contract.
    Ready {
        /// Layers under the session, in the order they wrap the stream.
        layers: &'static [AddedLayer],
    },
    /// The encryption cell has not been assessed, so no layer can be
    /// chosen. There is no connector for this column.
    NotUsable,
}

const NOISE_LAYER: &[AddedLayer] = &[AddedLayer::Noise];
const NO_ADDED_LAYER: &[AddedLayer] = &[];

/// The layers `column`'s encryption cell requires.
///
/// Clearnet declares no native encryption, so the plan is
/// [`AddedLayer::Noise`]. Tor declares classical encryption, so the plan
/// is empty. An unassessed encryption cell is not usable. A new
/// [`NativeEncryption`] variant has to say which of those it is.
#[must_use]
pub const fn stack_plan(column: NetworkColumn) -> StackPlan {
    match declaration(column).encryption() {
        Assessment::Assessed(NativeEncryption::NoneNative) => StackPlan::Ready {
            layers: NOISE_LAYER,
        },
        Assessment::Assessed(NativeEncryption::Classical) => StackPlan::Ready {
            layers: NO_ADDED_LAYER,
        },
        Assessment::NotAssessed => StackPlan::NotUsable,
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

/// A yes or no that has been assessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YesNo {
    /// The property holds.
    Yes,
    /// The property does not hold.
    No,
}

/// Correlation, or the origin of a relayed transaction. The assessed
/// answer on the networks where it has been written down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotProvided;

/// What an observer at this node's end can see of the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalVisibility {
    /// The connection's existence, timing, volume, and sizes.
    Visible,
    /// The same facts, as Tor traffic.
    VisibleAsTor,
}

/// Whether an inbound peer has an address a ban can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BannableInbound {
    /// The socket address.
    Yes,
    /// This zone, no address.
    NoAddress,
}

/// What a connection is a stream of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamKind {
    /// TCP.
    Tcp,
    /// A Tor stream.
    Tor,
}

/// The observed identity of an inbound peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundIdentity {
    /// The socket address.
    SocketAddress,
    /// This zone, no address.
    ZoneNoAddress,
}

/// Where a connector's deadlines come from. No duration is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeadlineInput {
    /// Measured on that connector. The number is not written yet.
    MeasuredPerConnector,
}

/// Rendezvous arrival priced by onion-service proof of work.
///
/// Flood resistance of streams inside an established circuit is not a
/// value yet. The Tor flood test is what would add one. Until then the
/// sentence stays in the design record, not in a one-variant type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rendezvous {
    /// Clearnet has no rendezvous.
    NotApplicable,
    /// Enabled.
    Enabled,
}

/// The relay's cover ruling for this connector, recorded on the column.
///
/// Owned by `TOR_COVER_POSTURE.md`. Not a property of the wire, and not
/// a value the transport layer edits. Not derived from encryption or from
/// address hiding. Those cells can agree with this one, and a later
/// connector may set only one of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverClass {
    /// An envelope is the only cover a wire observer cannot already see
    /// through. Substitution cover may run when the carrier was requested.
    OpenLink,
    /// The connector's own traffic is the cover. No envelope.
    Volume,
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
    /// Milliseconds. Not assessed means the relay does not stem here.
    measured_transit_ms: Assessment<u32>,
    cover_class: Assessment<CoverClass>,
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
    /// Measured transit, in milliseconds.
    ///
    /// [`Assessment::NotAssessed`] means the relay does not stem on this
    /// connector.
    #[must_use]
    pub const fn measured_transit_ms(self) -> Assessment<u32> {
        self.measured_transit_ms
    }
    /// The relay's cover ruling recorded on this column.
    ///
    /// Owned by `TOR_COVER_POSTURE.md`. Not a property of the wire, and
    /// not a value the transport layer edits. [`Assessment::NotAssessed`]
    /// is no envelope: the relay does not treat it as an open link.
    #[must_use]
    pub const fn cover_class(self) -> Assessment<CoverClass> {
        self.cover_class
    }

    /// A column that is not a built connector.
    ///
    /// The relay guard drives this through stem draw, own-edge draw, and
    /// the embargo. Production columns are [`declaration`]. Every cell
    /// this function does not take is not assessed.
    #[must_use]
    pub const fn synthetic(
        address_hidden_from_peer: Assessment<YesNo>,
        measured_transit_ms: Assessment<u32>,
        cover_class: Assessment<CoverClass>,
    ) -> Self {
        Self {
            addressing: Assessment::NotAssessed,
            encryption: Assessment::NotAssessed,
            destination_authenticated: Assessment::NotAssessed,
            address_hidden_from_peer,
            destination_hidden_from_local_observer: Assessment::NotAssessed,
            address_hidden_from_remote_observer: Assessment::NotAssessed,
            correlation: Assessment::NotAssessed,
            local_observer_visibility: Assessment::NotAssessed,
            relay_origin: Assessment::NotAssessed,
            bannable_inbound: Assessment::NotAssessed,
            stream: Assessment::NotAssessed,
            inbound_identity: Assessment::NotAssessed,
            deadline_inputs: Assessment::NotAssessed,
            rendezvous: Assessment::NotAssessed,
            measured_transit_ms,
            cover_class,
        }
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
            // The numbers are `verify_cost`'s. This column does not keep a second copy.
            rendezvous: Assessment::Assessed(Rendezvous::NotApplicable),
            measured_transit_ms: Assessment::Assessed(whole_ms(ADOPTED_TRANSIT_ASSUMPTION_MS)),
            cover_class: Assessment::Assessed(CoverClass::OpenLink),
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
            // The numbers are `verify_cost`'s. This column does not keep a second copy.
            rendezvous: Assessment::Assessed(Rendezvous::Enabled),
            measured_transit_ms: Assessment::Assessed(whole_ms(ANON_ZONE_TRANSIT_ASSUMPTION_MS)),
            cover_class: Assessment::Assessed(CoverClass::Volume),
        },
    }
}

/// The connector whose addressing cell is the family `address` presents.
///
/// Two connectors declaring one family is the D7 falsifier: the result is
/// [`None`] rather than a silent pick, and the crate test rejects that table.
#[must_use]
pub fn connector_for(address: &NetworkAddress) -> Option<ConnectorId> {
    let family = addressing_of(address);
    let mut found = None;
    for id in ConnectorId::ALL {
        let Assessment::Assessed(declared) = declaration(id.column()).addressing() else {
            continue;
        };
        if declared != family {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(*id);
    }
    found
}

#[cfg(test)]
mod tests {
    use super::{
        addressing_of, connector_for, declaration, stack_plan, AddedLayer, Addressing, Assessment,
        BannableInbound, ConnectorId, CoverClass, DeadlineInput, DestinationAuth, InboundIdentity,
        LocalVisibility, NativeEncryption, NetworkColumn, NotProvided, Rendezvous, StackPlan,
        StreamKind, YesNo,
    };
    use shekyl_net_address::NetworkAddress;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn cell<T>(value: Assessment<T>, assessed: impl Fn(T) -> &'static str) -> &'static str {
        match value {
            Assessment::NotAssessed => "not assessed",
            Assessment::Assessed(value) => assessed(value),
        }
    }

    fn yes_no(value: YesNo) -> &'static str {
        match value {
            YesNo::Yes => "yes",
            YesNo::No => "no",
        }
    }

    /// The words the D7 cells read as. The scan for reputation words lives
    /// here, next to the strings, and not on the public cell types.
    fn cell_texts(column: super::Declaration) -> Vec<&'static str> {
        vec![
            cell(column.addressing(), |value| match value {
                Addressing::Ip => "ipv4/ipv6",
                Addressing::OnionV3 => "onion v3",
            }),
            cell(column.encryption(), |value| match value {
                NativeEncryption::NoneNative => "none native",
                NativeEncryption::Classical => "native, classical only",
            }),
            cell(column.destination_authenticated(), |value| match value {
                DestinationAuth::No => "no",
                DestinationAuth::OneWay => "one way",
            }),
            cell(column.address_hidden_from_peer(), yes_no),
            cell(column.destination_hidden_from_local_observer(), yes_no),
            cell(column.address_hidden_from_remote_observer(), yes_no),
            cell(column.correlation(), |NotProvided| "not provided"),
            cell(column.local_observer_visibility(), |value| match value {
                LocalVisibility::Visible => "visible",
                LocalVisibility::VisibleAsTor => "visible as tor traffic",
            }),
            cell(column.relay_origin(), |NotProvided| "not provided"),
            cell(column.bannable_inbound(), |value| match value {
                BannableInbound::Yes => "yes",
                BannableInbound::NoAddress => "no address",
            }),
            cell(column.stream(), |value| match value {
                StreamKind::Tcp => "tcp",
                StreamKind::Tor => "tor stream",
            }),
            cell(column.inbound_identity(), |value| match value {
                InboundIdentity::SocketAddress => "socket address",
                InboundIdentity::ZoneNoAddress => "zone, no address",
            }),
            cell(column.deadline_inputs(), |value| match value {
                DeadlineInput::MeasuredPerConnector => "measured per connector",
            }),
            cell(column.rendezvous(), |value| match value {
                Rendezvous::NotApplicable => "not applicable",
                Rendezvous::Enabled => "enabled",
            }),
            cell(column.measured_transit_ms(), |_| "assessed milliseconds"),
            cell(column.cover_class(), |value| match value {
                CoverClass::OpenLink => "substitution envelope",
                CoverClass::Volume => "volume cover",
            }),
        ]
    }

    fn unassessed(column: NetworkColumn) -> usize {
        cell_texts(declaration(column))
            .iter()
            .filter(|text| **text == "not assessed")
            .count()
    }

    #[test]
    fn clearnet_and_tor_are_assessed() {
        assert_eq!(unassessed(NetworkColumn::Tor), 0);
        assert_eq!(unassessed(NetworkColumn::Clearnet), 0);
    }

    #[test]
    fn no_cell_uses_a_reputation_word() {
        for column in [NetworkColumn::Clearnet, NetworkColumn::Tor] {
            match column {
                NetworkColumn::Clearnet | NetworkColumn::Tor => {}
            }
            for text in cell_texts(declaration(column)) {
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
    }

    #[test]
    fn the_addressing_cell_selects_the_connector() {
        let samples = [
            (
                NetworkAddress::Ipv4 {
                    ip: Ipv4Addr::LOCALHOST,
                    port: 18080,
                },
                Some(ConnectorId::Clearnet),
            ),
            (
                NetworkAddress::Ipv6 {
                    ip: Ipv6Addr::LOCALHOST,
                    port: 18080,
                },
                Some(ConnectorId::Clearnet),
            ),
            (
                NetworkAddress::Tor {
                    host: "example.onion".to_owned(),
                    port: 18080,
                },
                Some(ConnectorId::Tor),
            ),
        ];
        for (address, expected) in samples {
            assert_eq!(connector_for(&address), expected);
            let family = addressing_of(&address);
            let owners: Vec<ConnectorId> = ConnectorId::ALL
                .iter()
                .copied()
                .filter(|id| declaration(id.column()).addressing() == Assessment::Assessed(family))
                .collect();
            assert!(owners.len() <= 1, "{family:?} claimed twice");
            assert_eq!(owners.first().copied(), expected);
        }
    }

    #[test]
    fn noise_is_added_only_where_native_encryption_is_absent() {
        match stack_plan(NetworkColumn::Clearnet) {
            StackPlan::Ready { layers } => assert_eq!(layers, &[AddedLayer::Noise]),
            StackPlan::NotUsable => panic!("clearnet meets the encryption contract"),
        }
        match stack_plan(NetworkColumn::Tor) {
            StackPlan::Ready { layers } => assert!(layers.is_empty()),
            StackPlan::NotUsable => panic!("tor meets the encryption contract"),
        }
        for column in [NetworkColumn::Clearnet, NetworkColumn::Tor] {
            match column {
                NetworkColumn::Clearnet | NetworkColumn::Tor => {}
            }
            let ready = matches!(stack_plan(column), StackPlan::Ready { .. });
            let built = ConnectorId::ALL.iter().any(|id| id.column() == column);
            assert_eq!(ready, built, "{column:?}");
        }
    }
}
