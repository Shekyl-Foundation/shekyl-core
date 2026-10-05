// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The transport layer's logic, with no sockets.
//!
//! Connectors declare what their network provides. [`stack_plan`] reads the
//! encryption cell and names the layers added under the session. Levin is
//! that session: it does not match on the connector. A connector with no
//! native encryption gets [`AddedLayer::Noise`] without a change to how
//! Levin reads the byte stream above the plan.
//!
//! The socket table counts reservations. The ban list is built and not
//! called from RPC. Deadlines are owners of [`shekyl_timing_engine`] once
//! a connector exists; none are written here. The Noise layer stays
//! [`shekyl_p2p_transport`]. The address union is [`NetworkAddress`].

#![deny(unsafe_code)]

// D10 names these flight sizes. They are the Noise crate's, checked here
// so a change to that crate is visible to the layer that will bound them.
const _: () = assert!(shekyl_p2p_transport::INITIATOR_FLIGHT_LEN == 1_224);
const _: () = assert!(shekyl_p2p_transport::RESPONDER_FLIGHT_LEN == 1_160);

mod admission;
mod ban;
mod budget;
mod cause;
mod declaration;
mod dial;

pub use admission::{
    CloseResult, Direction, ObservedEndpoint, OpenError, OpenSocket, SocketId, Sockets,
};
pub use ban::{deadline_after, BanLeft, BanList, Ipv4Subnet, ListedBan};
pub use budget::{LinkBudget, LinkDirection, MessageClass, Observed, Turn};
pub use cause::{c_header, CloseCause, CloseKind, Phase};
pub use declaration::{
    addressing_of, connector_for, declaration, stack_plan, AddedLayer, Addressing, Assessment,
    BannableInbound, ConnectorId, DeadlineInput, Declaration, DestinationAuth, InboundIdentity,
    LocalVisibility, NativeEncryption, NetworkColumn, NotProvided, Rendezvous, StackPlan,
    StreamKind, YesNo,
};
pub use dial::check_dial;
pub use shekyl_net_address::NetworkAddress;
