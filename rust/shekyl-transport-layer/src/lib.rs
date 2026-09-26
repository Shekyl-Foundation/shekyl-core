// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The transport layer's logic, with no sockets.
//!
//! Connectors declare what their network provides. The socket table counts
//! reservations. The ban list is built and not called from RPC. Deadlines
//! are owners of [`shekyl_timing_engine`] once a connector exists; none are
//! written here. The Noise layer stays [`shekyl_p2p_transport`].

#![deny(unsafe_code)]

// D10 names these flight sizes. They are the Noise crate's, checked here
// so a change to that crate is visible to the layer that will bound them.
const _: () = assert!(shekyl_p2p_transport::INITIATOR_FLIGHT_LEN == 1_224);
const _: () = assert!(shekyl_p2p_transport::RESPONDER_FLIGHT_LEN == 1_160);

mod address;
mod admission;
mod ban;
mod cause;
mod declaration;
mod dial;

pub use address::PeerAddress;
pub use admission::{CloseResult, Direction, OpenError, OpenSocket, SocketId, Sockets};
pub use ban::{BanList, Ipv4Subnet};
pub use cause::{c_header, CloseCause, CloseKind, Phase};
pub use declaration::{
    connector_for, declaration, Addressing, Assessment, BannableInbound, CellText, ConnectorId,
    DeadlineInput, Declaration, DestinationAuth, FloodResistance, InboundIdentity, LocalVisibility,
    NativeEncryption, NetworkColumn, NotProvided, Rendezvous, StreamKind, YesNo,
};
pub use dial::check_tor_dial;
