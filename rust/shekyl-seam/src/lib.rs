// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The seam between a connector and the Levin handler.
//!
//! The admission [`SocketId`] is the only id that crosses. The connector
//! admits on the shared [`Sockets`] table and owns the socket. This crate
//! posts `established`, `deliver`, and `closed` onto that connection's
//! strand. It does not run the strand, and it does not build a second
//! session.
//!
//! A `send` is one whole Levin message on the connector's byte cap. A
//! message that does not fit is not stored, and the cause is
//! [`CloseKind::SendQueueFull`]. The first cause wins.

#![deny(unsafe_code)]

mod dial;
mod drive;
mod endpoint;
mod hub;
mod loopback;

pub use dial::{Channel, Dial};
pub use drive::drive_inbound;
pub use endpoint::{admit, connector_from_index, direction_from_index, Endpoint, TOR_HOST_MAX};
pub use hub::{Attached, Hub, Post};
pub use loopback::Loopback;
pub use shekyl_transport_layer::{
    deadline_after, BanLeft, CloseCause, CloseKind, ConnectorId, Direction, Ipv4Subnet, ListedBan,
    SocketId, Sockets,
};
