// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The connectors' own stamping, for the fake dialers. A fake answers as a
//! connector would, from that connector's table, never with a meaning of its
//! own (`DIALER_OUTAGE_EVIDENCE.md` §2.2).

#![allow(dead_code)]

use shekyl_transport_layer::{
    CloseCause, CloseKind, ConnectorId, DialEnd, DialFailure, Reached, StreamEnd,
};

/// Each connector's stream-end table, as zone bind dispatches them.
pub fn tables(connector: ConnectorId, end: StreamEnd) -> DialFailure {
    match connector {
        ConnectorId::Clearnet => shekyl_clearnet::stamp_stream_end(end),
        ConnectorId::Tor => shekyl_tor::stamp_stream_end(end),
    }
}

/// The peer closing an open session on `connector`, as that connector's
/// drive records it.
pub fn peer_closed(connector: ConnectorId) -> DialEnd {
    DialEnd::new(
        tables(connector, StreamEnd::PeerClosed),
        CloseCause::new(CloseKind::PeerClosed),
    )
}

/// The peer rejecting the Levin handshake after the stream opened: the Levin
/// layer's refusal (§2.2).
pub fn levin_rejected(connector: ConnectorId) -> DialEnd {
    DialEnd::new(
        DialFailure::refused_by_peer(connector, Reached::StreamOpened),
        CloseCause::new(CloseKind::LevinHandshakeRejected),
    )
}

/// This node's strand refusing a session's payload, as the hub records it.
pub fn session_refused() -> DialEnd {
    DialEnd::new(
        DialFailure::local(shekyl_transport_layer::Retry::Again, Reached::StreamOpened),
        CloseCause::new(CloseKind::SessionRefused),
    )
}
