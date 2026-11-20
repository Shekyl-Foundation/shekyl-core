// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The connectors, as the session layer reaches them (brief §2).
//!
//! The layer dials through one [`Dial`]: the composition's, which routes
//! a clearnet endpoint to `shekyl-clearnet` and an onion to `shekyl-tor`;
//! or a test's, which opens an in-memory pair. What comes back is a
//! [`Channel`] the connector already admitted and built. The layer never
//! opens a socket and never builds a [`shekyl_capped_stream::StreamEnds`].
//!
//! Inbound channels do not pass through this trait: the connector that
//! accepted hands them to [`crate::SessionLayer::adopt`].

use std::future::Future;
use std::pin::Pin;

use shekyl_capped_stream::Session;
use shekyl_transport_layer::{ConnectorId, DialEnd, DialFailure, OpenSocket, StreamEnd};
use tokio::sync::oneshot;

use crate::endpoint::Endpoint;

/// A channel the connector already admitted and built.
pub struct Channel {
    /// The admission reservation. The session layer closes it, once.
    pub open: OpenSocket,
    /// The caller's end of the byte cap. The session task owns it.
    pub session: Session,
    /// What the row records.
    pub endpoint: Endpoint,
    /// Fires when the Levin handshake completes. `None` when this channel
    /// has no gap deadline. Dropping it ends the connector's wait.
    pub gap: Option<oneshot::Sender<()>>,
}

/// A channel still being opened: [`Dial::connect_async`]'s future.
/// Dropping it before it resolves cancels the connect, and the connector
/// releases whatever it reserved.
pub type ConnectFuture = Pin<Box<dyn Future<Output = Result<Channel, DialEnd>> + Send>>;

/// Opens outbound channels and names what a stream end means.
pub trait Dial: Send + Sync {
    /// Admit and build the channel to `endpoint`. A failure is the end the
    /// connector stamped (`DIALER_OUTAGE_EVIDENCE.md` §2.2), or this
    /// node's own before any I/O.
    fn connect_async(&self, endpoint: &Endpoint) -> ConnectFuture;

    /// What a stream end observed after the channel is evidence of, from
    /// `connector`'s own table. The session layer asks this; no
    /// connector-independent code assigns a meaning.
    fn stamp_stream_end(&self, connector: ConnectorId, end: StreamEnd) -> DialFailure;
}
