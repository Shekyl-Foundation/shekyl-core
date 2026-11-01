// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What each of this connector's dial failures is evidence of
//! (`DIALER_OUTAGE_EVIDENCE.md` §3.1, `OE-D3`; the transport lane reviews).
//!
//! A clearnet path is per destination: an on-path party can pass one
//! session and drop the rest, and Noise NN authenticates no one, so nothing
//! here proves misbehaviour. The ruled principle: **Local is only for a
//! failure independent of the destination.** A failure that depends on the
//! destination's address family or route is Uncertain, which the judge
//! counts when another path shows life and excuses in a total outage.
//!
//! Each row's D12 cause is today's kind, for the log and the C side; only
//! the evidence is new. Each row's retry is today's.

use std::io::ErrorKind;

use shekyl_transport_layer::{
    CloseCause, CloseKind, DialEnd, DialFailure, Reached, Retry, StreamEnd,
};

/// RFC 1928 §6. The destination refused the connection.
const SOCKS_CONNECTION_REFUSED: u8 = 0x05;
/// RFC 1928 §6. The command this node sent is not supported.
const SOCKS_COMMAND_NOT_SUPPORTED: u8 = 0x07;

/// What this connector's dial path saw before the channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observed {
    /// A direct connect the far end refused: its RST.
    ConnectRefused,
    /// A direct connect the far end reset.
    ConnectReset,
    /// A direct connect that failed otherwise: a kernel timeout, host or
    /// network unreachable, address not available, permission denied. Each
    /// depends on the destination's route or address family (ruled).
    ConnectUncertain,
    /// The connect to the operator's SOCKS proxy failed: this node's proxy.
    ProxyConnectFailed,
    /// The operator's SOCKS proxy answered with `reply`.
    ProxyReply(u8),
    /// The SOCKS exchange broke or was malformed: this node's proxy.
    ProxyMalformed,
    /// The proxy refused this node's authentication: this node's proxy.
    ProxyAuthentication,
    /// The dial deadline ran out.
    Deadline,
    /// This node refused the address before dialing: a check on the
    /// address, or a ban at admission. **Destination, for Rick** (§3.1):
    /// both depend on the destination, so neither is Local, and each is
    /// this node's standing verdict on that address, which no outage
    /// produces.
    RefusedHere(CloseCause),
    /// This node's own failure: the engine, the socket table, an address
    /// this connector cannot dial.
    OwnFailure,
    /// The peer's handshake message did not verify, or the peer closed or
    /// reset the connection mid-handshake.
    HandshakeRefusedByPeer,
    /// The peer's prefix is another network's.
    PrefixMismatch,
    /// This node's engine, crypto job or join failed in the handshake.
    HandshakeOwnFailure,
    /// The handshake deadline ran out.
    HandshakeDeadline,
}

impl Observed {
    /// What a failed direct connect, or a failed connect to the operator's
    /// proxy, saw.
    #[must_use]
    pub fn connect_error(error: ErrorKind, proxied: bool) -> Self {
        if proxied {
            return Self::ProxyConnectFailed;
        }
        match error {
            ErrorKind::ConnectionRefused => Self::ConnectRefused,
            ErrorKind::ConnectionReset => Self::ConnectReset,
            _ => Self::ConnectUncertain,
        }
    }

    /// The end this connector reports for what it saw.
    #[must_use]
    pub const fn end(self) -> DialEnd {
        let before = Reached::NoStream;
        match self {
            Self::ConnectRefused => DialEnd::new(
                DialFailure::destination(Retry::Again, before),
                CloseCause::new(CloseKind::DialFailed),
            ),
            Self::ConnectReset => DialEnd::new(
                DialFailure::destination(Retry::Final, before),
                CloseCause::new(CloseKind::LocalClose),
            ),
            Self::ConnectUncertain => DialEnd::new(
                DialFailure::uncertain(Retry::Final, before),
                CloseCause::new(CloseKind::LocalClose),
            ),
            Self::ProxyConnectFailed | Self::ProxyMalformed => DialEnd::new(
                DialFailure::local(Retry::Final, before),
                CloseCause::new(CloseKind::LocalClose),
            ),
            Self::ProxyAuthentication => DialEnd::new(
                DialFailure::local(Retry::Final, before),
                CloseCause::new(CloseKind::ProxyUnavailable),
            ),
            Self::ProxyReply(reply) => DialEnd::new(
                stamp_proxy_reply(reply),
                CloseCause::proxy_refused(reply as u16, 0),
            ),
            Self::Deadline | Self::HandshakeDeadline => DialEnd::new(
                DialFailure::uncertain(Retry::AgainInsideWindow, before),
                CloseCause::new(CloseKind::TransportTimeout),
            ),
            Self::RefusedHere(cause) => {
                DialEnd::new(DialFailure::destination(Retry::Final, before), cause)
            }
            Self::OwnFailure => DialEnd::local_close(),
            Self::HandshakeRefusedByPeer => DialEnd::new(
                DialFailure::destination(Retry::Final, before),
                CloseCause::new(CloseKind::TransportHandshakeFailed),
            ),
            Self::PrefixMismatch => DialEnd::new(
                DialFailure::destination(Retry::Final, before),
                CloseCause::new(CloseKind::PrefixMismatch),
            ),
            Self::HandshakeOwnFailure => DialEnd::new(
                DialFailure::local(Retry::Final, before),
                CloseCause::new(CloseKind::TransportHandshakeFailed),
            ),
        }
    }
}

/// What a reply from the operator's SOCKS proxy is evidence of. Refused
/// (`0x05`) is the destination; a command this node sent that the proxy
/// does not support (`0x07`) is this node's request; every other reply,
/// the ruleset refusal (`0x02`) and the address type (`0x08`) among them,
/// depends on the destination and is Uncertain (**for Rick**, §3.1:
/// `0x08` is the IPv6 case of the ruling arriving through a proxy).
/// Clearnet makes one attempt per test through a proxy, so each is final.
const fn stamp_proxy_reply(reply: u8) -> DialFailure {
    match reply {
        SOCKS_CONNECTION_REFUSED => DialFailure::destination(Retry::Final, Reached::NoStream),
        SOCKS_COMMAND_NOT_SUPPORTED => DialFailure::local(Retry::Final, Reached::NoStream),
        _ => DialFailure::uncertain(Retry::Final, Reached::NoStream),
    }
}

/// How a clearnet stream ended after it opened (§3.1). The peer closing
/// and a record that does not open are the destination's; an I/O error and
/// a send queue the far side did not drain are the link or the
/// destination; this node's own close or refusal is Local. A reset or a
/// bad record can be forged on path: that party already decides which
/// peers this node reaches, the permanent clearnet residual.
#[must_use]
pub const fn stamp_stream_end(end: StreamEnd) -> DialFailure {
    let opened = Reached::StreamOpened;
    match end {
        StreamEnd::PeerClosed => DialFailure::destination(Retry::Again, opened),
        StreamEnd::RecordRejected => DialFailure::destination(Retry::Final, opened),
        StreamEnd::IoError => DialFailure::uncertain(Retry::Again, opened),
        StreamEnd::SendQueueFull => DialFailure::uncertain(Retry::Final, opened),
        StreamEnd::SessionRefused | StreamEnd::LocalClose => {
            DialFailure::local(Retry::Final, opened)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use shekyl_transport_layer::{
        CloseCause, CloseKind, Evidence, Proof, Reached, Retry, StreamEnd,
    };

    use super::{stamp_stream_end, Observed};

    const DESTINATION: Evidence = Evidence::Destination(Proof::ABSENT);

    /// Every before-channel observation, against §3.1's table: its
    /// evidence, its retry and its D12 kind. Nothing proves misbehaviour on
    /// clearnet. The edit that makes this red is moving any row.
    #[test]
    fn each_clearnet_observation_is_stamped_as_the_table_says() {
        let refused_here = CloseCause::new(CloseKind::AdmissionRefused);
        for (observed, evidence, retry, kind) in [
            (
                Observed::ConnectRefused,
                DESTINATION,
                Retry::Again,
                CloseKind::DialFailed,
            ),
            (
                Observed::ConnectReset,
                DESTINATION,
                Retry::Final,
                CloseKind::LocalClose,
            ),
            (
                Observed::ConnectUncertain,
                Evidence::Uncertain,
                Retry::Final,
                CloseKind::LocalClose,
            ),
            (
                Observed::ProxyConnectFailed,
                Evidence::Local,
                Retry::Final,
                CloseKind::LocalClose,
            ),
            (
                Observed::ProxyMalformed,
                Evidence::Local,
                Retry::Final,
                CloseKind::LocalClose,
            ),
            (
                Observed::ProxyAuthentication,
                Evidence::Local,
                Retry::Final,
                CloseKind::ProxyUnavailable,
            ),
            (
                Observed::ProxyReply(0x05),
                DESTINATION,
                Retry::Final,
                CloseKind::ProxyRefused,
            ),
            (
                Observed::ProxyReply(0x07),
                Evidence::Local,
                Retry::Final,
                CloseKind::ProxyRefused,
            ),
            (
                Observed::ProxyReply(0x02),
                Evidence::Uncertain,
                Retry::Final,
                CloseKind::ProxyRefused,
            ),
            (
                Observed::ProxyReply(0x08),
                Evidence::Uncertain,
                Retry::Final,
                CloseKind::ProxyRefused,
            ),
            (
                Observed::Deadline,
                Evidence::Uncertain,
                Retry::AgainInsideWindow,
                CloseKind::TransportTimeout,
            ),
            (
                Observed::RefusedHere(refused_here),
                DESTINATION,
                Retry::Final,
                CloseKind::AdmissionRefused,
            ),
            (
                Observed::OwnFailure,
                Evidence::Local,
                Retry::Final,
                CloseKind::LocalClose,
            ),
            (
                Observed::HandshakeRefusedByPeer,
                DESTINATION,
                Retry::Final,
                CloseKind::TransportHandshakeFailed,
            ),
            (
                Observed::PrefixMismatch,
                DESTINATION,
                Retry::Final,
                CloseKind::PrefixMismatch,
            ),
            (
                Observed::HandshakeOwnFailure,
                Evidence::Local,
                Retry::Final,
                CloseKind::TransportHandshakeFailed,
            ),
            (
                Observed::HandshakeDeadline,
                Evidence::Uncertain,
                Retry::AgainInsideWindow,
                CloseKind::TransportTimeout,
            ),
        ] {
            let end = observed.end();
            assert_eq!(end.failure().evidence(), evidence, "{observed:?}");
            assert_eq!(end.failure().retry(), retry, "{observed:?}");
            assert_eq!(end.failure().reached(), Reached::NoStream, "{observed:?}");
            assert!(!end.failure().proves_misbehaviour(), "{observed:?}");
            assert_eq!(end.cause().kind(), kind, "{observed:?}");
        }
    }

    /// The ruling on `OE-D3`: only the far end's refusal or reset is the
    /// destination; every other direct connect error is Uncertain, network
    /// unreachable and address not available among them (an IPv6 address
    /// on a node with no IPv6 route must not be excused forever); any error
    /// through the operator's proxy is this node's proxy.
    #[test]
    fn a_connect_error_is_the_destination_only_when_the_far_end_answered() {
        assert_eq!(
            Observed::connect_error(ErrorKind::ConnectionRefused, false),
            Observed::ConnectRefused
        );
        assert_eq!(
            Observed::connect_error(ErrorKind::ConnectionReset, false),
            Observed::ConnectReset
        );
        for error in [
            ErrorKind::TimedOut,
            ErrorKind::NetworkUnreachable,
            ErrorKind::HostUnreachable,
            ErrorKind::AddrNotAvailable,
            ErrorKind::PermissionDenied,
            ErrorKind::Other,
        ] {
            assert_eq!(
                Observed::connect_error(error, false),
                Observed::ConnectUncertain,
                "{error:?}"
            );
        }
        for error in [ErrorKind::ConnectionRefused, ErrorKind::TimedOut] {
            assert_eq!(
                Observed::connect_error(error, true),
                Observed::ProxyConnectFailed,
                "{error:?}"
            );
        }
    }

    /// After the stream opened (§3.1): the peer's close and a bad record
    /// are the destination's, an I/O error and an undrained queue are
    /// Uncertain, this node's own close or refusal is Local.
    #[test]
    fn a_clearnet_streams_end_is_stamped_by_this_connector() {
        for (end, evidence) in [
            (StreamEnd::PeerClosed, DESTINATION),
            (StreamEnd::RecordRejected, DESTINATION),
            (StreamEnd::IoError, Evidence::Uncertain),
            (StreamEnd::SendQueueFull, Evidence::Uncertain),
            (StreamEnd::SessionRefused, Evidence::Local),
            (StreamEnd::LocalClose, Evidence::Local),
        ] {
            let failure = stamp_stream_end(end);
            assert_eq!(failure.evidence(), evidence, "{end:?}");
            assert_eq!(failure.reached(), Reached::StreamOpened, "{end:?}");
        }
    }
}
