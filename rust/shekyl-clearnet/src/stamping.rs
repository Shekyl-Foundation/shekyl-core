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
//! Each row's D12 cause is today's kind, for the log and the C side.
//! Each row's evidence and retry follow what the row means ([`Observed`]).

use std::io::ErrorKind;

use shekyl_transport_layer::{
    CloseCause, CloseKind, DialEnd, DialFailure, Reached, Retry, StreamEnd,
};

/// RFC 1928 §6. The destination refused the connection.
const SOCKS_CONNECTION_REFUSED: u8 = 0x05;
/// RFC 1928 §6. The command this node sent is not supported.
const SOCKS_COMMAND_NOT_SUPPORTED: u8 = 0x07;

/// What this connector's own code saw, for the dial it made: every
/// failure before the channel, and the one after-channel end that is its
/// own record layer's. What shared code observes on the stream after the
/// channel is [`stamp_stream_end`]'s.
///
/// Retry follows each row's meaning (Rick, 2026-10-31). A white test gets
/// one redial to rule out a true transient before it demotes, so a row is
/// [`Retry::Final`] only for a definitive answer: another network's prefix,
/// a message that does not verify. Nothing on clearnet proves misbehaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observed {
    /// A direct connect the far end refused: its RST.
    ConnectRefused,
    /// A direct connect the far end reset.
    ConnectReset,
    /// A direct connect that failed otherwise: a kernel timeout, host or
    /// network unreachable, address not available, permission denied. Each
    /// depends on the destination's route or address family (ruled); each
    /// is a timeout-like failure, read against the window as the deadline is.
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
    /// This node's own failure: the engine, the socket table, an address
    /// this connector cannot dial.
    OwnFailure,
    /// The peer's handshake message did not verify: a definitive answer.
    HandshakeUnverified,
    /// The peer closed or reset the connection mid-handshake.
    HandshakeBroken,
    /// The peer's prefix is another network's: a definitive answer.
    PrefixMismatch,
    /// This node's engine, crypto job or join failed in the handshake.
    HandshakeOwnFailure,
    /// The handshake deadline ran out.
    HandshakeDeadline,
    /// After the channel: a record did not open. This connector's record
    /// layer judged a message from the far end, and it did not verify.
    RecordRejected,
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
                DialFailure::destination(Retry::Again, before),
                CloseCause::new(CloseKind::LocalClose),
            ),
            Self::ConnectUncertain => DialEnd::new(
                DialFailure::uncertain(Retry::AgainInsideWindow, before),
                CloseCause::new(CloseKind::LocalClose),
            ),
            Self::ProxyConnectFailed | Self::ProxyMalformed => DialEnd::new(
                DialFailure::local(Retry::Again, before),
                CloseCause::new(CloseKind::LocalClose),
            ),
            Self::ProxyAuthentication => DialEnd::new(
                DialFailure::local(Retry::Again, before),
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
            Self::OwnFailure => DialEnd::local_close(),
            Self::HandshakeUnverified => DialEnd::new(
                DialFailure::destination(Retry::Final, before),
                CloseCause::new(CloseKind::TransportHandshakeFailed),
            ),
            Self::HandshakeBroken => DialEnd::new(
                DialFailure::destination(Retry::Again, before),
                CloseCause::new(CloseKind::TransportHandshakeFailed),
            ),
            Self::PrefixMismatch => DialEnd::new(
                DialFailure::destination(Retry::Final, before),
                CloseCause::new(CloseKind::PrefixMismatch),
            ),
            Self::HandshakeOwnFailure => DialEnd::new(
                DialFailure::local(Retry::Again, before),
                CloseCause::new(CloseKind::TransportHandshakeFailed),
            ),
            Self::RecordRejected => DialEnd::new(
                DialFailure::destination(Retry::Final, Reached::StreamOpened),
                CloseCause::new(CloseKind::RecordRejected),
            ),
        }
    }
}

/// What a reply from the operator's SOCKS proxy is evidence of, and whether
/// it is worth the redial, from what the reply means:
/// - refused (`0x05`): the destination answered, as a direct refusal does,
///   and keeps its redial;
/// - a command this node sent that the proxy does not support (`0x07`):
///   this node's request, Local, and keeps its redial (a Local failure never
///   counts);
/// - every other reply, the ruleset refusal (`0x02`) and the address type
///   (`0x08`) among them (**ruled Uncertain**, Rick 2026-10-31: each depends
///   on the destination; `0x08` is the IPv6 case through a proxy): the link
///   or the destination, read against the proxied window.
const fn stamp_proxy_reply(reply: u8) -> DialFailure {
    match reply {
        SOCKS_CONNECTION_REFUSED => DialFailure::destination(Retry::Again, Reached::NoStream),
        SOCKS_COMMAND_NOT_SUPPORTED => DialFailure::local(Retry::Again, Reached::NoStream),
        _ => DialFailure::uncertain(Retry::AgainInsideWindow, Reached::NoStream),
    }
}

/// How a clearnet stream ended after it opened (§3.1), from what shared
/// code observed. The peer closing is the destination's; an I/O error and a
/// send queue the far side did not drain are the link or the destination.
/// None is definitive, so each keeps its redial. A reset can be forged on
/// path: that party already decides which peers this node reaches, the
/// permanent clearnet residual.
#[must_use]
pub const fn stamp_stream_end(end: StreamEnd) -> DialFailure {
    let opened = Reached::StreamOpened;
    match end {
        StreamEnd::PeerClosed => DialFailure::destination(Retry::Again, opened),
        StreamEnd::IoError | StreamEnd::SendQueueFull => {
            DialFailure::uncertain(Retry::Again, opened)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use shekyl_transport_layer::{CloseKind, Evidence, Proof, Reached, Retry, StreamEnd};

    use super::{stamp_stream_end, Observed};

    const DESTINATION: Evidence = Evidence::Destination(Proof::ABSENT);

    /// Every observation, against §3.1's table: its evidence, its retry,
    /// how far it got and its D12 kind. Final only for a definitive answer
    /// (another network's prefix, a message that does not verify); nothing
    /// proves misbehaviour on clearnet. The edit that makes this red is
    /// moving any row, or letting a split-out row inherit Final.
    #[test]
    fn each_clearnet_observation_is_stamped_as_the_table_says() {
        let window = Retry::AgainInsideWindow;
        let none = Reached::NoStream;
        for (observed, evidence, retry, reached, kind) in [
            (
                Observed::ConnectRefused,
                DESTINATION,
                Retry::Again,
                none,
                CloseKind::DialFailed,
            ),
            (
                Observed::ConnectReset,
                DESTINATION,
                Retry::Again,
                none,
                CloseKind::LocalClose,
            ),
            (
                Observed::ConnectUncertain,
                Evidence::Uncertain,
                window,
                none,
                CloseKind::LocalClose,
            ),
            (
                Observed::ProxyConnectFailed,
                Evidence::Local,
                Retry::Again,
                none,
                CloseKind::LocalClose,
            ),
            (
                Observed::ProxyMalformed,
                Evidence::Local,
                Retry::Again,
                none,
                CloseKind::LocalClose,
            ),
            (
                Observed::ProxyAuthentication,
                Evidence::Local,
                Retry::Again,
                none,
                CloseKind::ProxyUnavailable,
            ),
            (
                Observed::ProxyReply(0x05),
                DESTINATION,
                Retry::Again,
                none,
                CloseKind::ProxyRefused,
            ),
            (
                Observed::ProxyReply(0x07),
                Evidence::Local,
                Retry::Again,
                none,
                CloseKind::ProxyRefused,
            ),
            (
                Observed::ProxyReply(0x02),
                Evidence::Uncertain,
                window,
                none,
                CloseKind::ProxyRefused,
            ),
            (
                Observed::ProxyReply(0x08),
                Evidence::Uncertain,
                window,
                none,
                CloseKind::ProxyRefused,
            ),
            (
                Observed::Deadline,
                Evidence::Uncertain,
                window,
                none,
                CloseKind::TransportTimeout,
            ),
            (
                Observed::OwnFailure,
                Evidence::Local,
                Retry::Again,
                none,
                CloseKind::LocalClose,
            ),
            (
                Observed::HandshakeUnverified,
                DESTINATION,
                Retry::Final,
                none,
                CloseKind::TransportHandshakeFailed,
            ),
            (
                Observed::HandshakeBroken,
                DESTINATION,
                Retry::Again,
                none,
                CloseKind::TransportHandshakeFailed,
            ),
            (
                Observed::PrefixMismatch,
                DESTINATION,
                Retry::Final,
                none,
                CloseKind::PrefixMismatch,
            ),
            (
                Observed::HandshakeOwnFailure,
                Evidence::Local,
                Retry::Again,
                none,
                CloseKind::TransportHandshakeFailed,
            ),
            (
                Observed::HandshakeDeadline,
                Evidence::Uncertain,
                window,
                none,
                CloseKind::TransportTimeout,
            ),
            (
                Observed::RecordRejected,
                DESTINATION,
                Retry::Final,
                Reached::StreamOpened,
                CloseKind::RecordRejected,
            ),
        ] {
            let end = observed.end();
            assert_eq!(end.failure().evidence(), evidence, "{observed:?}");
            assert_eq!(end.failure().retry(), retry, "{observed:?}");
            assert_eq!(end.failure().reached(), reached, "{observed:?}");
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

    /// After the stream opened (§3.1): the peer's close is the
    /// destination's, an I/O error and an undrained queue are Uncertain,
    /// and none is definitive.
    #[test]
    fn a_clearnet_streams_end_is_stamped_by_this_connector() {
        for (end, evidence) in [
            (StreamEnd::PeerClosed, DESTINATION),
            (StreamEnd::IoError, Evidence::Uncertain),
            (StreamEnd::SendQueueFull, Evidence::Uncertain),
        ] {
            let failure = stamp_stream_end(end);
            assert_eq!(failure.evidence(), evidence, "{end:?}");
            assert_eq!(failure.retry(), Retry::Again, "{end:?}");
            assert_eq!(failure.reached(), Reached::StreamOpened, "{end:?}");
        }
    }
}
