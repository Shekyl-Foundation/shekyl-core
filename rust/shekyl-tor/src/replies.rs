// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The SOCKS reply table: what each reply from this node's Tor says about
//! the dial, as the marks a [`CloseCause`] carries. This is the Tor
//! connector's knowledge (Rick, 2026-10-24); the transport layer holds
//! none of it and takes the marks as an argument.
//!
//! The extended codes (`0xF0` and up) arrive only when the managed
//! `SocksPort` asks for them (`auto ExtendedErrors`). Tor 0.4.9.11 leaves
//! that off (`port_cfg_new`), and without it
//! `stream_end_reason_to_socks5_response` reports an introduction timeout
//! as reply `0x04`.

use shekyl_transport_layer::{
    CloseCause, CloseKind, DialEnd, DialFailure, Marks, Reached, Retry, StreamEnd,
};

/// RFC 1928 §6. The destination host was not reached.
const SOCKS_HOST_UNREACHABLE: u16 = 0x04;
/// RFC 1928 §6. The destination refused the connection.
const SOCKS_CONNECTION_REFUSED: u16 = 0x05;
/// RFC 1928 §6. The command this node sent is not supported.
const SOCKS_COMMAND_NOT_SUPPORTED: u16 = 0x07;
/// RFC 1928 §6. The address type this node sent is not supported.
const SOCKS_ADDRESS_TYPE_NOT_SUPPORTED: u16 = 0x08;
/// Tor extended error (`socks-extensions`, proposal 304). Descriptor missing.
const TOR_DESCRIPTOR_MISSING: u16 = 0xF0;
/// Tor extended error. The descriptor is unusable.
const TOR_DESCRIPTOR_UNUSABLE: u16 = 0xF1;
/// Tor extended error. The introduction failed.
const TOR_INTRODUCTION_FAILED: u16 = 0xF2;
/// Tor extended error. Client authorization is missing. This node's request.
const TOR_CLIENT_AUTH_MISSING: u16 = 0xF4;
/// Tor extended error. Client authorization was rejected. This node's request.
const TOR_CLIENT_AUTH_REJECTED: u16 = 0xF5;
/// Tor extended error. Tor rejected the onion address. Validated before dial.
const TOR_ONION_ADDRESS_REJECTED: u16 = 0xF6;

/// RFC 1928 §6. General SOCKS server failure.
const SOCKS_GENERAL_FAILURE: u16 = 0x01;
/// RFC 1928 §6. Network unreachable.
const SOCKS_NETWORK_UNREACHABLE: u16 = 0x03;
/// RFC 1928 §6. TTL expired.
const SOCKS_TTL_EXPIRED: u16 = 0x06;
/// Tor extended error. The rendezvous timed out.
const TOR_RENDEZVOUS_TIMEOUT: u16 = 0xF3;
/// Tor extended error. The introduction timed out.
const TOR_INTRODUCTION_TIMEOUT: u16 = 0xF7;

/// This connector's judgement of an onion reply, as marks (Rick,
/// 2026-10-24). [`refused`] builds the cause.
///
/// Worth a retry: a missing descriptor (`0xF0`), a failed introduction
/// (`0xF2`), the two timeouts (`0xF3`, `0xF7`), network unreachable
/// (`0x03`), host unreachable (`0x04`) and TTL expired (`0x06`): each can
/// be the network or the directory on this try. Final: general failure
/// (`0x01`), connection refused (`0x05`) and an unusable descriptor
/// (`0xF1`). RFC 1928 calls `0x01` a general SOCKS server failure. On an
/// onion dial Tor sends it when a live service's port refuses, within a
/// second and only after a working rendezvous; a blocked link did not
/// produce it (2026-10-25). The client-authorization errors (`0xF4`,
/// `0xF5`), the rejected onion address (`0xF6`), and a command or address
/// type this node sent (`0x07`, `0x08`) are this node's request. Names
/// the destination: general failure, host unreachable, connection
/// refused, the missing or unusable descriptor, the failed introduction.
/// Nothing here proves misbehaviour: a SOCKS reply is the proxy's word.
///
/// Every reply worth a retry also carries [`Marks::WINDOW_TIMEOUT`]: at or
/// after the managed Tor's `SocksTimeout` it is final within its test,
/// because **Tor retried inside its own window** (Rick, 2026-10-26). Inside
/// that window Tor moves to another introduction point (Tor 0.4.9.14
/// `src/feature/hs/hs_client.c:1246`) and fetches the descriptor from
/// another directory (`:1717`, `:1739`, `:1758`). When the window runs out
/// on an onion stream (`src/core/or/connection_edge.c:1222`, `:1250`), Tor
/// answers with the stream-end reason `TIMEOUT`, `0x06`
/// (`src/core/or/reasons.c:128`), unless it recorded an onion code on the
/// stream first: with `ExtendedErrors` on, that code wins
/// (`src/core/or/connection_edge.c:3894`). A descriptor not found marks it
/// `0xF0` (`src/feature/hs/hs_client.c:1725`), a failed or timed-out
/// introduction `0xF2` or `0xF7` (`:1235`), a timed-out rendezvous `0xF3`
/// (`:1209`). So any of them at the window is Tor's timeout; the floor
/// device saw `0xF0` at 104 to 110 s (2026-10-26). Earlier, each is a
/// failure on this try and keeps its retries, as is an early `0x06` (a
/// lost circuit, or the service's own connect timing out, which Tor does
/// not retry on an onion stream, `src/core/or/relay.c:892`). The dialer
/// tells which from the attempt's own run, against the earliest the
/// managed Tor's `SocksTimeout` can expire.
pub const fn proxy_reply_marks(reply: u16) -> u8 {
    let retry = matches!(
        reply,
        TOR_DESCRIPTOR_MISSING
            | TOR_INTRODUCTION_FAILED
            | TOR_RENDEZVOUS_TIMEOUT
            | TOR_INTRODUCTION_TIMEOUT
            | SOCKS_NETWORK_UNREACHABLE
            | SOCKS_HOST_UNREACHABLE
            | SOCKS_TTL_EXPIRED
    );
    let names = matches!(
        reply,
        SOCKS_GENERAL_FAILURE
            | SOCKS_HOST_UNREACHABLE
            | SOCKS_CONNECTION_REFUSED
            | TOR_DESCRIPTOR_MISSING
            | TOR_DESCRIPTOR_UNUSABLE
            | TOR_INTRODUCTION_FAILED
    );
    let window = retry;
    (if retry { Marks::RETRY } else { 0 })
        | (if names { Marks::NAMES_DESTINATION } else { 0 })
        | (if window { Marks::WINDOW_TIMEOUT } else { 0 })
}

/// Replies that mean the request this node sent, not the onion.
///
/// The dial path logs these at error. They are final and name nothing.
/// `0xF4` and `0xF5` are both client-authorization errors.
pub const fn socks_reply_is_our_request(reply: u16) -> bool {
    matches!(
        reply,
        SOCKS_COMMAND_NOT_SUPPORTED
            | SOCKS_ADDRESS_TYPE_NOT_SUPPORTED
            | TOR_CLIENT_AUTH_MISSING
            | TOR_CLIENT_AUTH_REJECTED
            | TOR_ONION_ADDRESS_REJECTED
    )
}

/// The `ProxyRefused` cause for `reply`, judged by this connector's table.
#[must_use]
pub const fn refused(reply: u16) -> CloseCause {
    CloseCause::proxy_refused(reply, proxy_reply_marks(reply))
}

/// What a reply from this node's Tor is evidence of (`DIALER_OUTAGE_EVIDENCE.md`
/// §3.2, `OE-D4`, the Tor lane reviews). A reply is before the channel, so
/// no stream opened.
///
/// Each retry is the reply table's above, unchanged: **Tor does Tor** (Rick,
/// 2026-10-31). Tor has already retried inside its own window before it
/// answers (another introduction point, another directory), so a reply it
/// gives as final is its definitive answer, and the dialer does not add a
/// redial over it. This is why `0x01`, `0x05` and `0xF1` stay final where
/// clearnet's refusal keeps its redial.
///
/// - **Destination:** general failure (`0x01`: a live service's port
///   refuses, after a working rendezvous), connection refused (`0x05`),
///   the unusable descriptor (`0xF1`). Final.
/// - **Local:** a command this node sent that Tor does not support
///   (`0x07`): independent of the destination.
/// - **Uncertain, inside the window:** host unreachable (`0x04`), TTL
///   expired (`0x06`, Tor's own window), the missing descriptor (`0xF0`),
///   the failed introduction (`0xF2`), the two timeouts (`0xF3`, `0xF7`),
///   and network unreachable (`0x03`; which stream-end reason produces it
///   on a rendezvous stream is for the Tor lane to ground, and Uncertain is
///   the safe bucket until then). Each can be the link or the onion.
/// - **Uncertain, final:** the address type (`0x08`), the rejected onion
///   address (`0xF6`), client authorization (`0xF4`, `0xF5`) and a ruleset
///   refusal (`0x02`). Each depends on the destination, so none is Local
///   under the ruled principle (`OE-D3`: Local is only for failures
///   independent of the destination); Uncertain or Destination is the Tor
///   lane's call, and Uncertain is the bucket that never counts an outage.
/// - **Any other reply:** Uncertain, final.
#[must_use]
pub const fn stamp_reply(reply: u16) -> DialFailure {
    let retry = if proxy_reply_marks(reply) & Marks::RETRY != 0 {
        Retry::AgainInsideWindow
    } else {
        Retry::Final
    };
    match reply {
        SOCKS_GENERAL_FAILURE | SOCKS_CONNECTION_REFUSED | TOR_DESCRIPTOR_UNUSABLE => {
            DialFailure::destination(retry, Reached::NoStream)
        }
        SOCKS_COMMAND_NOT_SUPPORTED => DialFailure::local(retry, Reached::NoStream),
        _ => DialFailure::uncertain(retry, Reached::NoStream),
    }
}

/// How a reply from this node's Tor ends a dial: the evidence, and the D12
/// cause beside it for the log.
#[must_use]
pub const fn reply_end(reply: u16) -> DialEnd {
    DialEnd::new(stamp_reply(reply), refused(reply))
}

/// What this connector's dial path saw before the channel, other than a
/// SOCKS reply ([`reply_end`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observed {
    /// This node's SOCKS port refused, errored, rejected authentication or
    /// answered malformed: this node's proxy, independent of the onion.
    ProxyUnavailable,
    /// The dial deadline ran out: the link or the onion.
    Deadline,
    /// This node's own failure: the engine, the socket table, an address
    /// this connector cannot dial.
    OwnFailure,
}

impl Observed {
    /// The end this connector reports for what it saw.
    #[must_use]
    pub const fn end(self) -> DialEnd {
        match self {
            Self::ProxyUnavailable => DialEnd::new(
                DialFailure::local(Retry::Again, Reached::NoStream),
                CloseCause::new(CloseKind::ProxyUnavailable),
            ),
            Self::Deadline => DialEnd::new(
                DialFailure::uncertain(Retry::AgainInsideWindow, Reached::NoStream),
                CloseCause::new(CloseKind::TransportTimeout),
            ),
            Self::OwnFailure => DialEnd::local_close(),
        }
    }
}

/// How an onion stream ended after it opened (§3.2), from what shared
/// code observed. Every Tor stream crosses the one guard link, so a
/// circuit that collapses with this node's link looks the same as an onion
/// that hangs up: each end is Uncertain and keeps its redial.
#[must_use]
pub const fn stamp_stream_end(end: StreamEnd) -> DialFailure {
    match end {
        StreamEnd::PeerClosed | StreamEnd::IoError | StreamEnd::SendQueueFull => {
            DialFailure::uncertain(Retry::Again, Reached::StreamOpened)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use shekyl_transport_layer::{Evidence, Proof};

    /// Tor's stamping of every reply (§3.2): the destination set, the one
    /// local reply, and Uncertain for the rest, each keeping the reply
    /// table's retry. No reply proves misbehaviour: it is the proxy's word.
    /// The edit that makes this red is moving any reply between buckets.
    #[test]
    fn each_onion_reply_is_stamped_with_its_evidence() {
        let destination = [0x01, 0x05, 0xF1];
        let local = [0x07];
        for reply in 0u16..=0x0100 {
            let failure = stamp_reply(reply);
            let expected = if destination.contains(&reply) {
                Evidence::Destination(Proof::ABSENT)
            } else if local.contains(&reply) {
                Evidence::Local
            } else {
                Evidence::Uncertain
            };
            assert_eq!(failure.evidence(), expected, "reply {reply:#x}");
            assert!(!failure.proves_misbehaviour(), "reply {reply:#x}");
            assert_eq!(failure.reached(), Reached::NoStream, "reply {reply:#x}");
            let retries = proxy_reply_marks(reply) & Marks::RETRY != 0;
            assert_eq!(
                failure.retry(),
                if retries {
                    Retry::AgainInsideWindow
                } else {
                    Retry::Final
                },
                "reply {reply:#x}"
            );
            assert_eq!(reply_end(reply).cause(), refused(reply));
        }
    }

    /// After the stream opened, every end shared code observes is
    /// Uncertain on Tor (the one guard link) and keeps its redial.
    #[test]
    fn an_onion_streams_end_is_uncertain() {
        for end in [
            StreamEnd::PeerClosed,
            StreamEnd::IoError,
            StreamEnd::SendQueueFull,
        ] {
            let failure = stamp_stream_end(end);
            assert_eq!(failure.evidence(), Evidence::Uncertain, "{end:?}");
            assert_eq!(failure.retry(), Retry::Again, "{end:?}");
            assert_eq!(failure.reached(), Reached::StreamOpened, "{end:?}");
        }
    }

    /// This connector's reply table (Rick, 2026-10-24; `0x01` final on
    /// 2026-10-25; the retry set read against Tor's window on 2026-10-26):
    /// the retry set, the final set, the destination-naming replies, and
    /// the replies the dialer reads against Tor's window (the retry set). No reply proves misbehaviour:
    /// a SOCKS reply is the proxy's word.
    #[test]
    fn the_onion_reply_table_marks_retries_finals_and_destination_naming() {
        let retry = [0xF0, 0xF2, 0xF3, 0xF7, 0x03, 0x04, 0x06];
        let final_ = [0x01, 0x05, 0xF1, 0xF4, 0xF5, 0xF6, 0x07, 0x08];
        let naming = [0x01, 0x04, 0x05, 0xF0, 0xF1, 0xF2];
        for reply in 0u16..=0x0100 {
            let cause = refused(reply);
            assert_eq!(cause.reply_code(), reply);
            assert_eq!(
                cause.retry_worthy(),
                retry.contains(&reply),
                "reply {reply:#x}"
            );
            if final_.contains(&reply) {
                assert!(!cause.retry_worthy(), "reply {reply:#x} is final");
            }
            assert_eq!(
                cause.names_the_destination(),
                naming.contains(&reply),
                "reply {reply:#x}"
            );
            assert_eq!(
                cause.window_timeout(),
                retry.contains(&reply),
                "reply {reply:#x}"
            );
            assert!(!cause.proves_misbehaviour(), "reply {reply:#x}");
            assert_eq!(
                socks_reply_is_our_request(reply),
                [0x07, 0x08, 0xF4, 0xF5, 0xF6].contains(&reply),
                "reply {reply:#x}"
            );
        }
    }
}
