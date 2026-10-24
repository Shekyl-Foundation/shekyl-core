// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! D12's cause table. One enum. The C header is a projection of it.

use crate::declaration::{declaration, Assessment, DestinationAuth};
use crate::ConnectorId;

/// Where a cause may be recorded. `LocalClose` applies in every phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The channel does not exist yet.
    BeforeChannel,
    /// The channel exists and the Levin handshake is not done.
    Gap,
    /// The Levin handshake is done.
    AfterChannel,
}

/// Which row of the D12 table a cause belongs to.
///
/// [`PhaseClass::ChannelExists`] is the third row: any time after the
/// channel exists, which includes [`Phase::Gap`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PhaseClass {
    BeforeChannel,
    Gap,
    ChannelExists,
    Every,
}

macro_rules! close_kinds {
    ($(($disc:literal, $name:ident, $phase:ident, $marks:expr, $c_name:literal),)*) => {
        /// The D12 discriminant. Fieldless so the header can name each one.
        #[repr(u8)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum CloseKind {
            $($name = $disc,)*
        }

        impl CloseKind {
            pub const ALL: &'static [CloseKind] = &[$(Self::$name,)*];

            pub const fn code(self) -> u8 {
                match self {
                    $(Self::$name => $disc,)*
                }
            }

            /// The discriminant, or `None` when `code` is not in the table.
            #[must_use]
            pub const fn from_code(code: u8) -> Option<Self> {
                match code {
                    $($disc => Some(Self::$name),)*
                    _ => None,
                }
            }

            pub const fn c_name(self) -> &'static str {
                match self {
                    $(Self::$name => $c_name,)*
                }
            }

            /// The kind's name, NUL-terminated, for the C side's log
            /// lines: one table, so a new kind is named everywhere.
            #[must_use]
            pub const fn name_nul(self) -> &'static str {
                match self {
                    $(Self::$name => concat!(stringify!($name), "\0"),)*
                }
            }

            const fn phase_class(self) -> PhaseClass {
                match self {
                    $(Self::$name => PhaseClass::$phase,)*
                }
            }

            /// The transport layer's judgement of this kind, as the marks
            /// a cause of it carries by default. A `ProxyRefused` is judged
            /// by its reply instead ([`CloseCause::proxy_refused`]).
            const fn default_marks(self) -> u8 {
                match self {
                    $(Self::$name => $marks,)*
                }
            }

            /// Whether this cause is in that row of the D12 table.
            #[must_use]
            pub const fn applies_in(self, phase: Phase) -> bool {
                match self.phase_class() {
                    PhaseClass::Every => true,
                    PhaseClass::BeforeChannel => matches!(phase, Phase::BeforeChannel),
                    PhaseClass::Gap => matches!(phase, Phase::Gap),
                    PhaseClass::ChannelExists => {
                        matches!(phase, Phase::Gap | Phase::AfterChannel)
                    }
                }
            }
        }
    };
}

// The marks column is the transport layer's judgement of each kind (the
// gray lifecycle, Rick 2026-10-24): a connection problem is worth a retry;
// a cause that is the far side answering about this destination names it;
// nothing here proves misbehaviour, because this layer cannot tell a peer
// from an on-path party. The Levin layer adds that mark where its
// connector authenticates the destination.
close_kinds! {
    (1, PrefixMismatch, BeforeChannel, Marks::NONE, "SHEKYL_CLOSE_PREFIX_MISMATCH"),
    (2, TransportHandshakeFailed, BeforeChannel, Marks::NONE, "SHEKYL_CLOSE_TRANSPORT_HANDSHAKE_FAILED"),
    (3, TransportTimeout, BeforeChannel, Marks::RETRY, "SHEKYL_CLOSE_TRANSPORT_TIMEOUT"),
    (4, AdmissionRefused, BeforeChannel, Marks::NONE, "SHEKYL_CLOSE_ADMISSION_REFUSED"),
    (5, DialFailed, BeforeChannel, Marks::RETRY, "SHEKYL_CLOSE_DIAL_FAILED"),
    (6, ProxyRefused, BeforeChannel, Marks::NONE, "SHEKYL_CLOSE_PROXY_REFUSED"),
    (7, LevinHandshakeTimeout, Gap, Marks::RETRY, "SHEKYL_CLOSE_LEVIN_HANDSHAKE_TIMEOUT"),
    (8, LevinHandshakeRejected, Gap, Marks::NAMES_DESTINATION, "SHEKYL_CLOSE_LEVIN_HANDSHAKE_REJECTED"),
    (9, PeerClosed, ChannelExists, Marks::RETRY, "SHEKYL_CLOSE_PEER_CLOSED"),
    (10, RecordRejected, ChannelExists, Marks::NONE, "SHEKYL_CLOSE_RECORD_REJECTED"),
    (11, SessionRefused, ChannelExists, Marks::NONE, "SHEKYL_CLOSE_SESSION_REFUSED"),
    (12, IoError, ChannelExists, Marks::RETRY, "SHEKYL_CLOSE_IO_ERROR"),
    (13, SendQueueFull, ChannelExists, Marks::NONE, "SHEKYL_CLOSE_SEND_QUEUE_FULL"),
    (14, LocalClose, Every, Marks::NONE, "SHEKYL_CLOSE_LOCAL_CLOSE"),
    (15, InboundNotAccepted, BeforeChannel, Marks::NONE, "SHEKYL_CLOSE_INBOUND_NOT_ACCEPTED"),
    (16, ProxyUnavailable, BeforeChannel, Marks::RETRY, "SHEKYL_CLOSE_PROXY_UNAVAILABLE"),
}

/// The three marks a layer stamps on its own causes (the gray lifecycle,
/// Rick 2026-10-24). The redialer and the peer lists read only these.
/// They sit in the byte at offset 1 of [`CloseCause`], which the C header
/// projects as `marks`, and nowhere else.
pub struct Marks;

impl Marks {
    /// No mark: final, names nothing, proves nothing.
    pub const NONE: u8 = 0;
    /// A connection problem: the same destination is worth another attempt
    /// within the test.
    pub const RETRY: u8 = 1;
    /// The far side answered about this destination: the cause is evidence
    /// about the address that was dialed, not about the path to it.
    pub const NAMES_DESTINATION: u8 = 2;
    /// Authenticated proof that the peer misbehaved. Only a layer whose
    /// connector authenticates the destination may set it.
    pub const PROVES_MISBEHAVIOUR: u8 = 4;
    /// Every bit a cause may carry.
    pub const ALL: u8 = Self::RETRY | Self::NAMES_DESTINATION | Self::PROVES_MISBEHAVIOUR;
}

/// One close cause. `reply_code` is the overlay reply for
/// [`CloseKind::ProxyRefused`] and zero for every other kind. `marks` is
/// the layers' judgement of it ([`Marks`]).
///
/// `repr(C)` is the layout `shekyl_close_cause` projects. The header's
/// size and field offsets are these constants, so a Rust layout change
/// and a C typedef that no longer matches both fail.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseCause {
    kind: CloseKind,
    marks: u8,
    reply_code: u16,
}

const CLOSE_CAUSE_SIZE: usize = 4;
const CLOSE_CAUSE_ALIGN: usize = 2;
const CLOSE_CAUSE_KIND_OFFSET: usize = 0;
const CLOSE_CAUSE_MARKS_OFFSET: usize = 1;
const CLOSE_CAUSE_REPLY_OFFSET: usize = 2;

const _: () = {
    assert!(std::mem::size_of::<CloseCause>() == CLOSE_CAUSE_SIZE);
    assert!(std::mem::align_of::<CloseCause>() == CLOSE_CAUSE_ALIGN);
    assert!(std::mem::offset_of!(CloseCause, kind) == CLOSE_CAUSE_KIND_OFFSET);
    assert!(std::mem::offset_of!(CloseCause, marks) == CLOSE_CAUSE_MARKS_OFFSET);
    assert!(std::mem::offset_of!(CloseCause, reply_code) == CLOSE_CAUSE_REPLY_OFFSET);
};

impl CloseCause {
    /// A cause other than [`CloseKind::ProxyRefused`].
    ///
    /// `ProxyRefused` is [`Self::proxy_refused`]: it carries the overlay
    /// reply code. Passing that kind here is a programming error.
    #[must_use]
    pub const fn new(kind: CloseKind) -> Self {
        assert!(
            !matches!(kind, CloseKind::ProxyRefused),
            "ProxyRefused carries the overlay reply code"
        );
        Self {
            kind,
            marks: kind.default_marks(),
            reply_code: 0,
        }
    }

    /// `ProxyRefused` with the overlay's reply code, judged by the SOCKS
    /// layer's reply table ([`proxy_reply_marks`]). An unreachable onion
    /// is this cause.
    #[must_use]
    pub const fn proxy_refused(reply_code: u16) -> Self {
        Self {
            kind: CloseKind::ProxyRefused,
            marks: proxy_reply_marks(reply_code),
            reply_code,
        }
    }

    /// The Levin layer's stamp: this cause names the destination, and
    /// `connector` authenticates the destination, so what it names is the
    /// peer itself and the cause proves its misbehaviour. On a connector
    /// that does not authenticate, or a cause that names nothing, the
    /// cause is returned unchanged: an on-path party could have answered.
    ///
    /// [`Declaration::destination_authenticated`]: crate::Declaration::destination_authenticated
    #[must_use]
    pub const fn proving_misbehaviour_on(mut self, connector: ConnectorId) -> Self {
        let authenticated = match declaration(connector.column()).destination_authenticated() {
            Assessment::Assessed(DestinationAuth::OneWay) => true,
            Assessment::Assessed(DestinationAuth::No) | Assessment::NotAssessed => false,
        };
        if authenticated && self.names_the_destination() {
            self.marks |= Marks::PROVES_MISBEHAVIOUR;
        }
        self
    }

    /// The marks this cause carries ([`Marks`]).
    #[must_use]
    pub const fn marks(self) -> u8 {
        self.marks
    }

    /// Whether the layer that closed judged the destination worth another
    /// attempt within the same test: a connection problem, not an answer.
    #[must_use]
    pub const fn retry_worthy(self) -> bool {
        self.marks & Marks::RETRY != 0
    }

    /// Whether the layer that closed proved the peer misbehaved. Only an
    /// authenticated destination can be proven; the peer lists drop an
    /// address on this mark and on nothing else.
    #[must_use]
    pub const fn proves_misbehaviour(self) -> bool {
        self.marks & Marks::PROVES_MISBEHAVIOUR != 0
    }

    #[must_use]
    pub const fn kind(self) -> CloseKind {
        self.kind
    }

    #[must_use]
    pub const fn reply_code(self) -> u16 {
        self.reply_code
    }

    /// Whether this cause is evidence about the address that was dialed.
    ///
    /// [`CloseKind::LevinHandshakeRejected`] is the Levin layer judging
    /// the peer that answered. [`CloseKind::ProxyRefused`] counts for the
    /// replies that name the destination: RFC 1928 host unreachable
    /// (`0x04`) and connection refused (`0x05`), and the Tor SOCKS
    /// extended codes for a descriptor that is missing (`0xF0`) or
    /// unusable (`0xF1`) and an introduction that failed (`0xF2`).
    /// Introduction and rendezvous timeouts (`0xF7`, `0xF3`), general
    /// failure, a ruleset, network unreachable, and TTL expired do not.
    /// A command or address type this node sent (`0x07`, `0x08`), an onion
    /// address Tor rejected (`0xF6`; we validate it before dialing), and
    /// client-authorization errors (`0xF4`, `0xF5`) do not either. Any
    /// other reply does not.
    ///
    /// [`CloseKind::DialFailed`] does not. It is a direct connect that was
    /// refused, and on a proxied dial that connect is to this node's own
    /// SOCKS port, which says nothing about the destination.
    /// [`CloseKind::ProxyUnavailable`] does not: it is this node's own SOCKS
    /// proxy failing, a TCP connect to it that failed or an exchange it
    /// closed without a reply (Rick, 2026-10-14), and it names the proxy,
    /// never the onion. Every other
    /// kind is a timeout, this node's own close, or the peer's ordinary
    /// end of file.
    ///
    /// The extended codes arrive only when the managed `SocksPort` asks
    /// for them (`auto ExtendedErrors`). Tor 0.4.9.11 leaves that off
    /// (`port_cfg_new`), and without it `stream_end_reason_to_socks5_response`
    /// reports an introduction timeout as reply 4.
    #[must_use]
    pub const fn names_the_destination(self) -> bool {
        self.marks & Marks::NAMES_DESTINATION != 0
    }
}

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

/// The SOCKS layer's judgement of an onion reply, as marks (the Tor
/// connector's table, Rick 2026-10-24).
///
/// Worth a retry: a missing descriptor (`0xF0`), a failed introduction
/// (`0xF2`), the two timeouts (`0xF3`, `0xF7`), general failure (`0x01`),
/// network unreachable (`0x03`), host unreachable (`0x04`) and TTL expired
/// (`0x06`): each can be the network or the directory on this try. Final:
/// connection refused (`0x05`) and an unusable descriptor (`0xF1`), which
/// the destination answered; the client-authorization errors (`0xF4`,
/// `0xF5`), the rejected onion address (`0xF6`), and a command or address
/// type this node sent (`0x07`, `0x08`), which are this node's request.
/// Names the destination: host unreachable, connection refused, the
/// missing or unusable descriptor, the failed introduction. Nothing here
/// proves misbehaviour: a SOCKS reply is the proxy's word.
pub const fn proxy_reply_marks(reply: u16) -> u8 {
    let retry = matches!(
        reply,
        TOR_DESCRIPTOR_MISSING
            | TOR_INTRODUCTION_FAILED
            | TOR_RENDEZVOUS_TIMEOUT
            | TOR_INTRODUCTION_TIMEOUT
            | SOCKS_GENERAL_FAILURE
            | SOCKS_NETWORK_UNREACHABLE
            | SOCKS_HOST_UNREACHABLE
            | SOCKS_TTL_EXPIRED
    );
    let names = matches!(
        reply,
        SOCKS_HOST_UNREACHABLE
            | SOCKS_CONNECTION_REFUSED
            | TOR_DESCRIPTOR_MISSING
            | TOR_DESCRIPTOR_UNUSABLE
            | TOR_INTRODUCTION_FAILED
    );
    (if retry { Marks::RETRY } else { 0 }) | (if names { Marks::NAMES_DESTINATION } else { 0 })
}

/// Replies that mean the request this node sent, not the onion.
///
/// The dial path logs these at error. They do not forget the address.
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

const HEADER_PREAMBLE: &str = "\
// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
// Generated from shekyl_transport_layer::CloseKind. Do not edit.
// The Rust enum is the cause table. This header is the projection
// shekyl_ffi.h includes. A test fails if the two differ.

#ifndef SHEKYL_CLOSE_CAUSE_H
#define SHEKYL_CLOSE_CAUSE_H

#include <stddef.h>
#include <stdint.h>

/* One close cause. reply_code is the overlay reply for
   SHEKYL_CLOSE_PROXY_REFUSED and zero for every other kind. marks is
   the layers' judgement of the cause: SHEKYL_CLOSE_MARK_* bits.
   The size and offsets below are CloseCause's. */
typedef struct shekyl_close_cause {
    uint8_t kind;
    uint8_t marks;
    uint16_t reply_code;
} shekyl_close_cause;

";

/// The C header `shekyl_ffi.h` includes. Discriminants come from
/// [`CloseKind::ALL`]. Size and offsets come from [`CloseCause`].
#[must_use]
pub fn c_header() -> String {
    let mut out = String::from(HEADER_PREAMBLE);
    use std::fmt::Write as _;
    writeln!(
        out,
        "\
#if defined(__cplusplus)
static_assert(sizeof(shekyl_close_cause) == {CLOSE_CAUSE_SIZE}, \"close cause size\");
static_assert(offsetof(shekyl_close_cause, kind) == {CLOSE_CAUSE_KIND_OFFSET}, \"close cause kind\");
static_assert(offsetof(shekyl_close_cause, marks) == {CLOSE_CAUSE_MARKS_OFFSET}, \"close cause marks\");
static_assert(offsetof(shekyl_close_cause, reply_code) == {CLOSE_CAUSE_REPLY_OFFSET}, \"close cause reply_code\");
#else
_Static_assert(sizeof(shekyl_close_cause) == {CLOSE_CAUSE_SIZE}, \"close cause size\");
_Static_assert(offsetof(shekyl_close_cause, kind) == {CLOSE_CAUSE_KIND_OFFSET}, \"close cause kind\");
_Static_assert(offsetof(shekyl_close_cause, marks) == {CLOSE_CAUSE_MARKS_OFFSET}, \"close cause marks\");
_Static_assert(offsetof(shekyl_close_cause, reply_code) == {CLOSE_CAUSE_REPLY_OFFSET}, \"close cause reply_code\");
#endif
#define SHEKYL_CLOSE_MARK_RETRY {retry}
#define SHEKYL_CLOSE_MARK_NAMES_DESTINATION {names}
#define SHEKYL_CLOSE_MARK_PROVES_MISBEHAVIOUR {proves}
",
        retry = Marks::RETRY,
        names = Marks::NAMES_DESTINATION,
        proves = Marks::PROVES_MISBEHAVIOUR,
    )
    .expect("header write");
    for kind in CloseKind::ALL {
        writeln!(out, "#define {} {}", kind.c_name(), kind.code()).expect("header write");
    }
    out.push_str("#endif\n");
    out
}

#[cfg(test)]
mod tests {
    use super::{c_header, CloseCause, CloseKind, Marks, Phase};
    use crate::ConnectorId;

    #[test]
    fn the_header_is_the_enum() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../src/shekyl/close_cause.h"
        );
        let header = std::fs::read_to_string(path).expect("close cause header");
        assert_eq!(header, c_header());
    }

    #[test]
    fn each_cause_sits_in_its_d12_row() {
        let before = [
            CloseKind::PrefixMismatch,
            CloseKind::TransportHandshakeFailed,
            CloseKind::TransportTimeout,
            CloseKind::AdmissionRefused,
            CloseKind::DialFailed,
            CloseKind::ProxyRefused,
            CloseKind::LocalClose,
            CloseKind::InboundNotAccepted,
            CloseKind::ProxyUnavailable,
        ];
        let gap = [
            CloseKind::LevinHandshakeTimeout,
            CloseKind::LevinHandshakeRejected,
            CloseKind::PeerClosed,
            CloseKind::RecordRejected,
            CloseKind::SessionRefused,
            CloseKind::IoError,
            CloseKind::SendQueueFull,
            CloseKind::LocalClose,
        ];
        let after = [
            CloseKind::PeerClosed,
            CloseKind::RecordRejected,
            CloseKind::SessionRefused,
            CloseKind::IoError,
            CloseKind::SendQueueFull,
            CloseKind::LocalClose,
        ];
        assert_eq!(kinds_in(Phase::BeforeChannel), before);
        assert_eq!(kinds_in(Phase::Gap), gap);
        assert_eq!(kinds_in(Phase::AfterChannel), after);
    }

    fn kinds_in(phase: Phase) -> Vec<CloseKind> {
        CloseKind::ALL
            .iter()
            .copied()
            .filter(|kind| kind.applies_in(phase))
            .collect()
    }

    /// Every cause's marks are in [`Marks::ALL`], and nothing the transport
    /// layer constructs proves misbehaviour: that mark is the Levin
    /// layer's, on an authenticating connector.
    #[test]
    fn no_constructed_cause_proves_misbehaviour() {
        for kind in CloseKind::ALL {
            // `ProxyRefused` carries a reply; every reply is the loop below.
            if *kind == CloseKind::ProxyRefused {
                continue;
            }
            let cause = CloseCause::new(*kind);
            assert_eq!(
                cause.marks() & !Marks::ALL,
                0,
                "{kind:?} carries unknown bits"
            );
            assert!(
                !cause.proves_misbehaviour(),
                "{kind:?} proves nothing by itself"
            );
        }
        for reply in 0u16..=0x0100 {
            let cause = CloseCause::proxy_refused(reply);
            assert_eq!(cause.marks() & !Marks::ALL, 0);
            assert!(
                !cause.proves_misbehaviour(),
                "reply {reply:#x} proves nothing"
            );
        }
    }

    /// The transport layer's own table: connection problems are worth a
    /// retry, answers are not, and only a rejection names the destination.
    #[test]
    fn a_connection_problem_is_worth_a_retry_and_an_answer_is_not() {
        let retry = [
            CloseKind::TransportTimeout,
            CloseKind::DialFailed,
            CloseKind::LevinHandshakeTimeout,
            CloseKind::PeerClosed,
            CloseKind::IoError,
            CloseKind::ProxyUnavailable,
        ];
        for kind in CloseKind::ALL {
            if *kind == CloseKind::ProxyRefused {
                continue;
            }
            let cause = CloseCause::new(*kind);
            assert_eq!(cause.retry_worthy(), retry.contains(kind), "{kind:?}");
            assert_eq!(
                cause.names_the_destination(),
                *kind == CloseKind::LevinHandshakeRejected,
                "{kind:?}"
            );
        }
    }

    /// The Tor connector's reply table (Rick, 2026-10-24): the retry set,
    /// the final set, and the five destination-naming replies.
    #[test]
    fn the_onion_reply_table_marks_retries_finals_and_destination_naming() {
        let retry = [0xF0, 0xF2, 0xF3, 0xF7, 0x01, 0x03, 0x04, 0x06];
        let final_ = [0x05, 0xF1, 0xF4, 0xF5, 0xF6, 0x07, 0x08];
        let naming = [0x04, 0x05, 0xF0, 0xF1, 0xF2];
        for reply in 0u16..=0x0100 {
            let cause = CloseCause::proxy_refused(reply);
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
        }
    }

    /// The Levin layer's stamp follows the connector's authentication: a
    /// rejection proves misbehaviour on Tor and not on clearnet, and a cause
    /// that names nothing is never stamped.
    #[test]
    fn proof_of_misbehaviour_follows_destination_authentication() {
        let rejected = CloseCause::new(CloseKind::LevinHandshakeRejected);
        assert!(rejected
            .proving_misbehaviour_on(ConnectorId::Tor)
            .proves_misbehaviour());
        assert!(!rejected
            .proving_misbehaviour_on(ConnectorId::Clearnet)
            .proves_misbehaviour());
        let timeout = CloseCause::new(CloseKind::TransportTimeout);
        assert!(!timeout
            .proving_misbehaviour_on(ConnectorId::Tor)
            .proves_misbehaviour());
        assert_eq!(timeout.proving_misbehaviour_on(ConnectorId::Tor), timeout);
    }

    #[test]
    fn proxy_refused_carries_the_reply_code_and_other_causes_do_not() {
        let proxy = CloseCause::proxy_refused(0x501);
        assert_eq!(proxy.kind(), CloseKind::ProxyRefused);
        assert_eq!(proxy.reply_code(), 0x501);
        for kind in CloseKind::ALL {
            if *kind == CloseKind::ProxyRefused {
                continue;
            }
            assert_eq!(CloseCause::new(*kind).reply_code(), 0);
        }
    }

    #[test]
    fn local_close_applies_in_every_phase() {
        assert!(CloseKind::LocalClose.applies_in(Phase::BeforeChannel));
        assert!(CloseKind::LocalClose.applies_in(Phase::Gap));
        assert!(CloseKind::LocalClose.applies_in(Phase::AfterChannel));
        assert!(!CloseKind::DialFailed.applies_in(Phase::AfterChannel));
        assert!(!CloseKind::DialFailed.applies_in(Phase::Gap));
        assert!(!CloseKind::PeerClosed.applies_in(Phase::BeforeChannel));
        assert!(CloseKind::PeerClosed.applies_in(Phase::Gap));
        assert!(CloseKind::PeerClosed.applies_in(Phase::AfterChannel));
        assert!(CloseKind::LevinHandshakeTimeout.applies_in(Phase::Gap));
        assert!(!CloseKind::LevinHandshakeTimeout.applies_in(Phase::AfterChannel));
    }

    #[test]
    #[should_panic(expected = "ProxyRefused carries the overlay reply code")]
    fn a_proxy_refusal_without_a_reply_code_is_not_a_cause() {
        let _cause = CloseCause::new(CloseKind::ProxyRefused);
    }
}
