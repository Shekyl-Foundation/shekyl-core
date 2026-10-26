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
    (3, TransportTimeout, BeforeChannel, Marks::RETRY | Marks::WINDOW_TIMEOUT, "SHEKYL_CLOSE_TRANSPORT_TIMEOUT"),
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
    /// A timeout of the dial's own window: our dial deadline, or the
    /// connector's word that its own window ran out. It does not decide a
    /// retry by itself, since the same timeout can come early (a lost
    /// circuit): the dialer reads it against the attempt's run time, and a
    /// failure at or after the connector's window is final within its test
    /// (the dialer in-flight bound, revision 4, Rick 2026-10-26).
    pub const WINDOW_TIMEOUT: u8 = 8;
    /// Every bit a cause may carry.
    pub const ALL: u8 =
        Self::RETRY | Self::NAMES_DESTINATION | Self::PROVES_MISBEHAVIOUR | Self::WINDOW_TIMEOUT;
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

    /// `ProxyRefused` with the overlay's reply code and the connector's
    /// judgement of it as `marks`. The reply table is the connector's (the
    /// Tor connector's `proxy_reply_marks`, Rick 2026-10-24); this crate
    /// holds no SOCKS knowledge. A proxy reply is the proxy's word, so it
    /// never proves misbehaviour: that mark, and any bit outside
    /// [`Marks::ALL`], is dropped here. An unreachable onion is this cause.
    #[must_use]
    pub const fn proxy_refused(reply_code: u16, marks: u8) -> Self {
        Self {
            kind: CloseKind::ProxyRefused,
            marks: marks & (Marks::RETRY | Marks::NAMES_DESTINATION | Marks::WINDOW_TIMEOUT),
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

    /// Whether this cause is a timeout of the dial's own window
    /// ([`Marks::WINDOW_TIMEOUT`]). The dialer reads it against the
    /// attempt's run time.
    #[must_use]
    pub const fn window_timeout(self) -> bool {
        self.marks & Marks::WINDOW_TIMEOUT != 0
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
    /// the peer that answered. [`CloseKind::ProxyRefused`] names the
    /// destination when the connector's reply table says the reply does:
    /// the Tor connector's `proxy_reply_marks` holds that table, and the
    /// mark arrives with [`Self::proxy_refused`].
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
    #[must_use]
    pub const fn names_the_destination(self) -> bool {
        self.marks & Marks::NAMES_DESTINATION != 0
    }

    /// Whether the dial's channel existed before this close.
    ///
    /// The D12 phase says so: a kind that applies once the channel exists,
    /// and not before it, reached a peer. A proxy reply is before the
    /// channel, so it never did. [`CloseKind::LocalClose`] applies in
    /// every phase, and a dial this node closed itself is not a stream
    /// that opened. This is display for the managed-Tor supervisor, never
    /// a verdict on the link (`TOR_SUPERVISOR.md` §1 `TSR-Q14`, §4.2).
    #[must_use]
    pub const fn opened_a_stream(self) -> bool {
        let kind = self.kind;
        kind.applies_in(Phase::Gap) && !kind.applies_in(Phase::BeforeChannel)
    }
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
#define SHEKYL_CLOSE_MARK_WINDOW_TIMEOUT {window}
",
        retry = Marks::RETRY,
        names = Marks::NAMES_DESTINATION,
        proves = Marks::PROVES_MISBEHAVIOUR,
        window = Marks::WINDOW_TIMEOUT,
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
        // A proxy reply carries the connector's marks, less proof: whatever
        // the connector hands in, the cause proves nothing and carries no
        // unknown bit.
        for marks in 0u8..=0xFF {
            let cause = CloseCause::proxy_refused(0x01, marks);
            assert_eq!(cause.marks() & !Marks::ALL, 0, "marks {marks:#x}");
            assert!(
                !cause.proves_misbehaviour(),
                "marks {marks:#x} prove nothing on a proxy reply"
            );
            assert_eq!(
                cause.retry_worthy(),
                marks & Marks::RETRY != 0,
                "marks {marks:#x}"
            );
            assert_eq!(
                cause.names_the_destination(),
                marks & Marks::NAMES_DESTINATION != 0,
                "marks {marks:#x}"
            );
            assert_eq!(
                cause.window_timeout(),
                marks & Marks::WINDOW_TIMEOUT != 0,
                "marks {marks:#x}"
            );
        }
    }

    /// Of the transport layer's own causes, only its dial deadline is a
    /// window timeout: the dialer reads it against the attempt's run time
    /// (revision 4, Rick 2026-10-26). It stays worth a retry by itself.
    #[test]
    fn only_the_transport_timeout_is_a_window_timeout() {
        for kind in CloseKind::ALL {
            if *kind == CloseKind::ProxyRefused {
                continue;
            }
            let cause = CloseCause::new(*kind);
            assert_eq!(
                cause.window_timeout(),
                *kind == CloseKind::TransportTimeout,
                "{kind:?}"
            );
        }
        assert!(CloseCause::new(CloseKind::TransportTimeout).retry_worthy());
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
        let proxy = CloseCause::proxy_refused(0x501, Marks::NONE);
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

    /// A stream opened only for a kind whose phase is the gap or after
    /// the channel. A proxy reply and this node's own close did not.
    #[test]
    fn a_stream_opened_only_once_the_channel_existed() {
        let opened = [
            CloseKind::LevinHandshakeTimeout,
            CloseKind::LevinHandshakeRejected,
            CloseKind::PeerClosed,
            CloseKind::RecordRejected,
            CloseKind::SessionRefused,
            CloseKind::IoError,
            CloseKind::SendQueueFull,
        ];
        for kind in CloseKind::ALL {
            let cause = if *kind == CloseKind::ProxyRefused {
                CloseCause::proxy_refused(0x06, Marks::RETRY)
            } else {
                CloseCause::new(*kind)
            };
            assert_eq!(cause.opened_a_stream(), opened.contains(kind), "{kind:?}");
        }
    }
}
