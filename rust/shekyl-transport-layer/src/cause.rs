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
    ($(($disc:literal, $name:ident, $phase:ident, $c_name:literal),)*) => {
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

close_kinds! {
    (1, PrefixMismatch, BeforeChannel, "SHEKYL_CLOSE_PREFIX_MISMATCH"),
    (2, TransportHandshakeFailed, BeforeChannel, "SHEKYL_CLOSE_TRANSPORT_HANDSHAKE_FAILED"),
    (3, TransportTimeout, BeforeChannel, "SHEKYL_CLOSE_TRANSPORT_TIMEOUT"),
    (4, AdmissionRefused, BeforeChannel, "SHEKYL_CLOSE_ADMISSION_REFUSED"),
    (5, DialFailed, BeforeChannel, "SHEKYL_CLOSE_DIAL_FAILED"),
    (6, ProxyRefused, BeforeChannel, "SHEKYL_CLOSE_PROXY_REFUSED"),
    (7, LevinHandshakeTimeout, Gap, "SHEKYL_CLOSE_LEVIN_HANDSHAKE_TIMEOUT"),
    (8, LevinHandshakeRejected, Gap, "SHEKYL_CLOSE_LEVIN_HANDSHAKE_REJECTED"),
    (9, PeerClosed, ChannelExists, "SHEKYL_CLOSE_PEER_CLOSED"),
    (10, RecordRejected, ChannelExists, "SHEKYL_CLOSE_RECORD_REJECTED"),
    (11, SessionRefused, ChannelExists, "SHEKYL_CLOSE_SESSION_REFUSED"),
    (12, IoError, ChannelExists, "SHEKYL_CLOSE_IO_ERROR"),
    (13, SendQueueFull, ChannelExists, "SHEKYL_CLOSE_SEND_QUEUE_FULL"),
    (14, LocalClose, Every, "SHEKYL_CLOSE_LOCAL_CLOSE"),
    (15, InboundNotAccepted, BeforeChannel, "SHEKYL_CLOSE_INBOUND_NOT_ACCEPTED"),
    (16, ProxyUnavailable, BeforeChannel, "SHEKYL_CLOSE_PROXY_UNAVAILABLE"),
}

/// One close cause. `reply_code` is the overlay reply for
/// [`CloseKind::ProxyRefused`] and zero for every other kind.
///
/// `repr(C)` is the layout `shekyl_close_cause` projects. The header's
/// size and field offsets are these constants, so a Rust layout change
/// and a C typedef that no longer matches both fail.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseCause {
    kind: CloseKind,
    reply_code: u16,
}

const CLOSE_CAUSE_SIZE: usize = 4;
const CLOSE_CAUSE_ALIGN: usize = 2;
const CLOSE_CAUSE_KIND_OFFSET: usize = 0;
const CLOSE_CAUSE_REPLY_OFFSET: usize = 2;

const _: () = {
    assert!(std::mem::size_of::<CloseCause>() == CLOSE_CAUSE_SIZE);
    assert!(std::mem::align_of::<CloseCause>() == CLOSE_CAUSE_ALIGN);
    assert!(std::mem::offset_of!(CloseCause, kind) == CLOSE_CAUSE_KIND_OFFSET);
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
            reply_code: 0,
        }
    }

    /// `ProxyRefused` with the overlay's reply code. An unreachable onion
    /// is this cause.
    #[must_use]
    pub const fn proxy_refused(reply_code: u16) -> Self {
        Self {
            kind: CloseKind::ProxyRefused,
            reply_code,
        }
    }

    #[must_use]
    pub const fn kind(self) -> CloseKind {
        self.kind
    }

    #[must_use]
    pub const fn reply_code(self) -> u16 {
        self.reply_code
    }

    /// Whether remembering this cause should stop us dialing the address.
    ///
    /// Forgetting shrinks the dial set, and a shrunken set favours whoever
    /// is feeding us addresses. So the memory is written only when both of
    /// these hold (Rick, 2026-10-13):
    ///
    /// 1. The cause names the destination ([`Self::names_the_destination`]).
    /// 2. The connector's declaration says the destination is
    ///    authenticated to the dialer
    ///    ([`Declaration::destination_authenticated`]), so a party on the
    ///    path cannot produce that cause for an honest address.
    ///
    /// Clearnet authenticates no one (Noise NN), so no clearnet cause
    /// counts (R2, 2026-10-12): a party on the path can forge a reset and
    /// can forge a handshake rejection, and either would suppress an
    /// honest address. An onion address is the service's key, so on Tor
    /// the destination-naming causes count.
    ///
    /// The connector is read as data, not matched by name: a later
    /// connector gets its answer from its declaration column.
    ///
    /// [`Declaration::destination_authenticated`]: crate::Declaration::destination_authenticated
    #[must_use]
    pub const fn implicates_address(self, connector: ConnectorId) -> bool {
        let authenticated = match declaration(connector.column()).destination_authenticated() {
            Assessment::Assessed(DestinationAuth::OneWay) => true,
            Assessment::Assessed(DestinationAuth::No) | Assessment::NotAssessed => false,
        };
        authenticated && self.names_the_destination()
    }

    /// Whether this cause is evidence about the address that was dialed.
    ///
    /// [`CloseKind::LevinHandshakeRejected`] is the Levin layer judging
    /// the peer that answered. [`CloseKind::ProxyRefused`] counts for the
    /// replies that name the destination on an onion dial. RFC 1928 §6
    /// `0x01` is a general SOCKS server failure: the proxy's report, not
    /// the destination's. On an onion dial Tor sends that byte when a live
    /// service's target port refuses, within a second, and only after a
    /// working rendezvous. A blocked link never produced it (shekyl-dev
    /// `data/tsr-acceptance/2026-10-25-socks-reply-sources`, and both case A
    /// runs of 2026-10-25). [`implicates_address`] still requires the
    /// connector to authenticate the destination, so a clearnet dial
    /// remembers none of these replies. Host unreachable (`0x04`) and
    /// connection refused (`0x05`) name the destination in the RFC itself.
    /// Tor's extended codes do for a descriptor that is missing (`0xF0`) or
    /// unusable (`0xF1`) and an introduction that failed (`0xF2`).
    /// Introduction and rendezvous timeouts (`0xF7`, `0xF3`), a
    /// ruleset, network unreachable, and TTL expired do not: a blocked link
    /// answers `0x06` too, and remembering it would drop every peer.
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
        match self.kind {
            CloseKind::LevinHandshakeRejected => true,
            CloseKind::ProxyRefused => proxy_reply_names_the_destination(self.reply_code),
            _ => false,
        }
    }

    /// Whether the dial's proxied stream opened before it closed: a
    /// transport or Levin exchange that failed, a peer's close, a refused
    /// record or session all needed one. Every other kind is a dial that
    /// never reached a peer. This is the only thing a Tor dial's close says
    /// to the managed-Tor supervisor, and it is display, never a verdict
    /// on the link (`TOR_SUPERVISOR.md` §1 `TSR-Q14`, §4.2): which reply a
    /// failed onion dial gets is the destination's to choose as much as the
    /// link's (shekyl-dev `data/tsr-acceptance/2026-10-25-socks-reply-sources`).
    #[must_use]
    pub const fn opened_a_stream(self) -> bool {
        matches!(
            self.kind,
            CloseKind::PrefixMismatch
                | CloseKind::TransportHandshakeFailed
                | CloseKind::LevinHandshakeTimeout
                | CloseKind::LevinHandshakeRejected
                | CloseKind::PeerClosed
                | CloseKind::RecordRejected
                | CloseKind::SessionRefused
                | CloseKind::IoError
                | CloseKind::SendQueueFull
        )
    }
}

/// RFC 1928 §6: general SOCKS server failure. That is the proxy's report,
/// not a statement about the destination. On an onion dial Tor uses this
/// byte for a live service whose target port refuses, within a second and
/// only after a working rendezvous. A clearnet dial does not remember it:
/// [`CloseCause::implicates_address`] requires destination authentication.
const SOCKS_GENERAL_FAILURE: u16 = 0x01;
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

/// Onion SOCKS replies that name the destination.
///
/// `0x01` is here for an onion dial only. RFC 1928 calls it a general
/// SOCKS server failure, and Tor sends it when a live service's port
/// refuses. Host unreachable and connection refused name the destination
/// in the RFC. Tor's extended codes cover a missing or unusable descriptor
/// and a failed introduction. A clearnet connector never consults this
/// list ([`CloseCause::implicates_address`]).
const fn proxy_reply_names_the_destination(reply: u16) -> bool {
    matches!(
        reply,
        SOCKS_GENERAL_FAILURE
            | SOCKS_HOST_UNREACHABLE
            | SOCKS_CONNECTION_REFUSED
            | TOR_DESCRIPTOR_MISSING
            | TOR_DESCRIPTOR_UNUSABLE
            | TOR_INTRODUCTION_FAILED
    )
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
   SHEKYL_CLOSE_PROXY_REFUSED and zero for every other kind.
   The size and offsets below are CloseCause's. */
typedef struct shekyl_close_cause {
    uint8_t kind;
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
static_assert(offsetof(shekyl_close_cause, reply_code) == {CLOSE_CAUSE_REPLY_OFFSET}, \"close cause reply_code\");
#else
_Static_assert(sizeof(shekyl_close_cause) == {CLOSE_CAUSE_SIZE}, \"close cause size\");
_Static_assert(offsetof(shekyl_close_cause, kind) == {CLOSE_CAUSE_KIND_OFFSET}, \"close cause kind\");
_Static_assert(offsetof(shekyl_close_cause, reply_code) == {CLOSE_CAUSE_REPLY_OFFSET}, \"close cause reply_code\");
#endif
",
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
    use super::{c_header, CloseCause, CloseKind, Phase};
    use crate::declaration::{declaration, Assessment, DestinationAuth};
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

    /// The connector is read from its declaration: the answer follows the
    /// `destination_authenticated` cell, for every connector the table has.
    #[test]
    fn a_destination_naming_cause_counts_exactly_where_the_destination_is_authenticated() {
        let naming = CloseCause::new(CloseKind::LevinHandshakeRejected);
        assert!(naming.names_the_destination());
        for connector in ConnectorId::ALL {
            let authenticated = matches!(
                declaration(connector.column()).destination_authenticated(),
                Assessment::Assessed(DestinationAuth::OneWay)
            );
            assert_eq!(
                naming.implicates_address(*connector),
                authenticated,
                "{connector:?}"
            );
        }
        // Both answers are present in the table, so the loop tested both.
        assert!(naming.implicates_address(ConnectorId::Tor));
        assert!(!naming.implicates_address(ConnectorId::Clearnet));
    }

    /// R2: no cause writes the failed-address memory on clearnet. That
    /// covers every kind, the two that wrote it before
    /// (`DialFailed`, `LevinHandshakeRejected`) by name, and every proxy
    /// reply.
    #[test]
    fn no_clearnet_cause_implicates_the_address() {
        for kind in CloseKind::ALL {
            // `ProxyRefused` carries a reply; every reply is the loop below.
            if *kind == CloseKind::ProxyRefused {
                continue;
            }
            assert!(
                !CloseCause::new(*kind).implicates_address(ConnectorId::Clearnet),
                "{kind:?} on clearnet must leave the address dialable"
            );
        }
        for kind in [CloseKind::DialFailed, CloseKind::LevinHandshakeRejected] {
            assert!(CloseKind::ALL.contains(&kind), "{kind:?} is in ALL");
            assert!(!CloseCause::new(kind).implicates_address(ConnectorId::Clearnet));
        }
        for reply in 0u16..=0x0100 {
            assert!(
                !CloseCause::proxy_refused(reply).implicates_address(ConnectorId::Clearnet),
                "clearnet reply {reply:#x} must stay dialable"
            );
        }
    }

    /// On Tor exactly seven causes write the memory: a rejected handshake,
    /// and the six proxy replies `0x01`, `0x04`, `0x05`, `0xF0`, `0xF1`,
    /// `0xF2`. No other kind does: `DialFailed` on an onion dial is this
    /// node's SOCKS port. `0x06`, `0xF3` and `0xF7` stay dialable: a blocked
    /// link answers `0x06` too. This does not launch Tor and does not cover
    /// the directory attacker who can force reply 4.
    #[test]
    fn an_onion_dial_implicates_a_rejection_and_the_six_destination_naming_replies() {
        let mut counted = 0;
        for kind in CloseKind::ALL {
            if *kind == CloseKind::ProxyRefused {
                continue;
            }
            let implicated = CloseCause::new(*kind).implicates_address(ConnectorId::Tor);
            assert_eq!(
                implicated,
                *kind == CloseKind::LevinHandshakeRejected,
                "{kind:?} on an onion dial"
            );
            counted += usize::from(implicated);
        }
        assert!(!CloseCause::new(CloseKind::DialFailed).implicates_address(ConnectorId::Tor));
        counted += (0u16..=0x0100)
            .filter(|reply| CloseCause::proxy_refused(*reply).implicates_address(ConnectorId::Tor))
            .count();
        assert_eq!(counted, 7, "the rejection plus six replies");
        for reply in 0u16..=0x00FF {
            let cause = CloseCause::proxy_refused(reply);
            // The expected set is the spec's, written here. It is not
            // `proxy_reply_names_the_destination`.
            let onion = matches!(reply, 0x01 | 0x04 | 0x05 | 0xF0 | 0xF1 | 0xF2);
            assert_eq!(
                cause.implicates_address(ConnectorId::Tor),
                onion,
                "onion reply {reply:#x}"
            );
        }
        assert!(!CloseCause::proxy_refused(0x0100).implicates_address(ConnectorId::Tor));
    }

    /// A dial opened a stream exactly when its close needed one. No proxy
    /// reply did: whatever Tor answered, the dial reached no peer.
    #[test]
    fn a_stream_opened_only_for_the_kinds_that_need_one() {
        for reply in 0u16..=0x00FF {
            assert!(
                !CloseCause::proxy_refused(reply).opened_a_stream(),
                "{reply:#x}"
            );
        }
        for kind in CloseKind::ALL {
            if *kind == CloseKind::ProxyRefused {
                continue;
            }
            let expected = !matches!(
                kind,
                CloseKind::TransportTimeout
                    | CloseKind::AdmissionRefused
                    | CloseKind::DialFailed
                    | CloseKind::LocalClose
                    | CloseKind::InboundNotAccepted
                    | CloseKind::ProxyUnavailable
            );
            assert_eq!(
                CloseCause::new(*kind).opened_a_stream(),
                expected,
                "{kind:?}"
            );
        }
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
