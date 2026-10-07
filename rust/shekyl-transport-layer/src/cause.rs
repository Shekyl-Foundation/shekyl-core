// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! D12's cause table. One enum. The C header is a projection of it.

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

            pub const fn c_name(self) -> &'static str {
                match self {
                    $(Self::$name => $c_name,)*
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
    /// is feeding us addresses. A cause that does not name the destination
    /// leaves the address dialable.
    ///
    /// [`CloseKind::DialFailed`] is a connect to that address that failed.
    /// [`CloseKind::LevinHandshakeRejected`] is the Levin layer judging the
    /// peer. [`CloseKind::ProxyRefused`] depends on `connector`. A clearnet
    /// proxy's reply is the exit's claim about a host, and the cache would
    /// suppress that whole host for an hour, so no clearnet reply counts.
    /// An onion dial counts only the replies that name that onion: RFC 1928
    /// host unreachable (`0x04`) and connection refused (`0x05`), and the
    /// Tor SOCKS extended codes for a descriptor that is missing (`0xF0`)
    /// or unusable (`0xF1`) and an introduction that failed (`0xF2`).
    /// Introduction and rendezvous timeouts (`0xF7`, `0xF3`), general
    /// failure, a ruleset, network unreachable, and TTL expired do not.
    /// A command or address type this node sent (`0x07`, `0x08`), an onion
    /// address Tor rejected (`0xF6`; we validate it before dialing), and
    /// client-authorization errors (`0xF4`, `0xF5`) do not either. Any
    /// other reply does not.
    ///
    /// The extended codes arrive only when the managed `SocksPort` asks
    /// for them (`auto ExtendedErrors`). Tor 0.4.9.11 leaves that off
    /// (`port_cfg_new`), and without it `stream_end_reason_to_socks5_response`
    /// reports an introduction timeout as reply 4.
    #[must_use]
    pub const fn implicates_address(self, connector: ConnectorId) -> bool {
        match self.kind {
            CloseKind::DialFailed | CloseKind::LevinHandshakeRejected => true,
            CloseKind::ProxyRefused => {
                connector_is_tor(connector) && onion_reply_names_the_destination(self.reply_code)
            }
            _ => false,
        }
    }
}

const fn connector_is_tor(connector: ConnectorId) -> bool {
    matches!(connector, ConnectorId::Tor)
}

/// Onion SOCKS replies that name the destination.
///
/// RFC 1928 §6 `0x04` and `0x05`. Tor's extended codes (`socks-extensions`,
/// "Extended error codes"; proposal 304) `0xF0`, `0xF1`, and `0xF2`.
const fn onion_reply_names_the_destination(reply: u16) -> bool {
    matches!(reply, 0x04 | 0x05 | 0xF0 | 0xF1 | 0xF2)
}

/// Replies that mean the request this node sent, not the onion.
///
/// The dial path logs these at error. They do not forget the address.
pub const fn socks_reply_is_our_request(reply: u16) -> bool {
    matches!(reply, 0x07 | 0x08 | 0xF4 | 0xF5 | 0xF6)
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
    use super::{c_header, onion_reply_names_the_destination, CloseCause, CloseKind, Phase};
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

    /// Every reply byte, on both connectors. An onion dial counts `0x04`,
    /// `0x05`, `0xF0`, `0xF1`, and `0xF2`. `0xF3` and `0xF7` stay dialable.
    /// A clearnet proxy reply never counts. This does not launch Tor and
    /// does not cover the directory attacker who can force reply 4.
    #[test]
    fn implicates_address_over_every_reply_and_both_connectors() {
        for kind in CloseKind::ALL {
            if *kind == CloseKind::ProxyRefused {
                continue;
            }
            let cause = CloseCause::new(*kind);
            let expect = matches!(
                kind,
                CloseKind::DialFailed | CloseKind::LevinHandshakeRejected
            );
            for connector in [ConnectorId::Clearnet, ConnectorId::Tor] {
                assert_eq!(
                    cause.implicates_address(connector),
                    expect,
                    "{kind:?} on {connector:?}"
                );
            }
        }
        for reply in 0u16..=0x00FF {
            let cause = CloseCause::proxy_refused(reply);
            let onion = onion_reply_names_the_destination(reply);
            assert_eq!(
                cause.implicates_address(ConnectorId::Tor),
                onion,
                "onion reply {reply:#x}"
            );
            assert!(
                !cause.implicates_address(ConnectorId::Clearnet),
                "clearnet reply {reply:#x} must stay dialable"
            );
        }
        assert!(onion_reply_names_the_destination(0xF0));
        assert!(onion_reply_names_the_destination(0xF2));
        assert!(!onion_reply_names_the_destination(0xF3));
        assert!(!onion_reply_names_the_destination(0xF7));
        assert!(!CloseCause::proxy_refused(0x0100).implicates_address(ConnectorId::Tor));
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
