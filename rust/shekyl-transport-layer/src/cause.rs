// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! D12's cause table. One enum.

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
    ($(($disc:literal, $name:ident, $phase:ident),)*) => {
        /// The D12 discriminant.
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

// What each kind is evidence of is not here: the connector that observed
// the close stamps a `DialFailure` beside it (`failure.rs`,
// `DIALER_OUTAGE_EVIDENCE.md` §2.2). This table is what the log names.
close_kinds! {
    (1, PrefixMismatch, BeforeChannel),
    (2, TransportHandshakeFailed, BeforeChannel),
    (3, TransportTimeout, BeforeChannel),
    (4, AdmissionRefused, BeforeChannel),
    (5, DialFailed, BeforeChannel),
    (6, ProxyRefused, BeforeChannel),
    (7, LevinHandshakeTimeout, Gap),
    (8, LevinHandshakeRejected, Gap),
    (9, PeerClosed, ChannelExists),
    (10, RecordRejected, ChannelExists),
    (11, SessionRefused, ChannelExists),
    (12, IoError, ChannelExists),
    (13, SendQueueFull, ChannelExists),
    (14, LocalClose, Every),
    (15, InboundNotAccepted, BeforeChannel),
    (16, ProxyUnavailable, BeforeChannel),
    (17, AcceptRateExceeded, BeforeChannel),
    // The session layer's two (P2P_3_REMNANT_CUTOVER_BRIEF.md §7.4, §7.6):
    // a handshake whose network id is not ours is dropped, never banned;
    // an invoke whose response did not arrive within INVOKE_TIMEOUT.
    (18, NetworkMismatch, Gap),
    (19, InvokeTimeout, ChannelExists),
}

/// One close cause. `reply_code` is the overlay reply for
/// [`CloseKind::ProxyRefused`] and zero for every other kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseCause {
    kind: CloseKind,
    reply_code: u16,
}

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

    /// `ProxyRefused` with the overlay's reply code. What the reply is
    /// evidence of is the connector's stamping (the Tor connector's
    /// `stamp_reply`); this crate holds no SOCKS knowledge. An unreachable
    /// onion is this cause.
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
}

#[cfg(test)]
mod tests {
    use super::{CloseCause, CloseKind, Phase};

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
            CloseKind::AcceptRateExceeded,
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
            CloseKind::NetworkMismatch,
            CloseKind::InvokeTimeout,
        ];
        let after = [
            CloseKind::PeerClosed,
            CloseKind::RecordRejected,
            CloseKind::SessionRefused,
            CloseKind::IoError,
            CloseKind::SendQueueFull,
            CloseKind::LocalClose,
            CloseKind::InvokeTimeout,
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
