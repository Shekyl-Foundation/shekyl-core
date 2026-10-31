// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The clock named from relays' certificates (`TOR_SUPERVISOR.md` §4.2,
//! §5 "Certificates out of date"; Rick, 2026-10-30).
//!
//! With the clock three days ahead Tor named no clock: it logged "Received a
//! bad CERTS cell: At least one certificate expired." and reported handshake
//! problems (`REASON=DONE`). A wrong clock makes every relay's certificate
//! look expired or not yet valid; one relay presenting a bad certificate is
//! one relay. So the clock is named only when, within
//! `Policy::clock_evidence_within`, Tor logged the certificate line at least
//! [`AT_LEAST`] times and its handshake problems named at least
//! [`AT_LEAST`] distinct relays. The certificate line names no relay
//! (Tor's `torcert.c`), so the relays come from the problems' `HOSTID`.
//! `REASON=DONE` means the TLS handshake completed and Tor closed the
//! connection itself: a blocked network refuses or times out before that,
//! and cannot supply these relays.
//!
//! Fewer leaves the blocked link's wording, which names the clock first.

use super::super::posture::Cause;
use super::{duration_ns, Action, Core, Phase};
use crate::control::RelayFingerprint;

/// Certificate lines and distinct relays the clock needs (Rick, 2026-10-30).
pub(super) const AT_LEAST: usize = 3;

/// The latest certificate lines and the latest distinct relays, each kept to
/// [`AT_LEAST`]: the newest three are inside the window exactly when three
/// are, so nothing older is needed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ClockEvidence {
    /// When the latest certificate lines arrived, oldest first.
    certificates: Vec<u64>,
    /// The latest distinct relays a closed handshake named, and when each was
    /// last named, oldest first.
    relays: Vec<(RelayFingerprint, u64)>,
}

impl ClockEvidence {
    fn certificate(&mut self, now: u64) {
        self.certificates.push(now);
        if self.certificates.len() > AT_LEAST {
            self.certificates.remove(0);
        }
    }

    fn relay(&mut self, relay: RelayFingerprint, now: u64) {
        self.relays.retain(|(seen, _)| *seen != relay);
        self.relays.push((relay, now));
        if self.relays.len() > AT_LEAST {
            self.relays.remove(0);
        }
    }

    /// Both counts are met inside the window that ends `now`.
    fn stands(&self, now: u64, within: u64) -> bool {
        let inside = |at: u64| now.saturating_sub(at) <= within;
        self.certificates.len() == AT_LEAST
            && self.relays.len() == AT_LEAST
            && self.certificates.first().is_some_and(|at| inside(*at))
            && self.relays.first().is_some_and(|(_, at)| inside(*at))
    }
}

impl Core {
    /// Tor logged a certificate as expired or not yet valid.
    pub(super) fn certificate_out_of_date(&mut self, now: u64) -> Vec<Action> {
        self.clock_evidence.certificate(now);
        self.clock_named(now)
    }

    /// A handshake problem with `REASON=DONE` named this relay.
    pub(super) fn handshake_closed(&mut self, relay: RelayFingerprint, now: u64) -> Vec<Action> {
        self.clock_evidence.relay(relay, now);
        self.clock_named(now)
    }

    /// Tor says the link is blocked. While the certificates still name the
    /// clock, the clock is what blocks it: a problem's `warn` would otherwise
    /// overwrite the clock at every problem, as `REASON=CLOCK_SKEW` did (§7).
    pub(super) fn blocked(&mut self, now: u64) -> Vec<Action> {
        if self.clock_stands(now) {
            return self.clock_named(now);
        }
        self.external(now, Cause::ExternalBlocked)
    }

    fn clock_stands(&self, now: u64) -> bool {
        matches!(self.phase, Phase::Bootstrapping { .. })
            && self
                .clock_evidence
                .stands(now, duration_ns(self.policy.clock_evidence_within))
    }

    /// Name the clock when the evidence stands. A clock already named stays:
    /// Tor's own `CLOCK_SKEW` carries the offset, which this cause cannot.
    fn clock_named(&mut self, now: u64) -> Vec<Action> {
        if !self.clock_stands(now)
            || matches!(
                self.cause,
                Cause::CertificatesOutOfDate | Cause::ClockSkew { .. }
            )
        {
            return Vec::new();
        }
        self.external(now, Cause::CertificatesOutOfDate)
    }
}
