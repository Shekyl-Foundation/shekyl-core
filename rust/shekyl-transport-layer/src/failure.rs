// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a failed dial is evidence of: the judge's input (Rick, 2026-10-31,
//! `DIALER_OUTAGE_EVIDENCE.md` §2.2).
//!
//! One judge, in the dialer, decides what a failure does to the address.
//! It reads a [`DialFailure`] and the dialing connector's declaration, and
//! nothing else: the D12 [`crate::CloseCause`] travels beside it for the
//! log, and the judge's signature cannot see it.
//!
//! Who builds a `DialFailure`, and nobody else does:
//! - **the connector**, for every failure before the channel and every end
//!   of its own stream after it;
//! - **the Levin layer**, for a rejected handshake, a wrong network or a
//!   refused peer list ([`DialFailure::refused_by_peer`]), and a Levin
//!   handshake timeout ([`Evidence::Uncertain`]);
//! - **the dialer**, for its own failures ([`Evidence::Local`]).
//!
//! Shared code that observes a stream's end hands it to the connector to
//! stamp. No connector-independent code assigns a meaning. An inbound
//! refusal never builds one.

use crate::declaration::{declaration, Assessment, DestinationAuth};
use crate::ConnectorId;

/// What a failure says about the address that was dialed. The vocabulary
/// is the dialer's and closed (`OE-D1`): a connector that needs a meaning
/// outside it is a design round, not a new local rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// The far end answered, or is shown absent. Counts against the
    /// address whatever the link shows.
    Destination(Proof),
    /// This node's side failed, independent of the destination. Never
    /// counts against the address.
    Local,
    /// The link or the destination. Counts only when the connector's
    /// corroboration shows the link working around the failure.
    Uncertain,
}

/// Whether a [`Evidence::Destination`] failure proves the peer misbehaved.
///
/// Opaque: [`ProofKind::Misbehaviour`] is reached only through
/// [`DialFailure::refused_by_peer`], which reads the connector's
/// `destination_authenticated` declaration. On a connector that does not
/// authenticate the destination, an on-path party could have answered, so
/// nothing there can prove misbehaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof(ProofKind);

/// What a [`Proof`] holds, for readers. A reader can match on it; it
/// cannot build a [`Proof`] from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofKind {
    /// The far end answered about this destination, or is shown absent;
    /// nothing proves it misbehaved.
    Absent,
    /// Authenticated proof that the peer misbehaved. The address leaves
    /// the lists.
    Misbehaviour,
}

impl Proof {
    /// No proof of misbehaviour.
    pub const ABSENT: Self = Self(ProofKind::Absent);

    /// What this proof holds.
    #[must_use]
    pub const fn kind(self) -> ProofKind {
        self.0
    }

    /// The proof a peer's refusal carries on `connector`: misbehaviour
    /// when the connector authenticates the destination, else none.
    const fn of_refusal_on(connector: ConnectorId) -> Self {
        match declaration(connector.column()).destination_authenticated() {
            Assessment::Assessed(DestinationAuth::OneWay) => Self(ProofKind::Misbehaviour),
            Assessment::Assessed(DestinationAuth::No) | Assessment::NotAssessed => Self::ABSENT,
        }
    }
}

/// Whether the same destination is worth another attempt within its test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retry {
    /// The test ends here.
    Final,
    /// Another attempt, after the profile's retry wait.
    Again,
    /// Another attempt, unless this one ran to the connector's retry
    /// cutoff: a timeout of the dial's own window. The same timeout can
    /// come early (a lost circuit), so the dialer reads it against the
    /// attempt's run time (the full-window rule, Rick 2026-10-26).
    AgainInsideWindow,
}

/// How far the attempt got before it failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reached {
    /// No stream opened: the failure came before the channel.
    NoStream,
    /// A stream opened, then the attempt failed.
    StreamOpened,
}

/// A failed dial, as the judge reads it. Built only by the constructors
/// below, so a [`ProofKind::Misbehaviour`] failure is always
/// [`Retry::Final`] and only exists on a destination-authenticating
/// connector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DialFailure {
    evidence: Evidence,
    retry: Retry,
    reached: Reached,
}

impl DialFailure {
    /// The far end answered, or is shown absent, and proves nothing.
    #[must_use]
    pub const fn destination(retry: Retry, reached: Reached) -> Self {
        Self {
            evidence: Evidence::Destination(Proof::ABSENT),
            retry,
            reached,
        }
    }

    /// The peer refused this node: a rejected Levin handshake, a wrong
    /// network, a refused peer list. The proof is the connector's
    /// `destination_authenticated` declaration's, and the failure is
    /// final: an answer is not worth a redial.
    #[must_use]
    pub const fn refused_by_peer(connector: ConnectorId, reached: Reached) -> Self {
        Self {
            evidence: Evidence::Destination(Proof::of_refusal_on(connector)),
            retry: Retry::Final,
            reached,
        }
    }

    /// This node's side failed, independent of the destination.
    #[must_use]
    pub const fn local(retry: Retry, reached: Reached) -> Self {
        Self {
            evidence: Evidence::Local,
            retry,
            reached,
        }
    }

    /// The link or the destination.
    #[must_use]
    pub const fn uncertain(retry: Retry, reached: Reached) -> Self {
        Self {
            evidence: Evidence::Uncertain,
            retry,
            reached,
        }
    }

    /// What the failure is evidence of.
    #[must_use]
    pub const fn evidence(self) -> Evidence {
        self.evidence
    }

    /// Whether the test makes another attempt.
    #[must_use]
    pub const fn retry(self) -> Retry {
        self.retry
    }

    /// How far the attempt got.
    #[must_use]
    pub const fn reached(self) -> Reached {
        self.reached
    }

    /// Whether this failure proves the peer misbehaved.
    #[must_use]
    pub const fn proves_misbehaviour(self) -> bool {
        matches!(
            self.evidence,
            Evidence::Destination(Proof(ProofKind::Misbehaviour))
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{DialFailure, Evidence, Proof, ProofKind, Reached, Retry};
    use crate::ConnectorId;

    /// Proof of misbehaviour follows the connector's declaration: a peer's
    /// refusal proves it on Tor (an onion address is the service's key)
    /// and not on clearnet (Noise NN authenticates no one). The edit that
    /// makes this red is building the proof without reading the
    /// declaration.
    #[test]
    fn a_refusal_proves_misbehaviour_only_where_the_destination_is_authenticated() {
        for reached in [Reached::NoStream, Reached::StreamOpened] {
            let tor = DialFailure::refused_by_peer(ConnectorId::Tor, reached);
            assert!(tor.proves_misbehaviour());
            assert_eq!(
                tor.evidence(),
                Evidence::Destination(super::Proof(ProofKind::Misbehaviour))
            );
            let clearnet = DialFailure::refused_by_peer(ConnectorId::Clearnet, reached);
            assert!(!clearnet.proves_misbehaviour());
            assert_eq!(clearnet.evidence(), Evidence::Destination(Proof::ABSENT));
        }
    }

    /// A refusal is final on every connector: an answer is not worth a
    /// redial. With the proof built only by that constructor, every
    /// failure that proves misbehaviour is final. The edit that makes this
    /// red is letting a refusal take a caller's retry.
    #[test]
    fn a_refusal_is_final_on_every_connector() {
        for &connector in ConnectorId::ALL {
            for reached in [Reached::NoStream, Reached::StreamOpened] {
                assert_eq!(
                    DialFailure::refused_by_peer(connector, reached).retry(),
                    Retry::Final,
                    "{connector:?}"
                );
            }
        }
    }

    /// The other constructors never prove misbehaviour, whatever retry and
    /// reach they carry, and carry back exactly what they were given.
    #[test]
    fn only_a_refusal_can_prove_misbehaviour() {
        for retry in [Retry::Final, Retry::Again, Retry::AgainInsideWindow] {
            for reached in [Reached::NoStream, Reached::StreamOpened] {
                for (failure, evidence) in [
                    (
                        DialFailure::destination(retry, reached),
                        Evidence::Destination(Proof::ABSENT),
                    ),
                    (DialFailure::local(retry, reached), Evidence::Local),
                    (DialFailure::uncertain(retry, reached), Evidence::Uncertain),
                ] {
                    assert!(!failure.proves_misbehaviour());
                    assert_eq!(failure.evidence(), evidence);
                    assert_eq!(failure.retry(), retry);
                    assert_eq!(failure.reached(), reached);
                }
            }
        }
    }
}
