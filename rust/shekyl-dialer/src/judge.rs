// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The judge (`DIALER_OUTAGE_EVIDENCE.md` §4.1, `OE-D8`; §3.3 as ruled
//! 2026-11-15): what a failed test does to its address. It reads the
//! failure as the dialing connector stamped it and, for an uncertain one,
//! that connector's path reading taken after the failure. Nothing else:
//! it names no connector, and knows nothing about bytes, streams, probes or
//! checks. The peer list performs the verdict.
//!
//! - **Destination** counts, whatever the path; proof of misbehaviour drops
//!   (only a destination-authenticating connector can build it).
//! - **Local** is excused: this node's side, independent of the address.
//! - **Uncertain** asks the connector ([`shekyl_transport_layer::PathSource`]).
//!   One reading taken after the failure decides: working counts, impaired
//!   excuses, and none within the connector's wait excuses.

use shekyl_peerlist::Verdict;
use shekyl_transport_layer::{DialFailure, Evidence, PathReading, ProofKind};

/// What the judge decides when a test fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Judgement {
    /// The verdict, now.
    Now(Verdict),
    /// An uncertain failure: the verdict is the dialing connector's path
    /// reading taken after it ([`settle`]). Meanwhile the address is not
    /// drawn again; nothing else is held.
    AskThePath,
}

/// The judge, at the instant a test's final attempt fails.
#[must_use]
pub const fn judge(failure: DialFailure) -> Judgement {
    match failure.evidence() {
        Evidence::Destination(proof) => Judgement::Now(match proof.kind() {
            ProofKind::Misbehaviour => Verdict::Drop,
            ProofKind::Absent => Verdict::Counted,
        }),
        Evidence::Local => Judgement::Now(Verdict::Excused),
        Evidence::Uncertain => Judgement::AskThePath,
    }
}

/// An uncertain failure's verdict, from the reading the connector has
/// after it (`reading`) and whether the connector's wait has run out
/// (`waited_out`). `None` while it still waits: no reading, and time
/// left. A verdict reached late can err only toward excusing, since only a
/// reading counts and running out excuses.
#[must_use]
pub const fn settle(reading: Option<PathReading>, waited_out: bool) -> Option<Verdict> {
    match reading {
        Some(PathReading::Working) => Some(Verdict::Counted),
        Some(PathReading::Impaired) => Some(Verdict::Excused),
        None if waited_out => Some(Verdict::Excused),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use shekyl_peerlist::{ConnectorId, Verdict};
    use shekyl_transport_layer::{
        declaration, Assessment, DestinationAuth, DialFailure, Evidence, PathReading, ProofKind,
        Reached, Retry,
    };

    use super::{judge, settle, Judgement};

    /// Every failure the dialer can be handed: each evidence kind under
    /// each retry and reach, and each connector's peer refusal. The judge
    /// reads the evidence, never which connector stamped it, so the set
    /// need not be split by connector; each connector's own mapping of its
    /// replies to evidence is that connector's test.
    fn every_failure() -> Vec<DialFailure> {
        let mut failures = Vec::new();
        for retry in [Retry::Final, Retry::Again, Retry::AgainInsideWindow] {
            for reached in [Reached::NoStream, Reached::StreamOpened] {
                failures.push(DialFailure::destination(retry, reached));
                failures.push(DialFailure::uncertain(retry, reached));
                failures.push(DialFailure::local(retry, reached));
            }
        }
        for &connector in ConnectorId::ALL {
            for reached in [Reached::NoStream, Reached::StreamOpened] {
                failures.push(DialFailure::refused_by_peer(connector, reached));
            }
        }
        failures
    }

    /// The verdict a failure ends with, given the reading its connector
    /// has after it and whether the wait ran out.
    fn verdict_over(
        failure: DialFailure,
        reading: Option<PathReading>,
        waited_out: bool,
    ) -> Option<Verdict> {
        match judge(failure) {
            Judgement::Now(verdict) => Some(verdict),
            Judgement::AskThePath => settle(reading, waited_out),
        }
    }

    /// **Every invariant, over every failure and every reading**
    /// (`DIALER_OUTAGE_EVIDENCE.md` §4.2): a Destination failure counts
    /// whatever the path says, and drops only on proof; a Local one never
    /// counts; an Uncertain one counts only on a working reading, is
    /// excused on an impaired one or when the wait runs out, and otherwise
    /// waits. The edits that make this red: any arm reading what another
    /// reads, or running out of the wait counting.
    #[test]
    fn every_invariant_holds_over_every_reading() {
        for failure in every_failure() {
            for reading in [
                None,
                Some(PathReading::Working),
                Some(PathReading::Impaired),
            ] {
                for waited_out in [false, true] {
                    let expected = match failure.evidence() {
                        Evidence::Local => Some(Verdict::Excused),
                        Evidence::Destination(proof) => Some(match proof.kind() {
                            ProofKind::Misbehaviour => Verdict::Drop,
                            ProofKind::Absent => Verdict::Counted,
                        }),
                        Evidence::Uncertain => match (reading, waited_out) {
                            (Some(PathReading::Working), _) => Some(Verdict::Counted),
                            (Some(PathReading::Impaired), _) | (None, true) => {
                                Some(Verdict::Excused)
                            }
                            (None, false) => None,
                        },
                    };
                    assert_eq!(
                        verdict_over(failure, reading, waited_out),
                        expected,
                        "{failure:?} {reading:?} waited out: {waited_out}"
                    );
                }
            }
        }
    }

    /// Proof of misbehaviour is built only where the connector
    /// authenticates the destination: the judge drops on proof, so the
    /// proof must not exist elsewhere. The edit that makes this red is a
    /// connector stamping a refusal as proof without authentication.
    #[test]
    fn proof_exists_only_where_the_destination_is_authenticated() {
        for &connector in ConnectorId::ALL {
            let authenticated = matches!(
                declaration(connector.column()).destination_authenticated(),
                Assessment::Assessed(DestinationAuth::OneWay)
            );
            assert_eq!(
                DialFailure::refused_by_peer(connector, Reached::StreamOpened)
                    .proves_misbehaviour(),
                authenticated,
                "{connector:?}: proof only where the destination is authenticated"
            );
        }
    }
}
