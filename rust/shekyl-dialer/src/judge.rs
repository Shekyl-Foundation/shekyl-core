// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The judge (`DIALER_OUTAGE_EVIDENCE.md` §4.1, `OE-D8`): one function
//! decides what a failed test does to its address. It reads the failure as
//! the layer that observed it stamped it, the connector's declaration, and
//! the dialer's own observations of the link, and nothing else: never a
//! D12 cause, and never anything Tor says about its own network
//! (`TSR-Q14`). The peer list performs the verdict.
//!
//! Every instant here is on the byte-stamp clock (`monotonic_ms`), the
//! clock the activity stamps it reads are on; never an engine `Tick`.

use shekyl_peerlist::Verdict;
use shekyl_transport_layer::{
    Corroboration, DialFailure, Evidence, FailureJudging, ProofKind, StreamOpens,
};

/// The latest instants, in byte-stamp milliseconds, at which the dialer saw
/// one connector's link work (§3.3's closed list).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Observations {
    /// An attempt on the connector reached an open stream.
    pub stream_opened_ms: Option<u64>,
    /// A corroborating held session received a byte: a session whose
    /// handshake finished, inbound included only where the connector's
    /// declaration counts inbound sessions.
    pub session_received_ms: Option<u64>,
}

impl Observations {
    /// The latest sign of life the connector's declaration counts. A
    /// stream that opened counts only where the connector says it does.
    #[must_use]
    pub fn last_life(self, corroboration: Corroboration) -> Option<u64> {
        let opened = match corroboration.stream_opens {
            StreamOpens::Corroborate => self.stream_opened_ms,
            StreamOpens::Ignore => None,
        };
        opened.max(self.session_received_ms)
    }
}

/// What the judge decides when a test's failure is reported at `failed_ms`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Judgement {
    /// The verdict, now.
    Now(Verdict),
    /// An uncertain failure the link was shown working around before it:
    /// the verdict waits for the bracket's after side, at `deadline_ms`
    /// (`OE-D5`). The seat stays outstanding; nothing else is held.
    AtBracketEnd {
        /// When the after side closes: the failure plus δ.
        deadline_ms: u64,
    },
}

/// The judge, at the instant a test's final attempt fails. `observed` is
/// what the dialer had seen before this failure, the failing attempt's own
/// stream excluded.
///
/// - **Destination** counts, whatever the link shows; proof of misbehaviour
///   drops (only a destination-authenticating connector can build it).
/// - **Local** is excused: this node's side, independent of the address.
/// - **Uncertain** counts only if the link was shown working within δ
///   before the failure and within δ after it. With nothing in the δ
///   before, it is excused at once; otherwise the verdict waits for δ.
#[must_use]
pub fn judge(
    failure: DialFailure,
    judging: FailureJudging,
    observed: Observations,
    failed_ms: u64,
) -> Judgement {
    match failure.evidence() {
        Evidence::Destination(proof) => Judgement::Now(match proof.kind() {
            ProofKind::Misbehaviour => Verdict::Drop,
            ProofKind::Absent => Verdict::Counted,
        }),
        Evidence::Local => Judgement::Now(Verdict::Excused),
        Evidence::Uncertain => {
            let bracket = bracket_ms(judging);
            let before = observed
                .last_life(judging.corroboration)
                .is_some_and(|life| life.saturating_add(bracket) >= failed_ms);
            if before {
                Judgement::AtBracketEnd {
                    deadline_ms: failed_ms.saturating_add(bracket),
                }
            } else {
                Judgement::Now(Verdict::Excused)
            }
        }
    }
}

/// The bracket's after side: whether a sign of life at `life_ms` counts a
/// failure at `failed_ms`. It must come after the failure and no later than
/// the bracket's deadline, `failed_ms + δ`. A later one never counts it, so
/// a verdict resolved late can err only toward excusing: the deadline
/// excuses, and only a sign of life inside the bracket counts.
#[must_use]
pub const fn closes_the_bracket(judging: FailureJudging, failed_ms: u64, life_ms: u64) -> bool {
    failed_ms < life_ms && life_ms <= failed_ms.saturating_add(bracket_ms(judging))
}

/// δ in byte-stamp milliseconds, rounded up so the bracket never shrinks.
#[must_use]
pub const fn bracket_ms(judging: FailureJudging) -> u64 {
    judging.bracket_nanos.div_ceil(1_000_000)
}

#[cfg(test)]
mod tests {
    use shekyl_peerlist::{dial_profile, ConnectorId, Verdict};
    use shekyl_transport_layer::{
        DialFailure, Evidence, FailureJudging, ProofKind, Reached, Retry, StreamOpens,
    };

    use super::{bracket_ms, closes_the_bracket, judge, Judgement, Observations};

    const T_F: u64 = 1_000_000;

    fn uncertain() -> DialFailure {
        DialFailure::uncertain(Retry::AgainInsideWindow, Reached::NoStream)
    }

    fn sessions(ms: u64) -> Observations {
        Observations {
            stream_opened_ms: None,
            session_received_ms: Some(ms),
        }
    }

    fn opened(ms: u64) -> Observations {
        Observations {
            stream_opened_ms: Some(ms),
            session_received_ms: None,
        }
    }

    /// The brief's tests 4 and 5, on every connector: a Destination failure
    /// counts with no corroboration at all, proof drops, and a Local
    /// failure is excused whatever the link shows. The edit that makes this
    /// red is reading the link for either.
    #[test]
    fn destination_counts_and_local_is_excused_whatever_the_link_shows() {
        for &connector in ConnectorId::ALL {
            let judging = dial_profile(connector).judging;
            for observed in [Observations::default(), sessions(T_F)] {
                assert_eq!(
                    judge(
                        DialFailure::destination(Retry::Again, Reached::NoStream),
                        judging,
                        observed,
                        T_F
                    ),
                    Judgement::Now(Verdict::Counted),
                    "{connector:?}"
                );
                assert_eq!(
                    judge(
                        DialFailure::local(Retry::Again, Reached::NoStream),
                        judging,
                        observed,
                        T_F
                    ),
                    Judgement::Now(Verdict::Excused),
                    "{connector:?}"
                );
            }
        }
        let tor = dial_profile(ConnectorId::Tor).judging;
        assert_eq!(
            judge(
                DialFailure::refused_by_peer(ConnectorId::Tor, Reached::StreamOpened),
                tor,
                Observations::default(),
                T_F
            ),
            Judgement::Now(Verdict::Drop),
            "proof drops where the destination is authenticated"
        );
    }

    /// The bracket (`OE-D5`, the brief's test 2), on every connector: an
    /// uncertain failure counts only with a sign of life within δ before it
    /// and one after it; with nothing before it is excused at once, and with
    /// life on one side only it is excused. The edit that makes this red is
    /// reading one side only.
    #[test]
    fn an_uncertain_failure_counts_only_inside_a_closed_bracket() {
        for &connector in ConnectorId::ALL {
            let judging = dial_profile(connector).judging;
            let delta = bracket_ms(judging);
            let before = sessions(T_F - delta);
            assert_eq!(
                judge(uncertain(), judging, before, T_F),
                Judgement::AtBracketEnd {
                    deadline_ms: T_F + delta
                },
                "{connector:?}: life within δ before defers the verdict"
            );
            assert_eq!(
                judge(uncertain(), judging, sessions(T_F - delta - 1), T_F),
                Judgement::Now(Verdict::Excused),
                "{connector:?}: life older than δ is no corroboration"
            );
            assert_eq!(
                judge(uncertain(), judging, Observations::default(), T_F),
                Judgement::Now(Verdict::Excused),
                "{connector:?}: nothing before"
            );
            assert!(
                closes_the_bracket(judging, T_F, T_F + 1),
                "{connector:?}: life just after"
            );
            assert!(
                closes_the_bracket(judging, T_F, T_F + delta),
                "{connector:?}: life at the deadline"
            );
            assert!(
                !closes_the_bracket(judging, T_F, T_F + delta + 1),
                "{connector:?}: life past the deadline is not the after side"
            );
            assert!(
                !closes_the_bracket(judging, T_F, T_F),
                "{connector:?}: life at the failure is not after it"
            );
        }
    }

    /// Every failure a connector can stamp: each evidence kind under each
    /// retry and reach, the peer's own refusal, and on Tor every reply code.
    fn every_failure(connector: ConnectorId) -> Vec<DialFailure> {
        let mut failures = Vec::new();
        for retry in [Retry::Final, Retry::Again, Retry::AgainInsideWindow] {
            for reached in [Reached::NoStream, Reached::StreamOpened] {
                failures.push(DialFailure::destination(retry, reached));
                failures.push(DialFailure::uncertain(retry, reached));
                failures.push(DialFailure::local(retry, reached));
            }
        }
        for reached in [Reached::NoStream, Reached::StreamOpened] {
            failures.push(DialFailure::refused_by_peer(connector, reached));
        }
        if connector == ConnectorId::Tor {
            failures.extend((0..=0xFF).map(shekyl_tor::stamp_reply));
        }
        failures
    }

    /// Where a sign of life came from.
    #[derive(Clone, Copy, Debug)]
    enum Source {
        Session,
        Stream,
    }

    /// The verdict a failure at [`T_F`] ends with, given the last sign of
    /// life before it and one after it, each from `source`.
    fn verdict_over(
        failure: DialFailure,
        judging: FailureJudging,
        source: Source,
        before: Option<u64>,
        after: Option<u64>,
    ) -> Verdict {
        let at = |ms: Option<u64>| match source {
            Source::Session => Observations {
                stream_opened_ms: None,
                session_received_ms: ms,
            },
            Source::Stream => Observations {
                stream_opened_ms: ms,
                session_received_ms: None,
            },
        };
        let counted = |life: Option<u64>| {
            at(life)
                .last_life(judging.corroboration)
                .is_some_and(|life| closes_the_bracket(judging, T_F, life))
        };
        match judge(failure, judging, at(before), T_F) {
            Judgement::Now(verdict) => verdict,
            Judgement::AtBracketEnd { .. } if counted(after) => Verdict::Counted,
            Judgement::AtBracketEnd { .. } => Verdict::Excused,
        }
    }

    /// **Every invariant against each connector's declaration** (the
    /// brief's test 8; `DIALER_OUTAGE_EVIDENCE.md` §4.2): over every
    /// failure the connector can stamp and every timeline of signs of life,
    /// an Uncertain failure counts only when the connector's own
    /// corroboration shows the link working within δ before and after it
    /// (an outage, its onset and its end demote nothing and climb nothing);
    /// a Destination failure counts whatever the link shows, and drops only
    /// on proof; a Local one never counts. The edits that make this red:
    /// any of the three arms reading what another reads, or the stream
    /// declaration ignored.
    #[test]
    fn every_invariant_holds_on_each_connectors_declaration() {
        for &connector in ConnectorId::ALL {
            let judging = dial_profile(connector).judging;
            let delta = bracket_ms(judging);
            let streams = judging.corroboration.stream_opens == StreamOpens::Corroborate;
            for failure in every_failure(connector) {
                for source in [Source::Session, Source::Stream] {
                    for (before, after) in [
                        (None, None),
                        (Some(T_F - delta), None),
                        (Some(T_F - delta - 1), Some(T_F + 1)),
                        (None, Some(T_F + 1)),
                        (Some(T_F), Some(T_F + 1)),
                        (Some(T_F - delta), Some(T_F + delta)),
                        (Some(T_F), Some(T_F + delta + 1)),
                    ] {
                        let verdict = verdict_over(failure, judging, source, before, after);
                        let expected = match failure.evidence() {
                            Evidence::Local => Verdict::Excused,
                            Evidence::Destination(proof) => match proof.kind() {
                                ProofKind::Misbehaviour => Verdict::Drop,
                                ProofKind::Absent => Verdict::Counted,
                            },
                            Evidence::Uncertain => {
                                let seen = matches!(source, Source::Session) || streams;
                                let before = before.is_some_and(|ms| ms + delta >= T_F);
                                let after = after.is_some_and(|ms| T_F < ms && ms <= T_F + delta);
                                if seen && before && after {
                                    Verdict::Counted
                                } else {
                                    Verdict::Excused
                                }
                            }
                        };
                        assert_eq!(
                            verdict, expected,
                            "{connector:?} {failure:?} {source:?} {before:?} {after:?}"
                        );
                    }
                }
            }
            assert_eq!(
                DialFailure::refused_by_peer(connector, Reached::StreamOpened)
                    .proves_misbehaviour(),
                connector == ConnectorId::Tor,
                "proof only where the destination is authenticated"
            );
        }
    }

    /// Each connector's corroboration is its own declaration: a stream that
    /// opened shows a Tor link working (every Tor stream crosses the one
    /// guard link) and says nothing on clearnet (one destination's stream
    /// says nothing about another's path). The edit that makes this red is
    /// reading stream opens on every connector.
    #[test]
    fn a_stream_that_opened_corroborates_only_where_declared() {
        let tor = dial_profile(ConnectorId::Tor).judging;
        let clearnet = dial_profile(ConnectorId::Clearnet).judging;
        assert!(matches!(
            judge(uncertain(), tor, opened(T_F), T_F),
            Judgement::AtBracketEnd { .. }
        ));
        assert_eq!(
            judge(uncertain(), clearnet, opened(T_F), T_F),
            Judgement::Now(Verdict::Excused)
        );
    }
}
