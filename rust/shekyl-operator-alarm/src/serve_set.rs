// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serve-set producer for the [operator alarm channel](crate) — OA-1's
//! second, and SH-2b-2's reporting half.
//!
//! Same split as [`tor_posture`](crate::tor_posture): the *lifecycle* (when the
//! host starts, how often it refreshes, when it stops) lives in the wallet
//! orchestrator, and the *mapping* from what that lifecycle observed onto the
//! board lives here. Keeping the mapping in this crate is what lets
//! [`OperatorAlarms`]'s producer methods stay crate-private — raising an alarm
//! stays a statement this crate makes, rather than a capability handed to
//! every crate that can name a condition.
//!
//! The whole surface is one pure function over one value
//! ([`apply`] over [`ServeSetObservation`]), so the serving conditions are
//! testable with no persona, no store, no tor and no task — the same property
//! that made the tor producer testable without a binary.
//!
//! # The one asymmetry worth knowing
//!
//! Four of the five conditions are recoverable and clear themselves. The fifth,
//! [`OperatorAlarm::ServeSetBytesPruned`], is the board's only irreversible
//! entry — and it needs no durable acknowledgment, because
//! `PinnedServeSet::acquire` *refuses to start a host at all* over pruned
//! members. It re-derives at every start, more loudly than an alarm.

use shekyl_p_host::Staleness;

use crate::{AlarmCondition, DisarmedReason, OperatorAlarm, OperatorAlarms};

/// What one serving tick observed — the whole input to the mapping.
///
/// A single enum rather than a bag of optional readings, because the states are
/// mutually exclusive by construction: a wallet that is still catching up has no
/// meaningful staleness reading, and a refresh that failed produced no witness
/// to read one from. Making them separate arguments would create combinations
/// (`catching_up = true` *and* a staleness reading) that mean nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeSetObservation {
    /// The wallet has not caught up to the chain, so the staleness bound is not
    /// armed. Distinct from healthy: rendered "not checking yet".
    CatchingUp,
    /// No host is running — before the launch standoff elapses, or after
    /// shutdown. Nothing is being watched.
    NotServing,
    /// A refresh ran. `already_pruned` is the count of members whose leaf bytes
    /// were gone at the last pin (`PinnedServeSet::already_pruned`).
    Refreshed {
        /// This tick's tripwire reading.
        staleness: Staleness,
        /// Members whose leaf bytes are terminally gone.
        already_pruned: u32,
    },
    /// The refresh attempt itself failed, so there is no fresh reading. Carries
    /// the terminally-pruned count when the failure was the pruned-member
    /// refusal, which is the one failure that is not merely transient.
    RefreshFailed {
        /// `Some` when the failure was `PinError::MembersAlreadyPruned`.
        already_pruned: Option<u32>,
    },
}

/// Map one serving observation onto the board.
///
/// Total and side-effect-free apart from the board writes — the same contract
/// [`tor_posture::apply`](crate::tor_posture) keeps, and for the same reason:
/// the state machine is then testable by calling it.
pub fn apply(alarms: &OperatorAlarms, observation: ServeSetObservation) {
    match observation {
        ServeSetObservation::CatchingUp => {
            alarms.disarm(
                AlarmCondition::ServeSetIntegrity,
                DisarmedReason::CatchingUp,
            );
        }
        ServeSetObservation::NotServing => {
            alarms.disarm(
                AlarmCondition::ServeSetIntegrity,
                DisarmedReason::TransportStopped,
            );
        }
        ServeSetObservation::Refreshed {
            staleness,
            already_pruned,
        } => {
            alarms.arm(AlarmCondition::ServeSetIntegrity);
            // Terminally-pruned members outrank the tripwire: a set that reads
            // `Current` while some of its bytes are gone is current about the
            // wrong thing, and this is the reading that must not be lost.
            if already_pruned > 0 {
                alarms.raise(OperatorAlarm::ServeSetBytesPruned {
                    members: already_pruned,
                });
                return;
            }
            match staleness {
                Staleness::Current { .. } => alarms.clear(AlarmCondition::ServeSetIntegrity),
                Staleness::Stale { lag, .. } => {
                    alarms.raise(OperatorAlarm::ServeSetStale { lag });
                }
                Staleness::RolledBack { minted_at_tip, tip } => {
                    alarms.raise(OperatorAlarm::ServeSetRolledBack { minted_at_tip, tip });
                }
                Staleness::PinsDropped { dropped, claimed } => {
                    alarms.raise(OperatorAlarm::ServeSetPinsDropped { dropped, claimed });
                }
                Staleness::RefreshFailing { consecutive } => {
                    alarms.raise(OperatorAlarm::ServeSetRefreshFailing { consecutive });
                }
            }
        }
        ServeSetObservation::RefreshFailed { already_pruned } => {
            alarms.arm(AlarmCondition::ServeSetIntegrity);
            match already_pruned {
                Some(members) => {
                    alarms.raise(OperatorAlarm::ServeSetBytesPruned { members });
                }
                None => {
                    alarms.raise(OperatorAlarm::ServeSetRefreshFailing { consecutive: 1 });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AlarmLifetime, Arming, ConditionState, RaisedAlarm};

    fn live(alarms: &OperatorAlarms) -> Option<OperatorAlarm> {
        alarms
            .board()
            .condition(AlarmCondition::ServeSetIntegrity)
            .and_then(ConditionState::live)
            .map(RaisedAlarm::alarm)
    }

    fn arming(alarms: &OperatorAlarms) -> Option<Arming> {
        alarms
            .board()
            .condition(AlarmCondition::ServeSetIntegrity)
            .map(ConditionState::arming)
    }

    fn refreshed(staleness: Staleness) -> ServeSetObservation {
        ServeSetObservation::Refreshed {
            staleness,
            already_pruned: 0,
        }
    }

    #[test]
    fn catching_up_disarms_rather_than_reporting_health() {
        let alarms = OperatorAlarms::new();
        apply(&alarms, ServeSetObservation::CatchingUp);
        assert_eq!(
            arming(&alarms),
            Some(Arming::Disarmed(DisarmedReason::CatchingUp)),
            "a bound that is not armed must not read as a bound that passed",
        );
        assert!(live(&alarms).is_none());
    }

    #[test]
    fn a_current_set_clears_the_condition() {
        let alarms = OperatorAlarms::new();
        apply(&alarms, refreshed(Staleness::Stale { lag: 99, bound: 10 }));
        assert!(live(&alarms).is_some());
        apply(&alarms, refreshed(Staleness::Current { lag: 1 }));
        assert_eq!(arming(&alarms), Some(Arming::Armed));
        assert!(live(&alarms).is_none());
    }

    #[test]
    fn each_staleness_arm_maps_to_its_own_alarm() {
        let cases = [
            (
                Staleness::Stale { lag: 40, bound: 10 },
                OperatorAlarm::ServeSetStale { lag: 40 },
            ),
            (
                Staleness::RolledBack {
                    minted_at_tip: 900,
                    tip: 800,
                },
                OperatorAlarm::ServeSetRolledBack {
                    minted_at_tip: 900,
                    tip: 800,
                },
            ),
            (
                Staleness::PinsDropped {
                    dropped: 3,
                    claimed: 7,
                },
                OperatorAlarm::ServeSetPinsDropped {
                    dropped: 3,
                    claimed: 7,
                },
            ),
            (
                Staleness::RefreshFailing { consecutive: 4 },
                OperatorAlarm::ServeSetRefreshFailing { consecutive: 4 },
            ),
        ];
        for (staleness, expected) in cases {
            let alarms = OperatorAlarms::new();
            apply(&alarms, refreshed(staleness));
            assert_eq!(live(&alarms), Some(expected), "for {staleness:?}");
        }
    }

    /// The irreversible reading must not be masked by a healthy tripwire — a
    /// set that is "current" about shards whose bytes are gone is current about
    /// the wrong thing.
    #[test]
    fn pruned_bytes_outrank_a_current_tripwire() {
        let alarms = OperatorAlarms::new();
        apply(
            &alarms,
            ServeSetObservation::Refreshed {
                staleness: Staleness::Current { lag: 0 },
                already_pruned: 2,
            },
        );
        assert_eq!(
            live(&alarms),
            Some(OperatorAlarm::ServeSetBytesPruned { members: 2 }),
        );
        assert_eq!(
            live(&alarms).map(|a| a.lifetime()),
            Some(AlarmLifetime::LatchedRederived),
        );
    }

    #[test]
    fn a_pruned_refusal_latches_and_survives_the_lifecycle_ending() {
        let alarms = OperatorAlarms::new();
        apply(
            &alarms,
            ServeSetObservation::RefreshFailed {
                already_pruned: Some(1),
            },
        );
        // The host gives up and the lifecycle ends.
        apply(&alarms, ServeSetObservation::NotServing);
        assert_eq!(
            arming(&alarms),
            Some(Arming::Disarmed(DisarmedReason::TransportStopped)),
        );
        assert!(
            alarms.board().unacknowledged().is_empty(),
            "the fault is still live, not resolved — nothing reported it fixed",
        );
        assert_eq!(
            live(&alarms),
            Some(OperatorAlarm::ServeSetBytesPruned { members: 1 }),
            "shutting the lifecycle down does not un-prune the bytes",
        );
    }

    #[test]
    fn a_transient_refresh_failure_is_reported_before_the_host_counts_it() {
        let alarms = OperatorAlarms::new();
        apply(
            &alarms,
            ServeSetObservation::RefreshFailed {
                already_pruned: None,
            },
        );
        assert_eq!(
            live(&alarms),
            Some(OperatorAlarm::ServeSetRefreshFailing { consecutive: 1 }),
        );
    }
}
