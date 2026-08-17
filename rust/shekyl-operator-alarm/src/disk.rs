// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The disk-headroom producer for the [operator alarm channel](crate) —
//! `COMPLETETREE_ACTIVATION.md` Q-2's "warn at set points".
//!
//! Same split as [`serve_set`](crate::serve_set) and
//! [`tor_posture`](crate::tor_posture): the *measurement* (which filesystem,
//! how often, with what thresholds) belongs to the wallet orchestrator's
//! serving task, and the *mapping* from a reading onto the board lives here,
//! where it is a total function anyone can call in a test.
//!
//! # Why this is a condition and not a serve-set reading
//!
//! The serve-set conditions answer "does what the chain obligates match what
//! the store retains", and the store answers both halves. This one is about
//! the volume underneath the store: the wallet cannot fix it, the remedy is
//! a bigger disk or an Unbond, and it applies to every serving posture —
//! a market archiver that fills its volume fails challenges exactly as a
//! foundation node does. Folding it into `ServeSetIntegrity` would have an
//! operator reading "your serve-set is broken" for a full disk.

use crate::{AlarmCondition, DisarmedReason, OperatorAlarm, OperatorAlarms};

/// One free-space reading from the filesystem holding the curve-tree store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskObservation {
    /// The probe read the filesystem. `free_bytes` is what an unprivileged
    /// writer can still use; `threshold_bytes` is the floor it was compared
    /// against.
    Measured {
        /// Bytes available to an unprivileged writer.
        free_bytes: u64,
        /// The warning floor this reading is judged against.
        threshold_bytes: u64,
    },
    /// The probe failed — the path is gone, the syscall errored, the mount
    /// went away. Headroom is **unknown**, which is neither healthy nor an
    /// alarm.
    Unreadable,
    /// No host is running, so nothing is being measured.
    NotServing,
}

/// Map one disk reading onto the board.
///
/// Total and side-effect-free apart from the board writes — the contract
/// every producer in this crate keeps, so the state machine is testable by
/// calling it.
pub fn apply(alarms: &OperatorAlarms, observation: DiskObservation) {
    match observation {
        DiskObservation::NotServing => {
            alarms.disarm(
                AlarmCondition::ServingDiskHeadroom,
                DisarmedReason::TransportStopped,
            );
        }
        // A broken probe must not read as healthy, and must not read as an
        // alarm either: "I cannot tell" is its own state, and this channel
        // exists because those three are different sentences.
        DiskObservation::Unreadable => {
            alarms.disarm(
                AlarmCondition::ServingDiskHeadroom,
                DisarmedReason::DiskUnreadable,
            );
        }
        DiskObservation::Measured {
            free_bytes,
            threshold_bytes,
        } => {
            alarms.arm(AlarmCondition::ServingDiskHeadroom);
            // Strictly below: a reading exactly at the floor has not crossed
            // it, and an off-by-one that alarmed at the boundary would fire
            // on a disk that is doing precisely what was asked of it.
            if free_bytes < threshold_bytes {
                alarms.raise(OperatorAlarm::ServingDiskLow {
                    free_bytes,
                    threshold_bytes,
                });
            } else {
                alarms.clear(AlarmCondition::ServingDiskHeadroom);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Arming;

    fn state(alarms: &OperatorAlarms) -> crate::ConditionState {
        alarms
            .board()
            .condition(AlarmCondition::ServingDiskHeadroom)
            .expect("the condition has a row once observed")
    }

    /// The three readings are three different board states — the whole
    /// reason a snapshot channel exists rather than an event stream.
    #[test]
    fn healthy_low_and_unreadable_are_three_distinct_states() {
        let alarms = OperatorAlarms::new();

        apply(
            &alarms,
            DiskObservation::Measured {
                free_bytes: 100,
                threshold_bytes: 50,
            },
        );
        let healthy = state(&alarms);
        assert_eq!(healthy.arming, Arming::Armed);
        assert!(healthy.live.is_none(), "room to spare raises nothing");

        apply(
            &alarms,
            DiskObservation::Measured {
                free_bytes: 49,
                threshold_bytes: 50,
            },
        );
        let low = state(&alarms);
        assert_eq!(low.arming, Arming::Armed);
        assert_eq!(
            low.live.map(|raised| raised.alarm),
            Some(OperatorAlarm::ServingDiskLow {
                free_bytes: 49,
                threshold_bytes: 50,
            }),
            "crossing the floor raises, carrying both numbers so the \
             operator can size the fix"
        );

        // A probe that stops working must not look like the disk recovered.
        apply(&alarms, DiskObservation::Unreadable);
        let unknown = state(&alarms);
        assert_eq!(
            unknown.arming,
            Arming::Disarmed(DisarmedReason::DiskUnreadable),
            "unknown headroom is disarmed, never healthy"
        );
    }

    /// The condition is an `Episode`: freeing space ends it, and the next
    /// healthy reading clears it. Nothing latches, because nothing about a
    /// full disk outlives the fullness.
    #[test]
    fn freeing_space_clears_the_alarm() {
        let alarms = OperatorAlarms::new();
        apply(
            &alarms,
            DiskObservation::Measured {
                free_bytes: 1,
                threshold_bytes: 50,
            },
        );
        assert!(state(&alarms).live.is_some());

        apply(
            &alarms,
            DiskObservation::Measured {
                free_bytes: 51,
                threshold_bytes: 50,
            },
        );
        assert!(
            state(&alarms).live.is_none(),
            "a recovered disk clears rather than latching"
        );
        assert_eq!(
            OperatorAlarm::ServingDiskLow {
                free_bytes: 1,
                threshold_bytes: 50,
            }
            .lifetime(),
            crate::AlarmLifetime::Episode
        );
    }

    /// Exactly at the floor is not below it.
    #[test]
    fn a_reading_at_the_threshold_does_not_alarm() {
        let alarms = OperatorAlarms::new();
        apply(
            &alarms,
            DiskObservation::Measured {
                free_bytes: 50,
                threshold_bytes: 50,
            },
        );
        assert!(state(&alarms).live.is_none());
    }
}
