// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serve-health producer for the [operator alarm channel](crate) — the
//! `TJ-D` operator surface over the host's serve counters
//! (`ARCHIVAL_SHARD_FETCH.md` `SF-D6`), landed with the SH-2 resident key.
//!
//! Same split as [`serve_set`](crate::serve_set) and [`disk`](crate::disk):
//! the *reading* (which host, how often, windowed how) belongs to the wallet
//! orchestrator's serving task, and the *mapping* from a reading onto the
//! board lives here as a total function.
//!
//! # Why the input is a window, not the totals
//!
//! `ServeCounters` are session totals. An alarm raised on "the key has ever
//! refused" would never clear, and a persona whose actor stopped for one tick
//! and was reopened would carry the alarm for the session. The question an
//! operator is asking is "is this happening *now*", so the producer takes the
//! movement over the last tick — [`ServeCounters::since`] is the one place
//! that subtraction lives — and a tick with no movement in the fault
//! counters clears the row.
//!
//! # Why the key outranks the lookup
//!
//! One condition row holds one live alarm. A tick in which both the key
//! refused and a lookup failed reports the refusal: a host that cannot sign
//! loses the pass whether or not it could read the shard, and the remedy (a
//! wallet reopen for a stopped signer) is the one that restores credit.

use shekyl_p_host::ServeCounters;

use crate::{AlarmCondition, DisarmedReason, OperatorAlarm, OperatorAlarms};

/// What one serving tick observed about the host's answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeHealthObservation {
    /// No host is running, so nothing is being answered.
    NotServing,
    /// The movement in the host's counters since the previous tick
    /// (`ServeCounters::since`). The first tick after start windows against
    /// zero, which is the session so far.
    Tick(ServeCounters),
}

/// Map one serve-health observation onto the board.
///
/// Total and side-effect-free apart from the board writes — the contract
/// every producer in this crate keeps, so the state machine is testable by
/// calling it.
pub fn apply(alarms: &OperatorAlarms, observation: ServeHealthObservation) {
    match observation {
        ServeHealthObservation::NotServing => {
            alarms.disarm(AlarmCondition::ServeHealth, DisarmedReason::NotServing);
        }
        ServeHealthObservation::Tick(window) => {
            alarms.arm(AlarmCondition::ServeHealth);
            let refused = window
                .sign_failures
                .saturating_add(window.late_sign_failures);
            if refused > 0 {
                alarms.raise(OperatorAlarm::ServeSigningRefused {
                    pre_flight: window.sign_failures,
                    late: window.late_sign_failures,
                });
            } else if window.lookup_failures > 0 {
                alarms.raise(OperatorAlarm::ServeLookupsFailing {
                    failures: window.lookup_failures,
                });
            } else {
                alarms.clear(AlarmCondition::ServeHealth);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Arming, RaisedAlarm};

    fn state(alarms: &OperatorAlarms) -> crate::ConditionState {
        alarms
            .board()
            .condition(AlarmCondition::ServeHealth)
            .expect("the condition has a row once observed")
    }

    fn window(sign: u64, late: u64, lookup: u64) -> ServeCounters {
        ServeCounters {
            served: 3,
            refused: 0,
            lookup_failures: lookup,
            sign_failures: sign,
            late_sign_failures: late,
            accept_errors: 0,
        }
    }

    /// A tick with nothing refused and nothing unreadable is armed and
    /// clean — checked, not merely quiet.
    #[test]
    fn a_quiet_tick_is_armed_and_clear() {
        let alarms = OperatorAlarms::new();
        apply(&alarms, ServeHealthObservation::Tick(window(0, 0, 0)));
        let s = state(&alarms);
        assert_eq!(s.arming(), Arming::Armed);
        assert!(s.live().is_none());
    }

    /// Both refusal shapes raise one alarm carrying both counts, so the
    /// operator can see whether shards went out before the refusal.
    #[test]
    fn a_refusing_key_raises_with_both_shapes_counted() {
        let alarms = OperatorAlarms::new();
        apply(&alarms, ServeHealthObservation::Tick(window(2, 1, 5)));
        assert_eq!(
            state(&alarms).live().map(RaisedAlarm::alarm),
            Some(OperatorAlarm::ServeSigningRefused {
                pre_flight: 2,
                late: 1,
            }),
            "the key outranks the lookup when both moved"
        );
    }

    /// Lookup failures alone are their own alarm with their own remedy.
    #[test]
    fn failing_lookups_raise_when_the_key_did_not_refuse() {
        let alarms = OperatorAlarms::new();
        apply(&alarms, ServeHealthObservation::Tick(window(0, 0, 4)));
        assert_eq!(
            state(&alarms).live().map(RaisedAlarm::alarm),
            Some(OperatorAlarm::ServeLookupsFailing { failures: 4 }),
        );
    }

    /// The input is a window: a tick with no new refusals clears the row
    /// even though the session totals still carry the old ones.
    #[test]
    fn a_later_quiet_tick_clears_the_episode() {
        let alarms = OperatorAlarms::new();
        apply(&alarms, ServeHealthObservation::Tick(window(1, 0, 0)));
        assert!(state(&alarms).live().is_some());
        apply(&alarms, ServeHealthObservation::Tick(window(0, 0, 0)));
        assert!(state(&alarms).live().is_none());
        assert_eq!(state(&alarms).arming(), Arming::Armed);
    }

    /// Teardown disarms rather than clears: a stopped host is not a healthy
    /// one, and the last raised reading stays on the row.
    #[test]
    fn not_serving_disarms_and_keeps_the_last_reading() {
        let alarms = OperatorAlarms::new();
        apply(&alarms, ServeHealthObservation::Tick(window(1, 0, 0)));
        apply(&alarms, ServeHealthObservation::NotServing);
        let s = state(&alarms);
        assert_eq!(s.arming(), Arming::Disarmed(DisarmedReason::NotServing));
        assert!(s.live().is_some(), "disarming does not erase the reading");
    }

    /// The window helper is where the subtraction lives; a restart that
    /// reset the totals reads as no movement, not as a negative.
    #[test]
    fn since_is_saturating_per_counter() {
        let earlier = window(5, 2, 7);
        let later = window(6, 2, 3);
        let w = later.since(&earlier);
        assert_eq!((w.sign_failures, w.late_sign_failures), (1, 0));
        assert_eq!(
            w.lookup_failures, 0,
            "a reset total is not a negative movement"
        );
        assert_eq!(w.served, 0);
    }
}
