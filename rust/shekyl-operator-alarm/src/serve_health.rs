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
//! The window's **baseline** lives here too, as [`TickWindow`], rather than
//! as a local in the serving task. The first reading after start is windowed
//! against zero, so anything the host answered between bind and that first
//! read is reported rather than swallowed into the baseline; the task owns
//! only *when* to read, never what the reading is measured against. Keeping
//! the baseline beside `apply` also lets these tests drive the real sequence
//! (totals in, alarm out, quiet tick, clear) through the same two calls the
//! task makes.
//!
//! # What ranks above what
//!
//! One condition row holds one live alarm, so a tick with movement in more
//! than one fault counter reports the one whose remedy restores credit:
//!
//! 1. the key refused ([`OperatorAlarm::ServeSigningRefused`]) — a host that
//!    cannot sign loses the pass whether or not it could read the shard, and
//!    the remedy (a wallet reopen for a stopped signer) is the one that
//!    restores credit;
//! 2. a lookup failed ([`OperatorAlarm::ServeLookupsFailing`]) — the daemon
//!    tip or the serving store, named by the variant;
//! 3. an accept failed ([`OperatorAlarm::ServeListenerFailing`]) — alongside
//!    either of the above the door is at least partly open and those name
//!    the fix; alone, it is the only sign a persona gets of a listener that
//!    will never accept again, which is why `shekyl-p-serve` counts it.
//!
//! `ServeCounters::refused` — connections closed over the in-flight cap —
//! is deliberately **not** an alarm: a persona at its cap is serving, and the
//! cap is load discipline, not a fault. It reopens as a board row if a
//! measurement shows the cap itself losing passes
//! (`SERVING_MAX_STREAMS` is the carried placeholder that would move first).

use shekyl_p_host::ServeCounters;

use crate::{AlarmCondition, DisarmedReason, OperatorAlarm, OperatorAlarms};

/// What one serving tick observed about the host's answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeHealthObservation {
    /// No host is running, so nothing is being answered.
    NotServing,
    /// The movement in the host's counters since the previous tick
    /// (`ServeCounters::since`). The first tick after start windows against
    /// zero, which is the session so far. Produced by [`TickWindow::observe`].
    Tick(ServeCounters),
}

/// The baseline a serving tick's reading is windowed against.
///
/// One per host lifetime: constructed at start (baseline zero), fed the
/// host's session totals once per tick. The movement comes out as a
/// [`ServeHealthObservation::Tick`] and the reading becomes the next
/// baseline. A host restart inside a window resets the totals and
/// [`ServeCounters::since`] saturates, so that reads as no movement rather
/// than a negative.
#[derive(Debug, Default)]
pub struct TickWindow {
    last: ServeCounters,
}

impl TickWindow {
    /// A window whose first observation is measured against zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Window `now` against the previous reading and make it the baseline.
    pub fn observe(&mut self, now: ServeCounters) -> ServeHealthObservation {
        let movement = now.since(&self.last);
        self.last = now;
        ServeHealthObservation::Tick(movement)
    }
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
            } else if window.accept_errors > 0 {
                alarms.raise(OperatorAlarm::ServeListenerFailing {
                    accept_errors: window.accept_errors,
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

    /// A listener that cannot accept is a fault of its own when nothing else
    /// moved — the counter exists because this shape otherwise reads as a
    /// quiet epoch (a window with only `accept_errors` used to *clear* the
    /// row, which is exactly that misreading).
    #[test]
    fn a_failing_listener_raises_when_nothing_else_moved() {
        let alarms = OperatorAlarms::new();
        let mut w = window(0, 0, 0);
        w.accept_errors = 3;
        apply(&alarms, ServeHealthObservation::Tick(w));
        assert_eq!(
            state(&alarms).live().map(RaisedAlarm::alarm),
            Some(OperatorAlarm::ServeListenerFailing { accept_errors: 3 }),
        );
    }

    /// The listener ranks last: an accept error beside a refusal or a failed
    /// lookup means connections are getting through, and those variants name
    /// the remedy.
    #[test]
    fn the_key_and_the_lookup_outrank_the_listener() {
        let alarms = OperatorAlarms::new();
        let mut w = window(0, 0, 2);
        w.accept_errors = 9;
        apply(&alarms, ServeHealthObservation::Tick(w));
        assert_eq!(
            state(&alarms).live().map(RaisedAlarm::alarm),
            Some(OperatorAlarm::ServeLookupsFailing { failures: 2 }),
        );
        let mut w = window(1, 0, 2);
        w.accept_errors = 9;
        apply(&alarms, ServeHealthObservation::Tick(w));
        assert_eq!(
            state(&alarms).live().map(RaisedAlarm::alarm),
            Some(OperatorAlarm::ServeSigningRefused {
                pre_flight: 1,
                late: 0,
            }),
        );
    }

    /// Connections closed over the in-flight cap are load, not a fault: a
    /// persona at its cap is serving, and the row stays clear.
    #[test]
    fn refusals_over_the_cap_are_not_an_alarm() {
        let alarms = OperatorAlarms::new();
        let mut w = window(0, 0, 0);
        w.refused = 40;
        apply(&alarms, ServeHealthObservation::Tick(w));
        let s = state(&alarms);
        assert_eq!(s.arming(), Arming::Armed);
        assert!(s.live().is_none());
    }

    /// The first reading is windowed against zero, so a refusal the host
    /// answered before the task's first read is reported, not folded into
    /// the baseline and lost (the bug a hard-coded zero first report had).
    #[test]
    fn the_first_window_reports_everything_since_zero() {
        let alarms = OperatorAlarms::new();
        let mut tick = TickWindow::new();
        apply(&alarms, tick.observe(window(2, 0, 0)));
        assert_eq!(
            state(&alarms).live().map(RaisedAlarm::alarm),
            Some(OperatorAlarm::ServeSigningRefused {
                pre_flight: 2,
                late: 0,
            }),
            "a refusal that predates the first read is still this session's"
        );
    }

    /// The sequence the serving task drives, end to end through the same two
    /// calls it makes: totals in, movement out. A refusal between two reads
    /// raises; the same totals read again are a quiet tick and clear; a later
    /// lookup failure raises its own alarm against the moved baseline.
    #[test]
    fn a_window_over_live_totals_raises_on_movement_and_clears_when_quiet() {
        let alarms = OperatorAlarms::new();
        let mut tick = TickWindow::new();

        // Start: the host has answered nothing.
        apply(&alarms, tick.observe(ServeCounters::default()));
        assert_eq!(state(&alarms).arming(), Arming::Armed);
        assert!(state(&alarms).live().is_none());

        // Something refused between reads.
        let mut totals = window(1, 0, 0);
        apply(&alarms, tick.observe(totals));
        assert_eq!(
            state(&alarms).live().map(RaisedAlarm::alarm),
            Some(OperatorAlarm::ServeSigningRefused {
                pre_flight: 1,
                late: 0,
            }),
        );

        // Nothing moved: the session total still says one refusal, the
        // window says none.
        apply(&alarms, tick.observe(totals));
        assert!(
            state(&alarms).live().is_none(),
            "a quiet tick clears even though the totals still carry the refusal"
        );

        // A lookup fails later, measured against the moved baseline.
        totals.lookup_failures += 4;
        apply(&alarms, tick.observe(totals));
        assert_eq!(
            state(&alarms).live().map(RaisedAlarm::alarm),
            Some(OperatorAlarm::ServeLookupsFailing { failures: 4 }),
            "the earlier refusal is in the baseline, not in this window"
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
