// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serving task's serve-health *measurement* (`TJ-D`, `SF-D6`).
//!
//! Mapping onto the board is [`shekyl_operator_alarm::serve_health`] — this
//! module owns how often the host's counters are sampled and publishes the
//! windowed [`ServeHealthObservation`]s. A dedicated task rather than a
//! line in the refresh loop, for the reason the disk probe is one: the
//! counters are not a serve-set reading, and the refresh they would
//! otherwise ride on awaits the store actor with no timeout. A key that
//! starts refusing while a refresh is wedged is the case this row exists
//! for, and a reading taken after that refresh would arrive only when the
//! refresh did.

use std::sync::Arc;
use std::time::Duration;

use shekyl_operator_alarm::serve_health::{apply as report_health, TickWindow};
use shekyl_operator_alarm::OperatorAlarms;
use shekyl_p_host::ServeCounters;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Sample the host's counters until cancelled, then return so the serving
/// task can disarm the row as not-serving.
///
/// `sample` is one read of the session totals — in production
/// `ServeCounters::read` over the host's detached
/// [`ServeCounterReader`](shekyl_p_host::ServeCounterReader), which is why
/// this task never holds the host. The window ([`TickWindow`]) lives here
/// with the task that advances it: the first reading is windowed against
/// zero and taken immediately, so the board is armed with whatever the
/// host answered between bind and now rather than sitting `NotServing`
/// for a cadence, and so a refusal in that interval is reported rather
/// than folded into a baseline.
///
/// Returns only on `cancel`. The caller awaits the handle *before*
/// disarming the row, so a reading in flight at teardown cannot land after
/// `NotServing` and leave a stopped host reading as healthy.
pub(crate) fn spawn_health_probe(
    mut sample: impl FnMut() -> ServeCounters + Send + 'static,
    cadence: Duration,
    alarms: Arc<OperatorAlarms>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut window = TickWindow::new();
        report_health(&alarms, window.observe(sample()));
        let mut ticker = tokio::time::interval(cadence);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick completes immediately; the line above already
        // reported that reading.
        ticker.tick().await;
        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                _ = ticker.tick() => {
                    report_health(&alarms, window.observe(sample()));
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use shekyl_operator_alarm::serve_health::ServeHealthObservation;
    use shekyl_operator_alarm::{
        AlarmCondition, Arming, ConditionState, DisarmedReason, OperatorAlarm,
    };

    use super::*;

    const CADENCE: Duration = Duration::from_millis(10);

    async fn settle_until(
        alarms: &OperatorAlarms,
        want: impl Fn(&shekyl_operator_alarm::AlarmBoard) -> bool,
    ) -> bool {
        for _ in 0..200 {
            if want(&alarms.board()) {
                return true;
            }
            tokio::time::sleep(CADENCE).await;
        }
        false
    }

    fn live_alarm(board: &shekyl_operator_alarm::AlarmBoard) -> Option<OperatorAlarm> {
        board
            .condition(AlarmCondition::ServeHealth)
            .and_then(ConditionState::live)
            .map(shekyl_operator_alarm::RaisedAlarm::alarm)
    }

    /// The reading the finding is about: the counters advance while nothing
    /// else in the serving task makes progress. The probe's only awaits are
    /// its own ticker and the cancel, so the sampler here stands in for a
    /// host whose refresh is wedged on the store actor — the alarm must
    /// still fire within a cadence, clear on a quiet tick, and the task
    /// must stop when told so the caller's `NotServing` is the last word.
    #[tokio::test]
    async fn counters_advancing_under_a_wedged_refresh_still_raise_and_clear() {
        let alarms = Arc::new(OperatorAlarms::new());
        let sign_failures = Arc::new(AtomicU64::new(0));
        let cancel = CancellationToken::new();
        let sampled = Arc::clone(&sign_failures);
        let probe = spawn_health_probe(
            move || ServeCounters {
                sign_failures: sampled.load(Ordering::Relaxed),
                ..ServeCounters::default()
            },
            CADENCE,
            Arc::clone(&alarms),
            cancel.clone(),
        );

        let armed = settle_until(&alarms, |b| {
            b.condition(AlarmCondition::ServeHealth)
                .map(ConditionState::arming)
                .is_some_and(|a| a == Arming::Armed)
        })
        .await;
        assert!(
            armed,
            "the first reading arms the row without waiting a cadence"
        );
        assert!(
            live_alarm(&alarms.board()).is_none(),
            "nothing refused yet, so nothing is live"
        );

        // A key refusing *continuously*: the total moves between every two
        // samples, so the alarm is live on every tick until the refusals
        // stop, and the poll below cannot fall between a raise and the
        // next tick's clear. The exact movement per tick is `TickWindow`'s
        // test; this one asks whether the refusal reached the board at all.
        let raised = settle_until(&alarms, |b| {
            sign_failures.fetch_add(1, Ordering::Relaxed);
            matches!(
                live_alarm(b),
                Some(OperatorAlarm::ServeSigningRefused { pre_flight, late: 0 }) if pre_flight > 0
            )
        })
        .await;
        assert!(
            raised,
            "a refusing key must reach the board on the probe's own tick; \
             nothing here awaited a refresh"
        );

        // Quiet from here: the totals hold, the window reads no movement.
        let cleared = settle_until(&alarms, |b| live_alarm(b).is_none()).await;
        assert!(cleared, "a quiet tick clears the row");

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), probe)
            .await
            .expect("the probe returns once cancelled")
            .expect("the probe does not panic");
        // The caller disarms after the join; a reading cannot follow it.
        report_health(&alarms, ServeHealthObservation::NotServing);
        tokio::time::sleep(CADENCE * 3).await;
        assert_eq!(
            alarms
                .board()
                .condition(AlarmCondition::ServeHealth)
                .map(ConditionState::arming),
            Some(Arming::Disarmed(DisarmedReason::NotServing)),
            "no late reading overwrote the disarm"
        );
    }
}
