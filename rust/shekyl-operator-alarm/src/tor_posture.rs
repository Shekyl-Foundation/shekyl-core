// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The tor-posture producer for the [operator alarm channel](crate) — OA-1's
//! first, and the reason the channel exists before anything serves.
//!
//! `ARCHIVAL_BOND_2D2_SP_T0_TOR.md` §3c assigns the split explicitly: "liveness
//! policy lives in `shekyl-tor` because it is transport policy; the wallet layer
//! consumes posture and owns only the UX mapping (`82`)". This module is that
//! mapping and nothing else — it decides no retry, no backoff and no
//! give-up, because §3c already decided all three and there is no give-up state
//! to map.
//!
//! # The one rule that is easy to get wrong
//!
//! `Degraded` is an **episode**, not an edge. §3c: intermediate `Starting` /
//! `Connecting` are not published while degraded, a brief recovery publishes
//! `Ready { recovering: true }`, and the episode ends only at
//! `Ready { recovering: false }`. So a translator that treats any `Ready` as
//! "all better" reports a flapping tor as a series of resolved incidents, which
//! is the shape an operator learns to ignore. Here `recovering: true` keeps the
//! open incident open — same [`IncidentId`](super::IncidentId) throughout — and
//! only `recovering: false` clears it.
//!
//! # Why vanguard integrity is disarmed rather than quiet
//!
//! [`ServiceWarning`] rides the `warning` field, and that field exists on
//! [`TorPosture::Ready`] and on no other variant. While tor is starting,
//! bootstrapping, retrying or degraded, the wallet does not *know* whether the
//! guard topology is intact — it has no live incarnation to ask. Reporting that
//! as no-alarm would be indistinguishable from reporting it as checked-and-fine,
//! so the row is marked [`Disarmed`](super::Arming::Disarmed) instead. Same
//! reason the channel is a snapshot rather than a stream.

use std::sync::Arc;

use shekyl_tor::service::{ServiceFailure, ServiceWarning, TorPosture};
use shekyl_tor::vanguard_rotation::VanguardsWarning;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::{AlarmCondition, DegradedCause, DisarmedReason, OperatorAlarm, OperatorAlarms};

/// Drive the alarm board from a tor supervisor's posture channel until the
/// supervisor stops.
///
/// Takes the **receiver**, not the
/// [`TorService`](shekyl_tor::service::TorService): the mapping is a pure
/// function of published posture, so binding it to a live supervisor would make
/// it untestable without a verified tor binary on the machine running the test.
///
/// The task ends when the posture sender drops, which §3c defines as the
/// clean-shutdown signal ("a clean caller-initiated shutdown has no posture
/// state, deliberately"). On the way out it disarms both conditions rather than
/// clearing them: a supervisor that is gone is not a transport that is well.
pub fn spawn_tor_posture_translator(
    posture: watch::Receiver<TorPosture>,
    alarms: Arc<OperatorAlarms>,
) -> JoinHandle<()> {
    tokio::spawn(async move { translate(posture, &alarms).await })
}

async fn translate(mut posture: watch::Receiver<TorPosture>, alarms: &OperatorAlarms) {
    loop {
        // Scoped so the watch borrow is released before the await below.
        let current = posture.borrow_and_update().clone();
        apply(alarms, &current);
        if posture.changed().await.is_err() {
            break;
        }
    }
    alarms.disarm(
        AlarmCondition::TransportLiveness,
        DisarmedReason::TransportStopped,
    );
    alarms.disarm(
        AlarmCondition::VanguardIntegrity,
        DisarmedReason::TransportStopped,
    );
}

/// Map one published posture onto the board.
///
/// Total and side-effect-free apart from the board writes, so the whole state
/// machine — including the episode rule — is testable by calling it.
fn apply(alarms: &OperatorAlarms, posture: &TorPosture) {
    alarms.arm(AlarmCondition::TransportLiveness);
    match posture {
        // §3c: `Restarting` is "normal-operations transient — not the alarm
        // state", and `Starting` / `Connecting` are not published at all while
        // degraded, so reaching any of the three means no episode is open.
        TorPosture::Starting | TorPosture::Connecting { .. } | TorPosture::Restarting { .. } => {
            alarms.clear(AlarmCondition::TransportLiveness);
            alarms.disarm(
                AlarmCondition::VanguardIntegrity,
                DisarmedReason::TransportNotReady,
            );
        }
        TorPosture::Degraded { last } => {
            alarms.raise(OperatorAlarm::TransportDegraded {
                cause: Some(degraded_cause(last)),
            });
            alarms.disarm(
                AlarmCondition::VanguardIntegrity,
                DisarmedReason::TransportNotReady,
            );
        }
        TorPosture::Ready {
            warning,
            recovering,
            ..
        } => {
            if *recovering {
                // The episode is still open. Do not re-raise over the incident
                // — this posture carries no failure, so raising here would
                // replace a known cause with `None`; the only case that needs a
                // write is a translator that attached mid-episode and has no
                // incident to continue.
                if !alarms.is_raised(AlarmCondition::TransportLiveness) {
                    alarms.raise(OperatorAlarm::TransportDegraded { cause: None });
                }
            } else {
                alarms.clear(AlarmCondition::TransportLiveness);
            }

            alarms.arm(AlarmCondition::VanguardIntegrity);
            match warning {
                Some(ServiceWarning::Vanguards(w)) => alarms.raise(vanguard_alarm(w)),
                None => alarms.clear(AlarmCondition::VanguardIntegrity),
            }
        }
    }
}

/// Project a supervisor failure onto its operator-facing cause tag.
///
/// One arm per [`ServiceFailure`] variant and no catch-all, so a new failure
/// mode in the supervisor cannot reach an operator as a stale label.
fn degraded_cause(failure: &ServiceFailure) -> DegradedCause {
    match failure {
        ServiceFailure::Binary(_) => DegradedCause::BinaryRejected,
        ServiceFailure::Control(_) => DegradedCause::ControlChannelFailed,
        ServiceFailure::NoSocksListener => DegradedCause::NoSocksListener,
        ServiceFailure::BootstrapTimeout => DegradedCause::BootstrapTimeout,
        ServiceFailure::Exited(_) => DegradedCause::Exited,
        ServiceFailure::Internal(_) => DegradedCause::Internal,
        ServiceFailure::OnionPublish(_) => DegradedCause::OnionPublishFailed,
        ServiceFailure::Vanguards(_) => DegradedCause::VanguardsFailed,
    }
}

/// Project a vanguard warning onto its alarm.
///
/// The rendered causes (`String`s on two of the three variants) are dropped
/// deliberately: this vocabulary is bounded, and the detail belongs in the
/// transport crate's own logs, not in a value every board subscriber clones.
fn vanguard_alarm(warning: &VanguardsWarning) -> OperatorAlarm {
    match warning {
        VanguardsWarning::StateUnusable(_) => OperatorAlarm::VanguardStateRedrawn,
        VanguardsWarning::StateUnpersisted(_) => OperatorAlarm::VanguardStateUnpersisted,
        VanguardsWarning::RepairSkipped { decoded, announced } => {
            OperatorAlarm::VanguardRepairSkipped {
                decoded: *decoded,
                announced: *announced,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use super::*;
    use crate::{AlarmLifetime, Arming, ConditionState, IncidentId, RaisedAlarm};

    fn socks() -> SocketAddr {
        "127.0.0.1:9050".parse().expect("loopback addr")
    }

    fn ready(recovering: bool, warning: Option<ServiceWarning>) -> TorPosture {
        TorPosture::Ready {
            socks_addr: socks(),
            warning,
            recovering,
        }
    }

    fn degraded() -> TorPosture {
        TorPosture::Degraded {
            last: ServiceFailure::BootstrapTimeout,
        }
    }

    fn raised(alarms: &OperatorAlarms, condition: AlarmCondition) -> Option<RaisedAlarm> {
        alarms
            .board()
            .condition(condition)
            .and_then(ConditionState::raised)
    }

    fn arming(alarms: &OperatorAlarms, condition: AlarmCondition) -> Option<Arming> {
        alarms
            .board()
            .condition(condition)
            .map(ConditionState::arming)
    }

    fn transport_incident(alarms: &OperatorAlarms) -> Option<IncidentId> {
        raised(alarms, AlarmCondition::TransportLiveness).map(RaisedAlarm::incident)
    }

    /// The §3c oracle: a degraded tor that briefly recovers and degrades again
    /// is **one** incident, not two, and it ends only at the sustained-recovery
    /// edge.
    ///
    /// Negative control, run: disable the `recovering` branch in [`apply`] so
    /// any `Ready` clears, and this fails at the **first recovery** —
    /// `left: None, right: Some(IncidentId(1))` — on the incident-identity axis
    /// the defect lives on, not on a count or a final-state assertion that
    /// other bugs could also trip. The vanguard and shutdown tests stay green
    /// under that mutation, which is what makes the failure specific.
    #[test]
    fn a_flapping_transport_is_one_continuous_incident() {
        let alarms = OperatorAlarms::new();

        apply(&alarms, &degraded());
        let opened = transport_incident(&alarms).expect("the episode opens");

        apply(&alarms, &ready(true, None));
        assert_eq!(
            transport_incident(&alarms),
            Some(opened),
            "a brief recovery inside a degraded episode is not a resolution",
        );

        apply(&alarms, &degraded());
        assert_eq!(
            transport_incident(&alarms),
            Some(opened),
            "falling back into degraded continues the incident, it does not start one",
        );

        apply(&alarms, &ready(false, None));
        assert!(
            transport_incident(&alarms).is_none(),
            "sustained recovery is the alarm-clear edge",
        );
    }

    #[test]
    fn a_translator_attaching_mid_episode_does_not_read_healthy() {
        let alarms = OperatorAlarms::new();

        // The supervisor was already degraded and already partly recovered
        // before anyone subscribed; the failure that opened the episode was
        // published to nobody.
        apply(&alarms, &ready(true, None));
        assert_eq!(
            raised(&alarms, AlarmCondition::TransportLiveness).map(RaisedAlarm::alarm),
            Some(OperatorAlarm::TransportDegraded { cause: None }),
            "an incident with an unknown cause still beats a board that reads clean",
        );
    }

    #[test]
    fn a_known_cause_is_not_overwritten_by_a_recovery_posture() {
        let alarms = OperatorAlarms::new();
        apply(
            &alarms,
            &TorPosture::Degraded {
                last: ServiceFailure::NoSocksListener,
            },
        );
        apply(&alarms, &ready(true, None));
        assert_eq!(
            raised(&alarms, AlarmCondition::TransportLiveness).map(RaisedAlarm::alarm),
            Some(OperatorAlarm::TransportDegraded {
                cause: Some(DegradedCause::NoSocksListener)
            }),
            "the recovery posture carries no failure and must not erase the one that did",
        );
    }

    #[test]
    fn restarting_is_a_transient_and_not_an_alarm() {
        let alarms = OperatorAlarms::new();
        apply(
            &alarms,
            &TorPosture::Restarting {
                attempt: 2,
                retry_in: Duration::from_secs(4),
            },
        );
        assert!(transport_incident(&alarms).is_none());
        assert_eq!(
            arming(&alarms, AlarmCondition::TransportLiveness),
            Some(Arming::Armed),
            "the liveness check is running the whole time — that is why it can say nothing",
        );
    }

    #[test]
    fn vanguard_integrity_is_disarmed_whenever_there_is_no_live_incarnation() {
        let alarms = OperatorAlarms::new();
        for posture in [
            TorPosture::Starting,
            TorPosture::Connecting { progress: 40 },
            TorPosture::Restarting {
                attempt: 1,
                retry_in: Duration::from_secs(1),
            },
            degraded(),
        ] {
            apply(&alarms, &posture);
            assert_eq!(
                arming(&alarms, AlarmCondition::VanguardIntegrity),
                Some(Arming::Disarmed(DisarmedReason::TransportNotReady)),
                "no incarnation means the guard topology is unknown, not known-good: {posture:?}",
            );
        }
    }

    #[test]
    fn a_clean_ready_arms_vanguard_integrity_and_reports_nothing() {
        let alarms = OperatorAlarms::new();
        apply(&alarms, &ready(false, None));
        assert_eq!(
            arming(&alarms, AlarmCondition::VanguardIntegrity),
            Some(Arming::Armed),
        );
        assert!(raised(&alarms, AlarmCondition::VanguardIntegrity).is_none());
    }

    #[test]
    fn a_re_drawn_vanguard_set_latches_past_the_warning_disappearing() {
        let alarms = OperatorAlarms::new();
        apply(
            &alarms,
            &ready(
                false,
                Some(ServiceWarning::Vanguards(VanguardsWarning::StateUnusable(
                    "state file is not readable".to_owned(),
                ))),
            ),
        );
        let latched = raised(&alarms, AlarmCondition::VanguardIntegrity).expect("raised");
        assert_eq!(latched.alarm(), OperatorAlarm::VanguardStateRedrawn);
        assert_eq!(latched.lifetime(), AlarmLifetime::LatchedRederived);

        // The next pass persists cleanly, so the warning is gone — but the set
        // was already drawn fresh, and that is what the operator needs told.
        apply(&alarms, &ready(false, None));
        let held = raised(&alarms, AlarmCondition::VanguardIntegrity).expect("still raised");
        assert_eq!(held.incident(), latched.incident());
        assert!(held.condition_cleared());
    }

    #[test]
    fn an_unpersisted_vanguard_set_clears_when_the_write_succeeds() {
        let alarms = OperatorAlarms::new();
        apply(
            &alarms,
            &ready(
                false,
                Some(ServiceWarning::Vanguards(
                    VanguardsWarning::StateUnpersisted("disk full".to_owned()),
                )),
            ),
        );
        assert_eq!(
            raised(&alarms, AlarmCondition::VanguardIntegrity).map(RaisedAlarm::alarm),
            Some(OperatorAlarm::VanguardStateUnpersisted),
        );

        apply(&alarms, &ready(false, None));
        assert!(
            raised(&alarms, AlarmCondition::VanguardIntegrity).is_none(),
            "nothing rotated, so a successful write genuinely ends this one",
        );
    }

    #[test]
    fn a_skipped_repair_carries_its_counts() {
        let alarms = OperatorAlarms::new();
        apply(
            &alarms,
            &ready(
                false,
                Some(ServiceWarning::Vanguards(VanguardsWarning::RepairSkipped {
                    decoded: 7,
                    announced: 9,
                })),
            ),
        );
        assert_eq!(
            raised(&alarms, AlarmCondition::VanguardIntegrity).map(RaisedAlarm::alarm),
            Some(OperatorAlarm::VanguardRepairSkipped {
                decoded: 7,
                announced: 9
            }),
        );
    }

    #[test]
    fn every_service_failure_maps_to_its_own_cause() {
        use shekyl_tor::control::ControlError;
        let failures = [
            ServiceFailure::NoSocksListener,
            ServiceFailure::BootstrapTimeout,
            ServiceFailure::Exited(None),
            ServiceFailure::Internal("join error".to_owned()),
            ServiceFailure::Control(ControlError::ConnectionClosed),
        ];
        let mapped: Vec<DegradedCause> = failures.iter().map(degraded_cause).collect();
        let mut deduped = mapped.clone();
        deduped.dedup();
        assert_eq!(
            mapped.len(),
            deduped.len(),
            "distinct failures must not collapse onto one operator instruction",
        );
    }

    #[tokio::test]
    async fn a_stopped_supervisor_disarms_rather_than_clears() {
        let (tx, rx) = watch::channel(ready(
            false,
            Some(ServiceWarning::Vanguards(VanguardsWarning::StateUnusable(
                "unreadable".to_owned(),
            ))),
        ));
        let alarms = Arc::new(OperatorAlarms::new());
        let mut board = alarms.subscribe();
        let task = spawn_tor_posture_translator(rx, Arc::clone(&alarms));

        // The supervisor shuts down cleanly: §3c's sender-drop signal.
        drop(tx);
        task.await.expect("translator task");

        for condition in [
            AlarmCondition::TransportLiveness,
            AlarmCondition::VanguardIntegrity,
        ] {
            assert_eq!(
                arming(&alarms, condition),
                Some(Arming::Disarmed(DisarmedReason::TransportStopped)),
                "a supervisor that is gone is not a transport that is well",
            );
        }
        assert!(
            raised(&alarms, AlarmCondition::VanguardIntegrity).is_some(),
            "shutting tor down does not un-re-draw the guard set",
        );

        // The board really was published, not just mutated in place.
        assert!(board.has_changed().expect("channel alive"));
        assert!(board
            .borrow_and_update()
            .condition(AlarmCondition::TransportLiveness)
            .is_some());
    }
}
