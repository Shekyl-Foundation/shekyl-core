// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;

fn redrawn() -> OperatorAlarm {
    OperatorAlarm::VanguardStateRedrawn
}

fn degraded(cause: DegradedCause) -> OperatorAlarm {
    OperatorAlarm::TransportDegraded { cause: Some(cause) }
}

fn live_for(alarms: &OperatorAlarms, condition: AlarmCondition) -> Option<RaisedAlarm> {
    alarms
        .board()
        .condition(condition)
        .and_then(ConditionState::live)
}

fn queued(alarms: &OperatorAlarms) -> Vec<OperatorAlarm> {
    alarms
        .board()
        .unacknowledged()
        .iter()
        .map(|r| r.alarm())
        .collect()
}

/// Pins every variant's classification. A reclassification is then a diff
/// in this test, which is where the reopening criterion gets read.
#[test]
fn lifetime_classification_is_pinned_per_variant() {
    assert_eq!(
        OperatorAlarm::TransportDegraded { cause: None }.lifetime(),
        AlarmLifetime::Episode,
    );
    assert_eq!(
        OperatorAlarm::VanguardStateRedrawn.lifetime(),
        AlarmLifetime::LatchedRederived,
        "the fresh guard draw has already happened and the warning clears without it",
    );
    assert_eq!(
        OperatorAlarm::VanguardStateUnpersisted.lifetime(),
        AlarmLifetime::Episode,
        "nothing has rotated: a successful write genuinely ends this one",
    );
    assert_eq!(
        OperatorAlarm::VanguardRepairSkipped {
            decoded: 1,
            announced: 2
        }
        .lifetime(),
        AlarmLifetime::Episode,
    );
    assert_eq!(
        OperatorAlarm::ServeSetStale { lag: 12 }.lifetime(),
        AlarmLifetime::Episode,
        "a refresh that runs again re-pins and ends it",
    );
    assert_eq!(
        OperatorAlarm::ServeSetRefreshFailing { consecutive: 3 }.lifetime(),
        AlarmLifetime::Episode,
    );
    assert_eq!(
        OperatorAlarm::ServeSetPinsDropped {
            dropped: 2,
            claimed: 9
        }
        .lifetime(),
        AlarmLifetime::Episode,
        "a rollback deleted pin rows, not leaf bytes: the next re-pin recovers",
    );
    assert_eq!(
        OperatorAlarm::ServeSetPostureLost { frozen_count: 4 }.lifetime(),
        AlarmLifetime::Episode,
        "the flag is re-readable; a refresh that re-declares ends the episode",
    );
    assert_eq!(
        OperatorAlarm::ServeSetRolledBack {
            minted_at_tip: 9,
            tip: 4
        }
        .lifetime(),
        AlarmLifetime::Episode,
        "re-ingest past the fork and the next refresh re-pins",
    );
    assert_eq!(
        OperatorAlarm::ServeSetBytesPruned { members: 1 }.lifetime(),
        AlarmLifetime::LatchedRederived,
        "pruned leaf bytes are gone until a chain replay; a re-pin cannot restore them",
    );
}

/// The serving conditions are one condition row, not four — an operator
/// asking "can I still serve what I am bonded for" wants one answer.
#[test]
fn every_serve_set_alarm_reports_on_one_condition() {
    for alarm in [
        OperatorAlarm::ServeSetStale { lag: 1 },
        OperatorAlarm::ServeSetRefreshFailing { consecutive: 1 },
        OperatorAlarm::ServeSetPinsDropped {
            dropped: 1,
            claimed: 2,
        },
        OperatorAlarm::ServeSetPostureLost { frozen_count: 4 },
        OperatorAlarm::ServeSetBytesPruned { members: 1 },
        OperatorAlarm::ServeSetRolledBack {
            minted_at_tip: 9,
            tip: 4,
        },
    ] {
        assert_eq!(alarm.condition(), AlarmCondition::ServeSetIntegrity);
    }
}

#[test]
fn an_empty_board_is_not_an_all_clear() {
    let alarms = OperatorAlarms::new();
    assert!(alarms
        .board()
        .condition(AlarmCondition::TransportLiveness)
        .is_none());
    assert_eq!(alarms.board().live().count(), 0);
    assert!(alarms.board().unacknowledged().is_empty());
}

#[test]
fn re_reporting_a_live_condition_keeps_one_incident() {
    let alarms = OperatorAlarms::new();
    alarms.raise(degraded(DegradedCause::Exited));
    let first = live_for(&alarms, AlarmCondition::TransportLiveness).expect("live");

    // Same fault, re-reported with a fresher cause: one incident, updated.
    alarms.raise(degraded(DegradedCause::BootstrapTimeout));
    let again = live_for(&alarms, AlarmCondition::TransportLiveness).expect("live");
    assert_eq!(again.incident(), first.incident());
    assert_eq!(
        again.alarm(),
        degraded(DegradedCause::BootstrapTimeout),
        "the payload must follow the newest failure",
    );
}

#[test]
fn a_different_fault_on_the_same_condition_opens_a_new_incident() {
    let alarms = OperatorAlarms::new();
    alarms.raise(OperatorAlarm::VanguardStateUnpersisted);
    let first = live_for(&alarms, AlarmCondition::VanguardIntegrity).expect("live");

    alarms.raise(redrawn());
    let second = live_for(&alarms, AlarmCondition::VanguardIntegrity).expect("live");
    assert_ne!(second.incident(), first.incident());
    assert_eq!(second.alarm(), redrawn());
}

#[test]
fn an_episode_leaves_the_board_when_its_condition_clears() {
    let alarms = OperatorAlarms::new();
    alarms.raise(degraded(DegradedCause::Exited));
    alarms.clear(AlarmCondition::TransportLiveness);
    assert!(live_for(&alarms, AlarmCondition::TransportLiveness).is_none());
    assert!(
        alarms.board().unacknowledged().is_empty(),
        "an episode that ended is not something to acknowledge",
    );
    assert!(alarms.board().is_quiet());
}

#[test]
fn a_latch_moves_to_the_queue_when_its_condition_clears() {
    let alarms = OperatorAlarms::new();
    alarms.raise(redrawn());
    let open = live_for(&alarms, AlarmCondition::VanguardIntegrity).expect("live");

    // The producer reports it fine — which for this fault means only that
    // the *evidence* is gone. The re-draw stands.
    alarms.clear(AlarmCondition::VanguardIntegrity);
    assert!(live_for(&alarms, AlarmCondition::VanguardIntegrity).is_none());
    let held = *alarms.board().unacknowledged().first().expect("queued");
    assert_eq!(held.alarm(), redrawn());
    assert_eq!(held.incident(), open.incident());
    assert!(!alarms.board().is_quiet());
}

/// The defect this shape exists to make impossible: three vanguard faults
/// share one condition and only one latches, so a per-condition slot would
/// have to choose between the unacknowledged re-draw and the unrelated fault
/// that happened after it.
#[test]
fn a_later_unrelated_fault_cannot_evict_a_queued_latch() {
    let alarms = OperatorAlarms::new();
    alarms.raise(redrawn());
    alarms.clear(AlarmCondition::VanguardIntegrity);

    alarms.raise(OperatorAlarm::VanguardStateUnpersisted);
    assert_eq!(
        queued(&alarms),
        vec![redrawn()],
        "a later fault on the same condition must not discard the re-draw",
    );
    assert_eq!(
        live_for(&alarms, AlarmCondition::VanguardIntegrity).map(RaisedAlarm::alarm),
        Some(OperatorAlarm::VanguardStateUnpersisted),
    );
}

#[test]
fn a_queued_latch_outlives_its_condition_being_disarmed() {
    let alarms = OperatorAlarms::new();
    alarms.raise(redrawn());
    alarms.clear(AlarmCondition::VanguardIntegrity);
    alarms.disarm(
        AlarmCondition::VanguardIntegrity,
        DisarmedReason::TransportStopped,
    );
    assert_eq!(
        alarms
            .board()
            .condition(AlarmCondition::VanguardIntegrity)
            .map(ConditionState::arming),
        Some(Arming::Disarmed(DisarmedReason::TransportStopped)),
    );
    assert_eq!(
        queued(&alarms),
        vec![redrawn()],
        "losing the ability to re-observe a fault is not evidence it did not happen",
    );
}

#[test]
fn a_live_fault_is_not_in_the_queue_to_be_acknowledged() {
    let alarms = OperatorAlarms::new();
    alarms.raise(redrawn());
    let open = live_for(&alarms, AlarmCondition::VanguardIntegrity).expect("live");
    assert!(
        alarms.board().unacknowledged().is_empty(),
        "acknowledgment is not a mute button, and the shape is what says so",
    );
    assert!(!alarms.acknowledge(open.incident()));
    assert!(live_for(&alarms, AlarmCondition::VanguardIntegrity).is_some());
}

#[test]
fn acknowledging_a_queued_latch_clears_it() {
    let alarms = OperatorAlarms::new();
    alarms.raise(redrawn());
    alarms.clear(AlarmCondition::VanguardIntegrity);
    let held = *alarms.board().unacknowledged().first().expect("queued");
    assert!(alarms.acknowledge(held.incident()));
    assert!(alarms.board().unacknowledged().is_empty());
    assert!(alarms.board().is_quiet());
}

#[test]
fn acknowledging_a_stale_incident_cannot_dismiss_a_newer_one() {
    let alarms = OperatorAlarms::new();
    alarms.raise(redrawn());
    alarms.clear(AlarmCondition::VanguardIntegrity);
    let first = *alarms.board().unacknowledged().first().expect("queued");
    assert!(alarms.acknowledge(first.incident()));

    // A genuinely new occurrence, after the operator read the old id. The
    // reclaim path is not taken here because nothing is queued.
    alarms.raise(redrawn());
    alarms.clear(AlarmCondition::VanguardIntegrity);
    let second = *alarms.board().unacknowledged().first().expect("queued");
    assert_ne!(second.incident(), first.incident());
    assert!(
        !alarms.acknowledge(first.incident()),
        "an acknowledgment names the incident the operator read",
    );
    assert_eq!(queued(&alarms), vec![redrawn()]);
}

#[test]
fn a_recurrence_reclaims_its_queued_incident_rather_than_duplicating_it() {
    let alarms = OperatorAlarms::new();
    alarms.raise(redrawn());
    let opened = live_for(&alarms, AlarmCondition::VanguardIntegrity).expect("live");
    alarms.clear(AlarmCondition::VanguardIntegrity);

    // `LatchedRederived` means the producer re-detects the same unfixed
    // problem on every start. That is one fault, not two.
    alarms.raise(redrawn());
    assert!(
        alarms.board().unacknowledged().is_empty(),
        "a recurrence must not sit in the queue beside its own live copy",
    );
    let live = live_for(&alarms, AlarmCondition::VanguardIntegrity).expect("live");
    assert_eq!(live.incident(), opened.incident());
}

#[test]
fn a_recurrence_after_an_unrelated_fault_still_reclaims() {
    let alarms = OperatorAlarms::new();
    alarms.raise(redrawn());
    let opened = live_for(&alarms, AlarmCondition::VanguardIntegrity).expect("live");
    alarms.clear(AlarmCondition::VanguardIntegrity);
    alarms.raise(OperatorAlarm::VanguardStateUnpersisted);

    // The unrelated fault is live; the re-draw is queued. Re-detecting the
    // re-draw must take it back out of the queue, not leave a copy behind.
    alarms.raise(redrawn());
    assert!(alarms.board().unacknowledged().is_empty());
    let live = live_for(&alarms, AlarmCondition::VanguardIntegrity).expect("live");
    assert_eq!(live.alarm(), redrawn());
    assert_eq!(live.incident(), opened.incident());
}

#[test]
fn a_late_subscriber_sees_the_open_incident_immediately() {
    let alarms = OperatorAlarms::new();
    alarms.raise(degraded(DegradedCause::BinaryRejected));
    let rx = alarms.subscribe();
    assert_eq!(
        rx.borrow()
            .condition(AlarmCondition::TransportLiveness)
            .and_then(ConditionState::live)
            .map(RaisedAlarm::alarm),
        Some(degraded(DegradedCause::BinaryRejected)),
    );
}
