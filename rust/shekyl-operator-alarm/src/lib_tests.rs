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
    alarms.board().condition(condition).live()
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
    assert_eq!(
        OperatorAlarm::ServingDiskLow {
            free_bytes: 1,
            threshold_bytes: 50,
        }
        .lifetime(),
        AlarmLifetime::Episode,
        "freeing space ends it; nothing outlives the fullness",
    );
    assert_eq!(
        OperatorAlarm::ChainProgressStalled {
            last_height: 100,
            stalled_for_secs: 1_800,
        }
        .lifetime(),
        AlarmLifetime::Episode,
        "the tip advancing ends the stall outright",
    );
    assert_eq!(
        OperatorAlarm::EpochUnclaimed {
            oldest_epoch: 41,
            outstanding_epochs: 3,
        }
        .lifetime(),
        AlarmLifetime::Episode,
        "a claim confirming ends the backlog; it re-derives every tick",
    );
    assert_eq!(
        OperatorAlarm::ClaimForfeited {
            epoch: 17,
            forfeited_atomic: 250,
        }
        .lifetime(),
        AlarmLifetime::Episode,
        "Episode because the producer never clears it in-session; NOT \
         LatchedRederived because nothing re-detects a forfeit after \
         restart — the durable-record third class is the FOLLOWUPS row",
    );
    assert_eq!(
        OperatorAlarm::ServeSigningRefused {
            pre_flight: 1,
            late: 0,
        }
        .lifetime(),
        AlarmLifetime::Episode,
        "a per-tick window over the counters: a quiet tick ends it, and the \
         next tick re-derives it from the counters alone",
    );
    assert_eq!(
        OperatorAlarm::ServeLookupsFailing { failures: 1 }.lifetime(),
        AlarmLifetime::Episode,
        "same window; a tick in which every lookup succeeded ends it",
    );
    assert_eq!(
        OperatorAlarm::ServeListenerFailing { accept_errors: 1 }.lifetime(),
        AlarmLifetime::Episode,
        "same window; a tick in which every accept succeeded ends it",
    );
}

/// Serve health is its own row, not a serve-set reading: a persona can
/// hold every bonded shard and still lose every pass.
#[test]
fn serve_health_alarms_report_on_their_own_condition() {
    for alarm in [
        OperatorAlarm::ServeSigningRefused {
            pre_flight: 1,
            late: 1,
        },
        OperatorAlarm::ServeLookupsFailing { failures: 1 },
        OperatorAlarm::ServeListenerFailing { accept_errors: 1 },
    ] {
        assert_eq!(alarm.condition(), AlarmCondition::ServeHealth);
        assert_ne!(alarm.condition(), AlarmCondition::ServeSetIntegrity);
    }
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

/// A new board holds every condition, each one unreported: never a missing
/// row a reader could take for "all clear" (rule 43). Red edit: start
/// `AlarmBoard::default` with no rows, or drop a condition from
/// `AlarmCondition::ALL`.
#[test]
fn a_new_board_reads_every_condition_unreported() {
    let board = OperatorAlarms::new().board();
    let rows: Vec<_> = board.conditions().collect();
    assert_eq!(rows.len(), AlarmCondition::ALL.len());
    for (at, (condition, state)) in rows.into_iter().enumerate() {
        assert_eq!(
            condition,
            AlarmCondition::ALL[at],
            "the board's order is ALL's"
        );
        assert_eq!(
            state.arming(),
            Arming::Disarmed(DisarmedReason::Unreported),
            "{condition:?} reads unreported until its producer reports",
        );
        assert!(state.live().is_none());
    }
    assert!(board.unacknowledged().is_empty());
}

/// `AlarmCondition::ALL` lists every variant once. The match is exhaustive
/// in this crate, so a new condition does not compile until it has a place;
/// the loop then checks that the place is its own.
#[test]
fn every_condition_is_listed_once() {
    fn place(condition: AlarmCondition) -> usize {
        match condition {
            AlarmCondition::TransportLiveness => 0,
            AlarmCondition::OnionReachability => 1,
            AlarmCondition::VanguardIntegrity => 2,
            AlarmCondition::ServeSetIntegrity => 3,
            AlarmCondition::ServingDiskHeadroom => 4,
            AlarmCondition::ServeHealth => 5,
            AlarmCondition::ChainProgress => 6,
            AlarmCondition::EpochClaim => 7,
            AlarmCondition::ClaimForfeiture => 8,
            AlarmCondition::PendingFundsIntegrity => 9,
        }
    }
    for (at, condition) in AlarmCondition::ALL.into_iter().enumerate() {
        assert_eq!(
            place(condition),
            at,
            "{condition:?} is listed at its own place"
        );
    }
}

/// The onion's reachability has a row, unreported, before anything checks
/// it (`TSR-W3` adds the check). Red edit: delete the variant or its place
/// in `ALL`.
#[test]
fn the_onion_row_exists_unreported() {
    assert_eq!(
        OperatorAlarms::new()
            .board()
            .condition(AlarmCondition::OnionReachability)
            .arming(),
        Arming::Disarmed(DisarmedReason::Unreported),
    );
}

/// A check that ends without disarming leaves its rows "check stopped",
/// never armed and quiet; one that disarmed on its way out keeps its own
/// reason; a live alarm stays. Red edit: make `CheckGuard::drop` a no-op,
/// or have it disarm rows that are already disarmed.
#[test]
fn a_check_that_stops_reads_check_stopped() {
    let alarms = Arc::new(OperatorAlarms::new());
    {
        let _guard = alarms.check_guard(&[
            AlarmCondition::TransportLiveness,
            AlarmCondition::VanguardIntegrity,
            AlarmCondition::ServeHealth,
        ]);
        alarms.arm(AlarmCondition::TransportLiveness);
        alarms.raise(degraded(DegradedCause::Exited));
        alarms.arm(AlarmCondition::VanguardIntegrity);
        alarms.disarm(AlarmCondition::ServeHealth, DisarmedReason::NotServing);
    }
    let board = alarms.board();
    assert_eq!(
        board.condition(AlarmCondition::TransportLiveness).arming(),
        Arming::Disarmed(DisarmedReason::CheckStopped),
    );
    assert_eq!(
        board
            .condition(AlarmCondition::TransportLiveness)
            .live()
            .map(RaisedAlarm::alarm),
        Some(degraded(DegradedCause::Exited)),
        "a check that stopped observed nothing being fixed",
    );
    assert_eq!(
        board.condition(AlarmCondition::VanguardIntegrity).arming(),
        Arming::Disarmed(DisarmedReason::CheckStopped),
    );
    assert_eq!(
        board.condition(AlarmCondition::ServeHealth).arming(),
        Arming::Disarmed(DisarmedReason::NotServing),
        "a clean exit keeps the reason it gave",
    );
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
            .arming(),
        Arming::Disarmed(DisarmedReason::TransportStopped),
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
            .live()
            .map(RaisedAlarm::alarm),
        Some(degraded(DegradedCause::BinaryRejected)),
    );
}
