// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use std::sync::Arc;

use serde_json::{json, Value};
use shekyl_operator_alarm::cadence::{
    apply_chain_progress, apply_claim, apply_pending_outcomes, record_forfeit,
    ChainProgressObservation, ClaimObservation,
};
use shekyl_operator_alarm::disk::{self, DiskObservation};
use shekyl_operator_alarm::serve_health::{self, ServeHealthObservation};
use shekyl_operator_alarm::serve_set::{self, ServeSetObservation};
use shekyl_operator_alarm::tor_posture::spawn_tor_posture_translator;
use shekyl_operator_alarm::OperatorAlarms;
use shekyl_p_host::ServeCounters;
use shekyl_tor_control_wallet::service::{ServiceFailure, TorPosture};

use super::operator_alarm_result;

fn wire(alarms: &OperatorAlarms) -> Value {
    serde_json::to_value(operator_alarm_result(&alarms.board())).expect("serialize")
}

/// Wait, bounded, until the board says what `done` asks.
async fn settle(alarms: &OperatorAlarms, done: impl Fn(&Value) -> bool) -> Value {
    for _ in 0..500 {
        let now = wire(alarms);
        if done(&now) {
            return now;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    wire(alarms)
}

fn row<'a>(reply: &'a Value, condition: &str) -> &'a Value {
    reply["conditions"]
        .as_array()
        .expect("conditions is a list")
        .iter()
        .find(|r| r["condition"] == condition)
        .unwrap_or_else(|| panic!("no row for {condition}: {reply}"))
}

fn alarm_key(row: &Value) -> Option<String> {
    row["fault"]["alarm"]
        .as_object()
        .and_then(|o| o.keys().next().cloned())
}

/// A fresh board on the wire: every condition, in the board's order, each
/// one `{"disarmed": "unreported"}` with a `null` fault, and nothing
/// outstanding. Pinned whole, so a renamed keyword or a dropped row is a
/// diff here. Red edit: skip a disarmed row in `operator_alarm_result`, or
/// write `fault` only when it is set.
#[test]
fn a_fresh_board_reads_every_row_unreported_on_the_wire() {
    let rows: Vec<Value> = [
        "transport-liveness",
        "onion-reachability",
        "vanguard-integrity",
        "serve-set-integrity",
        "serve-disk-headroom",
        "serve-health",
        "chain-progress",
        "epoch-claim",
        "claim-forfeiture",
        "pending-funds-integrity",
    ]
    .into_iter()
    .map(|condition| {
        json!({
            "condition": condition,
            "arming": {"disarmed": "unreported"},
            "fault": null,
        })
    })
    .collect();
    assert_eq!(
        wire(&OperatorAlarms::new()),
        json!({"conditions": rows, "unacknowledged": []}),
    );
}

/// Every producer's condition reaches the reply, the serving task's three
/// (serve set, disk, serve health) and the persona's tor among them, each
/// raised through the producer that raises it in production. Red edit:
/// drop a row from `AlarmBoard::conditions`, or project a live alarm as
/// `null`.
#[tokio::test]
async fn every_producers_condition_reaches_the_reply() {
    let alarms = Arc::new(OperatorAlarms::new());

    // The cadence driver's four.
    apply_chain_progress(
        &alarms,
        ChainProgressObservation::Stalled {
            last_height: 40,
            stalled_for_secs: 900,
        },
    );
    apply_claim(
        &alarms,
        ClaimObservation::Behind {
            oldest_epoch: 3,
            outstanding_epochs: 2,
        },
    );
    record_forfeit(&alarms, 2, 111);
    apply_pending_outcomes(&alarms, 1, 0);

    // The serving task's three.
    serve_set::apply(
        &alarms,
        ServeSetObservation::RefreshFailed {
            already_pruned: None,
        },
    );
    disk::apply(
        &alarms,
        DiskObservation::Measured {
            free_bytes: 10,
            threshold_bytes: 20,
        },
    );
    serve_health::apply(
        &alarms,
        ServeHealthObservation::Tick(ServeCounters {
            sign_failures: 1,
            ..ServeCounters::default()
        }),
    );

    // The persona's tor, through its translator.
    let (posture, rx) = tokio::sync::watch::channel(TorPosture::Degraded {
        last: ServiceFailure::NoSocksListener,
    });
    let translator = spawn_tor_posture_translator(rx, Arc::clone(&alarms));

    let reply = settle(&alarms, |r| {
        alarm_key(row(r, "transport-liveness")).is_some()
    })
    .await;
    for (condition, alarm) in [
        ("transport-liveness", "transport-degraded"),
        ("serve-set-integrity", "serve-set-refresh-failing"),
        ("serve-disk-headroom", "serve-disk-low"),
        ("serve-health", "serve-signing-refused"),
        ("chain-progress", "chain-progress-stalled"),
        ("epoch-claim", "epoch-unclaimed"),
        ("claim-forfeiture", "claim-forfeited"),
        ("pending-funds-integrity", "reservation-spent-elsewhere"),
    ] {
        let at = row(&reply, condition);
        assert_eq!(at["arming"], json!({"armed": null}), "{condition}: {reply}");
        assert_eq!(
            alarm_key(at).as_deref(),
            Some(alarm),
            "{condition}: {reply}"
        );
    }
    assert_eq!(
        row(&reply, "transport-liveness")["fault"]["alarm"],
        json!({"transport-degraded": {"cause": {"socks-missing": null}}}),
    );
    assert_eq!(
        row(&reply, "chain-progress")["fault"]["alarm"],
        json!({"chain-progress-stalled": {"height": 40, "age": 900}}),
    );
    // Vanguard integrity is unknown while tor is degraded: disarmed, and
    // its fault is `null` because nothing is known, not because it is fine.
    assert_eq!(
        row(&reply, "vanguard-integrity")["arming"],
        json!({"disarmed": "transport-unready"}),
    );
    // The onion's row exists and is not checked by anything in this build.
    assert_eq!(
        row(&reply, "onion-reachability")["arming"],
        json!({"disarmed": "unreported"}),
    );

    drop(posture);
    translator.await.expect("the translator ends when its posture channel closes");
}

/// The rows carry nothing that names the persona's onion or a clock: the
/// only numbers are counts, heights, epochs, amounts and durations (agreed
/// with the Tor lane, 2026-11-28). Red edit: add a field the allow-list
/// does not name.
#[test]
fn the_reply_names_no_onion_and_no_clock() {
    let alarms = OperatorAlarms::new();
    apply_chain_progress(
        &alarms,
        ChainProgressObservation::Stalled {
            last_height: 1,
            stalled_for_secs: 2,
        },
    );
    let reply = wire(&alarms);
    let text = reply.to_string();
    for banned in [
        ".onion",
        "address",
        "service_id",
        "time",
        "timestamp",
        "_at",
    ] {
        assert!(
            !text.contains(banned),
            "the reply carries `{banned}`: {text}"
        );
    }
}
