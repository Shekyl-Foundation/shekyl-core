// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `operator alarm` and `operator alarm acknowledge <incident>` (OA-1): what
//! the wallet watches for its operator, said in plain words.
//!
//! Each fault is said as what is wrong and what to do about it (rule 82). A
//! condition that is not being checked says "not checked" and why, never
//! that it is fine: a check that cannot fire and a check that fired clean are
//! both quiet, and only the wallet's answer tells them apart. The command
//! reads the board when the operator asks, and at no other time.

use serde_json::{json, Value};

use super::{format_amount, require_open};
use crate::outcome::CommandResult;
use crate::rpc_client::RpcSession;

/// `operator alarm`: the wallet's board.
pub fn cmd_operator_alarm(rpc: &RpcSession) -> CommandResult {
    require_open(rpc)?;
    rpc.call("operator_alarm", json!({}))
        .map_err(|e| rpc.report("Failed to read the wallet's alarms", &e))
}

/// `operator alarm acknowledge <incident>`.
pub fn cmd_operator_alarm_acknowledge(rpc: &RpcSession, incident: u64) -> CommandResult {
    require_open(rpc)?;
    rpc.call(
        "operator_alarm_acknowledge",
        json!({ "incident": incident }),
    )
    .map_err(|e| rpc.report("Failed to acknowledge the alarm", &e))
}

pub(crate) fn show_operator_alarm(val: &Value) {
    for line in operator_alarm_lines(val) {
        crate::out_line!("{line}");
    }
}

pub(crate) fn show_acknowledged(val: &Value) {
    crate::out_line!("{}", acknowledged_line(val));
}

fn acknowledged_line(val: &Value) -> &'static str {
    match val.get("acknowledged").and_then(Value::as_bool) {
        Some(true) => "Acknowledged.",
        Some(false) => {
            "Nothing waiting for acknowledgment carries that incident number. A fault that is \
             still happening cannot be acknowledged; it leaves when it is fixed."
        }
        None => "(the wallet's answer did not say whether it acknowledged)",
    }
}

/// `operator alarm`'s lines: what needs the operator, what is waiting for
/// acknowledgment, what was checked and found clean, and what is not
/// checked.
fn operator_alarm_lines(val: &Value) -> Vec<String> {
    let Some(rows) = val.get("conditions").and_then(Value::as_array) else {
        return vec!["(the wallet's answer carried no conditions)".to_owned()];
    };
    let outstanding = val
        .get("unacknowledged")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);

    let mut faults = Vec::new();
    let mut clean = Vec::new();
    let mut unchecked = Vec::new();
    for row in rows {
        let name = condition_name(row.get("condition"));
        let fault = row.get("fault").filter(|f| !f.is_null());
        if let Some(fault) = fault {
            faults.push(format!(
                "  {name}: {} [incident {}]",
                alarm_sentence(fault.get("alarm")),
                incident(fault)
            ));
        }
        match row.get("arming") {
            Some(arming) if arming.get("armed").is_some() => {
                if fault.is_none() {
                    clean.push(name.to_owned());
                }
            }
            Some(arming) => unchecked.push(format!(
                "  {name}: not checked, {}.",
                disarmed_reason(arming)
            )),
            None => unchecked.push(format!(
                "  {name}: (the answer did not say whether it is checked)"
            )),
        }
    }

    let mut lines = Vec::new();
    if faults.is_empty() {
        lines.push("Nothing that is being checked needs you now.".to_owned());
    } else {
        lines.push("Needs you now:".to_owned());
        lines.extend(faults);
    }
    if !outstanding.is_empty() {
        lines.push(
            "Fixed, but they did damage you should know about; acknowledge each once you have \
             read it:"
                .to_owned(),
        );
        for fault in outstanding {
            let n = incident(fault);
            lines.push(format!(
                "  {}: {} Run `operator alarm acknowledge {n}`.",
                condition_name(fault.get("condition")),
                alarm_sentence(fault.get("alarm")),
            ));
        }
    }
    if !clean.is_empty() {
        lines.push(format!("Checked, nothing wrong: {}.", clean.join(", ")));
    }
    if !unchecked.is_empty() {
        lines.push("Not checked:".to_owned());
        lines.extend(unchecked);
    }
    lines
}

fn incident(fault: &Value) -> String {
    fault
        .get("incident")
        .and_then(Value::as_u64)
        .map_or_else(|| "(unnumbered)".to_owned(), |n| n.to_string())
}

/// A condition in words an operator knows (rule 81).
fn condition_name(condition: Option<&Value>) -> &'static str {
    match condition.and_then(Value::as_str).unwrap_or("") {
        "transport-liveness" => "Staking Tor connection",
        "onion-reachability" => "Reachable by challengers",
        "vanguard-integrity" => "Staking Tor guard set",
        "serve-set-integrity" => "Shards your stake must keep",
        "serve-disk-headroom" => "Disk space for staking data",
        "serve-health" => "Answering challenges",
        "chain-progress" => "Chain progress",
        "epoch-claim" => "Claiming staking rewards",
        "claim-forfeiture" => "Expired staking rewards",
        "pending-funds-integrity" => "Funds reserved for staking",
        _ => "(a condition this version does not know)",
    }
}

fn disarmed_reason(arming: &Value) -> &'static str {
    match arming.get("disarmed").and_then(Value::as_str).unwrap_or("") {
        "transport-unready" => "because the staking Tor connection is not ready",
        "transport-stopped" => "because the staking Tor connection has stopped",
        "catching-up" => "because the wallet is still catching up to the chain",
        "disk-unreadable" => "because the disk's free space could not be read",
        "host-down" => "because staking is not serving now",
        "driver-leg-parked" => {
            "because its check failed and stopped; reopen the wallet, and report it if it recurs"
        }
        "unreported" => "because no check is running for it",
        "check-stopped" => {
            "because its check stopped unexpectedly; reopen the wallet, and report it if it recurs"
        }
        _ => "for a reason this version does not know",
    }
}

/// One fault: what is wrong, then what to do.
fn alarm_sentence(alarm: Option<&Value>) -> String {
    let Some((key, body)) = alarm
        .and_then(Value::as_object)
        .and_then(|o| o.iter().next())
    else {
        return "(a fault the answer did not describe)".to_owned();
    };
    let n = |field: &str| body.get(field).and_then(Value::as_u64);
    let num = |field: &str| n(field).map_or_else(|| "?".to_owned(), |v| v.to_string());
    match key.as_str() {
        "transport-degraded" => format!(
            "the staking Tor connection keeps failing and is retrying slowly{}.",
            transport_cause(body.get("cause"))
        ),
        "vanguard-state-redrawn" => "the saved Tor guard set could not be used, so a new one \
            was drawn, which weakens your privacy each time it happens. Remove the damaged \
            guard file so the next one is kept."
            .to_owned(),
        "vanguard-state-unpersisted" => "the Tor guard set could not be saved, so the next \
            start would draw a new one. Check that the wallet's directory is writable and has \
            space."
            .to_owned(),
        "vanguard-view-incomplete" => format!(
            "part of Tor's view of the network could not be read ({} of {} entries), so \
             guards that left the network are kept for now. This usually passes; report it \
             if it does not.",
            num("decoded"),
            num("announced")
        ),
        "serve-set-stale" => format!(
            "the shards your stake must keep have not been refreshed for {} blocks, so newly \
             bonded shards may not be kept. Reopen the wallet; report it if it recurs.",
            num("block_count")
        ),
        "serve-set-refresh-failing" => format!(
            "refreshing the shards your stake must keep has failed {} times in a row. Check \
             that your node is running and synced, then reopen the wallet.",
            num("count")
        ),
        "serve-set-pins-dropped" => format!(
            "{} of the {} shards your stake must keep lost their hold after the chain rolled \
             back. The next refresh restores it; nothing to do unless this stays.",
            num("dropped_count"),
            num("member_count")
        ),
        "serve-set-posture-lost" => "the wallet's store no longer says it keeps every shard, \
            so shards could be discarded. Reopen the wallet; if this stays, rebuild the store \
            from the chain."
            .to_owned(),
        "serve-set-rolled-back" => format!(
            "the chain rolled back from height {} to {}. This resolves itself as the wallet \
             catches up.",
            num("minted_height"),
            num("height")
        ),
        "serve-set-bytes-pruned" => format!(
            "{} shards your stake must keep are gone from the store, and only rebuilding the \
             store from the chain brings them back. Until then those challenges fail.",
            num("member_count")
        ),
        "serve-disk-low" => format!(
            "the disk holding staking data has {} free, below the {} it needs. Add space or \
             stop staking before it runs out.",
            spoken_bytes(n("free")),
            spoken_bytes(n("free_min"))
        ),
        "chain-progress-stalled" => format!(
            "the wallet has seen no new block for {} (last height {}). Check that your node is \
             running, connected and synced; whether the chain itself stalled can be checked \
             against any other node.",
            spoken_age(n("age")),
            num("height")
        ),
        "epoch-unclaimed" => format!(
            "{} settled epochs are unclaimed, the oldest {}. Check that your node is reachable; \
             the wallet keeps trying.",
            num("epoch_count"),
            num("epoch")
        ),
        "claim-forfeited" => format!(
            "staking rewards worth {} SKL expired unclaimed this session, the newest from epoch \
             {}, because claiming them would have cost more than they were worth.",
            n("amount").map_or_else(|| "?".to_owned(), format_amount),
            num("epoch")
        ),
        "reservation-spent-elsewhere" => format!(
            "funds reserved for staking were spent by another transaction ({} records, {} \
             stakes held). Nothing else can spend them, so check the wallet's log and whether \
             its keys are safe.",
            num("record_count"),
            num("held_count")
        ),
        "serve-signing-refused" => format!(
            "your staking key refused to sign challenge answers ({} before sending, {} after), \
             so those challenges earn nothing. Reopen the wallet.",
            num("pre_flight"),
            num("late")
        ),
        "serve-lookup-failing" => format!(
            "{} challenges could not be answered because the store or your node could not be \
             read. Check that your node is running and synced first.",
            num("count")
        ),
        "serve-listener-failing" => format!(
            "the staking service failed to accept {} connections. If it keeps happening, \
             reopen the wallet.",
            num("count")
        ),
        _ => "(a fault this version does not know)".to_owned(),
    }
}

fn transport_cause(cause: Option<&Value>) -> &'static str {
    let key = cause
        .and_then(Value::as_object)
        .and_then(|o| o.keys().next())
        .map_or("", String::as_str);
    match key {
        "install-defect" => {
            ": the Tor program was refused or not found; reinstall the Tor that \
            came with this release"
        }
        "control-channel-failed" => ": the wallet lost its control connection to Tor",
        "socks-missing" => ": Tor started without a port to connect through",
        "launch-failed" => {
            ": Tor did not finish starting in time; check this computer's \
            network connection"
        }
        "exited" => ": the Tor process ended",
        "internal" => ": a fault in the wallet, not in Tor; please report it",
        "onion-refused" => ": Tor would not publish your staking address",
        "guards-refused" => ": Tor refused the wallet's guard settings; please report it",
        "" => "",
        _ => ": for a reason this version does not know",
    }
}

fn spoken_age(secs: Option<u64>) -> String {
    let Some(secs) = secs else {
        return "an unknown time".to_owned();
    };
    let (n, unit) = match secs {
        0..=119 => (secs, "second"),
        120..=7_199 => (secs / 60, "minute"),
        7_200..=172_799 => (secs / 3_600, "hour"),
        _ => (secs / 86_400, "day"),
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

fn spoken_bytes(bytes: Option<u64>) -> String {
    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;
    match bytes {
        None => "an unknown amount".to_owned(),
        Some(b) if b >= GIB => format!("{} GiB", b / GIB),
        Some(b) if b >= MIB => format!("{} MiB", b / MIB),
        Some(b) => format!("{b} bytes"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(arming: &Value) -> Vec<Value> {
        ["transport-liveness", "onion-reachability", "chain-progress"]
            .into_iter()
            .map(|condition| json!({"condition": condition, "arming": arming, "fault": null}))
            .collect()
    }

    /// A condition nobody checks says "not checked" and why, and the
    /// command never calls it fine. Red edit: count a disarmed row as clean.
    #[test]
    fn a_condition_not_checked_never_reads_fine() {
        let lines = operator_alarm_lines(&json!({
            "conditions": rows(&json!({"disarmed": "unreported"})),
            "unacknowledged": [],
        }));
        let text = lines.join("\n");
        assert!(!text.contains("nothing wrong"), "{text}");
        assert!(
            text.contains("Reachable by challengers: not checked"),
            "{text}"
        );
        assert!(text.contains("no check is running"), "{text}");
    }

    /// A fault says what is wrong and what to do, with its incident; a
    /// fault waiting for acknowledgment names the command that clears it.
    #[test]
    fn a_fault_says_what_is_wrong_and_what_to_do() {
        let lines = operator_alarm_lines(&json!({
            "conditions": [{
                "condition": "chain-progress",
                "arming": {"armed": null},
                "fault": {
                    "incident": 4,
                    "alarm": {"chain-progress-stalled": {"height": 40, "age": 900}},
                },
            }],
            "unacknowledged": [{
                "incident": 2,
                "condition": "pending-funds-integrity",
                "alarm": {"reservation-spent-elsewhere": {"record_count": 1, "held_count": 0}},
            }],
        }));
        let text = lines.join("\n");
        assert!(text.contains("Needs you now:"), "{text}");
        assert!(
            text.contains("no new block for 15 minutes (last height 40)"),
            "{text}"
        );
        assert!(text.contains("Check that your node is running"), "{text}");
        assert!(text.contains("[incident 4]"), "{text}");
        assert!(
            text.contains("Run `operator alarm acknowledge 2`."),
            "{text}"
        );
    }

    /// Checked rows with nothing wrong are said once, as checked.
    #[test]
    fn checked_and_clean_rows_are_said_as_checked() {
        let lines = operator_alarm_lines(&json!({
            "conditions": rows(&json!({"armed": null})),
            "unacknowledged": [],
        }));
        assert_eq!(
            lines,
            vec![
                "Nothing that is being checked needs you now.".to_owned(),
                "Checked, nothing wrong: Staking Tor connection, Reachable by challengers, \
                 Chain progress."
                    .to_owned(),
            ]
        );
    }

    #[test]
    fn an_acknowledgment_that_matched_nothing_says_why() {
        assert_eq!(
            acknowledged_line(&json!({"acknowledged": true})),
            "Acknowledged."
        );
        assert!(acknowledged_line(&json!({"acknowledged": false})).contains("still happening"));
    }
}
