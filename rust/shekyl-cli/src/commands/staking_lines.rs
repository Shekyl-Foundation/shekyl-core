// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The lines `stake` prints for work in flight and for endings
//! (`WALLET_RPC_STAKING_OUTCOMES.md` WR-Q1, WR-Q2, WR-Q6).

use serde_json::Value;
use shekyl_wallet_rpc::types::{InFlightEntry, StakingOutcomeEntry};

use super::super::format_amount;

/// The word a person types for each wire kind (`stake add`, `stake return`,
/// `stake release`; claims are the wallet's own). An unknown kind is a newer
/// server: echo it.
pub(super) fn kind_word(kind: &str) -> &str {
    match kind {
        "drain" => "return",
        "exit" => "release",
        other => other,
    }
}

/// `in_flight` and `outcomes` (WR-Q1, WR-Q2), one line each. Nothing is
/// printed when both are empty. An unknown state or outcome is echoed, never
/// hidden.
pub(super) fn print_staking_work(val: &Value) {
    let in_flight: Vec<InFlightEntry> = val
        .get("in_flight")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let outcomes: Vec<StakingOutcomeEntry> = val
        .get("outcomes")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    if !in_flight.is_empty() {
        crate::out_line!("In progress:");
        for entry in &in_flight {
            crate::out_line!("  {}", in_flight_line(entry));
        }
    }
    if !outcomes.is_empty() {
        crate::out_line!("Ended without completing:");
        for entry in &outcomes {
            crate::out_line!(
                "  {} {} at block {}: {}",
                kind_word(&entry.kind),
                entry.outcome.replace('_', " "),
                entry.at_height,
                entry.reason
            );
        }
        crate::out_line!(
            "Use \"stake acknowledge <{}>\" to clear an ending once you have read it.",
            outcomes
                .iter()
                .map(|e| kind_word(&e.kind))
                .collect::<Vec<_>>()
                .join("|")
        );
    }
}

pub(super) fn in_flight_line(entry: &InFlightEntry) -> String {
    let line = in_flight_state_line(entry);
    match funds_sentence(entry) {
        Some(funds) => {
            let line = line.trim_end();
            let stop = if line.ends_with('.') { "" } else { "." };
            format!("{line}{stop} {funds}")
        }
        None => line,
    }
}

/// What `reserved` has been read as. The sentence that says a transaction
/// was not mined is built only for [`ReservedReading::Holds`]. A zero hold
/// and an unread amount are also how a zero-fee claim looks, and the
/// staking scan cannot show whether that claim was mined
/// (`WALLET_RPC_STAKING_OUTCOMES.md` §5): it ends `ended_unconfirmed`.
enum ReservedReading {
    Holds(shekyl_units::AtomicUnits),
    HoldsNothing,
    Unread,
}

fn reserved_reading(entry: &InFlightEntry) -> ReservedReading {
    match entry.reserved.0.map(shekyl_units::AtomicUnits::from) {
        Some(amount) if amount != shekyl_units::AtomicUnits::ZERO => ReservedReading::Holds(amount),
        Some(_) => ReservedReading::HoldsNothing,
        None => ReservedReading::Unread,
    }
}

/// The record remains until the scan has passed this block. Said for a zero
/// hold and for an unread amount. It does not say the scan will decide
/// whether the record was mined.
fn record_stays_until(height: impl std::fmt::Display) -> String {
    format!("This record stays until the staking scan has passed block {height}.")
}

/// What an entry still holds (WR-Q6) and, when it has an end date, that
/// the record stays until the staking scan passes it. Only an entry that
/// holds something is said to hold funds that return: a zero-fee claim
/// reserves none. When the staking scan has not run, the amount is not
/// known yet, and the line says so rather than imply nothing is held.
fn funds_sentence(entry: &InFlightEntry) -> Option<String> {
    let end = entry.funds_return_at.0;
    match reserved_reading(entry) {
        ReservedReading::Holds(amount) => {
            let amount = format_amount(amount.to_raw());
            Some(match end {
                Some(h) => format!(
                    "It holds {amount}; if its transaction was not mined, that returns \
                     once the staking scan has passed block {h}."
                ),
                None => format!("It holds {amount}."),
            })
        }
        ReservedReading::HoldsNothing => {
            end.map(|h| format!("It holds nothing. {}", record_stays_until(h)))
        }
        ReservedReading::Unread => Some(match end {
            Some(h) => format!(
                "What it holds shows once the staking scan has run. {}",
                record_stays_until(h)
            ),
            None => "What it holds shows once the staking scan has run.".to_owned(),
        }),
    }
}

fn in_flight_state_line(entry: &InFlightEntry) -> String {
    let kind = kind_word(&entry.kind);
    match (entry.state.as_str(), entry.dispatched_at_height.0) {
        // A stake that is due and waiting says why (BD-Q3).
        ("pending", _) => match entry.reason.0.as_deref() {
            Some(reason) => format!("{kind}: waiting to be sent. {reason}"),
            None => format!("{kind}: waiting to be sent"),
        },
        ("dispatched", Some(h)) => format!(
            "{kind}: sent at block {h}, {} attempt{}",
            entry.attempts,
            if entry.attempts == 1 { "" } else { "s" }
        ),
        ("refused", _) => format!(
            "{kind}: refused. {}",
            entry.reason.0.as_deref().unwrap_or("")
        ),
        ("expired", _) => {
            let refused = entry
                .reason
                .0
                .as_deref()
                .map(|reason| format!(" {reason}"))
                .unwrap_or_default();
            format!("{kind}: can no longer be mined.{refused}")
        }
        ("held", _) => format!("{kind}: kept. {}", entry.reason.0.as_deref().unwrap_or("")),
        (other, _) => format!("{kind}: {other}"),
    }
}
