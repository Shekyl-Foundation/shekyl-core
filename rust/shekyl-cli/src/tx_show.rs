// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `tx show` (Rick, 2026-11-03). One report of one transaction.
//!
//! An open wallet that holds the id is the report, and the daemon is not
//! asked. Otherwise the report is the daemon's view. `--body` fetches the
//! bytes from the daemon. A failed wallet read stops the command.

use serde_json::Value;
use shekyl_rpc_types::DaemonNetwork;

use crate::commands::{format_amount_str, format_height, unspendable_reason_text};
use crate::console::{self, Source, TxRender};
use crate::daemon::{DaemonClient, DaemonError};
use crate::outcome::{failed, refusal, CommandResult};
use crate::rpc_client::RpcSession;

/// The daemon a show may ask, when one is configured.
pub(crate) struct DaemonEndpoint<'a> {
    pub client: &'a DaemonClient,
    pub network: DaemonNetwork,
}

/// One show. `wallet_records` is `None` when no wallet is open, and empty
/// when the open wallet does not hold the id.
pub(crate) struct TxShow<'a> {
    pub id: &'a str,
    pub wallet_records: Option<&'a str>,
    pub body: bool,
    pub daemon: Option<&'a DaemonEndpoint<'a>>,
}

/// `tx show <id> [--body]`.
pub(crate) fn command(
    rpc: &RpcSession,
    daemon: Option<&DaemonClient>,
    network: DaemonNetwork,
    id: &str,
    body: bool,
) -> CommandResult<String> {
    let id = canonical_id(id).map_err(refusal)?;
    let wallet_records = if rpc.is_open() {
        Some(read_wallet(rpc, &id)?)
    } else {
        None
    };
    let endpoint = daemon.map(|daemon| endpoint_for(daemon, network));
    report(&TxShow {
        id: &id,
        wallet_records: wallet_records.as_deref(),
        body,
        daemon: endpoint.as_ref(),
    })
    .map_err(refusal)
}

pub(crate) fn show(text: &String) {
    println!("{text}");
}

/// The report. Asks the daemon only when the wallet does not hold the id,
/// or when `--body` asks for the bytes.
pub(crate) fn report(show: &TxShow<'_>) -> Result<String, String> {
    let id = canonical_id(show.id)?;
    let held = show
        .wallet_records
        .is_some_and(|records| !records.is_empty());
    if held && !show.body {
        return Ok(show.wallet_records.expect("held means records").to_owned());
    }
    if held {
        let records = show.wallet_records.expect("held means records");
        let Some(daemon) = show.daemon else {
            return Ok(format!(
                "{records}\n\nThe serialized bytes could not be fetched from the daemon: {}",
                DaemonError::NotConfigured
            ));
        };
        return match fetch(daemon, &id, true) {
            Ok(render) => Ok(held_with_body(records, &id, &render)),
            Err(detail) => Ok(format!(
                "{records}\n\nThe serialized bytes could not be fetched from the daemon: {detail}"
            )),
        };
    }
    let Some(daemon) = show.daemon else {
        return Err(not_configured(show.wallet_records.is_some(), &id));
    };
    match fetch(daemon, &id, show.body) {
        Ok(TxRender::Shown { text, .. }) => Ok(text),
        Ok(TxRender::Unknown) => Err(neither(show.wallet_records.is_some(), &id)),
        Err(detail) => Err(format!(
            "{} The daemon could not be asked: {detail}",
            wallet_clause(show.wallet_records.is_some(), &id)
        )),
    }
}

/// The wallet's rows whose transaction id is `id`, or an empty string when
/// it holds none. A failed read is not "holds none": the command stops
/// rather than asking the daemon about an id the wallet might hold.
fn read_wallet(rpc: &RpcSession, id: &str) -> CommandResult<String> {
    match rpc.call("get_transfers", serde_json::json!({})) {
        Ok(val) => {
            let Some(rows) = val.get("transfers").and_then(Value::as_array) else {
                return failed("Malformed get_transfers response.");
            };
            Ok(format_records(rows, id))
        }
        Err(error) => Err(rpc.report("Failed to read this wallet's transactions", &error)),
    }
}

fn format_records(rows: &[Value], id: &str) -> String {
    rows.iter()
        .filter(|row| {
            row.get("tx_hash")
                .and_then(Value::as_str)
                .is_some_and(|hash| hash.eq_ignore_ascii_case(id))
        })
        .map(format_record)
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn format_record(row: &Value) -> String {
    let text = |name: &str| {
        row.get(name)
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_owned()
    };
    let mut lines = vec![
        format!("Transaction {}", text("tx_hash")),
        format!("  Direction:  {}", text("direction")),
        format!("  State:      {}", text("state")),
        format!("  Amount:     {} SKL", format_amount_str(&text("amount"))),
        format!("  Fee:        {} SKL", format_amount_str(&text("fee"))),
        format!("  Height:     {}", format_height(row)),
    ];
    if let Some(spent) = row.get("spent_height").and_then(Value::as_i64) {
        lines.push(format!("  Spent at:   {spent}"));
    }
    if let Some(reason) = row.get("unspendable_reason").and_then(Value::as_str) {
        lines.push(format!(
            "  Unspendable: {}",
            unspendable_reason_text(reason)
        ));
    }
    if let Some(kind) = row
        .get("attribution")
        .and_then(|attr| attr.get("kind"))
        .and_then(Value::as_str)
    {
        lines.push(format!("  Attribution: {kind}"));
    }
    if let Some(note) = row.get("note").and_then(Value::as_str) {
        lines.push(format!("  Note:        {note}"));
    }
    lines.join("\n")
}

fn held_with_body(records: &str, id: &str, render: &TxRender) -> String {
    let section = match render {
        TxRender::Unknown => format!("The daemon has no serialized bytes for {id}."),
        TxRender::Shown {
            body: Some(body), ..
        } => body.clone(),
        TxRender::Shown { text, body: None } => text.clone(),
    };
    format!("{records}\n\n{section}")
}

fn wallet_clause(wallet_open: bool, id: &str) -> String {
    if wallet_open {
        format!("This wallet has no record of {id}.")
    } else {
        "No wallet is open.".to_owned()
    }
}

fn neither(wallet_open: bool, id: &str) -> String {
    if wallet_open {
        format!("This wallet has no record of {id}, and the daemon has no transaction {id}.")
    } else {
        format!("No wallet is open, and the daemon has no transaction {id}.")
    }
}

fn not_configured(wallet_open: bool, id: &str) -> String {
    format!(
        "{} {}",
        wallet_clause(wallet_open, id),
        DaemonError::NotConfigured
    )
}

/// The daemon endpoint `command` builds.
pub(crate) fn endpoint_for<'a>(
    daemon: &'a DaemonClient,
    network: DaemonNetwork,
) -> DaemonEndpoint<'a> {
    DaemonEndpoint {
        client: daemon,
        network,
    }
}

fn fetch(daemon: &DaemonEndpoint<'_>, id: &str, body: bool) -> Result<TxRender, String> {
    let rpc = daemon
        .client
        .transport()
        .map_err(|error| with_hint(daemon, &error.to_string()))?;
    let source = Source::new(rpc, daemon.network.to_cryptonote());
    console::show_transaction(&source, id, body)
}

fn with_hint(daemon: &DaemonEndpoint<'_>, detail: &str) -> String {
    match daemon.client.down_hint() {
        Some(hint) => format!("{detail}\n{hint}"),
        None => detail.to_owned(),
    }
}

fn canonical_id(id: &str) -> Result<String, String> {
    let id = id.to_ascii_lowercase();
    if id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(id)
    } else {
        Err(format!(
            "tx show: {id:?} is not a transaction id (64 hexadecimal characters)"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn a_short_id_is_refused_before_either_source() {
        let error = report(&TxShow {
            id: "abcd",
            wallet_records: None,
            body: false,
            daemon: None,
        })
        .expect_err("not an id");
        assert!(error.contains("64 hexadecimal"), "{error}");
    }

    #[test]
    fn a_held_id_is_the_wallet_record_and_names_no_daemon() {
        let records = format!("wallet holds {}", id());
        let text = report(&TxShow {
            id: &id(),
            wallet_records: Some(&records),
            body: false,
            daemon: None,
        })
        .expect("the wallet is the report");
        assert_eq!(text, records);
    }

    #[test]
    fn neither_source_names_both() {
        let missing = report(&TxShow {
            id: &id(),
            wallet_records: Some(""),
            body: false,
            daemon: None,
        })
        .expect_err("no daemon configured");
        assert!(missing.contains("no record"), "{missing}");
        assert!(missing.contains("Daemon not configured"), "{missing}");

        let open = neither(true, &id());
        assert!(open.contains("no record of"), "{open}");
        assert!(open.contains("daemon has no transaction"), "{open}");
        let closed = neither(false, &id());
        assert!(closed.contains("No wallet is open"), "{closed}");
        assert!(closed.contains("daemon has no transaction"), "{closed}");
    }

    #[test]
    fn the_bytes_are_the_body_not_the_daemons_narrative() {
        let records = "wallet holds it";
        let text = held_with_body(
            records,
            &id(),
            &TxRender::Shown {
                text: "view".to_owned(),
                body: Some("abcd".repeat(20)),
            },
        );
        assert!(text.starts_with(records), "{text}");
        assert!(text.contains(&"abcd".repeat(20)), "{text}");
        assert!(
            !text.contains("view"),
            "the bytes, not the daemon's narrative: {text}"
        );
    }

    #[test]
    fn the_wallet_record_is_every_row_of_that_transaction() {
        let id = id();
        let other = "cd".repeat(32);
        let rows = serde_json::json!([
            {
                "id": format!("{id}:0"),
                "tx_hash": id,
                "direction": "INCOMING",
                "state": "MINED",
                "amount": "1",
                "fee": "0",
                "block_height": 4,
                "note": "rent"
            },
            {
                "id": format!("{id}:1"),
                "tx_hash": id.to_uppercase(),
                "direction": "INCOMING",
                "state": "MINED",
                "amount": "2",
                "fee": "0",
                "block_height": 4
            },
            {
                "id": &other,
                "tx_hash": other,
                "direction": "OUTGOING",
                "state": "PENDING",
                "amount": "9",
                "fee": "1"
            }
        ]);
        let text = format_records(rows.as_array().expect("rows"), &id);
        assert!(text.contains(&format!("Transaction {id}")), "{text}");
        assert!(text.contains("rent"), "{text}");
        assert!(!text.contains(&format!("{id}:0")), "no transfer id: {text}");
        assert!(!text.contains(&format!("{id}:1")), "no transfer id: {text}");
        assert!(!text.contains(&other), "another transaction: {text}");
    }

    /// The id `tx list` prints is the id `tx show` takes.
    ///
    /// Red edit: `listed_tx_id` returns the wallet's transfer id (`hash:0`).
    /// `tx show` then has no record of it.
    #[test]
    fn the_id_tx_list_prints_is_what_tx_show_takes() {
        let hash = id();
        let row = serde_json::json!({
            "id": format!("{hash}:0"),
            "tx_hash": hash,
            "direction": "INCOMING",
            "state": "MINED",
            "amount": "1",
            "fee": "0",
            "block_height": 4
        });
        let listed = crate::commands::listed_tx_id(&row);
        let records = format_records(std::slice::from_ref(&row), listed);
        let text = report(&TxShow {
            id: listed,
            wallet_records: Some(&records),
            body: false,
            daemon: None,
        })
        .expect("tx show of the listed id");
        assert!(
            text.contains(&format!("Transaction {hash}")),
            "the listed id did not show the transaction: {text}"
        );
        assert!(!text.contains(":0"), "the transfer id is not shown: {text}");
    }
}

#[cfg(test)]
#[path = "tx_show_regtest.rs"]
mod regtest;
