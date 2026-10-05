// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain/daemon health command.

use serde_json::{json, Value};

use crate::daemon::DaemonClient;
use crate::outcome::{failed, CommandResult};

pub fn cmd_chain_health(daemon: Option<&DaemonClient>) -> CommandResult {
    let dc = require_daemon(daemon)?;
    match dc.get_info() {
        Ok(info) => Ok(json!({
            "status": info.status,
            "height": info.height,
            "target_height": info.target_height,
            "difficulty": info.difficulty,
            "tx_count": info.tx_count,
            "outgoing_connections_count": info.outgoing_connections_count,
            "incoming_connections_count": info.incoming_connections_count,
        })),
        Err(e) => failed(e.to_string()),
    }
}

pub(crate) fn show_chain(val: &Value) {
    let status = val.get("status").and_then(|v| v.as_str()).unwrap_or("?");
    let height = val.get("height").and_then(Value::as_u64).unwrap_or(0);
    let target = val
        .get("target_height")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    println!("Chain health:");
    println!("  Status:       {status}");
    println!("  Height:       {height}");
    if target > 0 && target != height {
        println!("  Target:       {target} (syncing)");
    }
    println!(
        "  Difficulty:   {}",
        val.get("difficulty").and_then(Value::as_u64).unwrap_or(0)
    );
    println!(
        "  Tx count:     {}",
        val.get("tx_count").and_then(Value::as_u64).unwrap_or(0)
    );
    println!(
        "  Connections:  {} out / {} in",
        val.get("outgoing_connections_count")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        val.get("incoming_connections_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    );
}

fn require_daemon(
    daemon: Option<&DaemonClient>,
) -> Result<&DaemonClient, crate::outcome::CommandFailed> {
    match daemon {
        Some(dc) => Ok(dc),
        None => Err(crate::outcome::refusal(
            "Daemon not configured. Use --daemon-address to set the daemon endpoint.",
        )),
    }
}

/// `shard list all` — the daemon's coverage list, in the daemon's order.
pub fn cmd_shard_list_all(daemon: Option<&DaemonClient>) -> CommandResult {
    let dc = require_daemon(daemon)?;
    match dc.archival_shard_coverage() {
        Ok(list) => Ok(coverage_json(&list)),
        Err(e) => failed(e.to_string()),
    }
}

pub(crate) fn show_coverage(val: &Value) {
    println!(
        "{:<8} {:>16} {:>8} {:>8}",
        "Shard", "Pay", "Bonded", "Served"
    );
    let rows = val.get("shards").and_then(|v| v.as_array());
    let Some(rows) = rows.filter(|rows| !rows.is_empty()) else {
        println!("No shards.");
        return;
    };
    let profit = val
        .get("profit_estimate_available")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    for row in rows {
        print_coverage_row(row, profit);
    }
}

/// `shard list mine` — this wallet's shards. The wallet RPC does not report
/// them yet, so this refuses rather than printing an empty table.
pub fn cmd_shard_list_mine(_rpc: &crate::rpc_client::RpcSession) -> CommandResult {
    failed(
        "This wallet does not report which shards it holds yet. \
         Nothing was listed. \"shard list all\" shows every shard and its pay.",
    )
}

/// `shard show <id>` — one coverage row.
pub fn cmd_shard_show(daemon: Option<&DaemonClient>, shard_id: u64) -> CommandResult {
    let dc = require_daemon(daemon)?;
    match dc.archival_shard_coverage() {
        Ok(list) => match list.shards.iter().find(|row| row.shard_id == shard_id) {
            Some(row) => Ok(json!({
                "profit_estimate_available": list.profit_estimate_available,
                "shard": row_json(row),
            })),
            None => failed(format!("Shard {shard_id} is not in the list.")),
        },
        Err(e) => failed(e.to_string()),
    }
}

pub(crate) fn show_shard(val: &Value) {
    let profit = val
        .get("profit_estimate_available")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let Some(row) = val.get("shard") {
        print_coverage_row(row, profit);
    }
}

/// `shard fetch <id>` — ask the daemon to retrieve the shard. Text only.
pub fn cmd_shard_fetch(daemon: Option<&DaemonClient>, shard_id: u64) -> CommandResult {
    let dc = require_daemon(daemon)?;
    match dc.request_archival_shard(shard_id) {
        Ok(fetch) => Ok(json!({
            "shard_id": fetch.shard_id,
            "shard_hash": fetch.shard_hash,
            "block_count": fetch.block_count,
            "output_count": fetch.output_count,
        })),
        Err(e) => failed(e.to_string()),
    }
}

pub(crate) fn show_fetch(val: &Value) {
    println!(
        "Shard {} fetch requested.",
        val.get("shard_id").and_then(Value::as_u64).unwrap_or(0)
    );
    println!(
        "  Hash:    {}",
        val.get("shard_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
    );
    println!(
        "  Blocks:  {}",
        val.get("block_count").and_then(Value::as_u64).unwrap_or(0)
    );
    println!(
        "  Outputs: {}",
        val.get("output_count").and_then(Value::as_u64).unwrap_or(0)
    );
}

fn coverage_json(list: &crate::daemon::ArchivalShardCoverage) -> Value {
    json!({
        "profit_estimate_available": list.profit_estimate_available,
        "shards": list.shards.iter().map(row_json).collect::<Vec<_>>(),
    })
}

fn row_json(row: &crate::daemon::ShardCoverageRow) -> Value {
    json!({
        "shard_id": row.shard_id,
        "bonded_count": row.bonded_count,
        "served_count": row.served_count,
        "expected_profit_atomic": row.expected_profit_atomic,
    })
}

fn print_coverage_row(row: &Value, profit_available: bool) {
    let shard_id = row.get("shard_id").and_then(Value::as_u64).unwrap_or(0);
    let bonded = row.get("bonded_count").and_then(Value::as_u64).unwrap_or(0);
    let served = row.get("served_count").and_then(Value::as_u64).unwrap_or(0);
    let atomic = row
        .get("expected_profit_atomic")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let pay = if profit_available {
        crate::commands::format_amount(atomic)
    } else {
        "unavailable".to_owned()
    };
    println!("{shard_id:<8} {pay:>16} {bonded:>8} {served:>8}");
}
