// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain/daemon health and archival-shard commands.

use serde_json::{json, Value};
use shekyl_shard_visual::{render_candidate_png, ShardAggregate};

use super::require_open;
use crate::daemon::DaemonClient;
use crate::outcome::{failed, refusal, CommandResult};
use crate::rpc_client::RpcSession;

pub fn cmd_chain_health(daemon: Option<&DaemonClient>) -> CommandResult {
    let dc = require_daemon(daemon)?;
    match dc.get_info() {
        Ok(info) => {
            // The connection counts are a Status field, which a daemon may
            // withhold. Today a restricted daemon writes zeros there, and a
            // withheld part reads the same until this output learns to say
            // "not disclosed" (RK-Q8).
            let (outgoing, incoming) = info.node.shown().map_or((0, 0), |status| {
                (
                    status.outgoing_connections_count,
                    status.incoming_connections_count,
                )
            });
            Ok(json!({
                "status": info.status.0,
                "height": info.health.height,
                "target_height": info.health.target_height,
                // The low 64 bits, which is what the wire's `difficulty`
                // member carries and what this output has always shown.
                "difficulty": u64::try_from(info.chain.difficulty & u128::from(u64::MAX))
                    .unwrap_or(u64::MAX),
                "tx_count": info.chain.tx_count,
                "outgoing_connections_count": outgoing,
                "incoming_connections_count": incoming,
            }))
        }
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

/// The edge length `shard fetch --png` draws at when `--size` is not given.
/// The GUI's preview band is 64..=512; a file a user keeps gets the top of
/// it.
const DEFAULT_PNG_SIZE: u32 = 512;

/// `shard fetch <id> [--png <path>] [--size <n>]` — the shard's view
/// through the open wallet's daemon (`get_shard_view`, SV-D), which
/// fetches the body from a holder and folds the view hash. The wallet
/// answers with the aggregate; the picture, when asked for, is drawn here
/// with `shekyl-shard-visual` into a new owner-only file.
///
/// The wallet's refusals are shown as they arrive: still open, could not
/// be retrieved, not offered by this daemon. None of them is an empty
/// picture.
pub fn cmd_shard_fetch(
    rpc: &RpcSession,
    shard_id: u64,
    png: Option<&str>,
    size: Option<u32>,
) -> CommandResult {
    require_open(rpc)?;
    let view = rpc
        .call("get_shard_view", json!({ "shard_id": shard_id }))
        .map_err(|e| rpc.report("Shard view", &e))?;

    let Some(path) = png else {
        return Ok(view);
    };
    let size = size.unwrap_or(DEFAULT_PNG_SIZE);
    // The wallet's result is the renderer's aggregate plus the fields the
    // renderer does not take (archival_len, close_height), which serde
    // ignores. A result that does not parse is the wallet breaking its
    // own contract, not a bad shard.
    let aggregate: ShardAggregate = serde_json::from_value(view.clone()).map_err(|e| {
        refusal(format!(
            "Shard view: the wallet's answer is not an aggregate: {e}"
        ))
    })?;
    let bytes = render_candidate_png(&aggregate, size).map_err(|e| refusal(e.to_string()))?;

    let path = std::path::Path::new(path);
    let write = super::scripted::open_owner_only_excl(path, "shard image").and_then(
        |mut file| -> Result<(), Box<dyn std::error::Error>> {
            use std::io::Write;
            file.write_all(&bytes)?;
            file.flush()?;
            Ok(())
        },
    );
    match write {
        Ok(()) => {
            let mut out = view;
            out["png"] = json!({ "path": path.display().to_string(), "size": size });
            Ok(out)
        }
        Err(e) => failed(e.to_string()),
    }
}

pub(crate) fn show_fetch(val: &Value) {
    let field = |name: &str| val.get(name).and_then(Value::as_u64).unwrap_or(0);
    println!("Shard {} retrieved.", field("shard_id"));
    println!(
        "  View hash:        {}",
        val.get("shard_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
    );
    println!("  Closed at height: {}", field("close_height"));
    println!("  Archival bytes:   {}", field("archival_len"));
    println!("  Blocks:           {}", field("block_count"));
    println!("  Transactions:     {}", field("tx_count"));
    println!(
        "  Outputs:          {} ({} coinbase)",
        field("output_count"),
        field("coinbase_output_count")
    );
    println!("  Time span:        {} s", field("time_range_seconds"));
    if let Some(png) = val.get("png") {
        println!(
            "  Image:            candidate.v1 ({}px) written to {}",
            png.get("size").and_then(Value::as_u64).unwrap_or(0),
            png.get("path").and_then(|v| v.as_str()).unwrap_or("?")
        );
    }
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
