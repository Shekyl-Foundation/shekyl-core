// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain/daemon health and archival-shard commands.

use serde_json::{json, Value};
use shekyl_rpc_types::HexU128;
use shekyl_shard_visual::{render_candidate_png, ShardAggregate};

use super::require_open;
use crate::daemon::DaemonClient;
use crate::outcome::{failed, refusal, CommandResult};
use crate::rpc_client::RpcSession;

pub fn cmd_chain_health(daemon: Option<&DaemonClient>) -> CommandResult {
    let dc = require_daemon(daemon)?;
    match dc.get_info() {
        Ok(info) => {
            let mut body = json!({
                "status": info.status.0,
                "height": info.health.height,
                // Whether the daemon has caught up is its own flag. The
                // target is the core's, `null` when it has none, and is
                // shown beside the flag, never read as the flag.
                "synchronized": info.health.synchronized,
                "target_height": info.health.target_height,
                // The whole 128-bit value, in the wire's own encoding:
                // `0x` hex under the wire's name. A JSON number cannot hold
                // it, and this output used to write its low 64 bits as
                // `difficulty`, which is a wrong number past 2^64.
                "wide_difficulty": HexU128(info.chain.difficulty),
                "tx_count": info.chain.tx_count,
                // Whether the daemon runs P2P at all: its configuration,
                // told to every caller. The reply's decoder holds it equal
                // to the Peers part's state (Rick, 2026-10-14).
                "p2p": if info.health.offline { "off" } else { "on" },
            });
            // Status is wholly shown or wholly absent, and a restricted
            // daemon withholds it. A withheld part is not a zero, so the
            // keys stay off the object and the line below says the part
            // was not disclosed. A shown zero is a count.
            if let Some(status) = info.node.shown() {
                body["outgoing_connections_count"] = json!(status.outgoing_connections_count);
                body["incoming_connections_count"] = json!(status.incoming_connections_count);
            }
            Ok(body)
        }
        Err(e) => failed(e.to_string()),
    }
}

/// The line that says the daemon is still syncing, or `None` when it has
/// caught up.
///
/// Read from `synchronized`, the daemon's own flag. Until `get_info`
/// stopped writing its target as `0` for a synchronized node, this was
/// inferred from the target being non-zero and different from the height.
/// A synchronized daemon now reports a real target, so that inference
/// would call it syncing whenever a peer had claimed a taller chain.
///
/// A value without the flag is not this command's output; it is shown as
/// syncing, the reading that promises less.
fn sync_line(val: &Value) -> Option<String> {
    let synchronized = val
        .get("synchronized")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if synchronized {
        return None;
    }
    Some(match val.get("target_height").and_then(Value::as_u64) {
        Some(target) => format!("  Target:       {target} (syncing)"),
        None => "  Target:       none yet (syncing)".to_owned(),
    })
}

/// The difficulty line: the whole value, in decimal.
///
/// The value arrives as the wire's `0x` hex string and is read strictly. A
/// value that is missing or is not that form is said to be unreadable; it
/// is not printed as `0`, which is a difficulty.
fn difficulty_line(val: &Value) -> String {
    match val
        .get("wide_difficulty")
        .and_then(Value::as_str)
        .map(HexU128::parse)
    {
        Some(Ok(difficulty)) => format!("  Difficulty:   {}", difficulty.get()),
        _ => "  Difficulty:   unreadable".to_owned(),
    }
}

/// The connections line.
///
/// Both counts present, including a shown zero, print as counts. Either
/// key absent is a withheld Status part: a zero would claim the node has
/// no connections, which is a different fact.
fn connections_line(val: &Value) -> String {
    if p2p_is_off(val) {
        // A daemon started with P2P off has no connections by configuration;
        // its state is the line, not a count of zero.
        return "  P2P:          off".to_owned();
    }
    match (
        val.get("outgoing_connections_count")
            .and_then(Value::as_u64),
        val.get("incoming_connections_count")
            .and_then(Value::as_u64),
    ) {
        (Some(outgoing), Some(incoming)) => {
            format!("  Connections:  {outgoing} out / {incoming} in")
        }
        _ => "  Connections:  not disclosed".to_owned(),
    }
}

/// Whether the daemon said it runs with P2P off.
fn p2p_is_off(val: &Value) -> bool {
    val.get("p2p").and_then(Value::as_str) == Some("off")
}

/// A line for one of the chain's counts: the label, then the number.
///
/// A count that is missing or is not a number is said to be unreadable. It
/// is not printed as `0`: a height of zero is an empty chain and a
/// transaction count of zero is a chain with no transactions, and neither
/// is "this value did not arrive" (RK-D23).
fn count_line(label: &str, val: &Value, key: &str) -> String {
    // The label and its colon are padded to the column the other lines use.
    let label = format!("{label}:");
    match val.get(key).and_then(Value::as_u64) {
        Some(count) => format!("  {label:<14}{count}"),
        None => format!("  {label:<14}unreadable"),
    }
}

pub(crate) fn show_chain(val: &Value) {
    let status = val.get("status").and_then(|v| v.as_str()).unwrap_or("?");
    println!("Chain health:");
    println!("  Status:       {status}");
    println!("{}", count_line("Height", val, "height"));
    if let Some(line) = sync_line(val) {
        println!("{line}");
    }
    println!("{}", difficulty_line(val));
    println!("{}", count_line("Tx count", val, "tx_count"));
    println!("{}", connections_line(val));
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

#[cfg(test)]
mod tests {
    use super::{connections_line, count_line, difficulty_line, sync_line};
    use serde_json::json;

    /// A count prints in the column it always has, zero included.
    #[test]
    fn a_count_is_shown_as_it_arrived_and_zero_is_a_count() {
        let val = json!({ "height": 1_234_567, "tx_count": 0 });
        assert_eq!(
            count_line("Height", &val, "height"),
            "  Height:       1234567"
        );
        assert_eq!(
            count_line("Tx count", &val, "tx_count"),
            "  Tx count:     0"
        );
    }

    /// A count that did not arrive, or is not a number, is unreadable. It
    /// was printed as `0`, which reads as an empty chain.
    #[test]
    fn a_count_that_is_missing_or_not_a_number_is_unreadable_never_zero() {
        for val in [
            json!({}),
            json!({ "height": null, "tx_count": null }),
            json!({ "height": "12", "tx_count": "3" }),
            json!({ "height": -1, "tx_count": 1.5 }),
        ] {
            assert_eq!(
                count_line("Height", &val, "height"),
                "  Height:       unreadable",
                "{val}"
            );
            assert_eq!(
                count_line("Tx count", &val, "tx_count"),
                "  Tx count:     unreadable",
                "{val}"
            );
        }
    }

    /// Synchronized is the flag's word. A target above the height, which a
    /// synchronized daemon can now report, does not make it "syncing".
    #[test]
    fn a_synchronized_daemon_has_no_syncing_line_whatever_its_target() {
        for target in [json!(null), json!(0), json!(10), json!(9_999_999)] {
            assert_eq!(
                sync_line(&json!({
                    "height": 10, "synchronized": true, "target_height": target,
                })),
                None,
                "target {target}"
            );
        }
    }

    #[test]
    fn a_syncing_daemon_shows_its_target_or_says_it_has_none() {
        assert_eq!(
            sync_line(&json!({ "height": 10, "synchronized": false, "target_height": 500 })),
            Some("  Target:       500 (syncing)".to_owned())
        );
        // A target equal to the height was hidden by the old inference.
        assert_eq!(
            sync_line(&json!({ "height": 10, "synchronized": false, "target_height": 10 })),
            Some("  Target:       10 (syncing)".to_owned())
        );
        assert_eq!(
            sync_line(&json!({ "height": 10, "synchronized": false, "target_height": null })),
            Some("  Target:       none yet (syncing)".to_owned())
        );
    }

    /// The difficulty is shown whole. Past 2^64 the old output printed the
    /// low 64 bits: for 2^64 + 5 it printed 5.
    #[test]
    fn the_difficulty_is_shown_whole_past_64_bits() {
        assert_eq!(
            difficulty_line(&json!({ "wide_difficulty": "0x1e240" })),
            "  Difficulty:   123456"
        );
        assert_eq!(
            difficulty_line(&json!({ "wide_difficulty": "0x10000000000000005" })),
            "  Difficulty:   18446744073709551621"
        );
        assert_eq!(
            difficulty_line(&json!({
                "wide_difficulty": "0xffffffffffffffffffffffffffffffff"
            })),
            "  Difficulty:   340282366920938463463374607431768211455"
        );
    }

    /// A difficulty that is absent, a number, or not strict hex is not a
    /// difficulty of zero.
    #[test]
    fn an_unreadable_difficulty_is_not_shown_as_zero() {
        for val in [
            json!({}),
            json!({ "difficulty": 123_456 }),
            json!({ "wide_difficulty": 123_456 }),
            json!({ "wide_difficulty": "0x+ff" }),
            json!({ "wide_difficulty": "1e240" }),
        ] {
            assert_eq!(difficulty_line(&val), "  Difficulty:   unreadable", "{val}");
        }
    }

    #[test]
    fn a_value_without_the_flag_reads_as_syncing() {
        assert!(sync_line(&json!({ "height": 10, "target_height": null })).is_some());
    }

    /// A withheld Status part omits the keys. Printing that as zero would
    /// say the node has no connections. A shown zero still prints as zero:
    /// it is a count, from a daemon that disclosed it.
    #[test]
    fn withheld_connection_counts_are_not_a_zero() {
        assert_eq!(
            connections_line(&json!({})),
            "  Connections:  not disclosed"
        );
        assert_eq!(
            connections_line(&json!({ "outgoing_connections_count": 4 })),
            "  Connections:  not disclosed"
        );
        assert_eq!(
            connections_line(&json!({ "incoming_connections_count": 4 })),
            "  Connections:  not disclosed"
        );
        assert_eq!(
            connections_line(&json!({
                "outgoing_connections_count": 0,
                "incoming_connections_count": 0,
            })),
            "  Connections:  0 out / 0 in"
        );
        assert_eq!(
            connections_line(&json!({
                "outgoing_connections_count": 3,
                "incoming_connections_count": 1,
            })),
            "  Connections:  3 out / 1 in"
        );
    }

    /// **A daemon started with P2P off prints that state** (Rick,
    /// 2026-10-14): "P2P: off", not "0 out / 0 in", even though its Status
    /// part carries two zeros.
    #[test]
    fn a_daemon_with_p2p_off_prints_the_state_not_a_zero() {
        assert_eq!(
            connections_line(&json!({
                "p2p": "off",
                "outgoing_connections_count": 0,
                "incoming_connections_count": 0,
            })),
            "  P2P:          off"
        );
        assert_eq!(
            connections_line(&json!({
                "p2p": "on",
                "outgoing_connections_count": 0,
                "incoming_connections_count": 0,
            })),
            "  Connections:  0 out / 0 in",
            "a running node with no connections is a count"
        );
    }
}
