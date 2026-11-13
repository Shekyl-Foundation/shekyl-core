// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain/daemon health and archival-shard commands.

use serde_json::{json, Value};
use shekyl_rpc_types::wire::archival::{Coverage, CoverageShard};
use shekyl_rpc_types::wire::daemon::DaemonStatus;
use shekyl_shard_visual::{render_candidate_png, ShardAggregate};

use super::require_open;
use crate::daemon::DaemonClient;
use crate::outcome::{failed, refusal, CommandResult};
use crate::rpc_client::RpcSession;

/// `chain` — the daemon's `daemon_status` reply. `--json` prints it as the
/// wire serializes it: a part the connection's grant withholds is absent,
/// as on the wire, and no member is renamed or recomputed here.
pub fn cmd_chain_health(daemon: Option<&DaemonClient>) -> CommandResult<DaemonStatus> {
    let dc = require_daemon(daemon)?;
    dc.daemon_status().or_else(|e| failed(e.to_string()))
}

/// The line that says the daemon is still syncing, or `None` when it has
/// caught up.
///
/// Read from `synchronized`, the daemon's own flag, never inferred from the
/// target: a synchronized daemon reports a real target, so that inference
/// would call it syncing whenever a peer had claimed a taller chain. The
/// target is the block the core is syncing toward, the wire's
/// `target_height` unchanged.
fn sync_line(status: &DaemonStatus) -> Option<String> {
    if status.synchronized {
        return None;
    }
    Some(match status.target_height.0 {
        Some(target) => format!("  Target block: {} (syncing)", target.0),
        None => "  Target block: none yet (syncing)".to_owned(),
    })
}

/// The difficulty line: the whole 128-bit value, in decimal. It is in the
/// chain part, which a connection without the `chain` grant is not shown:
/// withheld is said, never a difficulty of zero.
fn difficulty_line(status: &DaemonStatus) -> String {
    match status.difficulty.shown() {
        Some(difficulty) => format!("  Difficulty:   {}", difficulty.get()),
        None => "  Difficulty:   not disclosed".to_owned(),
    }
}

/// The transaction count line, from the chain part like the difficulty.
fn tx_count_line(status: &DaemonStatus) -> String {
    match status.tx_count.shown() {
        Some(count) => format!("  Tx count:     {}", count.0),
        None => "  Tx count:     not disclosed".to_owned(),
    }
}

/// The connections line.
///
/// Both counts shown, including a shown zero, print as counts. A withheld
/// Status part is said to be withheld: a zero would claim the node has no
/// connections, which is a different fact. A daemon started offline has no
/// connections by configuration; its state is the line (Rick, 2026-10-14).
fn connections_line(status: &DaemonStatus) -> String {
    if status.offline {
        return "  P2P:          offline".to_owned();
    }
    match (
        status.peer_outbound_count.shown().and_then(|n| n.0),
        status.peer_inbound_count.shown().and_then(|n| n.0),
    ) {
        (Some(outgoing), Some(incoming)) => {
            format!("  Connections:  {} out / {} in", outgoing.0, incoming.0)
        }
        _ => "  Connections:  not disclosed".to_owned(),
    }
}

/// The human lines, from the typed reply. The tip is shown by its own
/// number, the wire's `height` unchanged (`HEIGHT_SEMANTICS.md` §1).
pub(crate) fn show_chain(status: &DaemonStatus) {
    println!("Chain health:");
    println!("  Block number: {}", status.height.0);
    if let Some(line) = sync_line(status) {
        println!("{line}");
    }
    println!("{}", difficulty_line(status));
    println!("{}", tx_count_line(status));
    println!("{}", connections_line(status));
}

fn require_daemon(
    daemon: Option<&DaemonClient>,
) -> Result<&DaemonClient, crate::outcome::CommandFailed> {
    match daemon {
        Some(dc) => Ok(dc),
        None => Err(crate::outcome::refusal(
            crate::daemon::DaemonError::NotConfigured.to_string(),
        )),
    }
}

/// `shard list all` — the daemon's `shard_coverage` reply, in the daemon's
/// order. `--json` prints it as the wire serializes it.
pub fn cmd_shard_list_all(daemon: Option<&DaemonClient>) -> CommandResult<Coverage> {
    let dc = require_daemon(daemon)?;
    dc.shard_coverage().or_else(|e| failed(e.to_string()))
}

pub(crate) fn show_coverage(list: &Coverage) {
    println!(
        "{:<8} {:>16} {:>8} {:>8}",
        "Shard", "Pay", "Bonded", "Served"
    );
    if list.shard.is_empty() {
        println!("No shards.");
        return;
    }
    for row in &list.shard {
        println!("{}", coverage_row_line(row));
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

/// `shard show <id>` — one row of the daemon's `shard_coverage` reply,
/// printed as the wire serializes it.
pub fn cmd_shard_show(
    daemon: Option<&DaemonClient>,
    shard_id: u64,
) -> CommandResult<CoverageShard> {
    let dc = require_daemon(daemon)?;
    let list = dc.shard_coverage().or_else(|e| failed(e.to_string()))?;
    match list.shard.into_iter().find(|row| row.id.0 == shard_id) {
        Some(row) => Ok(row),
        None => failed(format!("Shard {shard_id} is not in the list.")),
    }
}

pub(crate) fn show_shard(row: &CoverageShard) {
    println!("{}", coverage_row_line(row));
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
    println!("  Closed at block:  {}", field("close_height"));
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

/// One coverage row's line. The pay is the row's own estimate: the daemon
/// writes `profit` as `null` until a settlement pass has recorded work, and
/// a `null` is "unavailable", never a pay of zero.
fn coverage_row_line(row: &CoverageShard) -> String {
    let pay = row.profit.0.as_ref().map_or_else(
        || "unavailable".to_owned(),
        |profit| crate::commands::format_amount(profit.to_atomic_units().to_raw()),
    );
    format!(
        "{:<8} {pay:>16} {:>8} {:>8}",
        row.id.0, row.bonded_count.0, row.served_count.0
    )
}

#[cfg(test)]
mod tests {
    use super::{connections_line, coverage_row_line, difficulty_line, sync_line, tx_count_line};
    use serde_json::{json, Value};
    use shekyl_rpc_client::{wire, RpcMethod};
    use shekyl_rpc_types::wire::archival::CoverageShard;
    use shekyl_rpc_types::wire::daemon::DaemonStatus;
    use shekyl_rpc_types::Network;

    /// A full `daemon_status` (every part shown), as the typed reply.
    fn status(edit: impl FnOnce(&mut Value)) -> DaemonStatus {
        let mut value = crate::console::daemon_status_reply();
        edit(&mut value);
        serde_json::from_value(value).expect("the fixture is a daemon_status reply")
    }

    /// The Status part withheld, as a caller without the `status` grant
    /// reads it: the console fixture's own withholding, so the two cannot
    /// disagree about which members the part holds.
    fn without_status_part(value: &mut Value) {
        let withheld = crate::console::status_withheld(100);
        let members = value.as_object_mut().unwrap();
        members.retain(|key, _| withheld.get(key).is_some());
        value["grant"] = json!(["health", "chain", "pool", "submit", "mining-work"]);
    }

    /// `chain --json` prints the reply as the wire serializes it: served
    /// through a daemon, decoded into the typed reply the command returns,
    /// and serialized back, it is the served object member for member, for
    /// a connection that holds every grant and for one whose grant withholds
    /// the Status part. Red edit: return a hand-built object, or rename or
    /// recompute a member (the old `height` + 1, `wide_difficulty`,
    /// `outgoing_connections_count`).
    #[test]
    fn chain_json_is_the_wire_s_reply_for_a_full_and_a_view_grant() {
        let full = crate::console::daemon_status_reply();
        let mut view = full.clone();
        without_status_part(&mut view);
        for (grant, served) in [("full", full), ("view", view)] {
            let key = |name: &str| -> &'static str {
                Box::leak(format!("json_rpc:{name}").into_boxed_str())
            };
            let (address, _log) = crate::console::route_server_recording(vec![(
                key(<wire::DaemonStatus as RpcMethod>::NAME),
                shekyl_rpc_transport::json_rpc_result_body(&served),
            )]);
            let daemon = crate::daemon::DaemonClient::new(
                &format!("http://{address}"),
                None,
                None,
                Network::Mainnet,
            )
            .expect("the route server parses");
            let reply = super::cmd_chain_health(Some(&daemon)).expect("daemon_status");
            let printed = serde_json::to_value(&reply).expect("the reply serializes");
            assert_eq!(printed, served, "{grant} grant");
        }
    }

    /// Synchronized is the flag's word. A target above the tip, which a
    /// synchronized daemon can report, does not make it "syncing".
    #[test]
    fn a_synchronized_daemon_has_no_syncing_line_whatever_its_target() {
        for target in [json!(null), json!(0), json!(10), json!(9_999_999)] {
            let s = status(|v| {
                v["synchronized"] = json!(true);
                v["target_height"] = target.clone();
            });
            assert_eq!(sync_line(&s), None, "target {target}");
        }
    }

    /// A syncing daemon names the block it is syncing toward, the wire's
    /// `target_height` unchanged, or says it has none yet.
    #[test]
    fn a_syncing_daemon_shows_its_target_block_or_says_it_has_none() {
        let syncing = |target: Value| {
            status(|v| {
                v["synchronized"] = json!(false);
                v["target_height"] = target;
            })
        };
        assert_eq!(
            sync_line(&syncing(json!(500))),
            Some("  Target block: 500 (syncing)".to_owned())
        );
        // A target equal to the tip is still shown: the flag decides.
        assert_eq!(
            sync_line(&syncing(json!(99))),
            Some("  Target block: 99 (syncing)".to_owned())
        );
        assert_eq!(
            sync_line(&syncing(Value::Null)),
            Some("  Target block: none yet (syncing)".to_owned())
        );
    }

    /// The difficulty is shown whole. Past 2^64 an older output printed the
    /// low 64 bits: for 2^64 + 5 it printed 5.
    #[test]
    fn the_difficulty_is_shown_whole_past_64_bits() {
        for (hex, decimal) in [
            ("0x1e240", "123456"),
            ("0x10000000000000005", "18446744073709551621"),
            (
                "0xffffffffffffffffffffffffffffffff",
                "340282366920938463463374607431768211455",
            ),
        ] {
            let s = status(|v| v["difficulty"] = json!(hex));
            assert_eq!(difficulty_line(&s), format!("  Difficulty:   {decimal}"));
        }
    }

    /// A difficulty the wire did not encode as its strict hex is not a
    /// difficulty of zero: the reply does not decode at all.
    #[test]
    fn an_unreadable_difficulty_is_a_refused_reply_not_zero() {
        for bad in [json!(123_456), json!("0x+ff"), json!("1e240")] {
            let mut value = crate::console::daemon_status_reply();
            value["difficulty"] = bad.clone();
            assert!(
                serde_json::from_value::<DaemonStatus>(value).is_err(),
                "{bad}"
            );
        }
    }

    /// A withheld chain part (a connection without the `chain` grant) says
    /// so; it is not a difficulty or a transaction count of zero. The decode
    /// refuses a part that is partly present, so this list is the whole part.
    #[test]
    fn a_withheld_chain_part_is_not_disclosed_not_zero() {
        let s = status(|v| {
            let members = v.as_object_mut().unwrap();
            for key in [
                "difficulty",
                "difficulty_cumulative",
                "block_spacing",
                "tx_count",
                "block_weight_max",
                "block_weight_median",
                "time_adjusted",
                "emission",
                "emission_multiplier",
                "burn",
                "burn_total",
                "stake_share",
            ] {
                members.remove(key);
            }
        });
        assert_eq!(difficulty_line(&s), "  Difficulty:   not disclosed");
        assert_eq!(tx_count_line(&s), "  Tx count:     not disclosed");
    }

    /// A withheld Status part is not a zero. A shown zero still prints as
    /// zero: it is a count, from a daemon that disclosed it.
    #[test]
    fn withheld_connection_counts_are_not_a_zero() {
        assert_eq!(
            connections_line(&status(without_status_part)),
            "  Connections:  not disclosed"
        );
        let shown = |outgoing: u64, incoming: u64| {
            status(|v| {
                v["peer_outbound_count"] = json!(outgoing);
                v["peer_inbound_count"] = json!(incoming);
            })
        };
        assert_eq!(
            connections_line(&shown(0, 0)),
            "  Connections:  0 out / 0 in"
        );
        assert_eq!(
            connections_line(&shown(3, 1)),
            "  Connections:  3 out / 1 in"
        );
    }

    /// **A daemon started offline prints that state** (Rick, 2026-10-14):
    /// "P2P: offline", not a count.
    #[test]
    fn an_offline_daemon_prints_the_state_not_a_zero() {
        let offline = status(|v| {
            v["offline"] = json!(true);
            v["peered"] = Value::Null;
            v["peer_outbound_count"] = Value::Null;
            v["peer_inbound_count"] = Value::Null;
        });
        assert_eq!(connections_line(&offline), "  P2P:          offline");
        let running = status(|v| {
            v["peer_outbound_count"] = json!(0);
            v["peer_inbound_count"] = json!(0);
        });
        assert_eq!(
            connections_line(&running),
            "  Connections:  0 out / 0 in",
            "a running node with no connections is a count"
        );
    }

    /// A row's pay is its own: a `null` profit is "unavailable", never a pay
    /// of zero, whatever the other rows carry. Red edit: `map_or(0, ...)`.
    #[test]
    fn a_row_without_an_estimate_is_unavailable_not_zero() {
        let row = |profit: Value| -> CoverageShard {
            serde_json::from_value(json!({
                "id": 7, "freeze_height": 100, "bonded_count": 2,
                "served_count": 1, "scarcity": 500_000, "profit": profit,
            }))
            .expect("a coverage row")
        };
        assert!(
            coverage_row_line(&row(Value::Null)).contains("unavailable"),
            "{}",
            coverage_row_line(&row(Value::Null))
        );
        assert!(!coverage_row_line(&row(json!("5000000000"))).contains("unavailable"));
    }
}
