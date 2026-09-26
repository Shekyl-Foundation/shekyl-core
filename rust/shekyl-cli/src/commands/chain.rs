// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain/daemon health command.

use crate::daemon::DaemonClient;
use crate::outcome::{failed, CommandResult};

pub fn cmd_chain_health(daemon: Option<&DaemonClient>) -> CommandResult {
    let dc = require_daemon(daemon)?;
    match dc.get_info() {
        Ok(info) => {
            println!("Chain health:");
            println!("  Status:       {}", info.status);
            println!("  Height:       {}", info.height);
            if info.target_height > 0 && info.target_height != info.height {
                println!("  Target:       {} (syncing)", info.target_height);
            }
            println!("  Difficulty:   {}", info.difficulty);
            println!("  Tx count:     {}", info.tx_count);
            println!(
                "  Connections:  {} out / {} in",
                info.outgoing_connections_count, info.incoming_connections_count
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("{e}");
            failed()
        }
    }
}

fn require_daemon(
    daemon: Option<&DaemonClient>,
) -> Result<&DaemonClient, crate::outcome::CommandFailed> {
    match daemon {
        Some(dc) => Ok(dc),
        None => {
            eprintln!("Daemon not configured. Use --daemon-address to set the daemon endpoint.");
            Err(crate::outcome::CommandFailed)
        }
    }
}

/// `shard list all` — the daemon's coverage list, in the daemon's order.
pub fn cmd_shard_list_all(daemon: Option<&DaemonClient>) -> CommandResult {
    let dc = require_daemon(daemon)?;
    match dc.archival_shard_coverage() {
        Ok(list) => {
            print_coverage(&list);
            Ok(())
        }
        Err(e) => {
            eprintln!("{e}");
            failed()
        }
    }
}

/// `shard list mine` — this wallet's shards. The wallet RPC does not report
/// them yet, so this refuses rather than printing an empty table.
pub fn cmd_shard_list_mine(_rpc: &crate::rpc_client::RpcSession) -> CommandResult {
    eprintln!(
        "This wallet does not report which shards it holds yet. \
         Nothing was listed. \"shard list all\" shows every shard and its pay."
    );
    failed()
}

/// `shard show <id>` — one coverage row.
pub fn cmd_shard_show(daemon: Option<&DaemonClient>, shard_id: u64) -> CommandResult {
    let dc = require_daemon(daemon)?;
    match dc.archival_shard_coverage() {
        Ok(list) => match list.shards.iter().find(|row| row.shard_id == shard_id) {
            Some(row) => {
                print_coverage_row(row, list.profit_estimate_available);
                Ok(())
            }
            None => {
                eprintln!("Shard {shard_id} is not in the list.");
                failed()
            }
        },
        Err(e) => {
            eprintln!("{e}");
            failed()
        }
    }
}

/// `shard fetch <id>` — ask the daemon to retrieve the shard. Text only.
pub fn cmd_shard_fetch(daemon: Option<&DaemonClient>, shard_id: u64) -> CommandResult {
    let dc = require_daemon(daemon)?;
    match dc.request_archival_shard(shard_id) {
        Ok(fetch) => {
            println!("Shard {} fetch requested.", fetch.shard_id);
            println!("  Hash:    {}", fetch.shard_hash);
            println!("  Blocks:  {}", fetch.block_count);
            println!("  Outputs: {}", fetch.output_count);
            Ok(())
        }
        Err(e) => {
            eprintln!("{e}");
            failed()
        }
    }
}

fn print_coverage(list: &crate::daemon::ArchivalShardCoverage) {
    println!(
        "{:<8} {:>16} {:>8} {:>8}",
        "Shard", "Pay", "Bonded", "Served"
    );
    if list.shards.is_empty() {
        println!("No shards.");
        return;
    }
    for row in &list.shards {
        print_coverage_row(row, list.profit_estimate_available);
    }
}

fn print_coverage_row(row: &crate::daemon::ShardCoverageRow, profit_available: bool) {
    let pay = if profit_available {
        crate::commands::format_amount(row.expected_profit_atomic)
    } else {
        "unavailable".to_owned()
    };
    println!(
        "{:<8} {:>16} {:>8} {:>8}",
        row.shard_id, pay, row.bonded_count, row.served_count
    );
}
