// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain/daemon health command.

use crate::daemon::DaemonClient;

pub fn cmd_chain_health(daemon: Option<&DaemonClient>) {
    let Some(dc) = daemon else {
        eprintln!("Daemon not configured. Use --daemon-address to set the daemon endpoint.");
        return;
    };

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
        }
        Err(e) => eprintln!("{e}"),
    }
}

fn require_daemon(daemon: Option<&DaemonClient>) -> Option<&DaemonClient> {
    match daemon {
        Some(dc) => Some(dc),
        None => {
            eprintln!("Daemon not configured. Use --daemon-address to set the daemon endpoint.");
            None
        }
    }
}

/// `shard list all` — the daemon's pay-ordered coverage list.
pub fn cmd_shard_list_all(daemon: Option<&DaemonClient>) {
    let Some(dc) = require_daemon(daemon) else {
        return;
    };
    match dc.archival_shard_coverage() {
        Ok(list) => print_coverage(&list, None),
        Err(e) => eprintln!("{e}"),
    }
}

/// `shard list mine` — this wallet's shards. The wallet RPC does not report
/// them yet, so this refuses rather than printing an empty table.
pub fn cmd_shard_list_mine(rpc: &crate::rpc_client::RpcSession) {
    rpc.fail();
    eprintln!(
        "This wallet does not report which shards it holds yet. \
         Nothing was listed. \"shard list all\" shows every shard and its pay."
    );
}

/// `shard show <id>` — one coverage row.
pub fn cmd_shard_show(daemon: Option<&DaemonClient>, shard_id: u64) {
    let Some(dc) = require_daemon(daemon) else {
        return;
    };
    match dc.archival_shard_coverage() {
        Ok(list) => match list.shards.iter().find(|row| row.shard_id == shard_id) {
            Some(row) => print_coverage_row(row, list.profit_estimate_available),
            None => eprintln!("Shard {shard_id} is not in the list."),
        },
        Err(e) => eprintln!("{e}"),
    }
}

/// `shard fetch <id>` — ask the daemon to retrieve the shard. Text only.
pub fn cmd_shard_fetch(daemon: Option<&DaemonClient>, shard_id: u64) {
    let Some(dc) = require_daemon(daemon) else {
        return;
    };
    match dc.request_archival_shard(shard_id) {
        Ok(fetch) => {
            println!("Shard {} fetch requested.", fetch.shard_id);
            println!("  Hash:    {}", fetch.shard_hash);
            println!("  Blocks:  {}", fetch.block_count);
            println!("  Outputs: {}", fetch.output_count);
        }
        Err(e) => eprintln!("{e}"),
    }
}

fn print_coverage(list: &crate::daemon::ArchivalShardCoverage, only: Option<&[u64]>) {
    let mut rows = list.shards.clone();
    shuffle_equal_pay(&mut rows);
    println!(
        "{:<8} {:>16} {:>8} {:>8}",
        "Shard", "Pay", "Bonded", "Served"
    );
    let mut printed = 0usize;
    for row in &rows {
        if let Some(ids) = only {
            if !ids.contains(&row.shard_id) {
                continue;
            }
        }
        print_coverage_row(row, list.profit_estimate_available);
        printed += 1;
    }
    if printed == 0 {
        println!("No shards.");
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

/// Shuffle rows that share a pay figure, leaving the daemon's order of
/// distinct pay bands alone. Presentation only.
fn shuffle_equal_pay(rows: &mut [crate::daemon::ShardCoverageRow]) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut i = 0;
    while i < rows.len() {
        let pay = rows[i].expected_profit_atomic;
        let mut j = i + 1;
        while j < rows.len() && rows[j].expected_profit_atomic == pay {
            j += 1;
        }
        if j - i > 1 {
            // A per-process shuffle: hash the band with a fresh seed from
            // the clock so two operators do not share a stable tie-break.
            let mut seed = DefaultHasher::new();
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
                .hash(&mut seed);
            let mut state = seed.finish();
            for k in i..j {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let span = j - i;
                let swap = i + usize::try_from(state % u64::try_from(span).unwrap_or(1))
                    .unwrap_or(0)
                    % span;
                rows.swap(k, swap);
            }
        }
        i = j;
    }
}
