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
            let height = info.get("height").and_then(|h| h.as_u64()).unwrap_or(0);
            let target_height = info
                .get("target_height")
                .and_then(|h| h.as_u64())
                .unwrap_or(0);
            let difficulty = info.get("difficulty").and_then(|d| d.as_u64()).unwrap_or(0);
            let tx_count = info.get("tx_count").and_then(|t| t.as_u64()).unwrap_or(0);
            let outgoing_connections = info
                .get("outgoing_connections_count")
                .and_then(|c| c.as_u64())
                .unwrap_or(0);
            let incoming_connections = info
                .get("incoming_connections_count")
                .and_then(|c| c.as_u64())
                .unwrap_or(0);
            let status = info
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown");

            println!("Chain health:");
            println!("  Status:       {status}");
            println!("  Height:       {height}");
            if target_height > 0 && target_height != height {
                println!("  Target:       {target_height} (syncing)");
            }
            println!("  Difficulty:   {difficulty}");
            println!("  Tx count:     {tx_count}");
            println!("  Connections:  {outgoing_connections} out / {incoming_connections} in");
        }
        Err(e) => eprintln!("{e}"),
    }
}
