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
