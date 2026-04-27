// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Staking commands: stake, unstake, claim, staking_info, chain_health.

use crate::daemon::DaemonClient;
use crate::engine::EngineContext;

pub fn cmd_stake(ctx: &EngineContext, account_index: u32, tier: Option<u8>, amount: u64) {
    if !super::require_open(ctx) {
        return;
    }

    println!(
        "Staking {} SKL from account {account_index}...",
        super::format_amount(amount)
    );
    if let Some(t) = tier {
        println!("  Tier: {t}");
    }

    let params = serde_json::json!({
        "account_index": account_index,
        "amount": amount,
        "tier": tier.unwrap_or(0),
    });

    if !super::confirm("Confirm staking transaction?") {
        println!("Cancelled.");
        return;
    }

    match ctx.json_rpc("stake", &params.to_string()) {
        Ok(val) => {
            if let Some(tx_hash) = val.get("tx_hash").and_then(|h| h.as_str()) {
                println!("Staked successfully. Transaction: {tx_hash}");
            } else {
                println!("Stake submitted.");
                println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            }
        }
        Err(e) => eprintln!("Staking failed: {e}"),
    }
}

pub fn cmd_unstake(ctx: &EngineContext, account_index: u32) {
    if !super::require_open(ctx) {
        return;
    }

    if !super::confirm("Confirm unstake?") {
        println!("Cancelled.");
        return;
    }

    let params = serde_json::json!({ "account_index": account_index });
    match ctx.json_rpc("unstake", &params.to_string()) {
        Ok(val) => {
            if let Some(tx_hash) = val.get("tx_hash").and_then(|h| h.as_str()) {
                println!("Unstaked successfully. Transaction: {tx_hash}");
            } else {
                println!("Unstake submitted.");
                println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            }
        }
        Err(e) => eprintln!("Unstake failed: {e}"),
    }
}

pub fn cmd_claim(ctx: &EngineContext, account_index: u32) {
    if !super::require_open(ctx) {
        return;
    }

    if !super::confirm("Claim staking rewards?") {
        println!("Cancelled.");
        return;
    }

    let params = serde_json::json!({ "account_index": account_index });
    match ctx.json_rpc("claim_rewards", &params.to_string()) {
        Ok(val) => {
            if let Some(amount) = val.get("amount").and_then(|a| a.as_u64()) {
                println!("Claimed {} SKL in rewards.", super::format_amount(amount));
            } else {
                println!("Rewards claimed.");
                println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            }
        }
        Err(e) => eprintln!("Claim failed: {e}"),
    }
}

pub fn cmd_staking_info(ctx: &EngineContext, account_index: u32) {
    if !super::require_open(ctx) {
        return;
    }

    let params = serde_json::json!({ "account_index": account_index });
    match ctx.json_rpc("staking_info", &params.to_string()) {
        Ok(val) => {
            println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
        }
        Err(e) => eprintln!("Failed to get staking info: {e}"),
    }
}

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
