// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Staking commands over the WI-RPC-1 staking surface (WI-RPC-2b):
//! `stake`, `staked_balance`, `staked_outputs`, `staking_info`.
//!
//! The user asks to stake; the protocol dance (persona derivation, P-scan,
//! bond assembly, dispatch) stays hidden per rule 81. Read commands surface
//! the never-conflated staked-balance breakdown exactly as the RPC reports
//! it.

use serde_json::{json, Value};
use zeroize::Zeroize;

use super::{confirm, opt_amount, read_password, require_open};
use crate::rpc_client::RpcSession;

pub fn cmd_stake(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    println!("Staking bonds your wallet's funds as staking principal.");
    println!("The bond posts on-chain and the principal locks until unbonding.");
    if !confirm("Make this wallet a staker?") {
        println!("Staking cancelled.");
        return;
    }
    // Load-bearing, not UX: a mid-session wallet holds no seed, and only a
    // credentialed reopen re-materializes it for the persona derivation.
    let Some(mut password) = read_password("Wallet password: ") else {
        return;
    };
    println!("Staking (this may take a while)...");
    let result = rpc.call("stake", json!({ "password": password }));
    password.zeroize();

    match result {
        Ok(val) => {
            let slot = val
                .get("slot")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(-1);
            let resumed = val
                .get("resumed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if resumed {
                println!("Resumed an in-flight stake (slot {slot}).");
            } else {
                println!("Stake sealed (slot {slot}).");
            }
            println!("The bond will be dispatched to the network automatically.");
            println!("Track it with \"staking_info\".");
        }
        Err(e) => rpc.report("Failed to stake", &e),
    }
}

pub fn cmd_staked_balance(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("get_staked_balance", json!({})) {
        Ok(val) => print_staked_balance(&val, ""),
        Err(e) => rpc.report("Failed to get staked balance", &e),
    }
}

fn print_staked_balance(balance: &Value, indent: &str) {
    let field = |name: &str| opt_amount(balance, name);
    println!(
        "{indent}Bonded principal (confirmed): {} SKL",
        field("bonded_principal_confirmed")
    );
    println!(
        "{indent}Bonded principal (pending):   {} SKL",
        field("bonded_principal_pending")
    );
    println!(
        "{indent}Rewards received, unspent:    {} SKL",
        field("rewards_received_unspent")
    );
}

pub fn cmd_staked_outputs(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("get_staked_outputs", json!({})) {
        Ok(val) => {
            let outputs = val.get("staked_outputs").and_then(|v| v.as_array());
            let Some(outputs) = outputs.filter(|a| !a.is_empty()) else {
                println!("No staked outputs.");
                return;
            };
            println!(
                "{:<14} {:>18} {:>6} {:>14}",
                "Output", "Amount (SKL)", "Slot", "Unlock height"
            );
            for o in outputs {
                let gindex = o.get("gindex").and_then(|v| v.as_str()).unwrap_or("?");
                let amount = opt_amount(o, "amount");
                let slot = o
                    .get("p_slot")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(-1);
                let unlock = o
                    .get("unlock_height")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(0);
                println!("{gindex:<14} {amount:>18} {slot:>6} {unlock:>14}");
            }
        }
        Err(e) => rpc.report("Failed to get staked outputs", &e),
    }
}

/// `serve_complete_tree [on|off]` — the Foundation `CompleteTree` archival
/// serving posture. Deliberately a CLI-only surface: the GUI never exposes
/// it, so the one road into this mode runs through the stated terms below.
///
/// The terms are printed *before* the confirmation and name every cost the
/// design carries (`ARCHIVAL_CHALLENGE_MECHANISM.md`, Foundation
/// CompleteTree nodes): no rewards, no participation in the staking economy,
/// unbounded disk growth, and the slash side of serving intact. Rule 82:
/// the operator learns the failure modes here, not from the first alarm.
pub fn cmd_serve_complete_tree(rpc: &RpcSession, switch: Option<bool>) {
    if !require_open(rpc) {
        return;
    }
    let Some(enable) = switch else {
        match rpc.call("staking_info", json!({})) {
            Ok(val) => {
                let on = val
                    .get("serve_complete_tree")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                println!(
                    "CompleteTree archival serving: {}",
                    if on { "ACTIVATED" } else { "not activated" }
                );
                if !on {
                    println!("Use \"serve_complete_tree on\" to activate it (CLI only).");
                }
            }
            Err(e) => rpc.report("Failed to read serving posture", &e),
        }
        return;
    };

    if enable {
        println!("CompleteTree is the Foundation archival serving posture.");
        println!();
        println!("  * This wallet will pin and serve EVERY frozen shard of the chain's");
        println!("    output tree. New shards join automatically as they freeze, forever.");
        println!("  * Disk use grows without bound. Nothing is ever pruned.");
        println!("  * There is NO profit in this mode: CompleteTree nodes receive NO");
        println!("    staking rewards and take NO part in normal staking economics —");
        println!("    they sit outside the reward market by design.");
        println!("  * The slash side of serving still applies: a CompleteTree node that");
        println!("    stops serving long enough has its holdings cleared, and re-entry");
        println!("    is a rebond.");
        println!();
        if !confirm("Activate CompleteTree archival serving anyway?") {
            println!("CompleteTree serving left deactivated.");
            return;
        }
    } else if !confirm("Deactivate CompleteTree archival serving?") {
        println!("CompleteTree serving left as it is.");
        return;
    }

    match rpc.call("set_serve_complete_tree", json!({ "enabled": enable })) {
        Ok(val) => {
            let on = val
                .get("serve_complete_tree")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(enable);
            println!(
                "CompleteTree archival serving is now {}.",
                if on { "ACTIVATED" } else { "deactivated" }
            );
            let reopen = val
                .get("reopen_required")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if reopen {
                println!("Close and reopen the wallet for the change to take effect.");
            }
        }
        Err(e) => rpc.report("Failed to set serving posture", &e),
    }
}

pub fn cmd_staking_info(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("staking_info", json!({})) {
        Ok(val) => {
            let enabled = val
                .get("staking_enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            println!("Staking enabled: {}", if enabled { "yes" } else { "no" });
            if !enabled {
                println!("Use \"stake\" to make this wallet a staker.");
                return;
            }
            if let Some(balance) = val.get("balance") {
                println!("Staked balance:");
                print_staked_balance(balance, "  ");
            }
            let count = val
                .get("staked_output_count")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            println!("Staked outputs:  {count}");
            match val
                .get("pscan_synced_height")
                .and_then(serde_json::Value::as_i64)
            {
                Some(h) => println!("Staking scan height: {h}"),
                None => println!("Staking scan height: not yet scanned"),
            }
            // Surfaced only when on: the posture is a Foundation-operator
            // niche, and a "not activated" line on every ordinary staker
            // would read as something to go turn on.
            if val
                .get("serve_complete_tree")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                println!(
                    "CompleteTree archival serving: ACTIVATED (no staking rewards; \
                     see \"serve_complete_tree\")"
                );
            }
        }
        Err(e) => rpc.report("Failed to get staking info", &e),
    }
}
