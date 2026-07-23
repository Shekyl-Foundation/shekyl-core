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

use super::{confirm, format_amount_str, read_password, require_open};
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
            let slot = val.get("slot").and_then(|v| v.as_i64()).unwrap_or(-1);
            let resumed = val
                .get("resumed")
                .and_then(|v| v.as_bool())
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
    let field = |name: &str| {
        balance
            .get(name)
            .and_then(|v| v.as_str())
            .map(format_amount_str)
            .unwrap_or_else(|| "?".to_owned())
    };
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
            let outputs = val
                .get("staked_outputs")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if outputs.is_empty() {
                println!("No staked outputs.");
                return;
            }
            println!(
                "{:<14} {:>18} {:>6} {:>14}",
                "Output", "Amount (SKL)", "Slot", "Unlock height"
            );
            for o in &outputs {
                let gindex = o.get("gindex").and_then(|v| v.as_str()).unwrap_or("?");
                let amount = o
                    .get("amount")
                    .and_then(|v| v.as_str())
                    .map(format_amount_str)
                    .unwrap_or_else(|| "?".to_owned());
                let slot = o.get("p_slot").and_then(|v| v.as_i64()).unwrap_or(-1);
                let unlock = o.get("unlock_height").and_then(|v| v.as_i64()).unwrap_or(0);
                println!("{gindex:<14} {amount:>18} {slot:>6} {unlock:>14}");
            }
        }
        Err(e) => rpc.report("Failed to get staked outputs", &e),
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
                .and_then(|v| v.as_bool())
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
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            println!("Staked outputs:  {count}");
            match val.get("pscan_synced_height").and_then(|v| v.as_i64()) {
                Some(h) => println!("Staking scan height: {h}"),
                None => println!("Staking scan height: not yet scanned"),
            }
        }
        Err(e) => rpc.report("Failed to get staking info", &e),
    }
}
