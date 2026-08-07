// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Balance and address commands over the native RPC surface (WI-RPC-2a).

use serde_json::json;

use super::{format_amount_str, require_open};
use crate::rpc_client::RpcSession;

pub fn cmd_balance(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("get_balance", json!({})) {
        Ok(val) => {
            let field = |name: &str| {
                val.get(name)
                    .and_then(|v| v.as_str())
                    .map(format_amount_str)
                    .unwrap_or_else(|| "?".to_owned())
            };
            println!("Balance:");
            println!("  Unlocked:           {} SKL", field("unlocked"));
            println!("  Liquid:             {} SKL", field("liquid"));
            println!("  Pending:            {} SKL", field("pending"));
            println!("  Staked:             {} SKL", field("staked"));
            println!("  Claimable rewards:  {} SKL", field("claimable_rewards"));
        }
        Err(e) => rpc.report("Failed to get balance", &e),
    }
}

pub fn cmd_address(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("get_primary_address", json!({})) {
        Ok(val) => match val.get("address").and_then(|v| v.as_str()) {
            Some(address) => println!("{address}"),
            None => eprintln!("Malformed get_primary_address response."),
        },
        Err(e) => rpc.report("Failed to get address", &e),
    }
}

/// One-round-trip wallet summary over `get_wallet_info` (WI-RPC-4).
pub fn cmd_engine_info(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("get_wallet_info", json!({})) {
        Ok(val) => {
            let s = |name: &str| val.get(name).and_then(|v| v.as_str()).unwrap_or("?");
            let i = |name: &str| val.get(name).and_then(|v| v.as_i64()).unwrap_or(0);
            println!("Wallet: {}", s("name"));
            println!("  Network:         {}", s("network"));
            println!("  Capability:      {}", s("capability"));
            println!("  Address:         {}", s("address"));
            println!("  Wallet height:   {}", i("wallet_height"));
            match val.get("daemon_height").and_then(|v| v.as_i64()) {
                Some(h) => println!("  Daemon height:   {h}"),
                None => println!("  Daemon height:   unavailable"),
            }
            println!("  Restore height:  {}", i("restore_height"));
            if let Some(bal) = val.get("balance") {
                let field = |name: &str| {
                    bal.get(name)
                        .and_then(|v| v.as_str())
                        .map(format_amount_str)
                        .unwrap_or_else(|| "?".to_owned())
                };
                println!("  Balance unlocked: {} SKL", field("unlocked"));
                println!("  Balance liquid:   {} SKL", field("liquid"));
            }
            if let Some(staking) = val.get("staking") {
                let enabled = staking
                    .get("staking_enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                println!("  Staking enabled:  {enabled}");
            }
        }
        Err(e) => rpc.report("Failed to get wallet info", &e),
    }
}
