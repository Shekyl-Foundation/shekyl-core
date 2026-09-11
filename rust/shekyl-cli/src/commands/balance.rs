// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Balance and address commands over the native RPC surface (WI-RPC-2a).

use serde_json::json;

use super::{format_amount_str, require_open};
use crate::display::short_address;
use crate::rpc_client::RpcSession;

/// Fetch this wallet's primary address. `fail` is the report prefix on an
/// RPC error (`Failed to get address` / `Failed to get the payout address`).
pub(crate) fn primary_address(rpc: &RpcSession, fail: &str) -> Option<String> {
    match rpc.call("get_primary_address", json!({})) {
        Ok(val) => match val.get("address").and_then(|v| v.as_str()) {
            Some(address) => Some(address.to_owned()),
            None => {
                eprintln!("Malformed get_primary_address response.");
                None
            }
        },
        Err(e) => {
            rpc.report(fail, &e);
            None
        }
    }
}

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
            // The staking fields are ABSENT — never "0" — when the wallet's
            // staking state cannot be read (the wire degrade contract):
            // that absence renders as unavailability, not the generic "?",
            // and never as a zero that would read "nothing staked" (rule 82).
            let staking_field = |name: &str| {
                val.get(name)
                    .and_then(|v| v.as_str())
                    .map(|v| format!("{} SKL", format_amount_str(v)))
                    .unwrap_or_else(|| "unavailable (staking state could not be read)".to_owned())
            };
            println!("Balance:");
            println!("  Unlocked:           {} SKL", field("unlocked"));
            println!("  Liquid:             {} SKL", field("liquid"));
            println!("  Pending:            {} SKL", field("pending"));
            println!("  Staked:             {}", staking_field("staked"));
            println!(
                "  Claimable rewards:  {}",
                staking_field("claimable_rewards")
            );
        }
        Err(e) => rpc.report("Failed to get balance", &e),
    }
}

/// `address [--full | --out <path>]` (CU-4). Hybrid addresses run to
/// ~2,030 characters; the default is a short **display-only** form so the
/// terminal stays usable, with the full string behind `--full` (print) or
/// `--out <path>` (written to a new 0600 file, never overwriting — the same
/// file-creation shape as `--seed-out`; an address is public, the uniform
/// handling is for consistency, not secrecy).
pub fn cmd_address(rpc: &RpcSession, full: bool, out: Option<&str>) {
    if !require_open(rpc) {
        return;
    }
    let Some(address) = primary_address(rpc, "Failed to get address") else {
        return;
    };

    if let Some(path) = out {
        let path = std::path::Path::new(path);
        let write = super::scripted::open_owner_only_excl(path, "address file").and_then(
            |mut file| -> Result<(), Box<dyn std::error::Error>> {
                use std::io::Write;
                writeln!(file, "{address}")?;
                Ok(())
            },
        );
        match write {
            Ok(()) => println!(
                "Full address ({} characters) written to {}.",
                address.chars().count(),
                path.display()
            ),
            Err(e) => eprintln!("{e}"),
        }
        return;
    }

    if full {
        println!("{address}");
        return;
    }

    println!("{}", short_address(&address));
    println!(
        "(short display form of the {}-character address — not valid for \
         pasting; \"address --full\" prints it all, \"address --out <path>\" \
         writes it to a file)",
        address.chars().count()
    );
}

/// One-round-trip wallet summary over `get_wallet_info` (WI-RPC-4).
/// The REPL command is `wallet` (renamed from `engine_info`, CU-2; the old
/// name is a hidden alias).
pub fn cmd_wallet(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("get_wallet_info", json!({})) {
        Ok(val) => {
            let s = |name: &str| val.get(name).and_then(|v| v.as_str()).unwrap_or("?");
            // A missing required field is a malformed response, not a zero.
            // Height 0 is a real, plausible value — rendering it for an
            // absent field would report a fully unsynced wallet to a user
            // whose wallet may be fully synced.
            let i = |name: &str| {
                val.get(name)
                    .and_then(serde_json::Value::as_i64)
                    .map_or_else(|| "?".to_owned(), |h| h.to_string())
            };
            println!("Wallet: {}", s("name"));
            println!("  Network:         {}", s("network"));
            println!("  Capability:      {}", s("capability"));
            let addr = s("address");
            let shown = short_address(addr);
            println!("  Address:         {shown}");
            if shown != addr {
                println!("                   (display only; \"address --full\" prints it all)");
            }
            println!("  Wallet height:   {}", i("wallet_height"));
            match val.get("daemon_height").and_then(serde_json::Value::as_i64) {
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
            match val.get("staking") {
                Some(staking) => {
                    let enabled = staking
                        .get("staking_enabled")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    println!("  Staking enabled:  {enabled}");
                }
                // The staking block is ABSENT when the wallet's staking state
                // cannot be read (the wire degrade contract). Omitting the
                // line would read as though the question was never asked
                // (rule 82) — say what happened instead.
                None => {
                    println!("  Staking:          unavailable (staking state could not be read)");
                }
            }
        }
        Err(e) => rpc.report("Failed to get wallet info", &e),
    }
}
