// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Balance and address commands over the native RPC surface (WI-RPC-2a).

use serde_json::{json, Value};

use super::{format_amount_str, require_open};
use crate::display::short_address;
use crate::outcome::{failed, CommandFailed, CommandResult};
use crate::rpc_client::RpcSession;

/// Fetch this wallet's primary address. `fail` is the report prefix on an
/// RPC error (`Failed to get address` / `Failed to get the payout address`).
pub(crate) fn primary_address(rpc: &RpcSession, fail: &str) -> Result<String, CommandFailed> {
    match rpc.call("get_primary_address", json!({})) {
        Ok(val) => match val.get("address").and_then(|v| v.as_str()) {
            Some(address) => Ok(address.to_owned()),
            None => Err(crate::outcome::refusal(
                "Malformed get_primary_address response.",
            )),
        },
        Err(e) => Err(rpc.report(fail, &e)),
    }
}

pub fn cmd_balance(rpc: &RpcSession) -> CommandResult {
    require_open(rpc)?;
    match rpc.call("get_balance", json!({})) {
        Ok(val) => Ok(val),
        Err(e) => Err(rpc.report("Failed to get balance", &e)),
    }
}

pub(crate) fn show_balance(val: &Value) {
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
    // Received-but-unspendable money (PL-D3 §6.2): shown only when
    // non-zero, with the pointer to the rows that name the sender's
    // transaction (rule 82: the failure is first-class, not hidden).
    if let Some(unspendable) = val
        .get("unspendable")
        .and_then(|v| v.as_str())
        .filter(|v| *v != "0")
    {
        println!(
            "  Unspendable:        {} SKL  (received but unspendable — \
             see \"tx list\" rows in state UNSPENDABLE)",
            format_amount_str(unspendable)
        );
    }
    println!("  Staked:             {}", staking_field("staked"));
    println!(
        "  Claimable rewards:  {}",
        staking_field("claimable_rewards")
    );
}

/// `address [--full | --out <path>]` (CU-4). Hybrid addresses run to
/// ~2,030 characters; the default is a short **display-only** form so the
/// terminal stays usable, with the full string behind `--full` (print) or
/// `--out <path>` (written to a new 0600 file, never overwriting — the same
/// file-creation shape as `--seed-out`; an address is public, the uniform
/// handling is for consistency, not secrecy).
pub fn cmd_address(rpc: &RpcSession, full: bool, out: Option<&str>) -> CommandResult {
    require_open(rpc)?;
    let address = primary_address(rpc, "Failed to get address")?;
    let characters = address.chars().count();

    if let Some(path) = out {
        let path = std::path::Path::new(path);
        let write = super::scripted::open_owner_only_excl(path, "address file").and_then(
            |mut file| -> Result<(), Box<dyn std::error::Error>> {
                use std::io::Write;
                writeln!(file, "{address}")?;
                Ok(())
            },
        );
        return match write {
            Ok(()) => Ok(json!({
                "address": address,
                "form": "file",
                "path": path.display().to_string(),
                "characters": characters,
            })),
            Err(e) => failed(e.to_string()),
        };
    }

    Ok(json!({
        "address": address,
        "form": if full { "full" } else { "short" },
        "characters": characters,
    }))
}

pub(crate) fn show_address(val: &Value) {
    let address = val.get("address").and_then(|v| v.as_str()).unwrap_or("");
    let characters = val
        .get("characters")
        .and_then(Value::as_u64)
        .unwrap_or(address.chars().count() as u64);
    match val.get("form").and_then(|v| v.as_str()) {
        Some("file") => {
            let path = val.get("path").and_then(|v| v.as_str()).unwrap_or("?");
            println!("Full address ({characters} characters) written to {path}.");
        }
        Some("full") => println!("{address}"),
        _ => {
            println!("{}", short_address(address));
            println!(
                "(short display form of the {characters}-character address — not valid for \
                 pasting; \"address --full\" prints it all, \"address --out <path>\" \
                 writes it to a file)"
            );
        }
    }
}

/// One-round-trip wallet summary over `get_wallet_info` (WI-RPC-4).
/// The REPL command is `wallet` (renamed from `engine_info`, CU-2; the old
/// name is a hidden alias).
pub fn cmd_wallet(rpc: &RpcSession) -> CommandResult {
    require_open(rpc)?;
    match rpc.call("get_wallet_info", json!({})) {
        Ok(val) => Ok(val),
        Err(e) => Err(rpc.report("Failed to get wallet info", &e)),
    }
}

/// The wallet's three block lines. `wallet_height` and `daemon_height` are
/// the contract's counts: each line names the block the count reaches, so a
/// synced wallet shows its daemon's block. `restore_height` is a block's own
/// number (`HEIGHT_SEMANTICS.md` §1).
///
/// A missing field is a malformed response, shown as `?`, not a zero: 0 is
/// a real value, and reading it for an absent field would report an
/// unsynced wallet to a person whose wallet may be synced.
fn block_lines(val: &Value) -> [String; 3] {
    let count = |name: &str| val.get(name).and_then(serde_json::Value::as_u64);
    [
        match count("wallet_height") {
            Some(n) => format!(
                "  Synced to block: {}",
                crate::display::block_of_count_text(n, "nothing scanned yet")
            ),
            None => "  Synced to block: ?".to_owned(),
        },
        match count("daemon_height") {
            Some(n) => format!(
                "  Daemon block:    {}",
                crate::display::block_of_count_text(n, "nothing yet")
            ),
            None => "  Daemon block:    unavailable".to_owned(),
        },
        format!(
            "  Restore from block: {}",
            count("restore_height").map_or_else(|| "?".to_owned(), |b| b.to_string())
        ),
    ]
}

pub(crate) fn show_wallet(val: &Value) {
    let s = |name: &str| val.get(name).and_then(|v| v.as_str()).unwrap_or("?");
    println!("Wallet: {}", s("name"));
    println!("  Network:         {}", s("network"));
    println!("  Capability:      {}", s("capability"));
    let addr = s("address");
    let shown = short_address(addr);
    println!("  Address:         {shown}");
    if shown != addr {
        println!("                   (display only; \"address --full\" prints it all)");
    }
    for line in block_lines(val) {
        println!("{line}");
    }
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

#[cfg(test)]
mod tests {
    use super::block_lines;
    use serde_json::json;

    /// A wallet that has scanned nothing names no block; the daemon's count
    /// of 100 is block 99. Red edit: print the counts as they arrive.
    #[test]
    fn an_unscanned_wallet_names_no_block() {
        let lines = block_lines(&json!({
            "wallet_height": 0, "daemon_height": 100, "restore_height": 0,
        }));
        assert_eq!(lines[0], "  Synced to block: nothing scanned yet");
        assert_eq!(lines[1], "  Daemon block:    99");
        assert_eq!(lines[2], "  Restore from block: 0");
    }

    /// A synced wallet's block is its daemon's: both counts are 100, and
    /// both lines name block 99.
    #[test]
    fn a_synced_wallet_names_its_daemon_s_block() {
        let lines = block_lines(&json!({
            "wallet_height": 100, "daemon_height": 100, "restore_height": 40,
        }));
        assert_eq!(lines[0], "  Synced to block: 99");
        assert_eq!(lines[1], "  Daemon block:    99");
        assert_eq!(lines[2], "  Restore from block: 40");
    }

    /// An unreachable daemon is `null`: unavailable, not a block.
    #[test]
    fn an_unreachable_daemon_is_unavailable() {
        let lines = block_lines(&json!({
            "wallet_height": 100, "daemon_height": null, "restore_height": 0,
        }));
        assert_eq!(lines[1], "  Daemon block:    unavailable");
    }
}
