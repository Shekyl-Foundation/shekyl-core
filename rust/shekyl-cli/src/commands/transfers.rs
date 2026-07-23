// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transfer commands over the native RPC surface (WI-RPC-2a).
//!
//! The send flow follows the wallet-RPC three-phase contract:
//! `build_pending_tx` (funds reserved) → CLI-side confirmation showing the
//! actual fee → `submit_pending_tx` on an explicit "yes", or
//! `discard_pending_tx` on anything else. Confirmation lives here, not in
//! the server (rewrite-plan pin: the RPC surface is UI-free).

use serde_json::{json, Value};

use super::{confirm, format_amount, format_amount_str, require_open};
use crate::rpc_client::RpcSession;

/// Map the wallet2-era numeric `--priority N` flag onto the wallet-RPC
/// named tiers: 0-1 → ECONOMY, 2 (and unset) → STANDARD, 3+ → PRIORITY.
pub(crate) fn priority_tier(priority: Option<u32>) -> &'static str {
    match priority {
        None | Some(2) => "STANDARD",
        Some(0 | 1) => "ECONOMY",
        Some(_) => "PRIORITY",
    }
}

pub fn cmd_transfer(
    rpc: &RpcSession,
    amount: u64,
    dest: &str,
    priority: Option<u32>,
    no_confirm: bool,
) {
    if !require_open(rpc) {
        return;
    }

    let built = match rpc.call(
        "build_pending_tx",
        json!({
            "recipients": [{ "address": dest, "amount": amount.to_string() }],
            "priority": priority_tier(priority),
        }),
    ) {
        Ok(v) => v,
        Err(e) => {
            rpc.report("Failed to build transaction", &e);
            return;
        }
    };

    let Some(pending_tx_id) = built
        .get("pending_tx_id")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
    else {
        eprintln!("Malformed build_pending_tx response (missing pending_tx_id).");
        return;
    };
    let seen_gen = built
        .get("content_gen")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let fee = built
        .get("fee")
        .and_then(|v| v.as_str())
        .map(format_amount_str)
        .unwrap_or_else(|| "?".to_owned());

    println!("Transaction summary:");
    println!("  To:     {dest}");
    println!("  Amount: {} SKL", format_amount(amount));
    println!("  Fee:    {fee} SKL");

    let accepted = if no_confirm {
        if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            eprintln!("--no-confirm is only honored for non-interactive input; confirming.");
            confirm("Send this transaction?")
        } else {
            true
        }
    } else {
        confirm("Send this transaction?")
    };

    if !accepted {
        match rpc.call(
            "discard_pending_tx",
            json!({ "pending_tx_id": pending_tx_id }),
        ) {
            Ok(_) => println!("Transaction discarded."),
            Err(e) => rpc.report("Failed to discard pending transaction", &e),
        }
        return;
    }

    match rpc.call(
        "submit_pending_tx",
        json!({ "pending_tx_id": pending_tx_id, "seen_gen": seen_gen }),
    ) {
        Ok(val) => {
            let tx_hash = val.get("tx_hash").and_then(|v| v.as_str()).unwrap_or("?");
            println!("Transaction submitted: {tx_hash}");
        }
        Err(e) => rpc.report("Failed to submit transaction", &e),
    }
}

pub fn cmd_transfers(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("get_transfers", json!({})) {
        Ok(val) => {
            let transfers = val
                .get("transfers")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if transfers.is_empty() {
                println!("No transfers.");
                return;
            }
            println!(
                "{:<10} {:<10} {:>18} {:>10}  TxID",
                "Direction", "State", "Amount (SKL)", "Height"
            );
            for t in &transfers {
                print_transfer_row(t);
            }
        }
        Err(e) => rpc.report("Failed to get transfers", &e),
    }
}

fn print_transfer_row(t: &Value) {
    let s = |name: &str| t.get(name).and_then(|v| v.as_str()).unwrap_or("?");
    let direction = s("direction");
    let state = s("state");
    let amount = format_amount_str(s("amount"));
    let height = t.get("block_height").and_then(|v| v.as_i64()).unwrap_or(0);
    let tx_hash = s("tx_hash");
    println!("{direction:<10} {state:<10} {amount:>18} {height:>10}  {tx_hash}");
}

pub fn cmd_show_transfer(rpc: &RpcSession, id: &str) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("get_transfer_by_id", json!({ "id": id })) {
        Ok(val) => {
            let Some(t) = val.get("transfer") else {
                eprintln!("Malformed get_transfer_by_id response.");
                return;
            };
            let s = |name: &str| t.get(name).and_then(|v| v.as_str()).unwrap_or("?");
            println!("Transfer {}:", s("id"));
            println!("  Direction: {}", s("direction"));
            println!("  State:     {}", s("state"));
            println!("  TxID:      {}", s("tx_hash"));
            println!("  Amount:    {} SKL", format_amount_str(s("amount")));
            println!("  Fee:       {} SKL", format_amount_str(s("fee")));
            println!(
                "  Height:    {}",
                t.get("block_height").and_then(|v| v.as_i64()).unwrap_or(0)
            );
            if let Some(spent) = t.get("spent_height").and_then(|v| v.as_i64()) {
                println!("  Spent at:  {spent}");
            }
        }
        Err(e) => rpc.report("Failed to get transfer", &e),
    }
}

#[cfg(test)]
mod tests {
    use super::priority_tier;

    /// The named tiers are the OpenAPI `FeePriority` enum values; the
    /// default (no flag) is the server's documented STANDARD default.
    #[test]
    fn priority_flag_maps_onto_named_tiers() {
        assert_eq!(priority_tier(None), "STANDARD");
        assert_eq!(priority_tier(Some(0)), "ECONOMY");
        assert_eq!(priority_tier(Some(1)), "ECONOMY");
        assert_eq!(priority_tier(Some(2)), "STANDARD");
        assert_eq!(priority_tier(Some(3)), "PRIORITY");
        assert_eq!(priority_tier(Some(9)), "PRIORITY");
    }
}
