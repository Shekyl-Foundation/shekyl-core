// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transfer commands: transfer, transfers (list), show_transfer, sweep_all.

use crate::wallet::WalletContext;

pub fn cmd_transfer(ctx: &WalletContext, args: &[&str], account_index: u32) {
    if !super::require_open(ctx) {
        return;
    }
    if args.len() < 2 {
        eprintln!("Usage: transfer <amount> <address>");
        return;
    }

    let amount_str = args[0];
    let address = args[1];

    let atomic = match super::parse_amount(amount_str) {
        Some(a) => a,
        None => {
            eprintln!("Invalid amount: {amount_str}. Use decimal SKL (e.g. 1.5).");
            return;
        }
    };

    let destinations = serde_json::json!([{
        "amount": atomic,
        "address": address
    }]);

    println!("Sending {} SKL to {address}...", super::format_amount(atomic));

    match ctx.transfer(&destinations.to_string(), 0, account_index) {
        Ok(val) => {
            if let Some(tx_hash) = val.get("tx_hash").and_then(|h| h.as_str()) {
                println!("Transaction sent: {tx_hash}");
            } else if let Some(tx_hash_list) = val.get("tx_hash_list").and_then(|l| l.as_array()) {
                for h in tx_hash_list {
                    if let Some(hash) = h.as_str() {
                        println!("Transaction sent: {hash}");
                    }
                }
            } else {
                println!("Transfer submitted.");
                println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            }
        }
        Err(e) => eprintln!("Transfer failed: {e}"),
    }
}

pub fn cmd_transfers(ctx: &WalletContext, account_index: u32) {
    if !super::require_open(ctx) {
        return;
    }
    match ctx.get_transfers(true, true, true, false, false, account_index) {
        Ok(val) => {
            let mut found = false;
            for direction in &["in", "out", "pending"] {
                if let Some(txs) = val.get(direction).and_then(|v| v.as_array()) {
                    for tx in txs {
                        found = true;
                        let amount = tx.get("amount").and_then(|a| a.as_u64()).unwrap_or(0);
                        let height = tx.get("height").and_then(|h| h.as_u64()).unwrap_or(0);
                        let txid = tx.get("txid").and_then(|t| t.as_str()).unwrap_or("?");
                        println!(
                            "  [{direction:>7}] height={height:<8} amount={:<14} tx={txid}",
                            super::format_amount(amount)
                        );
                    }
                }
            }
            if !found {
                println!("No transactions found.");
            }
        }
        Err(e) => eprintln!("Failed to get transfers: {e}"),
    }
}

pub fn cmd_show_transfer(ctx: &WalletContext, txid: &str) {
    if !super::require_open(ctx) {
        return;
    }
    let params = serde_json::json!({ "txid": txid });
    match ctx.json_rpc("get_transfer_by_txid", &params.to_string()) {
        Ok(val) => {
            if let Some(transfer) = val.get("transfer") {
                println!("{}", serde_json::to_string_pretty(transfer).unwrap_or_default());
            } else {
                println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            }
        }
        Err(e) => eprintln!("Failed to get transfer: {e}"),
    }
}

pub fn cmd_sweep_all(
    ctx: &WalletContext,
    account_index: u32,
    subaddr_indices: &[u32],
    dest: &str,
    priority: Option<u32>,
) {
    if !super::require_open(ctx) {
        return;
    }

    eprintln!(
        "WARNING: Sweeping all outputs to a single address reveals that all\n\
         listed outputs belong to one wallet. This creates strong on-chain linkage."
    );

    match ctx.get_balance(account_index) {
        Ok(val) => {
            let balance = val.get("unlocked_balance").and_then(|b| b.as_u64()).unwrap_or(0);
            let amount_str = super::format_amount(balance);
            println!("Will sweep approximately {} SKL from account {account_index}.", amount_str);

            let addr_match = match ctx.get_address(account_index) {
                Ok(addr_val) => {
                    let own_addr = addr_val.get("address").and_then(|a| a.as_str()).unwrap_or("");
                    dest.starts_with(&own_addr[..8.min(own_addr.len())])
                }
                Err(_) => false,
            };
            if !addr_match {
                eprintln!("Destination is an external address. This will link your entire balance to that address on-chain.");
            }

            let prompt = format!("Type the total amount in SKL to confirm ({amount_str}): ");
            if !super::confirm_dangerous(&prompt, &amount_str) {
                println!("Cancelled.");
                return;
            }
        }
        Err(e) => {
            eprintln!("Failed to get balance: {e}");
            return;
        }
    }

    let mut params = serde_json::json!({
        "address": dest,
        "account_index": account_index,
    });
    if !subaddr_indices.is_empty() {
        params["subaddr_indices"] = serde_json::json!(subaddr_indices);
    }
    if let Some(p) = priority {
        params["priority"] = serde_json::json!(p);
    }

    match ctx.json_rpc("sweep_all", &params.to_string()) {
        Ok(val) => {
            if let Some(hashes) = val.get("tx_hash_list").and_then(|l| l.as_array()) {
                for h in hashes {
                    if let Some(hash) = h.as_str() {
                        println!("Swept: {hash}");
                    }
                }
            } else {
                println!("Sweep submitted.");
                println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            }
        }
        Err(e) => eprintln!("Sweep failed: {e}"),
    }
}
