// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transaction proof commands via json_rpc pass-through.

use crate::engine::EngineContext;

pub fn cmd_get_tx_key(ctx: &EngineContext, txid: &str) {
    if !super::require_open(ctx) {
        return;
    }
    let params = serde_json::json!({ "txid": txid });
    match ctx.json_rpc("get_tx_key", &params.to_string()) {
        Ok(val) => {
            if let Some(key) = val.get("tx_key").and_then(|k| k.as_str()) {
                println!("Tx key: {key}");
            } else {
                println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            }
        }
        Err(e) => eprintln!("Failed to get tx key: {e}"),
    }
}

pub fn cmd_check_tx_key(ctx: &EngineContext, txid: &str, tx_key: &str, address: &str) {
    if !super::require_open(ctx) {
        return;
    }
    let params = serde_json::json!({
        "txid": txid,
        "tx_key": tx_key,
        "address": address,
    });
    match ctx.json_rpc("check_tx_key", &params.to_string()) {
        Ok(val) => {
            let received = val.get("received").and_then(|r| r.as_u64()).unwrap_or(0);
            let confirmations = val
                .get("confirmations")
                .and_then(|c| c.as_u64())
                .unwrap_or(0);
            let in_pool = val
                .get("in_pool")
                .and_then(|p| p.as_bool())
                .unwrap_or(false);
            println!("Received: {} SKL", super::format_amount(received));
            if in_pool {
                println!("Status: in pool (unconfirmed)");
            } else {
                println!("Confirmations: {confirmations}");
            }
        }
        Err(e) => eprintln!("Check failed: {e}"),
    }
}

pub fn cmd_get_tx_proof(ctx: &EngineContext, txid: &str, address: &str, message: Option<&str>) {
    if !super::require_open(ctx) {
        return;
    }
    let mut params = serde_json::json!({
        "txid": txid,
        "address": address,
    });
    if let Some(msg) = message {
        params["message"] = serde_json::Value::String(msg.to_string());
    }
    match ctx.json_rpc("get_tx_proof", &params.to_string()) {
        Ok(val) => {
            if let Some(sig) = val.get("signature").and_then(|s| s.as_str()) {
                println!("Proof: {sig}");
            } else {
                println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            }
        }
        Err(e) => eprintln!("Failed to generate proof: {e}"),
    }
}

pub fn cmd_check_tx_proof(
    ctx: &EngineContext,
    txid: &str,
    address: &str,
    signature: &str,
    message: Option<&str>,
) {
    if !super::require_open(ctx) {
        return;
    }
    let mut params = serde_json::json!({
        "txid": txid,
        "address": address,
        "signature": signature,
    });
    if let Some(msg) = message {
        params["message"] = serde_json::Value::String(msg.to_string());
    }
    match ctx.json_rpc("check_tx_proof", &params.to_string()) {
        Ok(val) => {
            let good = val.get("good").and_then(|g| g.as_bool()).unwrap_or(false);
            if good {
                let received = val.get("received").and_then(|r| r.as_u64()).unwrap_or(0);
                let confirmations = val
                    .get("confirmations")
                    .and_then(|c| c.as_u64())
                    .unwrap_or(0);
                println!(
                    "Proof VALID. Received: {} SKL, Confirmations: {confirmations}",
                    super::format_amount(received)
                );
            } else {
                println!("Proof INVALID.");
            }
        }
        Err(e) => eprintln!("Check failed: {e}"),
    }
}

pub fn cmd_get_reserve_proof(
    ctx: &EngineContext,
    account_index: u32,
    amount: Option<u64>,
    message: Option<&str>,
) {
    if !super::require_open(ctx) {
        return;
    }
    let all = amount.is_none();
    let mut params = serde_json::json!({
        "all": all,
        "account_index": account_index,
    });
    if let Some(amt) = amount {
        params["amount"] = serde_json::Value::Number(amt.into());
    }
    if let Some(msg) = message {
        params["message"] = serde_json::Value::String(msg.to_string());
    }
    match ctx.json_rpc("get_reserve_proof", &params.to_string()) {
        Ok(val) => {
            if let Some(sig) = val.get("signature").and_then(|s| s.as_str()) {
                println!("Reserve proof: {sig}");
            } else {
                println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            }
        }
        Err(e) => eprintln!("Failed to generate reserve proof: {e}"),
    }
}

pub fn cmd_check_reserve_proof(
    ctx: &EngineContext,
    address: &str,
    signature: &str,
    message: Option<&str>,
) {
    if !super::require_open(ctx) {
        return;
    }
    let mut params = serde_json::json!({
        "address": address,
        "signature": signature,
    });
    if let Some(msg) = message {
        params["message"] = serde_json::Value::String(msg.to_string());
    }
    match ctx.json_rpc("check_reserve_proof", &params.to_string()) {
        Ok(val) => {
            let good = val.get("good").and_then(|g| g.as_bool()).unwrap_or(false);
            if good {
                let total = val.get("total").and_then(|t| t.as_u64()).unwrap_or(0);
                let spent = val.get("spent").and_then(|s| s.as_u64()).unwrap_or(0);
                println!("Reserve proof VALID.");
                println!(
                    "  Total: {} SKL, Spent: {} SKL",
                    super::format_amount(total),
                    super::format_amount(spent)
                );
            } else {
                println!("Reserve proof INVALID.");
            }
        }
        Err(e) => eprintln!("Check failed: {e}"),
    }
}
