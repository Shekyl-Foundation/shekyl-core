// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Message signing commands: sign, verify.
//! Uses Shekyl-specific domain separation (ShekylMessageSignature).

use crate::wallet::WalletContext;

pub fn cmd_sign(ctx: &WalletContext, message: &str) {
    if !super::require_open(ctx) {
        return;
    }
    let params = serde_json::json!({ "data": message });
    match ctx.json_rpc("sign", &params.to_string()) {
        Ok(val) => {
            if let Some(sig) = val.get("signature").and_then(|s| s.as_str()) {
                println!("Signature: {sig}");
            } else {
                println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            }
        }
        Err(e) => eprintln!("Signing failed: {e}"),
    }
}

pub fn cmd_verify(ctx: &WalletContext, address: &str, message: &str, signature: &str) {
    if !super::require_open(ctx) {
        return;
    }
    let params = serde_json::json!({
        "data": message,
        "address": address,
        "signature": signature,
    });
    match ctx.json_rpc("verify", &params.to_string()) {
        Ok(val) => {
            let good = val.get("good").and_then(|g| g.as_bool()).unwrap_or(false);
            if good {
                println!("Signature VALID.");
            } else {
                println!("Signature INVALID.");
            }
        }
        Err(e) => eprintln!("Verification failed: {e}"),
    }
}

pub fn cmd_version() {
    println!("shekyl-cli {}", env!("CARGO_PKG_VERSION"));
}

pub fn cmd_wallet_info(ctx: &WalletContext) {
    if !super::require_open(ctx) {
        return;
    }

    let height = ctx.get_height();
    println!("Wallet info:");
    println!("  Height: {height}");

    if let Ok(val) = ctx.get_address(0) {
        if let Some(addr) = val.get("address").and_then(|a| a.as_str()) {
            let truncated = if addr.len() > 16 {
                format!("{}...{}", &addr[..8], &addr[addr.len() - 8..])
            } else {
                addr.to_string()
            };
            println!("  Primary address: {truncated}");
        }
    }

    if let Ok(val) = ctx.json_rpc("get_accounts", "{}") {
        if let Some(accts) = val.get("subaddress_accounts").and_then(|a| a.as_array()) {
            println!("  Accounts: {}", accts.len());
        }
    }
}
