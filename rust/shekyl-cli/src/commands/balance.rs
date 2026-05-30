// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Balance and address commands.

use crate::engine::EngineContext;

pub fn cmd_address(ctx: &EngineContext, account_index: u32) {
    if !super::require_open(ctx) {
        return;
    }
    match ctx.get_address(account_index) {
        Ok(val) => {
            if let Some(addr) = val.get("address").and_then(|a| a.as_str()) {
                println!("Primary address: {addr}");
            } else {
                println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            }
        }
        Err(e) => eprintln!("Failed to get address: {e}"),
    }
}

pub fn cmd_balance(ctx: &EngineContext, account_index: u32) {
    if !super::require_open(ctx) {
        return;
    }
    match ctx.get_balance(account_index) {
        Ok(val) => {
            let balance = val.get("balance").and_then(|v| v.as_u64()).unwrap_or(0);
            let unlocked = val
                .get("unlocked_balance")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            println!("Balance:          {} SKL", super::format_amount(balance));
            println!("Unlocked balance: {} SKL", super::format_amount(unlocked));
        }
        Err(e) => eprintln!("Failed to get balance: {e}"),
    }
}
