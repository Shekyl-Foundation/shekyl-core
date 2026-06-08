// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Payment-request CLI stubs (FA-8d minimal V3.0).

use crate::engine::EngineContext;

pub fn cmd_request_new(ctx: &EngineContext, amount: u64, label: &str) {
    if !super::require_open(ctx) {
        return;
    }
    let params = serde_json::json!({
        "amount": amount,
        "label": label,
    })
    .to_string();
    match ctx.json_rpc("create_payment_request", &params) {
        Ok(val) => println!("{}", val),
        Err(e) => eprintln!("create_payment_request RPC not available (FA-8 stub): {e}"),
    }
}

pub fn cmd_requests_list(ctx: &EngineContext) {
    if !super::require_open(ctx) {
        return;
    }
    match ctx.json_rpc("list_payment_requests", "{}") {
        Ok(val) => println!("{}", val),
        Err(e) => eprintln!("list_payment_requests RPC not available (FA-8 stub): {e}"),
    }
}

pub fn cmd_history_incoming_unattributed(ctx: &EngineContext, account_index: u32) {
    if !super::require_open(ctx) {
        return;
    }
    let params = serde_json::json!({
        "account_index": account_index,
        "unattributed_only": true,
    })
    .to_string();
    match ctx.json_rpc("incoming_transfers", &params) {
        Ok(val) => println!("{}", val),
        Err(e) => eprintln!("incoming_transfers (unattributed filter) not available: {e}"),
    }
}
