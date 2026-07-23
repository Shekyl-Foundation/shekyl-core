// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fee display over the WI-RPC-1 fee surface (WI-RPC-2b): `fee`.
//!
//! Shows the daemon-quoted fee for each named tier plus the size/weight
//! estimate for a given transaction shape (default: the canonical
//! 2-in/2-out transfer). Principal send surface only — P-attributed
//! transactions use canonical fees with no user-facing choice
//! (`wallet_rpc.yaml` P-lane pin).

use serde_json::json;

use super::{format_amount_str, require_open};
use crate::rpc_client::RpcSession;

pub fn cmd_fee(rpc: &RpcSession, n_inputs: Option<i64>, n_outputs: Option<i64>) {
    if !require_open(rpc) {
        return;
    }

    let mut params = json!({});
    if let Some(n) = n_inputs {
        params["n_inputs"] = json!(n);
    }
    if let Some(n) = n_outputs {
        params["n_outputs"] = json!(n);
    }

    let quotes = match rpc.call("get_default_fee_priority", params) {
        Ok(v) => v,
        Err(e) => {
            rpc.report("Failed to get fee quotes", &e);
            return;
        }
    };

    let shape_in = n_inputs.unwrap_or(2);
    let shape_out = n_outputs.unwrap_or(2);
    println!("Fee quotes for a {shape_in}-input, {shape_out}-output transaction:");

    let tier = |name: &str| {
        quotes
            .get(name)
            .and_then(|v| v.as_str())
            .map(format_amount_str)
            .unwrap_or_else(|| "?".to_owned())
    };
    let default_tier = quotes
        .get("default_priority")
        .and_then(|v| v.as_str())
        .unwrap_or("STANDARD");
    for (label, field) in [
        ("ECONOMY", "economy_fee"),
        ("STANDARD", "standard_fee"),
        ("PRIORITY", "priority_fee"),
    ] {
        let marker = if label == default_tier {
            " (default)"
        } else {
            ""
        };
        println!("  {label:<9} {} SKL{marker}", tier(field));
    }

    // Size/weight for the same shape (fee omitted: floor estimate within
    // 9 bytes of exact per the contract).
    match rpc.call(
        "estimate_tx_size_and_weight",
        json!({ "n_inputs": shape_in, "n_outputs": shape_out }),
    ) {
        Ok(est) => {
            let size = est.get("size").and_then(|v| v.as_i64()).unwrap_or(0);
            let weight = est.get("weight").and_then(|v| v.as_i64()).unwrap_or(0);
            println!("Estimated size: {size} bytes (fee weight {weight})");
        }
        Err(e) => rpc.report("Failed to estimate transaction size", &e),
    }
}
