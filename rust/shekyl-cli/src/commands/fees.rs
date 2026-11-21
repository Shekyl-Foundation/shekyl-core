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

use serde_json::{json, Value};

use super::{opt_amount, require_open};
use crate::outcome::CommandResult;
use crate::rpc_client::RpcSession;

pub fn cmd_fee(rpc: &RpcSession, n_inputs: Option<i64>, n_outputs: Option<i64>) -> CommandResult {
    require_open(rpc)?;

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
            return Err(rpc.report("Failed to get fee quotes", &e));
        }
    };

    let shape_in = n_inputs.unwrap_or(2);
    let shape_out = n_outputs.unwrap_or(2);

    // Size/weight for the same shape (fee omitted: floor estimate within
    // 9 bytes of exact per the contract).
    let estimate = match rpc.call(
        "estimate_tx_size_and_weight",
        json!({ "n_inputs": shape_in, "n_outputs": shape_out }),
    ) {
        Ok(est) => est,
        Err(e) => return Err(rpc.report("Failed to estimate transaction size", &e)),
    };
    Ok(json!({
        "n_inputs": shape_in,
        "n_outputs": shape_out,
        "quotes": quotes,
        "estimate": estimate,
    }))
}

pub(crate) fn show_fee(val: &Value) {
    let shape_in = val.get("n_inputs").and_then(Value::as_i64).unwrap_or(2);
    let shape_out = val.get("n_outputs").and_then(Value::as_i64).unwrap_or(2);
    let quotes = val.get("quotes").cloned().unwrap_or(json!({}));
    crate::out_line!("Fee quotes for a {shape_in}-input, {shape_out}-output transaction:");

    // The tier `send` uses when `--priority` names none.
    let default_tier = shekyl_economics::FeePriority::default().name();
    for name in shekyl_economics::FeePriority::NAMES {
        let marker = if name == default_tier {
            " (default)"
        } else {
            ""
        };
        crate::out_line!("  {name:<9} {} SKL{marker}", opt_amount(&quotes, name));
    }

    let est = val.get("estimate").cloned().unwrap_or(json!({}));
    let size = est.get("size").and_then(Value::as_i64).unwrap_or(0);
    let weight = est.get("weight").and_then(Value::as_i64).unwrap_or(0);
    crate::out_line!("Estimated size: {size} bytes (fee weight {weight})");
}
