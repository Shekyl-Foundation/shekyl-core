// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Payment-request and payment-URI commands over the WI-RPC-1 receiving
//! surface (WI-RPC-2b): `request new`, `requests list`, `make_uri`,
//! `parse_uri`.
//!
//! The payment request is Shekyl's receive-attribution primitive — an opaque
//! `rid` carried on the `shekyl:` URI — replacing the wallet2-era
//! account/subaddress model (rule 60; WI-RPC-1 pin 1).

use serde_json::{json, Value};
use shekyl_types::Timestamp;

use super::{format_amount, format_amount_str, opt_amount, require_open};
use crate::outcome::{failed, CommandResult};
use crate::rpc_client::RpcSession;

pub fn cmd_request_new(
    rpc: &RpcSession,
    amount: u64,
    label: &str,
    expiry: Option<Timestamp>,
) -> CommandResult {
    require_open(rpc)?;
    let mut params = json!({
        "label": label,
        "amount": amount.to_string(),
    });
    if let Some(ts) = expiry {
        // Timestamp is #[serde(transparent)] over u64 — the wire stays a
        // plain unix-seconds integer.
        params["expiry"] = json!(ts.to_raw());
    }
    match rpc.call("create_payment_request", params) {
        Ok(val) => {
            let id = val.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            let uri = val.get("uri").and_then(|v| v.as_str()).unwrap_or("?");
            println!("Payment request created.");
            println!("  Request id: {id}");
            println!("  Amount:     {} SKL", format_amount(amount));
            println!("  URI:        {uri}");
            println!("Share the URI with the payer; \"requests list\" tracks its state.");
        }
        Err(e) => return Err(rpc.report("Failed to create payment request", &e)),
    };
    Ok(())
}

pub fn cmd_requests_list(rpc: &RpcSession, filter: crate::resolve::RequestFilter) -> CommandResult {
    require_open(rpc)?;
    match rpc.call("list_payment_requests", json!({ "filter": filter.wire() })) {
        Ok(val) => {
            let requests = val.get("payment_requests").and_then(|v| v.as_array());
            let Some(requests) = requests.filter(|a| !a.is_empty()) else {
                println!("No payment requests.");
                return Ok(());
            };
            println!(
                "{:<16} {:<10} {:>18} {:>10}  Label",
                "Request id", "State", "Amount (SKL)", "Created"
            );
            for r in requests {
                print_request_row(r);
            }
        }
        Err(e) => return Err(rpc.report("Failed to list payment requests", &e)),
    };
    Ok(())
}

fn print_request_row(r: &Value) {
    let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("?");
    let state = r.get("state").and_then(|v| v.as_str()).unwrap_or("?");
    let amount = opt_amount(r, "amount");
    let created = r
        .get("created_at")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    // Free-form label: neutralize control chars so a crafted value cannot
    // inject terminal escape sequences.
    let label = crate::display::sanitize_for_terminal(
        r.get("label").and_then(|v| v.as_str()).unwrap_or(""),
    );
    println!("{id:<16} {state:<10} {amount:>18} {created:>10}  {label}");
    if let Some(tx) = r.get("matched_tx_hash").and_then(|v| v.as_str()) {
        println!("{:<16} matched by tx {tx}", "");
    }
    if let Some(expiry) = r.get("expiry").and_then(serde_json::Value::as_i64) {
        println!("{:<16} expires at unix {expiry}", "");
    }
}

pub fn cmd_make_uri(
    rpc: &RpcSession,
    address: Option<&str>,
    amount: Option<u64>,
    label: Option<&str>,
) -> CommandResult {
    require_open(rpc)?;
    let mut params = json!({});
    if let Some(a) = address {
        params["address"] = json!(a);
    }
    if let Some(v) = amount {
        params["amount"] = json!(v.to_string());
    }
    if let Some(l) = label {
        params["label"] = json!(l);
    }
    match rpc.call("make_uri", params) {
        Ok(val) => match val.get("uri").and_then(|v| v.as_str()) {
            Some(uri) => println!("{uri}"),
            None => {
                eprintln!("Malformed make_uri response.");
                return failed();
            }
        },
        Err(e) => return Err(rpc.report("Failed to make URI", &e)),
    };
    Ok(())
}

pub fn cmd_parse_uri(rpc: &RpcSession, uri: &str) -> CommandResult {
    require_open(rpc)?;
    match rpc.call("parse_uri", json!({ "uri": uri })) {
        Ok(val) => {
            // Every string field here is decoded from an attacker-controlled
            // URI, so neutralize control chars before printing.
            use crate::display::sanitize_for_terminal as safe;
            let address = val.get("address").and_then(|v| v.as_str()).unwrap_or("?");
            println!("Address: {}", safe(address));
            if let Some(amount) = val.get("amount").and_then(|v| v.as_str()) {
                println!("Amount:  {} SKL", safe(&format_amount_str(amount)));
            }
            if let Some(label) = val.get("label").and_then(|v| v.as_str()) {
                println!("Label:   {}", safe(label));
            }
            if let Some(rid) = val.get("rid").and_then(|v| v.as_str()) {
                println!("Request: {}", safe(rid));
            }
            if let Some(expiry) = val.get("expiry").and_then(serde_json::Value::as_i64) {
                println!("Expiry:  unix {expiry}");
            }
        }
        Err(e) => return Err(rpc.report("Failed to parse URI", &e)),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::resolve::RequestFilter;

    /// The CLI filter is the OpenAPI `PaymentRequestFilter` enum. A word
    /// outside that set cannot be represented.
    #[test]
    fn filters_map_onto_the_wire_enum() {
        assert_eq!(RequestFilter::Pending.wire(), "PENDING");
        assert_eq!(RequestFilter::Matched.wire(), "MATCHED");
        assert_eq!(RequestFilter::All.wire(), "ALL");
    }
}
