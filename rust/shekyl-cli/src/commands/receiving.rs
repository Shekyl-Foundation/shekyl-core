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

use super::{format_amount, format_amount_str, require_open};
use crate::rpc_client::RpcSession;

pub fn cmd_request_new(rpc: &RpcSession, amount: u64, label: &str, expiry: Option<u64>) {
    if !require_open(rpc) {
        return;
    }
    let mut params = json!({
        "label": label,
        "amount": amount.to_string(),
    });
    if let Some(h) = expiry {
        params["expiry"] = json!(h);
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
        Err(e) => rpc.report("Failed to create payment request", &e),
    }
}

/// Map the CLI filter word onto the wire enum. Defaults to `ALL`.
fn filter_param(filter: Option<&str>) -> Result<&'static str, String> {
    match filter {
        None | Some("all") => Ok("ALL"),
        Some("pending") => Ok("PENDING"),
        Some("matched") => Ok("MATCHED"),
        Some(other) => Err(format!(
            "unknown filter {other:?}: expected pending, matched, or all"
        )),
    }
}

pub fn cmd_requests_list(rpc: &RpcSession, filter: Option<&str>) {
    if !require_open(rpc) {
        return;
    }
    let wire_filter = match filter_param(filter) {
        Ok(f) => f,
        Err(msg) => {
            eprintln!("requests list: {msg}");
            return;
        }
    };
    match rpc.call("list_payment_requests", json!({ "filter": wire_filter })) {
        Ok(val) => {
            let requests = val
                .get("payment_requests")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if requests.is_empty() {
                println!("No payment requests.");
                return;
            }
            println!(
                "{:<16} {:<10} {:>18} {:>10}  Label",
                "Request id", "State", "Amount (SKL)", "Created"
            );
            for r in &requests {
                print_request_row(r);
            }
        }
        Err(e) => rpc.report("Failed to list payment requests", &e),
    }
}

fn print_request_row(r: &Value) {
    let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("?");
    let state = r.get("state").and_then(|v| v.as_str()).unwrap_or("?");
    let amount = r
        .get("amount")
        .and_then(|v| v.as_str())
        .map(format_amount_str)
        .unwrap_or_else(|| "?".to_owned());
    let created = r.get("created_at").and_then(|v| v.as_i64()).unwrap_or(0);
    let label = r.get("label").and_then(|v| v.as_str()).unwrap_or("");
    println!("{id:<16} {state:<10} {amount:>18} {created:>10}  {label}");
    if let Some(tx) = r.get("matched_tx_hash").and_then(|v| v.as_str()) {
        println!("{:<16} matched by tx {tx}", "");
    }
    if let Some(expiry) = r.get("expiry").and_then(|v| v.as_i64()) {
        println!("{:<16} expires at height {expiry}", "");
    }
}

pub fn cmd_make_uri(
    rpc: &RpcSession,
    address: Option<&str>,
    amount: Option<u64>,
    label: Option<&str>,
) {
    if !require_open(rpc) {
        return;
    }
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
            None => eprintln!("Malformed make_uri response."),
        },
        Err(e) => rpc.report("Failed to make URI", &e),
    }
}

pub fn cmd_parse_uri(rpc: &RpcSession, uri: &str) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("parse_uri", json!({ "uri": uri })) {
        Ok(val) => {
            let address = val.get("address").and_then(|v| v.as_str()).unwrap_or("?");
            println!("Address: {address}");
            if let Some(amount) = val.get("amount").and_then(|v| v.as_str()) {
                println!("Amount:  {} SKL", format_amount_str(amount));
            }
            if let Some(label) = val.get("label").and_then(|v| v.as_str()) {
                println!("Label:   {label}");
            }
            if let Some(rid) = val.get("rid").and_then(|v| v.as_str()) {
                println!("Request: {rid}");
            }
            if let Some(expiry) = val.get("expiry").and_then(|v| v.as_i64()) {
                println!("Expiry:  height {expiry}");
            }
        }
        Err(e) => rpc.report("Failed to parse URI", &e),
    }
}

#[cfg(test)]
mod tests {
    use super::filter_param;

    /// CLI filter words map onto the OpenAPI `PaymentRequestFilter` enum;
    /// anything else refuses client-side without an RPC round-trip.
    #[test]
    fn filter_words_map_onto_the_wire_enum() {
        assert_eq!(filter_param(None).unwrap(), "ALL");
        assert_eq!(filter_param(Some("all")).unwrap(), "ALL");
        assert_eq!(filter_param(Some("pending")).unwrap(), "PENDING");
        assert_eq!(filter_param(Some("matched")).unwrap(), "MATCHED");
        assert!(filter_param(Some("bogus")).is_err());
    }
}
