// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transaction- and reserve-proof commands over the WI-RPC-3 surface:
//! `get_tx_proof`, `check_tx_proof`, `get_reserve_proof`,
//! `check_reserve_proof`.
//!
//! The `get_*` pair needs an open wallet (the prover). The `check_*`
//! pair is WALLET-LESS by contract — a verifier checks someone else's
//! proof against the chain — so those commands deliberately skip
//! `require_open` and work in a walletless session.
//!
//! Disclosure warnings mirror the contract's DISCLOSURE SEMANTICS
//! block: an OUTBOUND tx proof carries the raw per-tx key (tx-wide
//! disclosure; any holder can re-sign a fresh proof for the same tx),
//! and a reserve proof publishes the key images of live outputs (a
//! permanent spend-detection beacon for anyone who ever sees the
//! string). The CLI is the last surface before the user shares the
//! artifact, so the warnings print at generation time, through
//! [`Presentation::disclose`](crate::outcome::Presentation::disclose):
//! with the human proof on stdout, and on stderr when stdout is the
//! JSON transcript. They are not narration, so a script still prints them.

use serde_json::{json, Value};

use super::{format_amount, format_amount_str, opt_amount, require_open};
use crate::outcome::CommandResult;
use crate::rpc_client::RpcSession;

// ── Generation (open wallet required) ────────────────────────────────

pub fn cmd_get_tx_proof(
    rpc: &RpcSession,
    txid: &str,
    address: &str,
    message: Option<&str>,
) -> CommandResult {
    require_open(rpc)?;
    let result = rpc.call(
        "get_tx_proof",
        json!({
            "txid": txid,
            "address": address,
            "message": message.unwrap_or(""),
        }),
    );
    match result {
        Ok(val) => Ok(val),
        Err(e) => Err(rpc.report("Failed to generate tx proof", &e)),
    }
}

const OUTBOUND_TX_PROOF_DISCLOSURE: &str = "\
Warning: an OUTBOUND proof reveals this transaction's key. Any \
holder of the string can verify every output of the transaction \
and re-sign a proof for it under a new message. Share it only \
with the intended verifier.";

const INBOUND_TX_PROOF_DISCLOSURE: &str = "\
Note: an INBOUND proof reveals the amounts of your received \
outputs in this transaction to whoever holds the string.";

/// The sharing warning for a generated payment proof, when the direction
/// is one the contract defines. The human formatter does not print this:
/// [`crate::outcome::present`] skips formatters in JSON mode, and the
/// warning has to reach that mode too.
pub(crate) fn tx_proof_disclosure(val: &Value) -> Option<&'static str> {
    match val.get("direction").and_then(|v| v.as_str()) {
        Some("OUTBOUND") => Some(OUTBOUND_TX_PROOF_DISCLOSURE),
        Some("INBOUND") => Some(INBOUND_TX_PROOF_DISCLOSURE),
        _ => None,
    }
}

pub(crate) fn show_tx_proof(val: &Value) {
    let direction = val.get("direction").and_then(|v| v.as_str()).unwrap_or("?");
    let proof = val.get("proof").and_then(|v| v.as_str()).unwrap_or("");
    println!("Direction: {direction}");
    println!("{proof}");
}

pub fn cmd_get_reserve_proof(
    rpc: &RpcSession,
    amount: Option<u64>,
    message: Option<&str>,
) -> CommandResult {
    require_open(rpc)?;
    // Echo the parse-time binding before generating anything. The
    // `[amount] [message...]` grammar reads an amount-shaped first token as
    // the proof bound, so `get_reserve_proof 2026 budget review` proves
    // 2026 SKL with message "budget review" — not the full balance with
    // message "2026 budget review". Showing the bound amount and the exact
    // challenge message here makes a misbind visible at generation time; at
    // check time it would only surface as an inexplicable BAD proof
    // (rule 82).
    let binding = describe_reserve_binding(amount, message);
    let mut params = json!({ "message": message.unwrap_or("") });
    if let Some(a) = amount {
        params["amount"] = Value::String(a.to_string());
    }
    match rpc.call("get_reserve_proof", params) {
        Ok(mut val) => {
            if let Some(object) = val.as_object_mut() {
                object.insert("binding".to_owned(), json!(binding));
            }
            Ok(val)
        }
        Err(e) => Err(rpc.report("Failed to generate reserve proof", &e)),
    }
}

pub(crate) fn show_reserve_proof(val: &Value) {
    if let Some(binding) = val.get("binding").and_then(|v| v.as_str()) {
        println!("{binding}");
    }
    let proof = val.get("proof").and_then(|v| v.as_str()).unwrap_or("");
    let total = opt_amount(val, "total");
    let count = val.get("output_count").and_then(Value::as_u64).unwrap_or(0);
    println!("Proved reserve: {total} SKL across {count} output(s)");
    println!("{proof}");
}

/// Sharing warning for a generated reserve proof. Same channel as
/// [`tx_proof_disclosure`]: not part of the JSON result, and not skipped
/// when the transcript is a script.
pub(crate) const RESERVE_PROOF_DISCLOSURE: &str = "\
Warning: a reserve proof reveals the amounts AND key images of the \
proven outputs. Anyone who ever sees this string can detect the exact \
moment each proven output is spent, forever. Share it only with the \
intended verifier, and prefer an amount-bounded proof \
(\"prove reserve <amount>\") over proving the full balance.";

// ── Verification (wallet-less) ───────────────────────────────────────

pub fn cmd_check_tx_proof(
    rpc: &RpcSession,
    txid: &str,
    address: &str,
    proof: &str,
    message: Option<&str>,
) -> CommandResult {
    let result = rpc.call(
        "check_tx_proof",
        json!({
            "txid": txid,
            "address": address,
            "proof": proof,
            "message": message.unwrap_or(""),
        }),
    );
    match result {
        Ok(val) => Ok(val),
        Err(e) => Err(rpc.report("Failed to check tx proof", &e)),
    }
}

pub(crate) fn show_tx_check(val: &Value) {
    let valid = val.get("valid").and_then(Value::as_bool).unwrap_or(false);
    if !valid {
        println!("BAD proof: the proof does NOT verify for this txid/address/message.");
        return;
    }
    let direction = val.get("direction").and_then(|v| v.as_str()).unwrap_or("?");
    println!("Good proof ({direction}).");
    println!(
        "Received by the address: {} SKL",
        opt_amount(val, "received")
    );
    if let Some(outputs) = val.get("outputs").and_then(|v| v.as_array()) {
        for out in outputs {
            let idx = out.get("output_index").and_then(Value::as_u64).unwrap_or(0);
            println!("  output {idx}: {} SKL", opt_amount(out, "amount"));
        }
    }
    print_confirmations(val);
}

pub fn cmd_check_reserve_proof(
    rpc: &RpcSession,
    address: &str,
    proof: &str,
    message: Option<&str>,
) -> CommandResult {
    let result = rpc.call(
        "check_reserve_proof",
        json!({
            "address": address,
            "proof": proof,
            "message": message.unwrap_or(""),
        }),
    );
    match result {
        Ok(val) => Ok(val),
        Err(e) => Err(rpc.report("Failed to check reserve proof", &e)),
    }
}

pub(crate) fn show_reserve_check(val: &Value) {
    let valid = val.get("valid").and_then(Value::as_bool).unwrap_or(false);
    if !valid {
        println!("BAD proof: the proof does NOT verify for this address/message.");
        return;
    }
    let count = val.get("output_count").and_then(Value::as_u64).unwrap_or(0);
    println!("Good proof ({count} output(s)).");
    println!("Total proven:  {} SKL", opt_amount(val, "total"));
    println!("Since spent:   {} SKL", opt_amount(val, "spent"));
    if let (Some(total), Some(spent)) = (raw_amount(val, "total"), raw_amount(val, "spent")) {
        if let Some(live) = total.checked_sub(spent) {
            println!(
                "Live reserve:  {} SKL",
                format_amount_str(&live.to_string())
            );
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Render the parse-time binding of a `get_reserve_proof` invocation: the
/// amount bound ("the full balance" when unbounded) and the exact challenge
/// message the verifier must supply ("(none)" when empty — shown explicitly
/// so an accidentally-consumed message word is visible, not invisible).
fn describe_reserve_binding(amount: Option<u64>, message: Option<&str>) -> String {
    let bound = match amount {
        Some(a) => format!("{} SKL", format_amount(a)),
        None => "the full balance".to_owned(),
    };
    let msg = match message {
        Some(m) => format!("{m:?}"),
        None => "(none)".to_owned(),
    };
    format!("Proving: {bound}; challenge message: {msg}")
}

/// Read an `AtomicUnits` decimal-string field back as raw units.
fn raw_amount(v: &Value, key: &str) -> Option<u64> {
    v.get(key)?.as_str()?.parse::<u64>().ok()
}

/// Print the confirmation state of a checked tx proof (contract pin:
/// tip block = 1 confirmation; 0 = pool-only).
fn print_confirmations(val: &Value) {
    let in_pool = val
        .get("in_pool")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if in_pool {
        println!("The transaction is in the pool (0 confirmations).");
    } else if let Some(c) = val.get("confirmations").and_then(serde_json::Value::as_u64) {
        println!("Confirmations: {c}");
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{describe_reserve_binding, tx_proof_disclosure};

    #[test]
    fn payment_proof_disclosure_follows_direction() {
        assert!(tx_proof_disclosure(&json!({"direction": "OUTBOUND"}))
            .expect("outbound")
            .contains("transaction's key"));
        assert!(tx_proof_disclosure(&json!({"direction": "INBOUND"}))
            .expect("inbound")
            .contains("amounts"));
        assert!(tx_proof_disclosure(&json!({"direction": "OTHER"})).is_none());
        assert!(tx_proof_disclosure(&json!({})).is_none());
    }

    /// The generation-time echo names both bindings explicitly: an unbounded
    /// proof says "the full balance" (never a blank), and an empty challenge
    /// message says "(none)" — so a first message word silently consumed as
    /// the amount (`get_reserve_proof 2026 budget review`) is visible before
    /// the proof string is ever shared (rule 82).
    #[test]
    fn reserve_binding_echo_names_amount_and_message_explicitly() {
        assert_eq!(
            describe_reserve_binding(None, None),
            "Proving: the full balance; challenge message: (none)"
        );
        assert_eq!(
            describe_reserve_binding(None, Some("quarterly audit")),
            "Proving: the full balance; challenge message: \"quarterly audit\""
        );
        // The numeric-first-token misbind case: the echo shows 2026 SKL as
        // the bound and only "budget review" as the message.
        assert_eq!(
            describe_reserve_binding(Some(2_026_000_000_000), Some("budget review")),
            "Proving: 2026.000000000 SKL; challenge message: \"budget review\""
        );
        assert_eq!(
            describe_reserve_binding(Some(2_500_000_000), None),
            "Proving: 2.500000000 SKL; challenge message: (none)"
        );
    }
}
