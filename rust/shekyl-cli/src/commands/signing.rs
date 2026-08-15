// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Message-signing commands over the PR-SM-2 surface: `sign` /
//! `verify`.
//!
//! `sign` needs the open wallet and is **multi-second by design**
//! (~4 s on the smallest supported device): the expectation is printed
//! *before* the call so the pause reads as work being done, never as a
//! hang (rules 80/82). `verify` is session-less by contract (SM-R-6) —
//! it deliberately skips `require_open` and works in a walletless
//! session, because checking someone else's signature must not require
//! having a wallet at all.
//!
//! Output discipline: the armored signature is the one artifact and goes
//! to stdout alone; expectation and guidance lines go to stderr, so a
//! scripted `sign` can capture exactly the signature.

use serde_json::json;

use super::require_open;
use crate::rpc_client::RpcSession;

pub fn cmd_sign(rpc: &RpcSession, message: &str) {
    if !require_open(rpc) {
        return;
    }
    eprintln!("Signing — this takes a few seconds by design; please wait...");
    match rpc.call("sign_message", json!({ "message": message })) {
        Ok(val) => {
            let signature = val.get("signature").and_then(|v| v.as_str()).unwrap_or("");
            println!("{signature}");
            eprintln!(
                "Done. Share the message, this signature, and your address; anyone \
                 can verify them together with \"verify\" — no wallet needed. Keep \
                 the signature on a single line when pasting it."
            );
        }
        Err(e) => rpc.report("Failed to sign message", &e),
    }
}

pub fn cmd_verify(rpc: &RpcSession, address: &str, signature: &str, message: Option<&str>) {
    // Deliberately no `require_open`: verification is a public operation
    // over public inputs (SM-R-6).
    let result = rpc.call(
        "verify_message",
        json!({
            "address": address,
            "message": message.unwrap_or(""),
            "signature": signature,
        }),
    );
    match result {
        Ok(_) => println!("Signature is VALID for this address and message."),
        // The one negative *answer* gets a verdict line; every other
        // refusal (corrupted paste, unknown scheme, unbound address
        // format, malformed input) already carries its own remedy in the
        // server's sentence, which `report` prints verbatim.
        Err(e) if e.code() == Some(-29800) => {
            println!("Signature is INVALID: not a signature by that address over this message.");
        }
        Err(e) => rpc.report("Could not verify signature", &e),
    }
}
