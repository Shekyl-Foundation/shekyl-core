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
use shekyl_wallet_rpc::types::{SignMessageResult, VerifyMessageResult};
use shekyl_wallet_rpc::WalletRpcErrorCode;

use super::require_open;
use crate::rpc_client::{RpcError, RpcSession};

/// Refuse `@path` signature files larger than this. Any valid armored
/// signature fits the decoder's own 64 KiB encoded ceiling
/// (`MSG_SIG_MAX_ENCODED_LEN`, checked before whitespace filtering), so
/// twice that is generous slack for the prefix and mail-wrap whitespace
/// while keeping a typo'd path (a device node, a giant log) from being
/// read to EOF and shipped to the server just to bounce.
const SIG_FILE_MAX_BYTES: usize = 2 * shekyl_crypto_pq::message_signing::MSG_SIG_MAX_ENCODED_LEN;

pub fn cmd_sign(rpc: &RpcSession, message: &str) {
    if !require_open(rpc) {
        return;
    }
    eprintln!("Signing — this takes a few seconds by design; please wait...");
    match rpc.call("sign_message", json!({ "message": message })) {
        Ok(val) => match serde_json::from_value::<SignMessageResult>(val) {
            Ok(r) if !r.signature.is_empty() => {
                println!("{}", r.signature);
                eprintln!(
                    "Done. Share the message, this signature, and your address; anyone \
                     can verify them together with \"verify\" — no wallet needed. Keep \
                     the signature on a single line when pasting it, or write it to a \
                     file and pass @path to verify."
                );
            }
            Ok(_) | Err(_) => rpc.report(
                "Failed to sign message",
                &RpcError::Transport("server returned no signature".into()),
            ),
        },
        Err(e) => rpc.report("Failed to sign message", &e),
    }
}

pub fn cmd_verify(rpc: &RpcSession, address: &str, signature: &str, message: &str) {
    // Deliberately no `require_open`: verification is a public operation
    // over public inputs (SM-R-6).
    let signature = match load_signature(signature) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Could not verify signature: {e}");
            return;
        }
    };
    let result = rpc.call(
        "verify_message",
        json!({
            "address": address,
            "message": message,
            "signature": signature,
        }),
    );
    // The one wire code that is a negative *verdict* rather than a fault
    // — sourced from the server crate's own enum so a re-band cannot
    // silently demote INVALID into the generic failure path.
    let invalid = i64::from(WalletRpcErrorCode::MessageSigVerifyFailed.as_i32());
    match result {
        Ok(val) => match serde_json::from_value::<VerifyMessageResult>(val) {
            Ok(_) => println!("Signature is VALID for this address and message."),
            Err(_) => rpc.report(
                "Could not verify signature",
                &RpcError::Transport("unexpected server response".into()),
            ),
        },
        // The one negative *answer* gets a verdict line; every other
        // refusal (corrupted paste, unknown scheme, unbound address
        // format, malformed input) already carries its own remedy in the
        // server's sentence, which `report` prints verbatim.
        Err(e) if e.code() == Some(invalid) => {
            println!("Signature is INVALID: not a signature by that address over this message.");
        }
        Err(e) => rpc.report("Could not verify signature", &e),
    }
}

/// `@path` reads a signature from a file so a mail-wrapped 21.7 KB paste
/// does not have to survive `split_whitespace`. Bare tokens are used as-is.
///
/// The read is capped at [`SIG_FILE_MAX_BYTES`]: without a cap, a typo'd
/// path (a FIFO, `/dev/urandom`, a multi-GB log) is read to EOF before
/// any refusal — hanging or exhausting memory locally, or shipping a
/// payload the server bounces as an opaque HTTP 413 (rule 82: the
/// refusal must name the actual problem, at the earliest place that can
/// see it).
fn load_signature(token: &str) -> Result<String, String> {
    let Some(path) = token.strip_prefix('@') else {
        return Ok(token.to_owned());
    };
    if path.is_empty() {
        return Err("verify: @path needs a file path after @".into());
    }
    use std::io::Read as _;
    let file = std::fs::File::open(path)
        .map_err(|e| format!("could not open signature file {path}: {e}"))?;
    let mut contents = String::new();
    file.take(SIG_FILE_MAX_BYTES as u64 + 1)
        .read_to_string(&mut contents)
        .map_err(|e| format!("could not read signature file {path}: {e}"))?;
    if contents.len() > SIG_FILE_MAX_BYTES {
        return Err(format!(
            "{path} is larger than any valid signature file (over \
             {SIG_FILE_MAX_BYTES} bytes) — check that the path names the \
             saved signature"
        ));
    }
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::load_signature;

    #[test]
    fn load_signature_bare_token_is_unchanged() {
        assert_eq!(
            load_signature("shekylmsgsig1.AAAA").expect("bare"),
            "shekylmsgsig1.AAAA"
        );
    }

    #[test]
    fn load_signature_empty_at_is_a_usage_error() {
        assert!(load_signature("@").unwrap_err().contains("@path"));
    }

    #[test]
    fn load_signature_reads_an_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sig.txt");
        std::fs::write(&path, "shekylmsgsig1.FROMFILE\n").expect("write");
        let loaded = load_signature(&format!("@{}", path.display())).expect("read");
        assert_eq!(loaded, "shekylmsgsig1.FROMFILE\n");
    }

    /// The cap refuses with a remedy sentence and never reads past it —
    /// an oversized file is a named refusal, not an opaque server bounce.
    #[test]
    fn load_signature_refuses_a_file_over_the_cap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("huge.txt");
        std::fs::write(&path, "A".repeat(super::SIG_FILE_MAX_BYTES + 1)).expect("write");
        let err = load_signature(&format!("@{}", path.display())).unwrap_err();
        assert!(err.contains("larger than any valid signature"), "{err}");
    }
}
