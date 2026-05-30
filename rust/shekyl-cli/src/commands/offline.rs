// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Offline signing commands: describe_transfer, sign_transfer, submit_transfer.
//!
//! Cold signing workflow:
//!   1. [online watch-only]   transfer --do-not-relay <amount> <address> -> unsigned_txset
//!   2. [offline full engine] describe_transfer <unsigned_txset>         -> inspect
//!   3. [offline full engine] sign_transfer <unsigned_txset>             -> signed_txset
//!   4. [online watch-only]   submit_transfer <signed_txset>            -> broadcast

use crate::engine::EngineContext;

pub fn cmd_describe_transfer(ctx: &EngineContext, unsigned_hex: &str) {
    if !super::require_open(ctx) {
        return;
    }

    let params = serde_json::json!({ "unsigned_txset": unsigned_hex });
    match ctx.json_rpc("describe_transfer", &params.to_string()) {
        Ok(val) => {
            if let Some(desc) = val.get("desc").and_then(|d| d.as_array()) {
                for (i, tx) in desc.iter().enumerate() {
                    println!("Transaction {}:", i + 1);
                    if let Some(recipients) = tx.get("recipients").and_then(|r| r.as_array()) {
                        for r in recipients {
                            let addr = r.get("address").and_then(|a| a.as_str()).unwrap_or("?");
                            let amount = r.get("amount").and_then(|a| a.as_u64()).unwrap_or(0);
                            println!("  To: {addr}  Amount: {} SKL", super::format_amount(amount));
                        }
                    }
                    let fee = tx.get("fee").and_then(|f| f.as_u64()).unwrap_or(0);
                    println!("  Fee: {} SKL", super::format_amount(fee));
                    if let Some(change) = tx.get("change_address").and_then(|c| c.as_str()) {
                        let change_amt = tx
                            .get("change_amount")
                            .and_then(|a| a.as_u64())
                            .unwrap_or(0);
                        println!(
                            "  Change: {} SKL -> {change}",
                            super::format_amount(change_amt)
                        );
                    }
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            }
        }
        Err(e) => eprintln!("Failed to describe transfer: {e}"),
    }
}

pub fn cmd_sign_transfer(ctx: &EngineContext, unsigned_hex: &str, file: Option<&str>) {
    if !super::require_open(ctx) {
        return;
    }

    let hex_data = if unsigned_hex.is_empty() {
        if let Some(path) = file {
            match std::fs::read_to_string(path) {
                Ok(data) => data.trim().to_string(),
                Err(e) => {
                    eprintln!("Failed to read {path}: {e}");
                    return;
                }
            }
        } else {
            eprintln!("Provide unsigned hex or --file <path>.");
            return;
        }
    } else {
        unsigned_hex.to_string()
    };

    if !super::confirm("Sign this transaction?") {
        println!("Cancelled.");
        return;
    }

    let params = serde_json::json!({ "unsigned_txset": hex_data });
    match ctx.json_rpc("sign_transfer", &params.to_string()) {
        Ok(val) => {
            if let Some(signed) = val.get("signed_txset").and_then(|s| s.as_str()) {
                if let Some(output_file) = file {
                    let signed_path = format!("{output_file}.signed");
                    #[cfg(unix)]
                    {
                        use std::io::Write;
                        use std::os::unix::fs::OpenOptionsExt;
                        match std::fs::OpenOptions::new()
                            .write(true)
                            .create(true)
                            .truncate(true)
                            .mode(0o600)
                            .open(&signed_path)
                        {
                            Ok(mut f) => {
                                let _ = f.write_all(signed.as_bytes());
                                println!("Signed txset written to {signed_path}");
                            }
                            Err(e) => eprintln!("Failed to write file: {e}"),
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        if let Err(e) = std::fs::write(&signed_path, signed) {
                            eprintln!("Failed to write file: {e}");
                        } else {
                            println!("Signed txset written to {signed_path}");
                        }
                    }
                } else {
                    println!("Signed txset: {signed}");
                }
            }
            if let Some(hashes) = val.get("tx_hash_list").and_then(|l| l.as_array()) {
                for h in hashes {
                    if let Some(hash) = h.as_str() {
                        println!("Tx hash: {hash}");
                    }
                }
            }
        }
        Err(e) => eprintln!("Signing failed: {e}"),
    }
}

pub fn cmd_submit_transfer(ctx: &EngineContext, signed_hex: &str) {
    if !super::require_open(ctx) {
        return;
    }

    if !super::confirm("Submit signed transaction to network?") {
        println!("Cancelled.");
        return;
    }

    let params = serde_json::json!({ "tx_data_hex": signed_hex });
    match ctx.json_rpc("submit_transfer", &params.to_string()) {
        Ok(val) => {
            if let Some(hashes) = val.get("tx_hash_list").and_then(|l| l.as_array()) {
                for h in hashes {
                    if let Some(hash) = h.as_str() {
                        println!("Submitted: {hash}");
                    }
                }
            } else {
                println!("Transfer submitted.");
                println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            }
        }
        Err(e) => eprintln!("Submission failed: {e}"),
    }
}
