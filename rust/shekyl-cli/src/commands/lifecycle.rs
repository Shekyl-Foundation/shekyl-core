// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet lifecycle commands over the native RPC surface (WI-RPC-2a):
//! create, open, close, restore, refresh, status, password.

use serde_json::json;
use zeroize::Zeroize;

use super::{read_password, require_closed, require_open};
use crate::rpc_client::RpcSession;

pub fn cmd_create(rpc: &RpcSession, filename: &str) {
    if !require_closed(rpc) {
        return;
    }
    // Gate the one-time seed display BEFORE creating anything. The server never
    // re-exposes the seed, so a wallet created here whose backup we then cannot
    // safely show (stdout is a pipe/file, or the user declines under tmux)
    // would be permanently unrecoverable. Refuse and create nothing; scripted
    // creation has its own deliberate, file-based path.
    if let Err(e) = crate::display::preflight_secret_display() {
        eprintln!("{e}");
        eprintln!(
            "Refusing to create a wallet whose one-time seed backup cannot be shown here.\n\
             For non-interactive or scripted creation, use:\n  \
             shekyl-cli create <name> --seed-out <path> --password-file <path>"
        );
        return;
    }
    let Some(mut password) = read_password("New wallet password: ") else {
        return;
    };
    let Some(mut confirm) = read_password("Confirm password: ") else {
        password.zeroize();
        return;
    };
    if password != confirm {
        password.zeroize();
        confirm.zeroize();
        eprintln!("Passwords do not match.");
        return;
    }
    confirm.zeroize();

    let result = rpc.call(
        "create_wallet",
        json!({ "name": filename, "password": password }),
    );
    password.zeroize();

    match result {
        Ok(val) => {
            rpc.set_open(filename);
            println!("Created wallet: {filename}");
            // Mainnet/Stagenet return a BIP-39 mnemonic; Testnet a raw seed.
            let backup = val
                .get("mnemonic")
                .or_else(|| val.get("raw_seed_hex"))
                .and_then(|v| v.as_str());
            if let Some(backup) = backup {
                let mut secret = backup.to_owned();
                println!("Write down your seed backup NOW. It is shown only once.");
                // preflight_secret_display() above already guaranteed a safe
                // terminal, so show_secret has no non-TTY fallback that could
                // leak the seed to a pipe or file.
                crate::display::show_secret("Seed backup", &mut secret);
            }
        }
        Err(e) => rpc.report("Failed to create wallet", &e),
    }
}

pub fn cmd_open(rpc: &RpcSession, filename: &str) {
    if !require_closed(rpc) {
        return;
    }
    let Some(mut password) = read_password("Wallet password: ") else {
        return;
    };
    let result = rpc.call(
        "open_wallet",
        json!({ "name": filename, "password": password }),
    );
    password.zeroize();

    match result {
        Ok(_) => {
            rpc.set_open(filename);
            println!("Opened wallet: {filename}");
        }
        Err(e) => rpc.report("Failed to open wallet", &e),
    }
}

pub fn cmd_close(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("close_wallet", json!({})) {
        Ok(_) => {
            rpc.set_closed();
            println!("Wallet closed.");
        }
        Err(e) => rpc.report("Failed to close wallet", &e),
    }
}

pub fn cmd_restore(rpc: &RpcSession, filename: &str, seed_words: &[String]) {
    if !require_closed(rpc) {
        return;
    }
    let mut mnemonic = seed_words.join(" ");
    let Some(mut password) = read_password("New wallet password: ") else {
        mnemonic.zeroize();
        return;
    };

    eprint!("Restore height (block height the wallet existed at; 0 = scan from genesis): ");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut height_input = String::new();
    if std::io::stdin().read_line(&mut height_input).is_err() {
        mnemonic.zeroize();
        password.zeroize();
        eprintln!("Failed to read restore height.");
        return;
    }
    let height_input = height_input.trim();
    let restore_height: u64 = if height_input.is_empty() {
        0
    } else {
        match height_input.parse() {
            Ok(h) => h,
            Err(_) => {
                mnemonic.zeroize();
                password.zeroize();
                eprintln!("Invalid restore height: expected a block height number.");
                return;
            }
        }
    };

    let result = rpc.call(
        "restore_wallet",
        json!({
            "name": filename,
            "password": password,
            "mnemonic": mnemonic,
            "restore_height": restore_height,
        }),
    );
    mnemonic.zeroize();
    password.zeroize();

    match result {
        Ok(_) => {
            rpc.set_open(filename);
            println!("Restored wallet: {filename}");
            println!("Run \"refresh\" to scan the chain for your funds.");
        }
        Err(e) => rpc.report("Failed to restore wallet", &e),
    }
}

pub fn cmd_refresh(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    println!("Refreshing...");
    match rpc.call("refresh", json!({})) {
        Ok(val) => {
            let blocks = val
                .get("blocks_processed")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let detected = val
                .get("transfers_detected")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let height = val
                .get("synced_height")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            println!("Refreshed: {blocks} blocks processed, {detected} transfers detected.");
            println!("Wallet height: {height}");
            if let Some(fork) = val.get("reorg_fork_height").and_then(|v| v.as_i64()) {
                println!("Note: a chain reorg was detected and rewound (fork height {fork}).");
            }
        }
        Err(e) => rpc.report("Refresh failed", &e),
    }
}

/// Full rescan from the wallet's restore height (`rescan_blockchain`).
///
/// The `hard` flag is accepted for CLI familiarity with wallet2-era
/// `rescan_bc hard`; both soft and hard map to the same named Engine
/// rescan (there is no soft/partial rescan surface).
pub fn cmd_rescan(rpc: &RpcSession, _hard: bool) {
    if !require_open(rpc) {
        return;
    }
    println!("Rescanning from restore height...");
    match rpc.call("rescan_blockchain", json!({})) {
        Ok(val) => {
            let blocks = val
                .get("blocks_processed")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let detected = val
                .get("transfers_detected")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let height = val
                .get("synced_height")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            println!("Rescan complete: {blocks} blocks processed, {detected} transfers detected.");
            println!("Wallet height: {height}");
        }
        Err(e) => rpc.report("Rescan failed", &e),
    }
}

pub fn cmd_status(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    match rpc.call("get_height", json!({})) {
        Ok(val) => {
            let wallet = val
                .get("wallet_height")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            println!("Wallet height: {wallet}");
            // daemon_height is null when the daemon is unreachable; still show
            // the wallet height rather than reporting a total failure.
            match val.get("daemon_height").and_then(|v| v.as_i64()) {
                Some(daemon) => {
                    println!("Daemon height: {daemon}");
                    if daemon > wallet {
                        println!("Behind by {} blocks — run \"refresh\".", daemon - wallet);
                    } else {
                        println!("Synced.");
                    }
                }
                None => {
                    println!("Daemon height: unavailable (daemon unreachable).");
                    println!(
                        "Showing wallet height only — start/sync your node, then \"refresh\"."
                    );
                }
            }
        }
        Err(e) => rpc.report("Failed to get status", &e),
    }
}

pub fn cmd_password(rpc: &RpcSession) {
    if !require_open(rpc) {
        return;
    }
    let Some(mut old_password) = read_password("Current password: ") else {
        return;
    };
    let Some(mut new_password) = read_password("New password: ") else {
        old_password.zeroize();
        return;
    };
    let Some(mut confirm) = read_password("Confirm new password: ") else {
        old_password.zeroize();
        new_password.zeroize();
        return;
    };
    if new_password != confirm {
        old_password.zeroize();
        new_password.zeroize();
        confirm.zeroize();
        eprintln!("Passwords do not match.");
        return;
    }
    confirm.zeroize();

    let result = rpc.call(
        "change_password",
        json!({ "old_password": old_password, "new_password": new_password }),
    );
    old_password.zeroize();
    new_password.zeroize();

    match result {
        Ok(_) => println!("Password changed."),
        Err(e) => rpc.report("Failed to change password", &e),
    }
}
