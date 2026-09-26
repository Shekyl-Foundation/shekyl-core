// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet lifecycle commands over the native RPC surface (WI-RPC-2a):
//! create, open, close, restore, refresh, rescan, status, password.

use crate::outcome::{failed, CommandResult};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::{read_password, require_closed, require_open};
use crate::rpc_client::{params, RpcError, RpcSession};

pub fn cmd_create(rpc: &RpcSession, filename: &str) -> CommandResult {
    require_closed(rpc)?;
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

        return failed();
    }
    let Some(password) = read_password("New wallet password: ") else {
        return failed();
    };
    let Some(confirm) = read_password("Confirm password: ") else {
        return failed();
    };
    if password != confirm {
        eprintln!("Passwords do not match.");
        return failed();
    }
    drop(confirm);

    let result = rpc.call(
        "create_wallet",
        params::NamedPassword {
            name: filename,
            password: &password,
        },
    );

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
        Err(e) => return Err(rpc.report("Failed to create wallet", &e)),
    };
    Ok(())
}

pub fn cmd_open(rpc: &RpcSession, filename: &str) -> CommandResult {
    require_closed(rpc)?;
    let Some(password) = read_password("Wallet password: ") else {
        return failed();
    };
    let result = rpc.call(
        "open_wallet",
        params::NamedPassword {
            name: filename,
            password: &password,
        },
    );

    match result {
        Ok(_) => {
            rpc.set_open(filename);
            println!("Opened wallet: {filename}");
        }
        Err(e) => return Err(rpc.report("Failed to open wallet", &e)),
    };
    Ok(())
}

pub fn cmd_close(rpc: &RpcSession) -> CommandResult {
    require_open(rpc)?;
    match rpc.call("close_wallet", json!({})) {
        Ok(_) => {
            rpc.set_closed();
            println!("Wallet closed.");
        }
        Err(e) => return Err(rpc.report("Failed to close wallet", &e)),
    };
    Ok(())
}

pub fn cmd_restore(rpc: &RpcSession, filename: &str, seed_words: &[String]) -> CommandResult {
    require_closed(rpc)?;
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        eprintln!(
            "wallet restore in a script would put the seed in the script. \
             Use: shekyl-cli restore <name> --seed-file <path> --password-file <path>"
        );
        return failed();
    }
    // Seed material: wiped on drop like the password, on every path out of
    // this function rather than on the paths somebody remembered to annotate.
    let mnemonic = Zeroizing::new(seed_words.join(" "));
    let Some(password) = read_password("New wallet password: ") else {
        return failed();
    };

    eprint!("Restore height (block height the wallet existed at; 0 = scan from genesis): ");
    drop(std::io::Write::flush(&mut std::io::stderr()));
    let mut height_input = String::new();
    if std::io::stdin().read_line(&mut height_input).is_err() {
        eprintln!("Failed to read restore height.");
        return failed();
    }
    let height_input = height_input.trim();
    let restore_height: u64 = if height_input.is_empty() {
        0
    } else {
        match height_input.parse() {
            Ok(h) => h,
            Err(_) => {
                eprintln!("Invalid restore height: expected a block height number.");
                return failed();
            }
        }
    };

    let result = rpc.call(
        "restore_wallet",
        params::Restore {
            name: filename,
            password: &password,
            mnemonic: &mnemonic,
            restore_height,
        },
    );

    match result {
        Ok(_) => {
            rpc.set_open(filename);
            println!("Restored wallet: {filename}");
            println!("Run \"wallet refresh\" to scan the chain for your funds.");
        }
        Err(e) => return Err(rpc.report("Failed to restore wallet", &e)),
    };
    Ok(())
}

/// Read an `i64` counter out of a scan result, defaulting to `0`.
fn scan_counter(val: &Value, field: &str) -> i64 {
    val.get(field).and_then(Value::as_i64).unwrap_or(0)
}

/// Print the counters shared by the `refresh` and `rescan_blockchain`
/// results. Both project the same `RefreshSummary`, so the two commands
/// report it identically rather than through two drifting copies.
fn print_scan_result(headline: &str, val: &Value) {
    let blocks = scan_counter(val, "blocks_processed");
    let detected = scan_counter(val, "transfers_detected");
    let height = scan_counter(val, "synced_height");
    println!("{headline}: {blocks} blocks processed, {detected} transfers detected.");
    println!("Wallet height: {height}");
}

pub fn cmd_refresh(rpc: &RpcSession) -> CommandResult {
    require_open(rpc)?;
    println!("Refreshing...");
    match rpc.call("refresh", json!({})) {
        Ok(val) => {
            print_scan_result("Refreshed", &val);
            if let Some(fork) = val.get("reorg_fork_height").and_then(Value::as_i64) {
                println!("Note: a chain reorg was detected and rewound (fork height {fork}).");
            }
        }
        Err(e) => return Err(rpc.report("Refresh failed", &e)),
    };
    Ok(())
}

/// `rescan_blockchain` error codes that are refusals raised **before** the
/// wallet's scan state is reset (`docs/api/wallet_rpc.yaml`): wallet not
/// open, refresh in progress, daemon unreachable (the rescan preflights it —
/// `-29201` on this method means untouched; mid-scan daemon failure is
/// `-29203`), and rescan blocked by in-flight transactions. Anything else
/// — including `-29203 RESCAN_INCOMPLETE` — arrives after the reset is
/// durable, and the user needs to be told that.
const RESCAN_PRE_RESET_REFUSALS: [i64; 4] = [-29001, -29200, -29201, -29202];

/// Full rescan from the wallet's scan floor (`rescan_blockchain`).
///
/// `hard` is accepted so wallet2-era `rescan_bc hard` muscle memory does not
/// dead-end on "unknown command", but Shekyl has one rescan, not two: it
/// always rebuilds every scan-derived fact from the chain while preserving
/// what the chain cannot re-derive. Saying so out loud beats a modifier that
/// silently does nothing — a user who typed `hard` because the wallet looked
/// wrong would otherwise re-run the identical operation and conclude the
/// wallet is unrecoverable.
pub fn cmd_rescan(rpc: &RpcSession, hard: bool) -> CommandResult {
    require_open(rpc)?;
    if hard {
        println!(
            "Note: Shekyl has a single rescan — it already rebuilds all scan-derived \
             state. \"hard\" changes nothing."
        );
    }
    println!("Rebuilding your transaction history from the chain. This can take a while.");
    println!("Your transaction keys, notes, payment requests and staking records are kept.");
    match rpc.call("rescan_blockchain", json!({})) {
        Ok(val) => print_scan_result("Rescan complete", &val),
        Err(e) => {
            let reported = rpc.report("Rescan failed", &e);
            // Whether history survived is the only thing the user actually
            // needs from a failed rescan, and the three cases genuinely
            // differ — say which one this was rather than averaging them
            // into a hedge.
            match &e {
                RpcError::Rpc { code, .. } if RESCAN_PRE_RESET_REFUSALS.contains(code) => {
                    eprintln!("Nothing was changed — your wallet is exactly as it was.");
                }
                RpcError::Rpc { .. } => {
                    eprintln!(
                        "Your history was already cleared before this failure, and will stay \
                         empty until a rescan finishes. Run \"wallet rescan\" again once the \
                         problem above is resolved; nothing is lost that the chain cannot rebuild."
                    );
                }
                RpcError::Transport(_) => {
                    eprintln!(
                        "The connection dropped, so it is unclear how far the rescan got. Run \
                         \"status\" to see the wallet height, and \"wallet rescan\" again if the \
                         history is incomplete."
                    );
                }
            }
            return Err(reported);
        }
    }
    Ok(())
}

/// `status` — wallet and daemon sync heights. `daemon_down_hint` is the F1
/// recovery copy (CLI_USABILITY.md §CU-5): the wallet RPC reports an
/// unreachable daemon as `daemon_height: null`, and this surface owes the
/// same "start shekyld" line as the paths that dial the daemon directly.
pub fn cmd_status(rpc: &RpcSession, daemon_down_hint: Option<&str>) -> CommandResult {
    require_open(rpc)?;
    match rpc.call("get_height", json!({})) {
        Ok(val) => {
            let wallet = val
                .get("wallet_height")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            println!("Wallet height: {wallet}");
            // daemon_height is null when the daemon is unreachable; still show
            // the wallet height rather than reporting a total failure.
            match val.get("daemon_height").and_then(serde_json::Value::as_i64) {
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
                    match daemon_down_hint {
                        Some(hint) => println!("{hint} Then run \"refresh\"."),
                        None => println!(
                            "Showing wallet height only — start/sync your node, then \
                             \"refresh\"."
                        ),
                    }
                }
            }
        }
        Err(e) => return Err(rpc.report("Failed to get status", &e)),
    };
    Ok(())
}

pub fn cmd_password(rpc: &RpcSession) -> CommandResult {
    require_open(rpc)?;
    let Some(old_password) = read_password("Current password: ") else {
        return failed();
    };
    let Some(new_password) = read_password("New password: ") else {
        return failed();
    };
    let Some(confirm) = read_password("Confirm new password: ") else {
        return failed();
    };
    if new_password != confirm {
        eprintln!("Passwords do not match.");
        return failed();
    }
    drop(confirm);

    let result = rpc.call(
        "change_password",
        params::ChangePassword {
            old_password: &old_password,
            new_password: &new_password,
        },
    );

    match result {
        Ok(_) => println!("Password changed."),
        Err(e) => return Err(rpc.report("Failed to change password", &e)),
    };
    Ok(())
}
