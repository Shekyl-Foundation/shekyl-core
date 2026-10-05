// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet lifecycle commands over the native RPC surface (WI-RPC-2a):
//! create, open, close, restore, refresh, rescan, status, password.

use crate::outcome::{failed, CommandResult, Presentation};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::{read_password, require_closed, require_open};
use crate::rpc_client::{params, RpcError, RpcSession};

const SEED_FILE_HINT: &str = "\
Refusing to create a wallet whose one-time seed backup cannot be shown here.\n\
For a script or for JSON output, use:\n  \
shekyl-cli create <name> --seed-out <path> --password-file <path>";

pub fn cmd_create(rpc: &RpcSession, presentation: &Presentation, filename: &str) -> CommandResult {
    require_closed(rpc)?;
    // Gate the one-time seed display BEFORE creating anything. The server never
    // re-exposes the seed, so a wallet created here whose backup we then cannot
    // safely show would be permanently unrecoverable. Refuse and create nothing.
    // The file command is the deliberate path: `create --seed-out`.
    if !presentation.shows_seed_on_stdout() {
        return failed(SEED_FILE_HINT);
    }
    if let Err(e) = crate::display::preflight_secret_display() {
        return failed(format!("{e}\n{SEED_FILE_HINT}"));
    }
    let password = read_password("New wallet password: ")?;
    let confirm = read_password("Confirm password: ")?;
    if password != confirm {
        return failed("Passwords do not match.");
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
            // Announced here, ahead of the seed, because the seed is shown
            // and wiped before this function returns. The result carries
            // only the name. `present` also strips seed fields.
            println!("Created wallet: {filename}");
            let backup = val
                .get(concat!("mne", "monic"))
                .or_else(|| val.get("raw_seed_hex"))
                .and_then(|v| v.as_str());
            if let Some(backup) = backup {
                let mut secret = backup.to_owned();
                println!("Write down your seed backup NOW. It is shown only once.");
                crate::display::show_secret("Seed backup", &mut secret);
            }
            Ok(json!({"name": filename}))
        }
        Err(e) => Err(rpc.report("Failed to create wallet", &e)),
    }
}

/// Open `filename` with a password the caller already holds. Startup
/// `--wallet` and the prompt command share this.
pub fn open_with_password(rpc: &RpcSession, filename: &str, password: &str) -> CommandResult {
    require_closed(rpc)?;
    match rpc.call(
        "open_wallet",
        params::NamedPassword {
            name: filename,
            password,
        },
    ) {
        Ok(_) => {
            rpc.set_open(filename);
            Ok(json!({"name": filename}))
        }
        Err(e) => Err(rpc.report("Failed to open wallet", &e)),
    }
}

pub fn cmd_open(rpc: &RpcSession, filename: &str) -> CommandResult {
    let password = read_password("Wallet password: ")?;
    open_with_password(rpc, filename, &password)
}

pub(crate) fn show_opened(val: &Value) {
    let name = val.get("name").and_then(|v| v.as_str()).unwrap_or("?");
    println!("Opened wallet: {name}");
}

pub fn cmd_close(rpc: &RpcSession) -> CommandResult {
    require_open(rpc)?;
    match rpc.call("close_wallet", json!({})) {
        Ok(_) => {
            rpc.set_closed();
            Ok(json!({}))
        }
        Err(e) => Err(rpc.report("Failed to close wallet", &e)),
    }
}

pub(crate) fn show_closed(_val: &Value) {
    println!("Wallet closed.");
}

pub fn cmd_restore(
    rpc: &RpcSession,
    presentation: &Presentation,
    filename: &str,
    seed_words: &[String],
) -> CommandResult {
    require_closed(rpc)?;
    if !presentation.shows_seed_on_stdout() {
        return failed(
            "wallet restore here would put the seed on the script or the JSON transcript. \
             Use: shekyl-cli restore <name> --seed-file <path> --password-file <path>",
        );
    }
    // Seed material: wiped on drop like the password, on every path out of
    // this function rather than on the paths somebody remembered to annotate.
    let mnemonic = Zeroizing::new(seed_words.join(" "));
    let password = read_password("New wallet password: ")?;

    eprint!("Restore height (block height the wallet existed at; 0 = scan from genesis): ");
    drop(std::io::Write::flush(&mut std::io::stderr()));
    let mut height_input = String::new();
    if std::io::stdin().read_line(&mut height_input).is_err() {
        return failed("Failed to read restore height.");
    }
    let height_input = height_input.trim();
    let restore_height: u64 = if height_input.is_empty() {
        0
    } else {
        match height_input.parse() {
            Ok(h) => h,
            Err(_) => {
                return failed("Invalid restore height: expected a block height number.");
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
            Ok(json!({"name": filename, "restore_height": restore_height}))
        }
        Err(e) => Err(rpc.report("Failed to restore wallet", &e)),
    }
}

pub(crate) fn show_restored(val: &Value) {
    let name = val.get("name").and_then(|v| v.as_str()).unwrap_or("?");
    println!("Restored wallet: {name}");
    println!("Run \"wallet refresh\" to scan the chain for your funds.");
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

pub fn cmd_refresh(rpc: &RpcSession, presentation: &Presentation) -> CommandResult {
    require_open(rpc)?;
    presentation.say("Refreshing...");
    match rpc.call("refresh", json!({})) {
        Ok(val) => Ok(val),
        Err(e) => Err(rpc.report("Refresh failed", &e)),
    }
}

pub(crate) fn show_refresh(val: &Value) {
    print_scan_result("Refreshed", val);
    if let Some(fork) = val.get("reorg_fork_height").and_then(Value::as_i64) {
        println!("Note: a chain reorg was detected and rewound (fork height {fork}).");
    }
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
pub fn cmd_rescan(rpc: &RpcSession, presentation: &Presentation, hard: bool) -> CommandResult {
    require_open(rpc)?;
    if hard {
        presentation.say(
            "Note: Shekyl has a single rescan — it already rebuilds all scan-derived \
             state. \"hard\" changes nothing.",
        );
    }
    presentation.say("Rebuilding your transaction history from the chain. This can take a while.");
    presentation
        .say("Your transaction keys, notes, payment requests and staking records are kept.");
    match rpc.call("rescan_blockchain", json!({})) {
        Ok(val) => Ok(val),
        Err(e) => {
            let mut reported = rpc.report("Rescan failed", &e);
            // Whether history survived is the only thing the user actually
            // needs from a failed rescan, and the three cases genuinely
            // differ — say which one this was rather than averaging them
            // into a hedge.
            let follow = match &e {
                RpcError::Rpc { code, .. } if RESCAN_PRE_RESET_REFUSALS.contains(code) => {
                    "Nothing was changed — your wallet is exactly as it was."
                }
                RpcError::Rpc { .. } => {
                    "Your history was already cleared before this failure, and will stay \
                     empty until a rescan finishes. Run \"wallet rescan\" again once the \
                     problem above is resolved; nothing is lost that the chain cannot rebuild."
                }
                RpcError::Transport(_) => {
                    "The connection dropped, so it is unclear how far the rescan got. Run \
                     \"status\" to see the wallet height, and \"wallet rescan\" again if the \
                     history is incomplete."
                }
            };
            reported.message = format!("{}\n{follow}", reported.message);
            Err(reported)
        }
    }
}

pub(crate) fn show_rescan(val: &Value) {
    print_scan_result("Rescan complete", val);
}

/// `status` — wallet and daemon sync heights. `daemon_down_hint` is the F1
/// recovery copy (CLI_USABILITY.md §CU-5): the wallet RPC reports an
/// unreachable daemon as `daemon_height: null`, and this surface owes the
/// same "start shekyld" line as the paths that dial the daemon directly.
pub fn cmd_status(rpc: &RpcSession, daemon_down_hint: Option<&str>) -> CommandResult {
    require_open(rpc)?;
    match rpc.call("get_height", json!({})) {
        Ok(mut val) => {
            if let Some(hint) = daemon_down_hint {
                if let Some(object) = val.as_object_mut() {
                    object.insert("daemon_down_hint".to_owned(), json!(hint));
                }
            }
            Ok(val)
        }
        Err(e) => Err(rpc.report("Failed to get status", &e)),
    }
}

pub(crate) fn show_status(val: &Value) {
    let wallet = val
        .get("wallet_height")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    println!("Wallet height: {wallet}");
    // daemon_height is null when the daemon is unreachable; still show
    // the wallet height rather than reporting a total failure.
    match val.get("daemon_height").and_then(Value::as_i64) {
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
            match val.get("daemon_down_hint").and_then(|v| v.as_str()) {
                Some(hint) => println!("{hint} Then run \"refresh\"."),
                None => println!(
                    "Showing wallet height only — start/sync your node, then \
                     \"refresh\"."
                ),
            }
        }
    }
}

pub fn cmd_password(rpc: &RpcSession) -> CommandResult {
    require_open(rpc)?;
    let old_password = read_password("Current password: ")?;
    let new_password = read_password("New password: ")?;
    let confirm = read_password("Confirm new password: ")?;
    if new_password != confirm {
        return failed("Passwords do not match.");
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
        Ok(_) => Ok(json!({})),
        Err(e) => Err(rpc.report("Failed to change password", &e)),
    }
}

pub(crate) fn show_password(_val: &Value) {
    println!("Password changed.");
}
