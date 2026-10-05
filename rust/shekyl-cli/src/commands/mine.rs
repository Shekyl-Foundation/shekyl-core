// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Mining control from the wallet (CU-3). **The daemon still does the
//! hashing** — these verbs POST to the daemon's `/start_mining` /
//! `/stop_mining` / `/mining_status` path handlers; no RandomX runs in this
//! process. The original "the CLI doesn't mine" cut was about the wallet
//! *doing* the work, not *controlling* it (CLI_USABILITY.md §1).
//!
//! The daemon's built-in hasher is the same path it uses to check blocks:
//! always correct, not a competitive miner. A miner built for another coin
//! will not produce blocks this network accepts.
//!
//! Shared fail-closed gates before any mining daemon call (CLI_USABILITY.md
//! §CU-3): wallet open, unrestricted RPC, matching network. `mine start`
//! additionally refuses a daemon that is not synced (the daemon's own
//! `CHECK_CORE_READY`) and reminds — does not refuse — when the endpoint is
//! not loopback. Loopback is the silent default and the recommended posture;
//! a remote daemon the operator named is a valid advanced configuration.

use serde_json::{json, Value};

use crate::daemon::{DaemonClient, DaemonInfo};
use crate::display::short_address;
use crate::outcome::{failed, refusal, CommandFailed, CommandResult};
use crate::rpc_client::RpcSession;

/// The wallet-convenience default thread count: `min(available cores, 4)`.
/// Not a tuned miner — operators who care pass a count or drive `shekyld`
/// directly.
fn default_threads() -> u64 {
    let cores = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1) as u64;
    cores.min(4)
}

/// The shared fail-closed gates (CU-3 / §CU-5 F2, F3, F5). Returns the
/// daemon's `get_info` snapshot when every gate passes, so callers get the
/// sync fields without a second round-trip.
fn gate<'a>(
    rpc: &RpcSession,
    daemon: Option<&'a DaemonClient>,
    network: &str,
) -> Result<(&'a DaemonClient, DaemonInfo), CommandFailed> {
    // F5 — mining verbs are wallet verbs: the payout address is this
    // wallet's. The daemon console is the wallet-less path.
    if rpc.open_wallet_name().is_none() {
        return Err(refusal(
            "No wallet is open. Mining pays to this wallet's address — \
             open <name> (or create <name>) first.",
        ));
    }

    let Some(dc) = daemon else {
        return Err(refusal(
            "Daemon not configured. Use --daemon-address to set the daemon endpoint.",
        ));
    };

    // One get_info answers F2, F3, and the sync fields. A refused
    // connection carries the F1 "start shekyld" hint via DaemonClient.
    let info = dc.get_info().map_err(|e| refusal(e.to_string()))?;

    // F3 — restricted listener: admin RPCs are not served there.
    if info.restricted {
        return Err(refusal(
            "The daemon's RPC listener is restricted (view-only); mining control \
             needs the unrestricted RPC listener.",
        ));
    }

    // F2 — network mismatch: a testnet wallet pointing at a mainnet daemon
    // would mine (and pay out) on the wrong network. An omitted/empty nettype
    // is a malformed reply, not a skip.
    if info.nettype.is_empty() {
        return Err(refusal(format!(
            "The daemon at {} did not report its network; refusing mining control.",
            dc.url()
        )));
    }
    if info.nettype != network {
        return Err(refusal(format!(
            "Network mismatch: this CLI is on {network} but the daemon at {} reports {}.\n\
             Restart shekyl-cli or shekyld so both use the same \
             --testnet/--stagenet flag.",
            dc.url(),
            info.nettype
        )));
    }

    Ok((dc, info))
}

/// F4 — reminder, not a force. Loopback is the silent default; a named
/// remote daemon (for example a node on the same network boundary) is a
/// valid advanced configuration. The operator already chose the endpoint;
/// say the recommended posture out loud, then continue.
fn remind_if_remote(dc: &DaemonClient) {
    if dc.is_loopback() {
        return;
    }
    eprintln!(
        "Note: this daemon ({}) is not on this machine. Mining control is \
         admin RPC; the recommended posture is a daemon on this machine. \
         Continuing with the endpoint you named.",
        dc.url()
    );
}

/// Printed after a successful `mine start`. The built-in hasher is the
/// node's checker, not a competitive miner; a miner for another coin
/// (including stock Monero XMRig) will not produce accepted blocks.
const BUILT_IN_MINER_NOTICE: &str = "\
The daemon is using its built-in checker, which is correct but not the \
fastest miner for this CPU. For more hashrate, run a dedicated miner that \
uses this node's block template — a miner built for another coin will not \
produce blocks this network accepts.";

/// `mine start [threads|auto]` — start mining on the daemon, paying to this
/// wallet's primary address.
pub fn cmd_mine_start(
    rpc: &RpcSession,
    daemon: Option<&DaemonClient>,
    network: &str,
    threads: Option<u64>,
) -> CommandResult {
    let (dc, info) = gate(rpc, daemon, network)?;
    remind_if_remote(dc);

    // F6 — already mining: relay the daemon's state, no error tone.
    match dc.mining_status() {
        Ok(status) if status.active => {
            return Ok(json!({
                "started": false,
                "already_mining": true,
                "threads": status.threads_count,
            }));
        }
        Ok(_) => {}
        Err(e) => return failed(e.to_string()),
    }

    // F7 — not synced: `/start_mining` is CHECK_CORE_READY and will return
    // BUSY. Refuse here with the height copy rather than confirm-and-fail.
    if !info.synchronized {
        let of_target = if info.target_height > info.height {
            format!("height {} of {}", info.height, info.target_height)
        } else {
            format!("height {}", info.height)
        };
        return failed(format!(
            "The daemon is still syncing ({of_target}) and will not start mining \
             until it is caught up."
        ));
    }

    let address = super::balance::primary_address(rpc, "Failed to get the payout address")?;

    let threads = threads.unwrap_or_else(default_threads);
    match dc.start_mining(&address, threads) {
        Ok(()) => Ok(json!({
            "started": true,
            "threads": threads,
            "address": address,
        })),
        Err(e) => failed(format!("Failed to start mining: {e}")),
    }
}

pub(crate) fn show_mine_start(val: &Value) {
    if val
        .get("already_mining")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let threads = val.get("threads").and_then(Value::as_u64).unwrap_or(0);
        println!(
            "The daemon is already mining with {threads} thread(s). \
             Run \"mine stop\" first to change the thread count."
        );
        return;
    }
    let threads = val.get("threads").and_then(Value::as_u64).unwrap_or(0);
    let address = val.get("address").and_then(|v| v.as_str()).unwrap_or("");
    println!(
        "Mining started: {threads} thread(s) on the daemon, paying to {}.",
        short_address(address)
    );
    println!(
        "The daemon owns the mining threads — they keep running after this \
         CLI exits. \"mine stop\" stops them."
    );
    println!("{BUILT_IN_MINER_NOTICE}");
}

/// `mine stop` — stop mining on the daemon.
pub fn cmd_mine_stop(
    rpc: &RpcSession,
    daemon: Option<&DaemonClient>,
    network: &str,
) -> CommandResult {
    let (dc, _info) = gate(rpc, daemon, network)?;

    match dc.mining_status() {
        Ok(status) if !status.active => return Ok(json!({"stopped": false, "idle": true})),
        Ok(_) => {}
        Err(e) => return failed(e.to_string()),
    }

    match dc.stop_mining() {
        Ok(()) => Ok(json!({"stopped": true})),
        Err(e) => failed(format!("Failed to stop mining: {e}")),
    }
}

pub(crate) fn show_mine_stop(val: &Value) {
    if val.get("idle").and_then(Value::as_bool).unwrap_or(false) {
        println!("The daemon is not mining.");
    } else {
        println!("Mining stopped.");
    }
}

/// `mine status` — the daemon's mining state. The daemon's `pow_algorithm`
/// string is deliberately not rendered (CU-3: operators do not need a
/// protocol-algorithm name; the daemon now always reports RandomX).
pub fn cmd_mine_status(
    rpc: &RpcSession,
    daemon: Option<&DaemonClient>,
    network: &str,
) -> CommandResult {
    let (dc, _info) = gate(rpc, daemon, network)?;

    match dc.mining_status() {
        Ok(status) => Ok(json!({
            "active": status.active,
            "threads": status.threads_count,
            "speed": status.speed,
            "address": status.address,
            "difficulty": status.difficulty,
        })),
        Err(e) => failed(e.to_string()),
    }
}

pub(crate) fn show_mine_status(val: &Value) {
    if !val.get("active").and_then(Value::as_bool).unwrap_or(false) {
        println!("Mining: idle.");
        return;
    }
    println!("Mining: active");
    println!(
        "  Threads:    {}",
        val.get("threads").and_then(Value::as_u64).unwrap_or(0)
    );
    println!(
        "  Hash rate:  {} H/s",
        val.get("speed").and_then(Value::as_u64).unwrap_or(0)
    );
    if let Some(address) = val.get("address").and_then(|v| v.as_str()) {
        if !address.is_empty() {
            println!("  Paying to:  {}", short_address(address));
        }
    }
    let difficulty = val.get("difficulty").and_then(Value::as_u64).unwrap_or(0);
    if difficulty > 0 {
        println!("  Difficulty: {difficulty}");
    }
}

#[cfg(test)]
mod tests {
    use super::BUILT_IN_MINER_NOTICE;

    #[test]
    fn built_in_miner_notice_names_the_template_not_a_drop_in_xmrig() {
        assert!(
            BUILT_IN_MINER_NOTICE.contains("block template"),
            "notice must tell the operator the work comes from this node"
        );
        assert!(
            BUILT_IN_MINER_NOTICE.contains("another coin"),
            "notice must refuse the stock-Monero-miner reading"
        );
        assert!(
            !BUILT_IN_MINER_NOTICE.contains("XMRig"),
            "do not name a miner that speaks a different template dialect"
        );
    }
}
