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
//! Every verb passes the same fail-closed gates before any daemon call
//! (CLI_USABILITY.md §CU-3): wallet open (the payout address comes from this
//! wallet), loopback daemon only, unrestricted RPC, and matching network.
//! `mine start` additionally warns-and-confirms on a syncing daemon and
//! refuses politely when mining is already active.

use crate::daemon::DaemonClient;
use crate::display::short_address;
use crate::rpc_client::RpcSession;
use serde_json::json;

/// The wallet-convenience default thread count: `min(available cores, 4)`.
/// Not a tuned miner — operators who care pass a count or drive `shekyld`
/// directly.
fn default_threads() -> u64 {
    let cores = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1) as u64;
    cores.min(4)
}

/// The shared fail-closed gates (CU-3 gates 1–4 / §CU-5 F2–F5). Returns the
/// daemon's `get_info` snapshot when every gate passes, so callers get the
/// sync fields without a second round-trip.
fn gate<'a>(
    rpc: &RpcSession,
    daemon: Option<&'a DaemonClient>,
    network: &str,
) -> Option<(&'a DaemonClient, serde_json::Value)> {
    // F5 — mining verbs are wallet verbs: the payout address is this
    // wallet's. The daemon console is the wallet-less path.
    if rpc.open_wallet_name().is_none() {
        eprintln!(
            "No wallet is open. Mining pays to this wallet's address — \
             open <name> (or create <name>) first."
        );
        return None;
    }

    let Some(dc) = daemon else {
        eprintln!("Daemon not configured. Use --daemon-address to set the daemon endpoint.");
        return None;
    };

    // F4 — mining RPCs are admin surface; refuse CLI-side before any
    // network round-trip rather than relaying the daemon's own refusal.
    if !dc.is_loopback() {
        eprintln!(
            "Mining is controlled on the daemon's own host; this CLI is pointed at {}.\n\
             Run shekyl-cli on that machine, or use the daemon's own console.",
            dc.url()
        );
        return None;
    }

    // One get_info answers gates 3–4 and the sync fields. A refused
    // connection carries the F1 "start shekyld" hint via DaemonClient.
    let info = match dc.get_info() {
        Ok(info) => info,
        Err(e) => {
            eprintln!("{e}");
            return None;
        }
    };

    // F3 — restricted listener: admin RPCs are not served there.
    if info
        .get("restricted")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        eprintln!(
            "The daemon's RPC listener is restricted (view-only); mining control \
             needs the unrestricted loopback listener."
        );
        return None;
    }

    // F2 — network mismatch: a testnet wallet pointing at a mainnet daemon
    // would mine (and pay out) on the wrong network.
    let nettype = info.get("nettype").and_then(|v| v.as_str()).unwrap_or("");
    if !nettype.is_empty() && nettype != network {
        eprintln!(
            "Network mismatch: this CLI is on {network} but the daemon at {} reports {nettype}.\n\
             Restart shekyl-cli or shekyld so both use the same \
             --testnet/--stagenet flag.",
            dc.url()
        );
        return None;
    }

    Some((dc, info))
}

/// `mine start [threads|auto]` — start mining on the daemon, paying to this
/// wallet's primary address.
pub fn cmd_mine_start(
    rpc: &RpcSession,
    daemon: Option<&DaemonClient>,
    network: &str,
    threads: Option<u64>,
) {
    let Some((dc, info)) = gate(rpc, daemon, network) else {
        return;
    };

    // F6 — already mining: relay the daemon's state, no error tone.
    match dc.mining_status() {
        Ok(status) => {
            if status
                .get("active")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                let threads_now = status
                    .get("threads_count")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                println!(
                    "The daemon is already mining with {threads_now} thread(s). \
                     Run \"mine stop\" first to change the thread count."
                );
                return;
            }
        }
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    }

    // F7 — syncing daemon: mining now may mine a stale chain.
    let busy_syncing = info
        .get("busy_syncing")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let synchronized = info
        .get("synchronized")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    if busy_syncing || !synchronized {
        let height = info
            .get("height")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let target = info
            .get("target_height")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let of_target = if target > height {
            format!("height {height} of {target}")
        } else {
            format!("height {height}")
        };
        if !super::confirm(&format!(
            "The daemon is still syncing ({of_target}) — mining now may mine a stale chain."
        )) {
            println!("Mining not started.");
            return;
        }
    }

    let address = match rpc.call("get_primary_address", json!({})) {
        Ok(val) => match val.get("address").and_then(|v| v.as_str()) {
            Some(address) => address.to_owned(),
            None => {
                eprintln!("Malformed get_primary_address response.");
                return;
            }
        },
        Err(e) => {
            rpc.report("Failed to get the payout address", &e);
            return;
        }
    };

    let threads = threads.unwrap_or_else(default_threads);
    match dc.start_mining(&address, threads) {
        Ok(_) => {
            println!(
                "Mining started: {threads} thread(s) on the daemon, paying to {}.",
                short_address(&address)
            );
            println!(
                "The daemon owns the mining threads — they keep running after this \
                 CLI exits. \"mine stop\" stops them."
            );
        }
        Err(e) => eprintln!("Failed to start mining: {e}"),
    }
}

/// `mine stop` — stop mining on the daemon.
pub fn cmd_mine_stop(rpc: &RpcSession, daemon: Option<&DaemonClient>, network: &str) {
    let Some((dc, _info)) = gate(rpc, daemon, network) else {
        return;
    };

    match dc.mining_status() {
        Ok(status) => {
            if !status
                .get("active")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                println!("The daemon is not mining.");
                return;
            }
        }
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    }

    match dc.stop_mining() {
        Ok(_) => println!("Mining stopped."),
        Err(e) => eprintln!("Failed to stop mining: {e}"),
    }
}

/// `mine status` — the daemon's mining state. The daemon's `pow_algorithm`
/// string is deliberately not rendered: the inherited label table still
/// emits Cryptonight names for dead pre-RandomX variants
/// (`core_rpc_server.cpp` `on_mining_status`); deleting those arms is
/// daemon-side rule-60 cleanup tracked in docs/FOLLOWUPS.md
/// (Target: pre-genesis).
pub fn cmd_mine_status(rpc: &RpcSession, daemon: Option<&DaemonClient>, network: &str) {
    let Some((dc, _info)) = gate(rpc, daemon, network) else {
        return;
    };

    match dc.mining_status() {
        Ok(status) => {
            let active = status
                .get("active")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if !active {
                println!("Mining: idle.");
                return;
            }
            let threads = status
                .get("threads_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let speed = status
                .get("speed")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            println!("Mining: active");
            println!("  Threads:    {threads}");
            println!("  Hash rate:  {speed} H/s");
            if let Some(address) = status.get("address").and_then(|v| v.as_str()) {
                if !address.is_empty() {
                    println!("  Paying to:  {}", short_address(address));
                }
            }
            if let Some(difficulty) = status.get("difficulty").and_then(serde_json::Value::as_u64) {
                println!("  Difficulty: {difficulty}");
            }
        }
        Err(e) => eprintln!("{e}"),
    }
}
