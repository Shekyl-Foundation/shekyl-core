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

use crate::daemon::{DaemonClient, DaemonInfo};
use crate::display::short_address;
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

/// Parsed mining verb. Lives next to the handlers so `resolve` does not grow
/// another grammar island in the command match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParsedMine {
    Start { threads: Option<u64> },
    Stop,
    Status,
}

/// `mine start [threads|auto]` / `mine stop` / `mine status`. Extra tokens
/// are a usage diagnostic, never a silent drop (rule 82).
pub(crate) fn parse_mine(args: &[&str]) -> Result<ParsedMine, String> {
    match args {
        ["start"] => Ok(ParsedMine::Start { threads: None }),
        ["start", token] => Ok(ParsedMine::Start {
            threads: parse_thread_token(token)?,
        }),
        ["stop"] => Ok(ParsedMine::Stop),
        ["status"] => Ok(ParsedMine::Status),
        _ => Err(
            "mine: usage is \"mine start [threads|auto]\", \"mine stop\", \
             or \"mine status\""
                .to_owned(),
        ),
    }
}

fn parse_thread_token(raw: &str) -> Result<Option<u64>, String> {
    match raw {
        "auto" => Ok(None),
        other => match other.parse::<u64>() {
            Ok(n) if n >= 1 => Ok(Some(n)),
            _ => Err(format!(
                "mine start: threads must be a positive number or \"auto\", got {raw:?}"
            )),
        },
    }
}

/// The shared fail-closed gates (CU-3 / §CU-5 F2, F3, F5). Returns the
/// daemon's `get_info` snapshot when every gate passes, so callers get the
/// sync fields without a second round-trip.
fn gate<'a>(
    rpc: &RpcSession,
    daemon: Option<&'a DaemonClient>,
    network: &str,
) -> Option<(&'a DaemonClient, DaemonInfo)> {
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

    // One get_info answers F2, F3, and the sync fields. A refused
    // connection carries the F1 "start shekyld" hint via DaemonClient.
    let info = match dc.get_info() {
        Ok(info) => info,
        Err(e) => {
            eprintln!("{e}");
            return None;
        }
    };

    // F3 — restricted listener: admin RPCs are not served there.
    if info.restricted {
        eprintln!(
            "The daemon's RPC listener is restricted (view-only); mining control \
             needs the unrestricted RPC listener."
        );
        return None;
    }

    // F2 — network mismatch: a testnet wallet pointing at a mainnet daemon
    // would mine (and pay out) on the wrong network. An omitted/empty nettype
    // is a malformed reply, not a skip.
    if info.nettype.is_empty() {
        eprintln!(
            "The daemon at {} did not report its network; refusing mining control.",
            dc.url()
        );
        return None;
    }
    if info.nettype != network {
        eprintln!(
            "Network mismatch: this CLI is on {network} but the daemon at {} reports {}.\n\
             Restart shekyl-cli or shekyld so both use the same \
             --testnet/--stagenet flag.",
            dc.url(),
            info.nettype
        );
        return None;
    }

    Some((dc, info))
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
) {
    let Some((dc, info)) = gate(rpc, daemon, network) else {
        return;
    };
    remind_if_remote(dc);

    // F6 — already mining: relay the daemon's state, no error tone.
    match dc.mining_status() {
        Ok(status) => {
            if status.active {
                println!(
                    "The daemon is already mining with {} thread(s). \
                     Run \"mine stop\" first to change the thread count.",
                    status.threads_count
                );
                return;
            }
        }
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    }

    // F7 — not synced: `/start_mining` is CHECK_CORE_READY and will return
    // BUSY. Refuse here with the height copy rather than confirm-and-fail.
    if !info.synchronized {
        let of_target = if info.target_height > info.height {
            format!("height {} of {}", info.height, info.target_height)
        } else {
            format!("height {}", info.height)
        };
        eprintln!(
            "The daemon is still syncing ({of_target}) and will not start mining \
             until it is caught up."
        );
        return;
    }

    let Some(address) = super::balance::primary_address(rpc, "Failed to get the payout address")
    else {
        return;
    };

    let threads = threads.unwrap_or_else(default_threads);
    match dc.start_mining(&address, threads) {
        Ok(()) => {
            println!(
                "Mining started: {threads} thread(s) on the daemon, paying to {}.",
                short_address(&address)
            );
            println!(
                "The daemon owns the mining threads — they keep running after this \
                 CLI exits. \"mine stop\" stops them."
            );
            println!("{BUILT_IN_MINER_NOTICE}");
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
            if !status.active {
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
        Ok(()) => println!("Mining stopped."),
        Err(e) => eprintln!("Failed to stop mining: {e}"),
    }
}

/// `mine status` — the daemon's mining state. The daemon's `pow_algorithm`
/// string is deliberately not rendered (CU-3: operators do not need a
/// protocol-algorithm name; the daemon now always reports RandomX).
pub fn cmd_mine_status(rpc: &RpcSession, daemon: Option<&DaemonClient>, network: &str) {
    let Some((dc, _info)) = gate(rpc, daemon, network) else {
        return;
    };

    match dc.mining_status() {
        Ok(status) => {
            if !status.active {
                println!("Mining: idle.");
                return;
            }
            println!("Mining: active");
            println!("  Threads:    {}", status.threads_count);
            println!("  Hash rate:  {} H/s", status.speed);
            if !status.address.is_empty() {
                println!("  Paying to:  {}", short_address(&status.address));
            }
            if status.difficulty > 0 {
                println!("  Difficulty: {}", status.difficulty);
            }
        }
        Err(e) => eprintln!("{e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_mine, ParsedMine, BUILT_IN_MINER_NOTICE};

    #[test]
    fn mine_grammar_accepts_exact_arity_and_rejects_strays() {
        assert_eq!(
            parse_mine(&["start"]).unwrap(),
            ParsedMine::Start { threads: None }
        );
        assert_eq!(
            parse_mine(&["start", "auto"]).unwrap(),
            ParsedMine::Start { threads: None }
        );
        assert_eq!(
            parse_mine(&["start", "2"]).unwrap(),
            ParsedMine::Start { threads: Some(2) }
        );
        assert_eq!(parse_mine(&["stop"]).unwrap(), ParsedMine::Stop);
        assert_eq!(parse_mine(&["status"]).unwrap(), ParsedMine::Status);

        for args in [
            &[][..],
            &["begin"][..],
            &["start", "0"][..],
            &["start", "four"][..],
            &["start", "2", "extra"][..],
            &["stop", "now"][..],
            &["status", "--json"][..],
        ] {
            assert!(parse_mine(args).is_err(), "{args:?}");
        }
    }

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
