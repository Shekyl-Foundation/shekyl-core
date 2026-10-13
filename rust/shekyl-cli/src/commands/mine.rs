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

use crate::daemon::DaemonClient;
use crate::display::short_address;
use crate::outcome::{failed, refusal, CommandFailed, CommandResult};
use crate::rpc_client::RpcSession;
use shekyl_rpc_types::{
    core_rpc_version_string, DaemonNetwork, GetInfoResponse, IdentityExpectation, IdentityMismatch,
    IdentityRefusal,
};

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
) -> Result<(&'a DaemonClient, GetInfoResponse), CommandFailed> {
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

    // F2 — the daemon's identity, read before anything else is asked of
    // it. A refused connection carries the F1 "start shekyld" hint via
    // DaemonClient.
    let version = dc
        .get_version_result()
        .map_err(|e| refusal(e.to_string()))?;
    identity_gate(network, dc.url(), &version)?;

    // One get_info answers F3 and the sync fields.
    let info = dc.get_info().map_err(|e| refusal(e.to_string()))?;

    // F3 — restricted listener: admin RPCs are not served there.
    if info.restricted {
        return Err(refusal(
            "The daemon's RPC listener is restricted (view-only); mining control \
             needs the unrestricted RPC listener.",
        ));
    }

    Ok((dc, info))
}

/// F2 — the daemon must be this CLI's network: a testnet wallet pointing at
/// a mainnet daemon would mine (and pay out) on the wrong network.
///
/// `version` is `get_version`'s `result`, which is where a daemon names its
/// network (`get_info` repeated it until 3.54, RK-Q6). It is read by the one
/// reader of that reply, [`IdentityExpectation::read`], so the gate refuses
/// on the same four axes every other client does: the RPC version, the
/// consensus rules, the network and the genesis block. A network that is
/// omitted or unknown does not decode, so there is no empty case to skip.
/// A `--regtest` daemon reports `fakechain`, which no CLI network is, and
/// is refused as it always was.
fn identity_gate(network: &str, url: &str, version: &Value) -> Result<(), CommandFailed> {
    let ours = [
        DaemonNetwork::Mainnet,
        DaemonNetwork::Testnet,
        DaemonNetwork::Stagenet,
    ]
    .into_iter()
    .find(|candidate| candidate.as_str() == network)
    .ok_or_else(|| {
        refusal(format!(
            "This CLI is on a network it cannot name to the daemon ({network}); mining \
             control needs mainnet, testnet or stagenet."
        ))
    })?;
    IdentityExpectation::exact(ours)
        .read(version)
        .map(|_| ())
        .map_err(|IdentityRefusal { mismatch, .. }| refusal(identity_message(&mismatch, url)))
}

/// This CLI's wording of an identity refusal, one sentence per axis. The
/// wallet and the console word the same verdict their own way; the axes are
/// compared once, in [`IdentityExpectation::read`]. What failed to parse in
/// an unreadable reply is the daemon's own text and is not repeated here.
fn identity_message(mismatch: &IdentityMismatch, url: &str) -> String {
    match *mismatch {
        IdentityMismatch::Network { ours, theirs } => format!(
            "Network mismatch: this CLI is on {ours} but the daemon at {url} reports {theirs}.\n\
             Restart shekyl-cli or shekyld so both use the same \
             --testnet/--stagenet flag."
        ),
        IdentityMismatch::Wire { ours, theirs } => {
            let older = if theirs < ours {
                "daemon"
            } else {
                "shekyl-cli"
            };
            format!(
                "Version mismatch: this shekyl-cli speaks RPC {} but the daemon at {url} \
                 speaks {}.\nThe {older} is the older one; update it.",
                core_rpc_version_string(ours),
                core_rpc_version_string(theirs),
            )
        }
        IdentityMismatch::WireUnreadable { ours } => format!(
            "Version mismatch: the daemon at {url} did not answer `get_version` in a form \
             this shekyl-cli (RPC {}) can read, so the two are on different versions.\n\
             Update whichever is older.",
            core_rpc_version_string(ours),
        ),
        IdentityMismatch::Rules { .. } => format!(
            "Rules mismatch: the daemon at {url} was built with different consensus \
             settings from this shekyl-cli.\nUse a shekyl-cli and shekyld from the same \
             release."
        ),
        IdentityMismatch::Genesis { network, .. } => format!(
            "Chain mismatch: the daemon at {url} is on a different {network} chain from \
             the one this shekyl-cli was built for.\nUse a shekyl-cli and shekyld from \
             the same release."
        ),
    }
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
    if !info.health.synchronized {
        let height = info.health.height;
        // The target is for the message only; the refusal is the flag's.
        let of_target = match info.health.target_height.into_option() {
            Some(target) if target > height => format!("height {height} of {target}"),
            _ => format!("height {height}"),
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
    use super::{identity_gate, BUILT_IN_MINER_NOTICE};
    use shekyl_rpc_types::{
        genesis_hash_for, DaemonNetwork, GetVersionResponse, HashHex, Nullable, RpcStatus,
        CONSENSUS_CONSTANTS_DIGEST_HASH, CORE_RPC_VERSION,
    };

    const URL: &str = "http://127.0.0.1:12029";

    /// What a daemon of this build answers `get_version` with on `network`.
    fn version_reply(network: DaemonNetwork) -> serde_json::Value {
        serde_json::to_value(GetVersionResponse {
            status: RpcStatus::ok(),
            version: CORE_RPC_VERSION,
            release: false,
            current_height: 10,
            target_height: Nullable::NULL,
            consensus_constants_digest: CONSENSUS_CONSTANTS_DIGEST_HASH,
            nettype: network,
            genesis_hash: HashHex::from_bytes(genesis_hash_for(network)),
        })
        .expect("a get_version reply serializes")
    }

    #[test]
    fn the_gate_passes_a_daemon_on_this_clis_network() {
        for network in [
            DaemonNetwork::Mainnet,
            DaemonNetwork::Testnet,
            DaemonNetwork::Stagenet,
        ] {
            identity_gate(network.as_str(), URL, &version_reply(network))
                .unwrap_or_else(|e| panic!("{network}: {}", e.message));
        }
    }

    /// F2, read from `get_version` (RK-Q6): a daemon on another network is
    /// refused, and the refusal names both networks and the endpoint.
    #[test]
    fn the_gate_refuses_a_daemon_on_another_network() {
        let refused = identity_gate("testnet", URL, &version_reply(DaemonNetwork::Mainnet))
            .expect_err("a mainnet daemon is not a testnet daemon");
        assert!(
            refused.message.starts_with("Network mismatch:")
                && refused.message.contains("this CLI is on testnet")
                && refused.message.contains("reports mainnet")
                && refused.message.contains(URL),
            "{}",
            refused.message
        );
    }

    /// A `--regtest` daemon reports `fakechain`. No CLI network is that, so
    /// mining control refuses it, as it did when the network came from
    /// `get_info`.
    #[test]
    fn the_gate_refuses_a_fakechain_daemon() {
        let refused = identity_gate("mainnet", URL, &version_reply(DaemonNetwork::Fakechain))
            .expect_err("a fakechain daemon is not a mainnet daemon");
        assert!(
            refused.message.contains("reports fakechain"),
            "{}",
            refused.message
        );
    }

    /// The reply has no network to compare unless it is this build's reply:
    /// a daemon on another RPC version is refused on that, by version.
    #[test]
    fn the_gate_refuses_a_daemon_on_another_rpc_version() {
        let mut reply = version_reply(DaemonNetwork::Testnet);
        reply["version"] = (CORE_RPC_VERSION - 1).into();
        let refused = identity_gate("testnet", URL, &reply).expect_err("an older daemon");
        assert!(
            refused.message.starts_with("Version mismatch:")
                && refused.message.contains("The daemon is the older one"),
            "{}",
            refused.message
        );
    }

    /// A reply that does not name a network is not a daemon on this one.
    #[test]
    fn the_gate_refuses_a_reply_without_a_network() {
        let mut reply = version_reply(DaemonNetwork::Testnet);
        reply.as_object_mut().expect("object").remove("nettype");
        let refused = identity_gate("testnet", URL, &reply).expect_err("no network named");
        assert!(
            refused.message.starts_with("Version mismatch:"),
            "{}",
            refused.message
        );
        assert!(
            !refused.message.contains("nettype"),
            "the daemon's own text is not repeated: {}",
            refused.message
        );
    }

    #[test]
    fn the_gate_refuses_a_cli_network_it_cannot_name() {
        let refused = identity_gate("fakechain", URL, &version_reply(DaemonNetwork::Fakechain))
            .expect_err("the CLI is never on fakechain");
        assert!(refused.message.contains("fakechain"), "{}", refused.message);
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
