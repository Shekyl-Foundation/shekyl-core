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
//! §CU-3): unrestricted RPC and a matching network. The mine words do not
//! require an open wallet; the daemon pays its `mine-address` (IG-Q21).
//! `mine start` additionally refuses a daemon that is not synced (the
//! daemon's own `CHECK_CORE_READY`) and reminds — does not refuse — when
//! the endpoint is not on this machine, because mining will run on that
//! machine's CPU.

use serde_json::{json, Value};
use shekyl_rpc_types::mining::MineSpeed;

use crate::daemon::{DaemonClient, DaemonError};
use crate::display::short_address;
use crate::outcome::{failed, refusal, CommandFailed, CommandResult};
use shekyl_rpc_types::GetInfoResponse;

/// The wallet-convenience default thread count: `min(available cores, 4)`.
/// Not a tuned miner — operators who care pass a count or drive `shekyld`
/// directly.
fn default_threads() -> u64 {
    let cores = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1) as u64;
    cores.min(4)
}

/// The shared fail-closed gates (CU-3 / §CU-5 F2, F3). Returns the
/// daemon's `get_info` snapshot when every gate passes, so callers get the
/// sync fields without a second round-trip.
///
/// No wallet check. The shell does not supply a payout address (IG-Q21);
/// the daemon mines to its `mine-address`.
fn gate(daemon: Option<&DaemonClient>) -> Result<(&DaemonClient, GetInfoResponse), CommandFailed> {
    let Some(dc) = daemon else {
        return Err(refusal(DaemonError::NotConfigured.to_string()));
    };

    // F2 and the sync fields are one `get_info`. The handshake inside it
    // refuses a daemon on another network before mining is asked. A refused
    // connection carries the F1 "start shekyld" hint via DaemonClient.
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

/// Reminder, not a refusal. Mining on a daemon that is not on this machine
/// uses that machine's CPU.
fn remote_mining_note(dc: &DaemonClient) -> Option<String> {
    if dc.is_loopback() {
        None
    } else {
        Some(format!(
            "Note: this daemon ({}) is not on this machine. Mining will run on that machine's CPU.",
            dc.url()
        ))
    }
}

fn remind_if_remote(dc: &DaemonClient) {
    if let Some(note) = remote_mining_note(dc) {
        eprintln!("{note}");
    }
}

/// Printed after a successful `mine start`. The built-in hasher is the
/// node's checker, not a competitive miner; a miner for another coin
/// (including stock Monero XMRig) will not produce accepted blocks.
const BUILT_IN_MINER_NOTICE: &str = "\
The daemon is using its built-in checker, which is correct but not the \
fastest miner for this CPU. For more hashrate, run a dedicated miner that \
uses this node's block template — a miner built for another coin will not \
produce blocks this network accepts.";

/// `mine start [threads|auto]` — start mining on the daemon.
///
/// The daemon pays its `mine-address`. The shell sends only the thread
/// count, and does not require an open wallet (IG-Q21).
pub fn cmd_mine_start(daemon: Option<&DaemonClient>, threads: Option<u64>) -> CommandResult {
    let (dc, info) = gate(daemon)?;
    remind_if_remote(dc);

    // F6 — already mining: relay the daemon's state, no error tone.
    let address = match dc.mining_status() {
        Ok(status) if status.active => {
            return Ok(json!({
                "started": false,
                "already_mining": true,
                "threads": status.threads_count,
            }));
        }
        Ok(status) => status.address,
        Err(e) => return failed(e.to_string()),
    };

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

    let threads = threads.unwrap_or_else(default_threads);
    match dc.start_mining(threads) {
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
pub fn cmd_mine_stop(daemon: Option<&DaemonClient>) -> CommandResult {
    let (dc, _info) = gate(daemon)?;

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
pub fn cmd_mine_status(daemon: Option<&DaemonClient>) -> CommandResult {
    let (dc, _info) = gate(daemon)?;

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
    let rate = val
        .get("speed")
        .cloned()
        .and_then(|speed| serde_json::from_value::<MineSpeed>(speed).ok())
        .map_or_else(|| "0 H/s".to_owned(), MineSpeed::hashes_per_second_text);
    println!("  Hash rate:  {rate}");
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
    use crate::daemon::identity_line;
    use shekyl_rpc_types::{
        genesis_hash_for, GetVersionResponse, HashHex, IdentityExpectation, Network, Nullable,
        RpcStatus, CONSENSUS_CONSTANTS_DIGEST_HASH, CORE_RPC_VERSION,
    };

    const URL: &str = "http://127.0.0.1:12029";

    /// What a daemon of this build answers `get_version` with on `network`.
    fn version_reply(network: Network) -> serde_json::Value {
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
        // Every network the table has, regtest included (NI-R1, NI-R4).
        for network in Network::ALL {
            IdentityExpectation::exact(network)
                .read(&version_reply(network))
                .unwrap_or_else(|error| panic!("{network}: {error:?}"));
        }
    }

    /// F2, read from `get_version` (RK-Q6): a daemon on another network is
    /// refused, and the refusal names both networks and the endpoint.
    #[test]
    fn the_gate_refuses_a_daemon_on_another_network() {
        let refused = IdentityExpectation::exact(Network::Testnet)
            .read(&version_reply(Network::Mainnet))
            .expect_err("a mainnet daemon is not a testnet daemon");
        let line = identity_line(&refused.mismatch, URL);
        assert!(
            line.contains("network mismatch")
                && line.contains("This CLI is on testnet")
                && line.contains("reports mainnet")
                && line.contains(URL),
            "{line}"
        );
    }

    /// A regtest daemon reports `regtest`, a network like the others
    /// (NI-Q8): a mainnet CLI refuses it on the network axis, naming it.
    #[test]
    fn the_gate_refuses_a_regtest_daemon_from_mainnet() {
        let refused = IdentityExpectation::exact(Network::Mainnet)
            .read(&version_reply(Network::Regtest))
            .expect_err("a regtest daemon is not a mainnet daemon");
        let line = identity_line(&refused.mismatch, URL);
        assert!(line.contains("reports regtest"), "{line}");
    }

    /// The reply has no network to compare unless it is this build's reply:
    /// a daemon on another RPC version is refused on that, by version.
    #[test]
    fn the_gate_refuses_a_daemon_on_another_rpc_version() {
        let mut reply = version_reply(Network::Testnet);
        reply["version"] = (CORE_RPC_VERSION - 1).into();
        let refused = IdentityExpectation::exact(Network::Testnet)
            .read(&reply)
            .expect_err("an older daemon");
        let line = identity_line(&refused.mismatch, URL);
        assert!(
            line.contains("RPC contract mismatch") && line.contains("the daemon is the older one"),
            "{line}"
        );
    }

    /// A reply that does not name a network is not a daemon on this one.
    #[test]
    fn the_gate_refuses_a_reply_without_a_network() {
        let mut reply = version_reply(Network::Testnet);
        reply.as_object_mut().expect("object").remove("nettype");
        let refused = IdentityExpectation::exact(Network::Testnet)
            .read(&reply)
            .expect_err("no network named");
        let line = identity_line(&refused.mismatch, URL);
        assert!(line.contains("does not match the RPC contract"), "{line}");
        assert!(line.contains("cannot be named here"), "{line}");
        assert!(
            !line.contains("nettype"),
            "the daemon's own text is not repeated: {line}"
        );
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

    /// A loopback daemon is the silent default: no reminder.
    #[test]
    fn a_loopback_daemon_is_not_reminded() {
        let daemon = crate::daemon::DaemonClient::new(
            "http://127.0.0.1:18081",
            None,
            None,
            Network::Mainnet,
        )
        .expect("loopback parses");
        assert!(super::remote_mining_note(&daemon).is_none());
    }

    /// A non-loopback daemon is reminded, and mining still starts.
    ///
    /// The reminder is the daemon URL. The start goes to the console's route
    /// server (`console/tests.rs`). When G3 moves the session onto one
    /// `SyncDaemon`, this test moves with it and keeps that server.
    ///
    /// `cmd_mine_start` takes no session, so it cannot ask whether a wallet
    /// is open.
    #[test]
    fn a_remote_daemon_is_reminded_and_mining_still_starts() {
        let remote = crate::daemon::DaemonClient::new(
            "http://203.0.113.5:18081",
            None,
            None,
            Network::Mainnet,
        )
        .expect("remote address parses");
        let note = super::remote_mining_note(&remote).expect("a remote daemon is reminded");
        assert_eq!(
            note,
            "Note: this daemon (http://203.0.113.5:18081) is not on this machine. \
             Mining will run on that machine's CPU."
        );

        let info = shekyl_rpc_transport::json_rpc_result_body(&info_reply());
        let (address, log) = crate::console::route_server_recording(vec![
            ("json_rpc:get_info", info),
            (
                "/mining_status",
                r#"{"status":"OK","active":false,"speed":{"count":0,"window":0},"threads_count":0,"address":"4test","pow_algorithm":"randomx","block_target":120,"block_reward":0,"difficulty":1,"wide_difficulty":"1","difficulty_top64":0,"height":0,"pool_retired":false,"no_template":null}"#.to_owned(),
            ),
            ("/start_mining", r#"{"status":"OK"}"#.to_owned()),
        ]);
        let daemon = crate::daemon::DaemonClient::new(
            &format!("http://{address}"),
            None,
            None,
            Network::Mainnet,
        )
        .expect("the route server parses");

        let result = super::cmd_mine_start(Some(&daemon), Some(1)).expect("mining starts");
        assert_eq!(result["started"], true);
        let asked = log.lock().expect("log");
        assert!(
            asked.iter().any(|(path, _)| path == "/start_mining"),
            "mine start with no wallet reached /start_mining: {asked:?}"
        );
    }

    fn info_reply() -> serde_json::Value {
        use shekyl_rpc_types::{
            HashHex, Hidden, InfoChain, InfoEconomics, InfoHealth, InfoIdentity, InfoPeers,
            InfoPool, InfoStatus, RpcStatus,
        };
        serde_json::to_value(shekyl_rpc_types::GetInfoResponse {
            status: RpcStatus::ok(),
            health: InfoHealth {
                height: 1,
                top_block_hash: HashHex::from_bytes([7; 32]),
                target_height: shekyl_rpc_types::Nullable::NULL,
                synchronized: true,
                busy_syncing: false,
                following_degraded: false,
                p2p: shekyl_rpc_types::HealthP2p::Running { has_peers: true },
            },
            identity: InfoIdentity {
                protocol_version: 3,
            },
            chain: InfoChain {
                difficulty: 1,
                cumulative_difficulty: 1,
                target: 120,
                tx_count: 0,
                block_weight_limit: 600_000,
                block_weight_median: 300_000,
                adjusted_time: 0,
            },
            economics: InfoEconomics {
                already_generated_coins: shekyl_units::AtomicUnits::ZERO,
                release_multiplier: 1_000_000,
                burn_pct: 0,
                total_burned: shekyl_units::AtomicUnits::ZERO,
                staker_emission_share_effective: 0,
            },
            pool: InfoPool::Live { tx_pool_size: 0 },
            node: Hidden::Shown(InfoStatus {
                start_time: 1,
                free_space: 1,
                database_size: 1,
                version: "test".to_owned(),
                connections: shekyl_rpc_types::StatusConnections::Running {
                    outgoing: 0,
                    incoming: 0,
                },
                alt_blocks_count: 0,
                rpc_connections_count: 0,
            }),
            peers: Hidden::Shown(shekyl_rpc_types::InfoP2p::Running(InfoPeers {
                public_incoming_socket_count: 0,
                public_outgoing_socket_count: 0,
                tor_incoming_socket_count: 0,
                tor_outgoing_socket_count: 0,
                white_peerlist_size: 0,
                grey_peerlist_size: 0,
            })),
            host: Hidden::Withheld,
            restricted: false,
        })
        .expect("a get_info reply serializes")
    }
}
