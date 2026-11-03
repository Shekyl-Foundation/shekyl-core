// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The shell's daemon client.
//!
//! One [`SyncDaemon`](shekyl_rpc_transport::SyncDaemon), connected on the
//! first request. The SOCKS proxy, the loopback down-hint and the timeout
//! are this client's; the bytes are the shared transport's.

use serde_json::Value;
use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use shekyl_rpc_client::RpcError;
use shekyl_rpc_transport::SyncDaemon;

use shekyl_rpc_transport::network_posture::{host_of, is_loopback_host};
use shekyl_rpc_types::mining::{MinerThreads, MiningStatusResponse, StartMiningRequest};
use shekyl_rpc_types::{GetInfoResponse, RpcStatus};

/// Errors from the daemon RPC client with differentiated failure modes.
#[derive(Debug)]
pub enum DaemonError {
    NotConfigured,
    ConnectionRefused {
        detail: String,
        /// Recovery copy naming the daemon invocation that would fix it
        /// (`shekyld --testnet` + port), filled by the client for loopback
        /// endpoints (CU-1; CLI_USABILITY.md §CU-5 F1). `None` for a remote
        /// daemon, where "start it" would mislead.
        hint: Option<String>,
    },
    SocksFailure(String),
    TlsFailure(String),
    MalformedResponse(String),
    /// A JSON-RPC refusal: the error class and the diagnostic code.
    RpcError {
        class: String,
        diagnostic: String,
    },
    /// Path-RPC status `BUSY` — `/start_mining` is `CHECK_CORE_READY`
    /// (`is_synchronized`); a syncing daemon will not mine.
    Busy,
    /// Any other non-OK path-RPC status, shown as the daemon wrote it.
    Refused(String),
    Other(String),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => write!(
                f,
                "Daemon not configured. Use --daemon-address to set the daemon endpoint."
            ),
            Self::ConnectionRefused { detail, hint } => {
                write!(
                    f,
                    "Daemon connection refused (is the daemon running?). Detail: {detail}"
                )?;
                if let Some(hint) = hint {
                    write!(f, "\n{hint}")?;
                }
                Ok(())
            }
            Self::SocksFailure(detail) => write!(
                f,
                "SOCKS/Tor proxy connection failed (check --proxy and Tor status). Detail: {detail}"
            ),
            Self::TlsFailure(detail) => write!(
                f,
                "TLS verification failed for daemon (the connection uses the system roots). Detail: {detail}"
            ),
            Self::MalformedResponse(detail) => {
                write!(f, "Daemon returned a malformed response: {detail}")
            }
            Self::RpcError { class, diagnostic } => write!(f, "{class} {diagnostic}"),
            Self::Busy => write!(
                f,
                "The daemon is still syncing and will not start mining until it is caught up."
            ),
            Self::Refused(message) => write!(f, "The daemon refused: {message}"),
            Self::Other(detail) => write!(f, "Daemon client error: {detail}"),
        }
    }
}

impl std::error::Error for DaemonError {}

/// How long one daemon request waits. The views, mining, `tx show`, the
/// shard reads and the startup check share it.
const DAEMON_TIMEOUT: Duration = Duration::from_secs(30);

/// The shell's one daemon client. The connection is opened on the first
/// request, so a run that never asks the daemon does not dial it.
pub struct DaemonClient {
    url: String,
    /// The SOCKS proxy this client was built with, so every request uses
    /// the same circuit.
    proxy: Option<String>,
    /// See [`DaemonError::ConnectionRefused`]: attached to every refused
    /// connection this client reports.
    down_hint: Option<String>,
    rpc: OnceLock<Arc<SyncDaemon>>,
}

/// Normalize a daemon address to the URL form the transports expect: a
/// scheme-less `host:port` is `http://host:port`; a URL is itself. The one
/// reading of `--daemon-address`, for the self-hosted server's scan
/// transport and the REPL's direct client alike.
#[must_use]
pub fn daemon_url(daemon_address: &str) -> String {
    if daemon_address.contains("://") {
        daemon_address.to_owned()
    } else {
        format!("http://{daemon_address}")
    }
}

/// Whether `address` names a loopback host, in any form the CLI accepts
/// (`host:port`, `http://host:port`, `[::1]:port`).
///
/// This is the one loopback predicate: [`host_of`] + [`is_loopback_host`],
/// the same classification the startup disclosure uses. A substring match
/// on `127.0.0.1` would both miss `127.0.0.0/8` / mapped IPv6 and accept
/// `127.0.0.1.evil.com`. Loopback is the silent default, not a force — a
/// remote `--daemon-address` is a valid configuration
/// (CLI_USABILITY.md §CU-3 F4).
#[must_use]
pub fn is_loopback_endpoint(address: &str) -> bool {
    is_loopback_host(host_of(address))
}

impl DaemonClient {
    /// Build a new daemon client.
    ///
    /// - `daemon_address`: e.g. `"http://127.0.0.1:11029"` or `"https://remote:11029"`.
    /// - `proxy`: optional SOCKS5 proxy address, e.g. `"socks5://127.0.0.1:9050"`.
    ///   The transport passes it to `SyncDaemon`. An `https://` daemon uses
    ///   the system root store (RT-W12 removes that arm).
    /// - `down_hint`: recovery copy attached to refused connections (the
    ///   caller knows the network and whether the endpoint is loopback).
    pub fn new(
        daemon_address: &str,
        proxy: Option<&str>,
        down_hint: Option<String>,
    ) -> Result<Self, DaemonError> {
        if daemon_address.is_empty() {
            return Err(DaemonError::NotConfigured);
        }

        Ok(Self {
            url: daemon_url(daemon_address),
            proxy: proxy.map(str::to_owned),
            down_hint,
            rpc: OnceLock::new(),
        })
    }

    /// The shared client, connected on the first call. Views, `tx show`,
    /// mining, the shard reads and the startup check all post through it.
    pub fn transport(&self) -> Result<Arc<SyncDaemon>, DaemonError> {
        if let Some(existing) = self.rpc.get() {
            return Ok(Arc::clone(existing));
        }
        let rpc = Arc::new(
            SyncDaemon::connect(self.url.clone(), self.proxy.clone(), DAEMON_TIMEOUT)
                .map_err(|error| classify_transport(&error))?,
        );
        // A concurrent first request may have stored one. Either client
        // speaks to the same daemon.
        match self.rpc.set(Arc::clone(&rpc)) {
            Ok(()) => Ok(rpc),
            Err(_) => Ok(Arc::clone(
                self.rpc.get().expect("another call stored the client"),
            )),
        }
    }

    fn rpc(&self) -> Result<Arc<SyncDaemon>, DaemonError> {
        self.transport()
    }

    /// The SOCKS proxy, when the client was built with one.
    #[must_use]
    pub fn proxy(&self) -> Option<&str> {
        self.proxy.as_deref()
    }

    /// Attach this client's recovery hint to a refused connection. Applied
    /// at the one seam every request passes through, so each caller's error
    /// display carries the copy without knowing about it.
    fn with_down_hint(&self, err: DaemonError) -> DaemonError {
        match err {
            DaemonError::ConnectionRefused { detail, hint: None } => {
                DaemonError::ConnectionRefused {
                    detail,
                    hint: self.down_hint.clone(),
                }
            }
            other => other,
        }
    }

    /// POST JSON to `path` (a daemon route, with or without a leading `/`).
    fn post_json(&self, path: &str, body: &Value) -> Result<Value, DaemonError> {
        let bytes = serde_json::to_vec(body)
            .map_err(|error| DaemonError::MalformedResponse(error.to_string()))?;
        let raw = self
            .rpc()?
            .post(path, bytes)
            .map_err(|error| self.with_down_hint(classify_transport(&error)))?;
        serde_json::from_slice(&raw)
            .map_err(|error| DaemonError::MalformedResponse(error.to_string()))
    }

    /// Call a JSON-RPC method on the daemon. `method` is the table's name
    /// ([`posted_json`]). The envelope is [`SyncDaemon::json_rpc`].
    fn json_rpc<Reply: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: &impl serde::Serialize,
    ) -> Result<Reply, DaemonError> {
        self.rpc()?
            .json_rpc(method, params)
            .map_err(|error| self.with_down_hint(json_rpc_error(error)))
    }

    /// Fetch daemon info (`get_info`). Used by `chain_health` and mining gates.
    ///
    /// The reply is the shared [`GetInfoResponse`], which decodes strictly:
    /// a member that is absent means the contract moved, not a safe zero. In
    /// particular a missing `restricted` cannot read as unrestricted.
    pub fn get_info(&self) -> Result<GetInfoResponse, DaemonError> {
        self.json_rpc(posted_json("get_info")?, &serde_json::json!({}))
    }

    /// `get_version`'s `result`, undecoded. Used by the mining gates.
    ///
    /// Undecoded because reading it is `shekyl_rpc_types`' (`RK-D25`): the
    /// caller hands it to [`shekyl_rpc_types::IdentityExpectation::read`],
    /// which reads the version before anything else. It is where a daemon
    /// names its network; `get_info` stopped repeating it at 3.54 (RK-Q6).
    pub fn get_version_result(&self) -> Result<Value, DaemonError> {
        self.json_rpc::<serde_json::Value>(posted_json("get_version")?, &serde_json::json!({}))
    }

    /// Operator coverage list. Empty params; the daemon orders the rows.
    /// Decoded as `shekyl-rpc-types`' wire type, the one the daemon answers
    /// with: an empty list is an omitted field (epee's), so a node with no
    /// closed shard still decodes.
    pub fn archival_shard_coverage(
        &self,
    ) -> Result<shekyl_rpc_types::GetArchivalShardCoverageResponse, DaemonError> {
        self.json_rpc(
            posted_json("get_archival_shard_coverage")?,
            &serde_json::json!({}),
        )
    }

    /// The configured daemon URL, for copy that names the endpoint
    /// (CLI_USABILITY.md §CU-5 F4).
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The F1 recovery copy this client was built with (`None` for remote
    /// daemons). For surfaces that report daemon-unreachable through a path
    /// that never dials this client — `status` reads `daemon_height: null`
    /// off the wallet RPC — and still owe the "start shekyld" line.
    #[must_use]
    pub fn down_hint(&self) -> Option<&str> {
        self.down_hint.as_deref()
    }

    /// True when the configured endpoint is a loopback address.
    ///
    /// Mining control does **not** refuse non-loopback (F4 is a reminder):
    /// the silent default is this machine, and a named remote daemon is an
    /// advanced configuration the operator is allowed to keep. Classification
    /// uses [`is_loopback_endpoint`].
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        is_loopback_endpoint(&self.url)
    }

    /// POST to one of the daemon's DJSON **path** handlers (`/start_mining`,
    /// `/stop_mining`, `/mining_status`, …). These are not `/json_rpc`
    /// methods. Success is a flat object whose `status` is `"OK"`; a grant
    /// or method refusal is the JSON-RPC error object on HTTP 200 (RW-Q3).
    fn path_rpc(&self, path: &str, body: &Value) -> Result<Value, DaemonError> {
        let parsed = self.post_json(path, body)?;
        classify_path_body(parsed)
    }

    /// Start the daemon's miner. It mines to the daemon's `mine-address`.
    /// The request is `{ threads }` (N2).
    pub fn start_mining(&self, threads: u64) -> Result<(), DaemonError> {
        let count = u32::try_from(threads)
            .ok()
            .and_then(std::num::NonZeroU32::new)
            .ok_or_else(|| DaemonError::Other("thread count is not a positive count".into()))?;
        let body = serde_json::to_value(StartMiningRequest {
            threads: MinerThreads::Count(count),
        })
        .map_err(|error| DaemonError::MalformedResponse(error.to_string()))?;
        self.path_rpc(posted_rest("/start_mining")?, &body)
            .map(|_| ())
    }

    /// Stop mining on the daemon (CU-3).
    pub fn stop_mining(&self) -> Result<(), DaemonError> {
        self.path_rpc(posted_rest("/stop_mining")?, &serde_json::json!({}))
            .map(|_| ())
    }

    /// Query the daemon's mining state (CU-3).
    pub fn mining_status(&self) -> Result<MiningStatusResponse, DaemonError> {
        let value = self.path_rpc(posted_rest("/mining_status")?, &serde_json::json!({}))?;
        serde_json::from_value(value)
            .map_err(|e| DaemonError::MalformedResponse(format!("mining_status: {e}")))
    }
}

pub(crate) fn posted_json(name: &str) -> Result<&'static str, DaemonError> {
    shekyl_rpc_types::methods::json_rpc(name)
        .map(|method| method.name)
        .ok_or_else(|| DaemonError::Other(format!("{name} is not a daemon method")))
}

pub(crate) fn posted_rest(path: &str) -> Result<&'static str, DaemonError> {
    shekyl_rpc_types::methods::rest_path(path)
        .map(|method| method.name)
        .ok_or_else(|| DaemonError::Other(format!("{path} is not a daemon method")))
}

fn json_rpc_error(error: shekyl_rpc_transport::JsonRpcError) -> DaemonError {
    match error {
        shekyl_rpc_transport::JsonRpcError::Transport(error) => classify_transport(&error),
        shekyl_rpc_transport::JsonRpcError::Refusal(refusal) => DaemonError::RpcError {
            class: format!("{:?}", refusal.class),
            diagnostic: refusal.diagnostic.code,
        },
        shekyl_rpc_transport::JsonRpcError::Malformed(detail) => {
            DaemonError::MalformedResponse(detail)
        }
    }
}

/// A JSON-RPC `error` object, as its class and diagnostic code.
fn refusal_of(error: &Value) -> DaemonError {
    match shekyl_rpc_types::errors::read_error_object(error) {
        Some(refusal) => DaemonError::RpcError {
            class: format!("{:?}", refusal.class),
            diagnostic: refusal.diagnostic.code,
        },
        None => {
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(-1);
            DaemonError::Refused(format!("unclassified {code}"))
        }
    }
}

/// Decode a path-RPC body. The JSON-RPC error object (grant, parse, method)
/// is checked before `status`, because a refusal on this surface has no
/// `status` field (RW-Q3).
fn classify_path_body(parsed: Value) -> Result<Value, DaemonError> {
    if let Some(err) = parsed.get("error") {
        if err.is_object() {
            return Err(refusal_of(err));
        }
        if let Some(message) = err.as_str() {
            return Err(DaemonError::Refused(message.to_owned()));
        }
    }
    match parsed.get("status").and_then(|s| s.as_str()) {
        Some(status) => classify_path_status(status).map(|()| parsed),
        None => Err(DaemonError::MalformedResponse(
            "missing 'status' field".into(),
        )),
    }
}

/// Map a path-RPC `status` field. `"OK"` continues; known refusals become
/// typed errors so callers never print `daemon replied: BUSY`.
fn classify_path_status(status: &str) -> Result<(), DaemonError> {
    match RpcStatus(status.to_owned()).kind() {
        shekyl_rpc_types::StatusKind::Ok => Ok(()),
        shekyl_rpc_types::StatusKind::Busy => Err(DaemonError::Busy),
        shekyl_rpc_types::StatusKind::Offline | shekyl_rpc_types::StatusKind::Other => {
            Err(DaemonError::Refused(status.to_owned()))
        }
    }
}

fn classify_transport(err: &RpcError) -> DaemonError {
    match err {
        RpcError::ConnectionError(detail) => DaemonError::ConnectionRefused {
            detail: detail.clone(),
            hint: None,
        },
        other => DaemonError::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_path_body, classify_path_status, is_loopback_endpoint, DaemonError,
        GetInfoResponse,
    };

    #[test]
    fn loopback_classification_uses_the_canonical_host_check() {
        for addr in [
            "127.0.0.1:11029",
            "http://127.0.0.1:11029",
            "http://localhost:11029",
            "http://[::1]:11029",
            "[::1]:11029",
            "127.0.0.2:11029",
            "http://[::ffff:127.0.0.1]:11029",
        ] {
            assert!(is_loopback_endpoint(addr), "expected loopback: {addr}");
        }
        for addr in [
            "node.example.com:11029",
            "http://127.0.0.1.evil.com:11029",
            "10.0.0.5:11029",
            "http://192.168.1.10:11029",
        ] {
            assert!(
                !is_loopback_endpoint(addr),
                "expected non-loopback (warn, do not refuse): {addr}"
            );
        }
    }

    #[test]
    fn path_status_maps_known_refusals() {
        assert!(classify_path_status("OK").is_ok());
        assert!(matches!(
            classify_path_status("BUSY"),
            Err(DaemonError::Busy)
        ));
        match classify_path_status("Already mining") {
            Err(DaemonError::Refused(msg)) => assert_eq!(msg, "Already mining"),
            other => panic!("expected Refused, got {other:?}"),
        }
        match classify_path_status("Failed, wrong address") {
            Err(DaemonError::Refused(msg)) => assert!(msg.contains("wrong address")),
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn path_body_reads_a_json_rpc_error_envelope() {
        let class = shekyl_rpc_types::errors::ErrorClass::OutsideTheGrant;
        let parsed = serde_json::json!({
            "error": {
                "code": class.code(),
                "message": "this connection's grant does not include mining",
                "data": {
                    "code": "rpc.grant",
                    "params": [],
                    "message": "this connection's grant does not include mining"
                }
            }
        });
        match classify_path_body(parsed) {
            Err(DaemonError::RpcError { class, diagnostic }) => {
                assert_eq!(class, "OutsideTheGrant");
                assert_eq!(diagnostic, "rpc.grant");
            }
            other => panic!("expected RpcError, got {other:?}"),
        }
    }

    /// A complete `get_info` reply, as the daemon serializes it.
    fn get_info_reply() -> serde_json::Value {
        use shekyl_rpc_types::{
            HashHex, Hidden, InfoChain, InfoEconomics, InfoHealth, InfoIdentity, InfoPeers,
            InfoPool, InfoStatus, RpcStatus,
        };
        serde_json::to_value(GetInfoResponse {
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

    /// The mining gates read `restricted` and `synchronized` from this
    /// reply. One missing either does not decode — above all a missing
    /// `restricted` must not read as unrestricted. The network gate reads
    /// `get_version` (RK-Q6); its tests are beside it in `commands/mine.rs`.
    #[test]
    fn get_info_refuses_a_missing_gate_field() {
        for gate in ["restricted", "synchronized", "height"] {
            let mut reply = get_info_reply();
            reply.as_object_mut().expect("object").remove(gate);
            assert!(
                serde_json::from_value::<GetInfoResponse>(reply).is_err(),
                "a reply without `{gate}` must not decode"
            );
        }

        let info: GetInfoResponse =
            serde_json::from_value(get_info_reply()).expect("complete get_info");
        assert!(!info.restricted);
        assert!(info.health.synchronized);
    }
}
