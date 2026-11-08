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

use shekyl_rpc_transport::network_posture::{host_of, is_loopback_host};
use shekyl_rpc_transport::{JsonRpcError, PostFault, SyncDaemon, TransportFault};
use shekyl_rpc_types::mining::{MinerThreads, MiningStatusResponse, StartMiningRequest};
use shekyl_rpc_types::{
    core_rpc_version_string, GetInfoResponse, IdentityExpectation, IdentityMismatch, Network,
    RpcStatus,
};

/// Errors from the daemon RPC client with differentiated failure modes.
#[derive(Clone, Debug)]
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
    /// The identity handshake refused this daemon. The line is
    /// [`identity_line`].
    Identity(String),
    /// A JSON-RPC refusal. The operator line is [`shekyl_rpc_types::errors::RpcError::report`].
    Refusal(shekyl_rpc_types::errors::RpcError),
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
            Self::Identity(line) => write!(f, "{line}"),
            Self::Refusal(refusal) => write!(f, "{}", refusal.report()),
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
    /// The network this shell is on. The handshake requires the daemon to
    /// report the same one.
    network: Network,
    rpc: OnceLock<Arc<SyncDaemon>>,
    /// The handshake, computed once and reused (RK-Q6). `version` does not
    /// consult it.
    identity: OnceLock<Result<(), DaemonError>>,
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
    ///   caller knows whether the endpoint is loopback).
    /// - `network`: this shell's network. One client has one.
    pub fn new(
        daemon_address: &str,
        proxy: Option<&str>,
        down_hint: Option<String>,
        network: Network,
    ) -> Result<Self, DaemonError> {
        if daemon_address.is_empty() {
            return Err(DaemonError::NotConfigured);
        }

        Ok(Self {
            url: daemon_url(daemon_address),
            proxy: proxy.map(str::to_owned),
            down_hint,
            network,
            rpc: OnceLock::new(),
            identity: OnceLock::new(),
        })
    }

    /// The network this client handshakes against.
    #[must_use]
    pub fn network(&self) -> Network {
        self.network
    }

    /// The shared connection, opened on the first call. No handshake.
    fn connect(&self) -> Result<Arc<SyncDaemon>, DaemonError> {
        if let Some(existing) = self.rpc.get() {
            return Ok(Arc::clone(existing));
        }
        let rpc = Arc::new(
            SyncDaemon::connect(self.url.clone(), self.proxy.clone(), DAEMON_TIMEOUT)
                .map_err(|error| self.error_of_post(error))?,
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

    /// The handshake, once. A later request reuses the verdict.
    ///
    /// A connection failure is not cached: the daemon may be started
    /// between two commands. An identity refusal is cached, because asking
    /// again cannot succeed against the same daemon.
    fn ensure_identity(&self) -> Result<(), DaemonError> {
        if let Some(cached) = self.identity.get() {
            return cached.clone();
        }
        let verdict = match self.handshake() {
            Ok(()) => Ok(()),
            Err(error @ DaemonError::Identity(_)) => Err(error),
            Err(other) => return Err(other),
        };
        match self.identity.set(verdict.clone()) {
            Ok(()) => verdict,
            Err(_) => self.identity.get().expect("the verdict was stored").clone(),
        }
    }

    fn handshake(&self) -> Result<(), DaemonError> {
        let rpc = self.connect()?;
        let result = match Self::read_version(&rpc) {
            Ok(result) => result,
            Err(JsonRpcError::Malformed(detail)) => {
                return Err(DaemonError::Identity(format!(
                    "{} (evidence: {detail})",
                    identity_line(&IdentityMismatch::unreadable(), self.url())
                )));
            }
            Err(other) => return Err(self.error_of_json_rpc(other)),
        };
        IdentityExpectation::exact(self.network)
            .read(&result)
            .map(|_| ())
            .map_err(|refusal| {
                let message = identity_line(&refusal.mismatch, self.url());
                DaemonError::Identity(match refusal.evidence {
                    Some(evidence) => format!("{message} (evidence: {evidence})"),
                    None => message,
                })
            })
    }

    /// `get_version`'s `result`, with no identity check. The handshake and
    /// `version` are the two readers; a daemon `version` is willing to
    /// describe is one the handshake would refuse.
    fn read_version(rpc: &SyncDaemon) -> Result<Value, JsonRpcError> {
        let method = posted_json("get_version")
            .map_err(|error| JsonRpcError::Malformed(error.to_string()))?;
        rpc.json_rpc(method, &serde_json::json!({}))
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

    /// POST `body` to `path` after the handshake.
    pub(crate) fn post(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, DaemonError> {
        self.ensure_identity()?;
        self.post_unchecked(path, body)
    }

    /// POST `body` to `path` without the handshake. `version` reads
    /// `/get_info` through this: a daemon it is describing is one the
    /// handshake would refuse.
    pub(crate) fn post_unchecked(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, DaemonError> {
        self.connect()?
            .post(path, body)
            .map_err(|error| self.error_of_post(error))
    }

    /// POST JSON to `path` (a daemon route, with or without a leading `/`).
    fn post_json(&self, path: &str, body: &Value) -> Result<Value, DaemonError> {
        let bytes = serde_json::to_vec(body)
            .map_err(|error| DaemonError::MalformedResponse(error.to_string()))?;
        let raw = self.post(path, bytes)?;
        serde_json::from_slice(&raw)
            .map_err(|error| DaemonError::MalformedResponse(error.to_string()))
    }

    /// Call a JSON-RPC method on the daemon. `method` is the table's name
    /// ([`posted_json`]). The envelope is [`SyncDaemon::json_rpc`]. The
    /// handshake runs first.
    pub(crate) fn json_rpc<Reply: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: &impl serde::Serialize,
    ) -> Result<Reply, DaemonError> {
        self.ensure_identity()?;
        self.connect()?
            .json_rpc(method, params)
            .map_err(|error| self.error_of_json_rpc(error))
    }

    /// Fetch daemon info (`get_info`). Used by `chain_health` and mining gates.
    ///
    /// The reply is the shared [`GetInfoResponse`], which decodes strictly:
    /// a member that is absent means the contract moved, not a safe zero. In
    /// particular a missing `restricted` cannot read as unrestricted.
    pub fn get_info(&self) -> Result<GetInfoResponse, DaemonError> {
        self.json_rpc(posted_json("get_info")?, &serde_json::json!({}))
    }

    /// `get_version`'s `result`, undecoded, with no identity check.
    ///
    /// Undecoded because reading it is `shekyl_rpc_types`' (`RK-D25`): the
    /// handshake hands it to [`IdentityExpectation::read`], and `version`
    /// to [`shekyl_rpc_types::daemon_rpc_version`]. It is where a daemon
    /// names its network; `get_info` stopped repeating it at 3.54 (RK-Q6).
    pub fn get_version_result(&self) -> Result<Value, DaemonError> {
        let rpc = self.connect()?;
        Self::read_version(&rpc).map_err(|error| self.error_of_json_rpc(error))
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

/// The shell's wording of an identity refusal, one sentence per axis.
///
/// The wallet words the same verdict its own way. The axes are compared
/// once, in [`IdentityExpectation::read`]. `url` is the daemon this shell
/// reached.
pub(crate) fn identity_line(mismatch: &IdentityMismatch, url: &str) -> String {
    match *mismatch {
        IdentityMismatch::Wire { ours, theirs } => {
            let older = if theirs < ours {
                "daemon"
            } else {
                "this build"
            };
            format!(
                "refusing to render: RPC contract mismatch. This build is {}, the daemon at \
                 {url} is {} — the {older} is the older one; update it.",
                core_rpc_version_string(ours),
                core_rpc_version_string(theirs),
            )
        }
        IdentityMismatch::WireUnreadable { ours } => format!(
            "refusing to render: the daemon at {url}'s `get_version` does not match the RPC \
             contract this build was compiled against, so the two are on different RPC \
             versions. This build is {}. The reply could not be read, so the daemon's \
             version cannot be named here; align the two builds.",
            core_rpc_version_string(ours),
        ),
        IdentityMismatch::Rules { ours, theirs } => format!(
            "refusing to render: consensus-constant mismatch. This build's digest is {ours}, \
             the daemon at {url} reports {theirs}. The RPC contract matches, so neither side \
             is a stale release — one tree's config/ differs from the other, which is a \
             different rule set rather than a version skew. Compare \
             config/consensus_constants.json and config/economics_params.json between the two \
             builds.",
        ),
        IdentityMismatch::Network { ours, theirs } => format!(
            "refusing to render: network mismatch. This CLI is on {ours}, the daemon at {url} \
             reports {theirs}."
        ),
        IdentityMismatch::Genesis {
            ours,
            theirs,
            network,
        } => format!(
            "refusing to render: genesis mismatch. The daemon at {url} starts at {theirs}, \
             this build's {network} genesis is {ours}. Whatever else agrees, that is a \
             different chain."
        ),
    }
}

impl DaemonClient {
    fn error_of_json_rpc(&self, error: JsonRpcError) -> DaemonError {
        match error {
            JsonRpcError::Transport(fault) => self.error_of_post(fault),
            JsonRpcError::Refusal(refusal) => DaemonError::Refusal(refusal),
            JsonRpcError::Malformed(detail) => DaemonError::MalformedResponse(detail),
        }
    }

    fn error_of_post(&self, fault: PostFault) -> DaemonError {
        let error = match fault {
            PostFault::Connection(fault) => from_transport(fault),
            PostFault::Protocol(error) => DaemonError::Other(error.to_string()),
        };
        self.with_down_hint(error)
    }
}

/// A JSON-RPC `error` object, as its class and diagnostic code.
fn refusal_of(error: &Value) -> DaemonError {
    match shekyl_rpc_types::errors::read_error_object(error) {
        Some(refusal) => DaemonError::Refusal(refusal),
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

fn from_transport(fault: TransportFault) -> DaemonError {
    match fault {
        TransportFault::Proxy(detail) => DaemonError::SocksFailure(detail),
        TransportFault::Tls(detail) => DaemonError::TlsFailure(detail),
        TransportFault::Unreachable(detail) => {
            DaemonError::ConnectionRefused { detail, hint: None }
        }
        TransportFault::Runtime(detail) => DaemonError::Other(detail),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_path_body, classify_path_status, from_transport, is_loopback_endpoint,
        DaemonError, GetInfoResponse,
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
            Err(DaemonError::Refusal(refusal)) => {
                assert_eq!(refusal.report(), "OutsideTheGrant rpc.grant");
            }
            other => panic!("expected a refusal, got {other:?}"),
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
            peers: Hidden::Shown(shekyl_rpc_types::InfoP2p::Running(
                InfoPeers::new(vec![shekyl_rpc_types::InfoConnectorPeers {
                    connector: shekyl_rpc_types::InfoConnector::Clearnet,
                    incoming_sockets: 0,
                    outgoing_sockets: 0,
                    white_peerlist_size: 0,
                    gray_peerlist_size: 0,
                }])
                .expect("one row is in order"),
            )),
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

    /// A proxy fault, a TLS-connector fault, and an unreachable daemon stay
    /// three errors. The variant is the classification; the sentence is not.
    #[test]
    fn a_named_transport_fault_keeps_its_name() {
        use shekyl_rpc_transport::TransportFault;
        let proxy = from_transport(TransportFault::Proxy(
            "invalid --proxy for the daemon transport: missing port".into(),
        ));
        assert!(matches!(proxy, DaemonError::SocksFailure(_)), "{proxy}");
        let socks = from_transport(TransportFault::Proxy("socks: refused".into()));
        assert!(matches!(socks, DaemonError::SocksFailure(_)), "{socks}");
        let tls = from_transport(TransportFault::Tls(
            "TLS connector unavailable: no roots".into(),
        ));
        assert!(matches!(tls, DaemonError::TlsFailure(_)), "{tls}");
        let refused = from_transport(TransportFault::Unreachable("connection refused".into()));
        assert!(
            matches!(refused, DaemonError::ConnectionRefused { .. }),
            "{refused}"
        );
    }
}
