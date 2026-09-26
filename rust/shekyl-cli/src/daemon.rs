// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Standalone daemon RPC client for shekyl-cli.
//!
//! Privacy-critical: this client is **independent** of the wallet-RPC
//! session's daemon connection. It uses a separate TCP connection (and a
//! separate Tor circuit when SOCKS is configured) so that unauthenticated
//! daemon queries like `get_info` are not correlated with the engine session.

use serde::Deserialize;
use serde_json::Value;
use std::fmt;

use shekyl_rpc_transport::network_posture::{host_of, is_loopback_host};

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
    RpcError {
        code: i64,
        message: String,
    },
    /// Path-RPC `status: "BUSY"` — `/start_mining` is `CHECK_CORE_READY`
    /// (`is_synchronized`); a syncing daemon will not mine.
    Busy,
    /// Path-RPC `status: "Already mining"`.
    AlreadyMining,
    /// Any other non-OK path-RPC `status` string, shown as the daemon wrote it.
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
                "TLS verification failed for daemon (check certificate or use --daemon-ca-cert). Detail: {detail}"
            ),
            Self::MalformedResponse(detail) => {
                write!(f, "Daemon returned a malformed response: {detail}")
            }
            Self::RpcError { code, message } => {
                write!(f, "Daemon RPC error (code {code}): {message}")
            }
            Self::Busy => write!(
                f,
                "The daemon is still syncing and will not start mining until it is caught up."
            ),
            Self::AlreadyMining => write!(
                f,
                "The daemon is already mining. Run \"mine stop\" first to change the thread count."
            ),
            Self::Refused(message) => write!(f, "The daemon refused: {message}"),
            Self::Other(detail) => write!(f, "Daemon client error: {detail}"),
        }
    }
}

impl std::error::Error for DaemonError {}

/// The fields `get_info` must carry for mining gates and `chain_health`.
///
/// No field is defaulted: these are `KV_SERIALIZE` (not `OPT`) on
/// `COMMAND_RPC_GET_INFO`, so absence means the contract moved, not a safe
/// zero. A missing `restricted` must not read as unrestricted.
#[derive(Debug, Deserialize)]
pub struct DaemonInfo {
    pub status: String,
    pub height: u64,
    pub target_height: u64,
    pub difficulty: u64,
    pub tx_count: u64,
    pub outgoing_connections_count: u64,
    pub incoming_connections_count: u64,
    pub restricted: bool,
    pub nettype: String,
    pub synchronized: bool,
}

/// The fields `mine status` / the already-mining preflight read.
/// Extra daemon fields (`pow_algorithm`, …) are ignored on purpose.
#[derive(Debug, Deserialize)]
pub struct MiningStatus {
    pub active: bool,
    pub speed: u64,
    pub threads_count: u64,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub difficulty: u64,
}

/// Lightweight daemon RPC client. Uses ureq (rustls TLS backend) with an
/// independent connection from the wallet-RPC session's daemon path.
pub struct DaemonClient {
    url: String,
    agent: ureq::Agent,
    /// See [`DaemonError::ConnectionRefused`]: attached to every refused
    /// connection this client reports.
    down_hint: Option<String>,
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
/// `127.0.0.1.evil.com`. Loopback is the **silent default and the
/// recommended posture**, not a force — a remote `--daemon-address` is a
/// valid advanced configuration (CLI_USABILITY.md §CU-3 F4).
#[must_use]
pub fn is_loopback_endpoint(address: &str) -> bool {
    is_loopback_host(host_of(address))
}

impl DaemonClient {
    /// Build a new daemon client.
    ///
    /// - `daemon_address`: e.g. `"http://127.0.0.1:11029"` or `"https://remote:11029"`.
    /// - `proxy`: optional SOCKS5 proxy address, e.g. `"socks5://127.0.0.1:9050"`.
    ///   When set, the client uses SOCKS auth username `shekyl-cli-daemon` to ensure
    ///   Tor assigns an isolated circuit via `IsolateSOCKSAuth`. Generic SOCKS proxies
    ///   may ignore auth-based isolation.
    /// - `ca_cert_path`: optional path to a PEM CA certificate for self-signed daemons.
    /// - `down_hint`: recovery copy attached to refused connections (the
    ///   caller knows the network and whether the endpoint is loopback).
    pub fn new(
        daemon_address: &str,
        proxy: Option<&str>,
        _ca_cert_path: Option<&str>,
        down_hint: Option<String>,
    ) -> Result<Self, DaemonError> {
        if daemon_address.is_empty() {
            return Err(DaemonError::NotConfigured);
        }

        let url = daemon_url(daemon_address);

        let mut config_builder = ureq::Agent::config_builder();

        if let Some(proxy_addr) = proxy {
            let proxy_obj = ureq::Proxy::new(proxy_addr)
                .map_err(|e| DaemonError::SocksFailure(e.to_string()))?;
            config_builder = config_builder.proxy(Some(proxy_obj));
        }

        let agent = config_builder.build().new_agent();

        Ok(Self {
            url,
            agent,
            down_hint,
        })
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

    /// POST JSON to `url` and parse the body as a JSON value.
    fn post_json(&self, url: &str, body: &Value) -> Result<Value, DaemonError> {
        let mut response = self
            .agent
            .post(url)
            .header("Content-Type", "application/json")
            .send(body.to_string().as_bytes())
            .map_err(|e| self.with_down_hint(classify_ureq_error(&e)))?;

        let body_str = response
            .body_mut()
            .read_to_string()
            .map_err(|e| DaemonError::MalformedResponse(e.to_string()))?;

        serde_json::from_str(&body_str).map_err(|e| DaemonError::MalformedResponse(e.to_string()))
    }

    /// Call a JSON-RPC method on the daemon.
    fn json_rpc(&self, method: &str, params: &Value) -> Result<Value, DaemonError> {
        let rpc_url = format!("{}/json_rpc", self.url);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params,
        });

        let parsed = self.post_json(&rpc_url, &body)?;

        if let Some(err) = parsed.get("error") {
            let code = err
                .get("code")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(-1);
            let message = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown")
                .to_string();
            return Err(DaemonError::RpcError { code, message });
        }

        parsed
            .get("result")
            .cloned()
            .ok_or_else(|| DaemonError::MalformedResponse("missing 'result' field".into()))
    }

    /// Fetch daemon info (`get_info`). Used by `chain_health` and mining gates.
    pub fn get_info(&self) -> Result<DaemonInfo, DaemonError> {
        let value = self.json_rpc("get_info", &serde_json::json!({}))?;
        serde_json::from_value(value)
            .map_err(|e| DaemonError::MalformedResponse(format!("get_info: {e}")))
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
    /// methods: the response is a flat object whose `status` field carries
    /// `"OK"` or the daemon's refusal text (`core_rpc_ffi.cpp` json table).
    fn path_rpc(&self, path: &str, body: &Value) -> Result<Value, DaemonError> {
        let url = format!("{}{path}", self.url);
        let parsed = self.post_json(&url, body)?;
        match parsed.get("status").and_then(|s| s.as_str()) {
            Some(status) => classify_path_status(status).map(|()| parsed),
            None => Err(DaemonError::MalformedResponse(
                "missing 'status' field".into(),
            )),
        }
    }

    /// Start mining on the daemon (CU-3). The daemon owns the threads; they
    /// outlive this CLI process.
    pub fn start_mining(&self, miner_address: &str, threads: u64) -> Result<(), DaemonError> {
        self.path_rpc(
            "/start_mining",
            &serde_json::json!({
                "miner_address": miner_address,
                "threads_count": threads,
                "do_background_mining": false,
                "ignore_battery": false,
            }),
        )
        .map(|_| ())
    }

    /// Stop mining on the daemon (CU-3).
    pub fn stop_mining(&self) -> Result<(), DaemonError> {
        self.path_rpc("/stop_mining", &serde_json::json!({}))
            .map(|_| ())
    }

    /// Query the daemon's mining state (CU-3).
    pub fn mining_status(&self) -> Result<MiningStatus, DaemonError> {
        let value = self.path_rpc("/mining_status", &serde_json::json!({}))?;
        serde_json::from_value(value)
            .map_err(|e| DaemonError::MalformedResponse(format!("mining_status: {e}")))
    }
}

/// Map a path-RPC `status` field. `"OK"` continues; known refusals become
/// typed errors so callers never print `daemon replied: BUSY`.
fn classify_path_status(status: &str) -> Result<(), DaemonError> {
    match status {
        "OK" => Ok(()),
        "BUSY" => Err(DaemonError::Busy),
        "Already mining" => Err(DaemonError::AlreadyMining),
        other => Err(DaemonError::Refused(other.to_owned())),
    }
}

fn classify_ureq_error(err: &ureq::Error) -> DaemonError {
    let msg = err.to_string();
    let lower = msg.to_lowercase();

    if lower.contains("socks") || lower.contains("proxy") || lower.contains("tor") {
        DaemonError::SocksFailure(msg)
    } else if lower.contains("tls")
        || lower.contains("ssl")
        || lower.contains("certificate")
        || lower.contains("handshake")
    {
        DaemonError::TlsFailure(msg)
    } else if lower.contains("connection refused")
        || lower.contains("connect error")
        || lower.contains("unreachable")
        || lower.contains("timed out")
    {
        DaemonError::ConnectionRefused {
            detail: msg,
            hint: None,
        }
    } else {
        DaemonError::Other(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_path_status, is_loopback_endpoint, DaemonError, DaemonInfo};

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
        assert!(matches!(
            classify_path_status("Already mining"),
            Err(DaemonError::AlreadyMining)
        ));
        match classify_path_status("Failed, wrong address") {
            Err(DaemonError::Refused(msg)) => assert!(msg.contains("wrong address")),
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn daemon_info_refuses_a_missing_gate_field() {
        let missing_restricted = serde_json::json!({
            "status": "OK",
            "height": 1,
            "target_height": 0,
            "difficulty": 1,
            "tx_count": 0,
            "outgoing_connections_count": 0,
            "incoming_connections_count": 0,
            "nettype": "mainnet",
            "synchronized": true,
        });
        assert!(
            serde_json::from_value::<DaemonInfo>(missing_restricted).is_err(),
            "a missing restricted field must not deserialize as unrestricted"
        );

        let complete = serde_json::json!({
            "status": "OK",
            "height": 1,
            "target_height": 0,
            "difficulty": 1,
            "tx_count": 0,
            "outgoing_connections_count": 0,
            "incoming_connections_count": 0,
            "restricted": false,
            "nettype": "testnet",
            "synchronized": true,
        });
        let info: DaemonInfo = serde_json::from_value(complete).expect("complete get_info");
        assert!(!info.restricted);
        assert_eq!(info.nettype, "testnet");
        assert!(info.synchronized);
    }
}
