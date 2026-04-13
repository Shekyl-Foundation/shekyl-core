// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Standalone daemon RPC client for shekyl-cli.
//!
//! Privacy-critical: this client is **independent** of the wallet2 FFI
//! connection. It uses a separate TCP connection (and a separate Tor circuit
//! when SOCKS is configured) so that unauthenticated daemon queries like
//! `get_info` are not correlated with the wallet session.

use serde_json::Value;
use std::fmt;

/// Errors from the daemon RPC client with differentiated failure modes.
#[derive(Debug)]
pub enum DaemonError {
    NotConfigured,
    ConnectionRefused(String),
    SocksFailure(String),
    TlsFailure(String),
    MalformedResponse(String),
    RpcError { code: i64, message: String },
    Other(String),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => write!(
                f,
                "Daemon not configured. Use --daemon-address to set the daemon endpoint."
            ),
            Self::ConnectionRefused(detail) => write!(
                f,
                "Daemon connection refused (is the daemon running?). Detail: {detail}"
            ),
            Self::SocksFailure(detail) => write!(
                f,
                "SOCKS/Tor proxy connection failed (check --proxy and Tor status). Detail: {detail}"
            ),
            Self::TlsFailure(detail) => write!(
                f,
                "TLS verification failed for daemon (check certificate or use --daemon-ca-cert). Detail: {detail}"
            ),
            Self::MalformedResponse(detail) => write!(
                f,
                "Daemon returned a malformed response: {detail}"
            ),
            Self::RpcError { code, message } => write!(
                f,
                "Daemon RPC error (code {code}): {message}"
            ),
            Self::Other(detail) => write!(f, "Daemon client error: {detail}"),
        }
    }
}

impl std::error::Error for DaemonError {}

/// Lightweight daemon RPC client. Uses ureq (rustls TLS backend) with an
/// independent connection from the wallet2 FFI path.
pub struct DaemonClient {
    url: String,
    agent: ureq::Agent,
}

impl DaemonClient {
    /// Build a new daemon client.
    ///
    /// - `daemon_address`: e.g. `"http://localhost:11028"` or `"https://remote:11028"`.
    /// - `proxy`: optional SOCKS5 proxy address, e.g. `"socks5://127.0.0.1:9050"`.
    ///   When set, the client uses SOCKS auth username `shekyl-cli-daemon` to ensure
    ///   Tor assigns an isolated circuit via `IsolateSOCKSAuth`. Generic SOCKS proxies
    ///   may ignore auth-based isolation.
    /// - `ca_cert_path`: optional path to a PEM CA certificate for self-signed daemons.
    pub fn new(
        daemon_address: &str,
        proxy: Option<&str>,
        _ca_cert_path: Option<&str>,
    ) -> Result<Self, DaemonError> {
        if daemon_address.is_empty() {
            return Err(DaemonError::NotConfigured);
        }

        let url = if daemon_address.contains("://") {
            daemon_address.to_string()
        } else {
            format!("http://{daemon_address}")
        };

        let mut config_builder = ureq::Agent::config_builder();

        if let Some(proxy_addr) = proxy {
            let proxy_obj = ureq::Proxy::new(proxy_addr)
                .map_err(|e| DaemonError::SocksFailure(e.to_string()))?;
            config_builder = config_builder.proxy(Some(proxy_obj));
        }

        let agent = config_builder.build().new_agent();

        Ok(Self { url, agent })
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

        let mut response = self
            .agent
            .post(&rpc_url)
            .header("Content-Type", "application/json")
            .send(body.to_string().as_bytes())
            .map_err(classify_ureq_error)?;

        let body_str = response
            .body_mut()
            .read_to_string()
            .map_err(|e| DaemonError::MalformedResponse(e.to_string()))?;

        let parsed: Value = serde_json::from_str(&body_str)
            .map_err(|e| DaemonError::MalformedResponse(e.to_string()))?;

        if let Some(err) = parsed.get("error") {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
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

    /// Fetch daemon info (`get_info`). Used by `chain_health`.
    pub fn get_info(&self) -> Result<Value, DaemonError> {
        self.json_rpc("get_info", &serde_json::json!({}))
    }
}

fn classify_ureq_error(err: ureq::Error) -> DaemonError {
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
        DaemonError::ConnectionRefused(msg)
    } else {
        DaemonError::Other(msg)
    }
}
