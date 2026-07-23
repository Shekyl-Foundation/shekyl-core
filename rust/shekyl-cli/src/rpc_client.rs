// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! JSON-RPC client session for shekyl-cli (WI-RPC-2a).
//!
//! Shape B (`docs/V3_WALLET_DECISION_LOG.md` 2026-04-25): the CLI is always
//! an RPC client of `shekyl-wallet-rpc` — it holds no Engine and no wallet2
//! FFI handle, and can do nothing the OpenAPI contract
//! (`docs/api/wallet_rpc.yaml`) does not expose.
//!
//! Two transports:
//!
//! - **Self-hosted (default):** the CLI spawns an in-process
//!   `shekyl-wallet-rpc` server over a private, owner-only UDS socket
//!   ([`shekyl_wallet_rpc::spawn_in_process`]) and speaks HTTP/1.1 over that
//!   socket. One-shot commands and the REPL both use this mode.
//! - **Remote (`--rpc-url`):** the CLI connects to an externally managed
//!   `shekyl-wallet-rpc` daemon over HTTP (or a `uds://` socket path).
//!
//! The session also tracks which wallet the CLI believes is open. That flag
//! is presentation state (prompt text, "no wallet open" preflights) — the
//! server's tenant state is authoritative, and every RPC error from a stale
//! flag is shown to the user as-is.

use std::cell::{Cell, RefCell};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use shekyl_wallet_rpc::{InProcessHandle, Network};

/// JSON-RPC failure surfaced to command handlers.
#[derive(Debug)]
pub enum RpcError {
    /// The server returned a JSON-RPC error object. Wallet-RPC error
    /// messages are contractually stable and secret-free
    /// (`docs/api/wallet_rpc.yaml`), so they are shown to the user as-is.
    Rpc {
        /// Allocated `WalletRpcErrorCode` value.
        code: i64,
        /// Stable, secret-free message.
        message: String,
        /// Optional structured `error.data`.
        data: Option<Value>,
    },
    /// Transport-level failure (socket, HTTP framing, malformed response).
    Transport(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rpc { code, message, .. } => write!(f, "{message} (code {code})"),
            Self::Transport(detail) => write!(f, "RPC transport error: {detail}"),
        }
    }
}

impl std::error::Error for RpcError {}

impl RpcError {
    /// The allocated JSON-RPC error code, when this is a server-side error.
    pub fn code(&self) -> Option<i64> {
        match self {
            Self::Rpc { code, .. } => Some(*code),
            Self::Transport(_) => None,
        }
    }
}

/// Where RPC requests go.
enum Transport {
    /// HTTP/1.1 over a Unix domain socket.
    Uds(PathBuf),
    /// HTTP(S) over TCP to an external daemon.
    Http(String),
}

/// The runtime and server handle backing a self-hosted session.
struct Hosted {
    /// Keeps the in-process server's tasks alive for the session lifetime.
    runtime: tokio::runtime::Runtime,
    handle: Option<InProcessHandle>,
}

/// One CLI session's connection to `shekyl-wallet-rpc`.
pub struct RpcSession {
    transport: Transport,
    hosted: Option<Hosted>,
    next_id: Cell<u64>,
    open_wallet: RefCell<Option<String>>,
    /// When set, RPC error reports include the structured `error.data`.
    pub debug: bool,
}

impl RpcSession {
    /// Spawn an in-process `shekyl-wallet-rpc` server over a private UDS
    /// socket and connect to it (the Shape B self-hosted default).
    pub fn host_in_process(
        wallet_dir: PathBuf,
        network: Network,
        daemon_address: String,
        debug: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Multi-thread runtime: Engine create/open paths use
        // `tokio::task::block_in_place`, which a current-thread runtime
        // does not support.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let handle = runtime
            .block_on(shekyl_wallet_rpc::spawn_in_process(
                wallet_dir,
                network,
                daemon_address,
            ))
            .map_err(|e| format!("failed to start in-process wallet RPC: {e}"))?;
        let socket = handle
            .socket_path()
            .ok_or("in-process wallet RPC did not expose a UDS socket")?
            .to_path_buf();
        Ok(Self {
            transport: Transport::Uds(socket),
            hosted: Some(Hosted {
                runtime,
                handle: Some(handle),
            }),
            next_id: Cell::new(1),
            open_wallet: RefCell::new(None),
            debug,
        })
    }

    /// Connect to an externally managed `shekyl-wallet-rpc` daemon.
    ///
    /// Accepts `http://…` / `https://…` URLs or a `uds:///path/to.sock`
    /// socket path.
    pub fn connect(rpc_url: &str, debug: bool) -> Result<Self, String> {
        let transport = if let Some(path) = rpc_url.strip_prefix("uds://") {
            if path.is_empty() {
                return Err("--rpc-url uds:// path must not be empty".into());
            }
            Transport::Uds(PathBuf::from(path))
        } else if rpc_url.starts_with("http://") || rpc_url.starts_with("https://") {
            Transport::Http(rpc_url.trim_end_matches('/').to_owned())
        } else {
            return Err(format!(
                "invalid --rpc-url '{rpc_url}': expected http://host:port, \
                 https://host:port, or uds:///path/to.sock"
            ));
        };
        Ok(Self {
            transport,
            hosted: None,
            next_id: Cell::new(1),
            open_wallet: RefCell::new(None),
            debug,
        })
    }

    /// Whether the CLI believes a wallet is open on this session.
    pub fn is_open(&self) -> bool {
        self.open_wallet.borrow().is_some()
    }

    /// Record that `name` is now the open wallet.
    pub fn set_open(&self, name: &str) {
        *self.open_wallet.borrow_mut() = Some(name.to_owned());
    }

    /// Record that no wallet is open.
    pub fn set_closed(&self) {
        *self.open_wallet.borrow_mut() = None;
    }

    /// Perform a JSON-RPC call and return the `result` value.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let id = self.next_id.get();
        self.next_id.set(id.wrapping_add(1));
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let raw = match &self.transport {
            Transport::Uds(path) => http_post_uds(path, &body)?,
            Transport::Http(url) => http_post_tcp(url, &body)?,
        };

        let parsed: Value = serde_json::from_str(&raw)
            .map_err(|e| RpcError::Transport(format!("malformed JSON-RPC response: {e}")))?;
        if let Some(err) = parsed.get("error") {
            return Err(RpcError::Rpc {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(-32603),
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error")
                    .to_owned(),
                data: err.get("data").cloned(),
            });
        }
        parsed
            .get("result")
            .cloned()
            .ok_or_else(|| RpcError::Transport("response missing 'result'".into()))
    }

    /// Print an RPC failure to stderr. Server messages are stable and
    /// secret-free by contract; `--debug` additionally shows `error.data`.
    pub fn report(&self, context: &str, err: &RpcError) {
        eprintln!("{context}: {err}");
        if self.debug {
            if let RpcError::Rpc {
                data: Some(data), ..
            } = err
            {
                eprintln!("[DEBUG] error.data = {data}");
            }
        }
    }

    /// Shut the session down: close any open wallet (best effort) and stop
    /// the self-hosted server, removing its socket and private directory.
    pub fn shutdown(self) {
        if self.is_open() {
            if let Err(e) = self.call("close_wallet", json!({})) {
                eprintln!("Warning: failed to close wallet: {e}");
            }
        }
        if let Some(mut hosted) = self.hosted {
            if let Some(handle) = hosted.handle.take() {
                if let Err(e) = hosted.runtime.block_on(handle.shutdown()) {
                    eprintln!("Warning: in-process wallet RPC shutdown failed: {e}");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP transport
// ---------------------------------------------------------------------------

/// POST the JSON-RPC body over a Unix domain socket (HTTP/1.1,
/// `Connection: close`) and return the response body.
fn http_post_uds(path: &Path, body: &Value) -> Result<String, RpcError> {
    let payload = serde_json::to_vec(body)
        .map_err(|e| RpcError::Transport(format!("serialize request: {e}")))?;
    let mut stream = std::os::unix::net::UnixStream::connect(path).map_err(|e| {
        RpcError::Transport(format!(
            "cannot connect to wallet RPC socket {}: {e}",
            path.display()
        ))
    })?;

    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.write_all(&payload))
        .map_err(|e| RpcError::Transport(format!("write request: {e}")))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| RpcError::Transport(format!("read response: {e}")))?;
    parse_http_response(&raw)
}

/// POST the JSON-RPC body to an HTTP(S) endpoint and return the response
/// body. JSON-RPC application errors ride back as HTTP 200 with an `error`
/// object, which the caller decodes.
fn http_post_tcp(url: &str, body: &Value) -> Result<String, RpcError> {
    let mut response = ureq::post(url)
        .header("Content-Type", "application/json")
        .send(body.to_string().as_bytes())
        .map_err(|e| RpcError::Transport(e.to_string()))?;
    response
        .body_mut()
        .read_to_string()
        .map_err(|e| RpcError::Transport(format!("read response: {e}")))
}

/// Minimal HTTP/1.1 response parser for the `Connection: close` UDS path:
/// checks the status line, then extracts the body (chunked or
/// length/EOF-delimited).
fn parse_http_response(raw: &[u8]) -> Result<String, RpcError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| RpcError::Transport("non-UTF-8 HTTP response".into()))?;
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| RpcError::Transport("truncated HTTP response".into()))?;

    let status_line = head.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| RpcError::Transport(format!("bad HTTP status line: {status_line}")))?;
    if status != 200 {
        return Err(RpcError::Transport(format!(
            "wallet RPC returned HTTP {status}"
        )));
    }

    let chunked = head.lines().skip(1).any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });
    if chunked {
        decode_chunked(body)
    } else {
        // `Connection: close` — the body runs to EOF (Content-Length, when
        // present, matches by construction).
        Ok(body.to_owned())
    }
}

/// Decode a chunked transfer-encoded body.
fn decode_chunked(mut body: &str) -> Result<String, RpcError> {
    let mut out = String::new();
    loop {
        let (size_line, rest) = body
            .split_once("\r\n")
            .ok_or_else(|| RpcError::Transport("truncated chunked body".into()))?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| RpcError::Transport(format!("bad chunk size: {size_hex:?}")))?;
        if size == 0 {
            return Ok(out);
        }
        if rest.len() < size + 2 {
            return Err(RpcError::Transport("truncated chunk".into()));
        }
        out.push_str(&rest[..size]);
        body = &rest[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_length_response() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(parse_http_response(raw).unwrap(), "{}");
    }

    #[test]
    fn parses_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert_eq!(parse_http_response(raw).unwrap(), "{}");
    }

    #[test]
    fn rejects_non_200() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
        let err = parse_http_response(raw).unwrap_err();
        assert!(matches!(err, RpcError::Transport(_)), "{err}");
        assert!(err.to_string().contains("401"), "{err}");
    }

    #[test]
    fn connect_rejects_unknown_scheme() {
        assert!(RpcSession::connect("ftp://host", false).is_err());
        assert!(RpcSession::connect("uds://", false).is_err());
        assert!(RpcSession::connect("http://127.0.0.1:29500", false).is_ok());
        assert!(RpcSession::connect("uds:///tmp/x.sock", false).is_ok());
    }
}
