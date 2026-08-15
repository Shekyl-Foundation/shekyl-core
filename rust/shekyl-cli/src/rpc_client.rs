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
//!   `shekyl-wallet-rpc` **server** over HTTP (or a `uds://` socket path).
//!   "Server" throughout, never "daemon" — in this codebase the daemon is the
//!   *node* (`daemon::DaemonClient`), and the CLI talks to both at once.
//!
//! The session also tracks which wallet the CLI believes is open. That flag
//! is presentation state (prompt text, "no wallet open" preflights) — the
//! server's tenant state is authoritative, and every RPC error from a stale
//! flag is shown to the user as-is.

use std::cell::{Cell, RefCell};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};
use shekyl_wallet_rpc::{InProcessHandle, Network};
use zeroize::Zeroizing;

/// Idle read/write timeout for the self-hosted / `uds://` HTTP transport.
/// Bounds an infinite hang against an untrusted `--rpc-url uds://` server
/// that accepts the request but never replies. Applied per read/write
/// syscall (not total), so a slow-but-progressing operation is unaffected;
/// only a genuinely stalled socket trips it.
const UDS_IO_TIMEOUT: Duration = Duration::from_secs(600);

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
    /// HTTP(S) over TCP to an external `shekyl-wallet-rpc` server (the
    /// `--rpc-url` target — not the node daemon; cf. `daemon::DaemonClient`),
    /// through a ureq agent that carries the `--proxy` SOCKS config (if any) —
    /// so a proxied `--rpc-url` is genuinely proxied, which the network-posture
    /// disclosure relies on.
    Http { url: String, agent: ureq::Agent },
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
        proxy: Option<String>,
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
                proxy,
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

    /// Connect to an externally managed `shekyl-wallet-rpc` **server** (not the
    /// node daemon — cf. [`crate::daemon::DaemonClient`]).
    ///
    /// Accepts `http://…` / `https://…` URLs or a `uds:///path/to.sock` socket
    /// path. `proxy` (a SOCKS address) applies **only** to the HTTP(S)
    /// transport; a `uds://` session is a local socket with no network path to
    /// route, so the argument is ignored for it.
    pub fn connect(rpc_url: &str, proxy: Option<&str>, debug: bool) -> Result<Self, String> {
        let transport = match parse_rpc_url(rpc_url)? {
            RpcUrlForm::Uds(path) => Transport::Uds(PathBuf::from(path)),
            RpcUrlForm::Http => Transport::Http {
                url: rpc_url.trim_end_matches('/').to_owned(),
                agent: build_http_agent(proxy)?,
            },
        };
        let session = Self {
            transport,
            hosted: None,
            next_id: Cell::new(1),
            open_wallet: RefCell::new(None),
            debug,
        };
        // A remote server may already have a wallet open (opened by the
        // operator or another client). Probe once so is_open()/require_open()
        // and the prompt reflect the server's actual tenant state — otherwise
        // every wallet command is blocked ("no wallet open") against an
        // already-open remote wallet, with no in-CLI recovery. Best-effort:
        // get_primary_address needs an open wallet but not the daemon, so a
        // success means "open"; any error (including "no wallet open", or a
        // transport failure) leaves the flag closed, which is safe — commands
        // still reach the server and surface its authoritative errors.
        if session.call("get_primary_address", json!({})).is_ok() {
            session.set_open("(remote)");
        }
        Ok(session)
    }

    /// The UDS socket path requests go to, when this is a UDS session.
    pub fn socket_path(&self) -> Option<&Path> {
        match &self.transport {
            Transport::Uds(path) => Some(path),
            Transport::Http { .. } => None,
        }
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
    // By-value `params` is the call-boundary contract: every command site
    // hands ownership of its request object here; taking `&Value` would
    // churn all of them for no behavior change.
    #[allow(clippy::needless_pass_by_value)]
    pub fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let id = self.next_id.get();
        self.next_id.set(id.wrapping_add(1));
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        // The response buffer holds cleartext secret material for some
        // methods (create_wallet returns the new BIP-39 mnemonic / raw seed).
        // Wrap it so the serialized bytes are wiped on drop (rule 35); the
        // request-side serialization is wiped inside the transport helpers.
        let raw = Zeroizing::new(match &self.transport {
            Transport::Uds(path) => http_post_uds(path, &body)?,
            Transport::Http { url, agent } => http_post_tcp(agent, url, &body)?,
        });

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
    // The serialized request holds cleartext secrets (password / mnemonic) for
    // create/restore/open/change_password. Wipe the bytes on drop (rule 35) so
    // the request buffer does not outlive the caller's own zeroize.
    let payload = Zeroizing::new(
        serde_json::to_vec(body)
            .map_err(|e| RpcError::Transport(format!("serialize request: {e}")))?,
    );
    let mut stream = std::os::unix::net::UnixStream::connect(path).map_err(|e| {
        RpcError::Transport(format!(
            "cannot connect to wallet RPC socket {}: {e}",
            path.display()
        ))
    })?;
    // Bound an infinite hang against an untrusted `uds://` server that accepts
    // the request but never replies (self-hosted mode is trusted; this guards
    // the external `--rpc-url uds://` path).
    drop(stream.set_read_timeout(Some(UDS_IO_TIMEOUT)));
    drop(stream.set_write_timeout(Some(UDS_IO_TIMEOUT)));

    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.write_all(&payload))
        .map_err(|e| RpcError::Transport(format!("write request: {e}")))?;

    // The response can carry secret material (create_wallet returns the seed);
    // wipe the read buffer on drop.
    let mut raw = Zeroizing::new(Vec::new());
    stream
        .read_to_end(&mut raw)
        .map_err(|e| RpcError::Transport(format!("read response: {e}")))?;
    parse_http_response(&raw)
}

/// POST the JSON-RPC body to an HTTP(S) endpoint and return the response
/// body. JSON-RPC application errors ride back as HTTP 200 with an `error`
/// object, which the caller decodes.
/// The accepted `--rpc-url` forms.
enum RpcUrlForm<'a> {
    /// A `uds://` socket path, guaranteed non-empty.
    Uds(&'a str),
    /// An `http(s)://` URL with a non-empty host.
    Http,
}

/// Parse `--rpc-url` into an accepted form, or explain why it is rejected.
///
/// **Single source of acceptance.** [`RpcSession::connect`] and
/// [`is_supported_rpc_url`] both route through this, so the two cannot disagree
/// about what is acceptable — previously they were only kept in step by a
/// comment and a test name. That gap was reachable: a hostless `http://`,
/// `http:///`, or `http://:29500` passed both the prefix check and `connect`,
/// which then returned `Ok` (the post-connect probe is best-effort and swallows
/// the failure) and left the operator to hit a confusing error later — while the
/// network-posture disclosure, parsing the same string properly, warned about an
/// endpoint with an empty host.
///
/// The host check reuses [`crate::network_posture::host_of`] rather than a
/// second parser, for the same reason: one extractor cannot disagree with
/// itself about what a host is.
fn parse_rpc_url(rpc_url: &str) -> Result<RpcUrlForm<'_>, String> {
    if let Some(path) = rpc_url.strip_prefix("uds://") {
        if path.is_empty() {
            return Err("--rpc-url uds:// path must not be empty".into());
        }
        return Ok(RpcUrlForm::Uds(path));
    }
    if rpc_url.starts_with("http://") || rpc_url.starts_with("https://") {
        if crate::network_posture::host_of(rpc_url).is_empty() {
            return Err(format!(
                "invalid --rpc-url '{rpc_url}': missing host \
                 (expected http://host:port or https://host:port)"
            ));
        }
        return Ok(RpcUrlForm::Http);
    }
    Err(format!(
        "invalid --rpc-url '{rpc_url}': expected http://host:port, \
         https://host:port, or uds:///path/to.sock"
    ))
}

/// Whether `rpc_url` is a form [`RpcSession::connect`] accepts. The
/// network-posture disclosure gates on this so it never warns about an endpoint
/// `connect` will immediately reject — no connection is opened, so there is
/// nothing to disclose.
#[must_use]
pub fn is_supported_rpc_url(rpc_url: &str) -> bool {
    parse_rpc_url(rpc_url).is_ok()
}

/// Build the ureq agent for the `--rpc-url` HTTP transport, applying the
/// operator's `--proxy` SOCKS config when set. This is what makes a proxied
/// `--rpc-url` actually route through the proxy — mirrors `daemon::DaemonClient`
/// so both CLI HTTP paths honor `--proxy` identically.
fn build_http_agent(proxy: Option<&str>) -> Result<ureq::Agent, String> {
    let mut config = ureq::Agent::config_builder();
    if let Some(proxy_addr) = proxy {
        let proxy_obj = ureq::Proxy::new(proxy_addr)
            .map_err(|e| format!("invalid --proxy '{proxy_addr}': {e}"))?;
        config = config.proxy(Some(proxy_obj));
    }
    Ok(config.build().new_agent())
}

fn http_post_tcp(agent: &ureq::Agent, url: &str, body: &Value) -> Result<String, RpcError> {
    // Serialized request holds cleartext secrets; wipe on drop (rule 35).
    let payload = Zeroizing::new(body.to_string().into_bytes());
    let mut response = agent
        .post(url)
        .header("Content-Type", "application/json")
        .send(payload.as_slice())
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
    // Split header/body on the raw bytes. The header is ASCII (parsed as
    // UTF-8), but the body may contain multibyte UTF-8 (addresses, labels,
    // error text) that must not be sliced at a non-char boundary — so it stays
    // bytes until fully reassembled.
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| RpcError::Transport("truncated HTTP response".into()))?;
    let head = std::str::from_utf8(&raw[..sep])
        .map_err(|_| RpcError::Transport("non-UTF-8 HTTP header".into()))?;
    let body = &raw[sep + 4..];

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
    let body = if chunked {
        decode_chunked(body)?
    } else {
        // `Connection: close` — the body runs to EOF (Content-Length, when
        // present, matches by construction).
        body.to_vec()
    };
    String::from_utf8(body).map_err(|_| RpcError::Transport("non-UTF-8 HTTP body".into()))
}

/// Decode a chunked transfer-encoded body.
///
/// Operates on raw bytes and concatenates chunk data byte-for-byte: a
/// multibyte UTF-8 sequence can straddle a chunk boundary, so slicing each
/// chunk as `&str` would panic on a non-char boundary. The caller validates
/// UTF-8 once on the fully reassembled body.
fn decode_chunked(body: &[u8]) -> Result<Vec<u8>, RpcError> {
    let mut out: Vec<u8> = Vec::new();
    let mut rest = body;
    loop {
        let nl = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| RpcError::Transport("truncated chunked body".into()))?;
        let size_hex = std::str::from_utf8(&rest[..nl])
            .ok()
            .and_then(|line| line.split(';').next())
            .map(str::trim)
            .ok_or_else(|| RpcError::Transport("bad chunk size line".into()))?;
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| RpcError::Transport(format!("bad chunk size: {size_hex:?}")))?;
        let after = &rest[nl + 2..];
        if size == 0 {
            return Ok(out);
        }
        if after.len() < size + 2 {
            return Err(RpcError::Transport("truncated chunk".into()));
        }
        out.extend_from_slice(&after[..size]);
        rest = &after[size + 2..];
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
    fn chunked_response_splits_multibyte_utf8_across_chunks() {
        // Body `{"m":"—"}` (— is U+2014 = 0xE2 0x80 0x94) split so the em-dash
        // straddles the chunk boundary: chunk 1 = `{"m":"` + 0xE2 (7 bytes),
        // chunk 2 = 0x80 0x94 + `"}` (4 bytes). Byte-wise reassembly must
        // decode it; slicing each chunk as &str would panic / reject it.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    7\r\n{\"m\":\"\xe2\r\n4\r\n\x80\x94\"}\r\n0\r\n\r\n";
        assert_eq!(parse_http_response(raw).unwrap(), "{\"m\":\"\u{2014}\"}");
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
        assert!(RpcSession::connect("ftp://host", None, false).is_err());
        assert!(RpcSession::connect("uds://", None, false).is_err());
        // Hostless HTTP(S) forms are rejected up front rather than returning
        // Ok and failing later: the post-connect probe is best-effort and
        // swallows the failure, so a malformed URL would otherwise surface as
        // a confusing error at the first real command — and would reach the
        // network-posture disclosure as an empty host.
        for bad in ["http://", "https://", "http:///", "http://:29500"] {
            let err = RpcSession::connect(bad, None, false)
                .err()
                .unwrap_or_else(|| panic!("hostless '{bad}' must be rejected"));
            assert!(err.contains("missing host"), "{bad}: {err}");
        }
        assert!(RpcSession::connect("http://127.0.0.1:29500", None, false).is_ok());
        assert!(RpcSession::connect("uds:///tmp/x.sock", None, false).is_ok());
        // A well-formed SOCKS proxy builds the agent (reachability is not
        // checked at connect time — the open-state probe is best-effort).
        assert!(RpcSession::connect(
            "http://127.0.0.1:29500",
            Some("socks5://127.0.0.1:9050"),
            false
        )
        .is_ok());
    }

    #[test]
    fn is_supported_rpc_url_tracks_connect_accepted_forms() {
        // Accepted forms match connect_rejects_unknown_scheme above.
        assert!(is_supported_rpc_url("http://host:1"));
        assert!(is_supported_rpc_url("https://host:1"));
        assert!(is_supported_rpc_url("uds:///tmp/x.sock"));
        // Rejected: empty uds path, unknown scheme, bare host:port, and any
        // hostless HTTP(S) form. This tracks `connect` by construction now —
        // both route through `parse_rpc_url` — so this test documents the rule
        // rather than being the thing that keeps the two in step.
        assert!(!is_supported_rpc_url("uds://"));
        assert!(!is_supported_rpc_url("ftp://host"));
        for bad in ["http://", "https://", "http:///", "http://:29500"] {
            assert!(
                !is_supported_rpc_url(bad),
                "hostless '{bad}' must be rejected"
            );
        }
        assert!(!is_supported_rpc_url("host:11028"));
    }
}
