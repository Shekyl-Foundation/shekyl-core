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
//!   `shekyl-wallet-rpc` server over a private, owner-only local endpoint
//!   ([`shekyl_wallet_rpc::spawn_in_process`]) and speaks HTTP/1.1 over it.
//!   On Unix that is a UDS socket in a 0700 directory; on Windows it is an
//!   owner-only named pipe, dialled through `shekyl_win_sec::open_verified`,
//!   which refuses the pipe before a byte is written unless its owner and
//!   integrity are ours (`WINDOWS_WALLET_SUPPORT.md` §8.1 — the directory's
//!   containment has no pipe analogue, so the check is load-bearing here).
//!   One-shot commands and the REPL both use this mode.
//! - **Remote (`--rpc-url`):** the CLI connects to an externally managed
//!   `shekyl-wallet-rpc` **server** over HTTP (or, on Unix, a `uds://` socket
//!   path; Windows ships no local external form, and `uds://` is refused at
//!   parse there, naming the platform).
//!   "Server" throughout, never "daemon" — in this codebase the daemon is the
//!   *node* (`daemon::DaemonClient`), and the CLI talks to both at once.
//!
//! The session also tracks which wallet the CLI believes is open. That flag
//! is presentation state (prompt text, "no wallet open" preflights) — the
//! server's tenant state is authoritative, and every RPC error from a stale
//! flag is shown to the user as-is.

use std::cell::{Cell, RefCell};
use std::io::{Read, Write};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
#[cfg(unix)]
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};
use shekyl_wallet_rpc::{InProcessHandle, InProcessListen, Network};
use zeroize::Zeroizing;

/// Idle read/write timeout for the self-hosted / `uds://` HTTP transport.
/// Bounds an infinite hang against an untrusted `--rpc-url uds://` server
/// that accepts the request but never replies. Applied per read/write
/// syscall (not total), so a slow-but-progressing operation is unaffected;
/// only a genuinely stalled socket trips it.
///
/// Unix only: the Windows dial has no external form to guard, and after the
/// peer check passes the other end is either this process or a §6
/// out-of-scope process (`WINDOWS_WALLET_SUPPORT.md` §8.1).
#[cfg(unix)]
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
    #[cfg(unix)]
    Uds(PathBuf),
    /// HTTP/1.1 over the self-hosted named pipe (Windows). Opened — and
    /// peer-verified before any byte is written — on every call by
    /// `shekyl_win_sec::open_verified`; the name is the only state held.
    #[cfg(windows)]
    NamedPipe(String),
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

/// Initial capacity for a serialized request.
///
/// Sized so the largest secret-bearing request — `restore_wallet`, which
/// carries a wallet name, a password and a 25-word mnemonic — serializes
/// without the buffer having to grow at all: envelope ~80 B, name up to a
/// filesystem name's 255 B, mnemonic ~200 B, password typically far less.
/// Growth is safe (see [`WipedBuf`]), so this is an allocation-count choice
/// rather than a correctness bound: a longer password simply grows the
/// buffer, wiping as it goes.
const REQUEST_BUF_CAPACITY: usize = 1024;

/// A byte sink that wipes **every allocation it has ever owned**, not only
/// the last one.
///
/// A `Zeroizing<Vec<u8>>` is not by itself a safe place to serialize a secret
/// *into*. Serializing with serde_json's `to_vec` fills a plain `Vec` and
/// only wraps it afterwards — which rule 35 forbids at point of creation, and
/// which loses on two counts:
///
/// 1. an error partway through serialization drops that bare buffer with the
///    secret fields already written into it, unwiped;
/// 2. worse, and on the *success* path: `Vec` growth copies into a fresh
///    allocation and frees the old one without wiping. The zeroize crate says
///    so itself — "Cannot ensure that previous reallocations did not leave
///    values on the heap." serde_json starts that buffer at 128 bytes, and a
///    `restore_wallet` request exceeds 128 bytes every single time, so the
///    **seed phrase was guaranteed** to be left behind in released heap while
///    the wrapper dutifully wiped the final buffer and reported success.
///
/// This sink grows by hand instead: it allocates the replacement, copies into
/// it, and drops the outgrown `Zeroizing` — wiping it — before the allocator
/// can hand that memory to anything else.
struct WipedBuf(Zeroizing<Vec<u8>>);

impl WipedBuf {
    fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl Write for WipedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let needed = self.0.len() + buf.len();
        if needed > self.0.capacity() {
            // Amortized doubling, performed here rather than left to `Vec` so
            // that the outgrown allocation is wiped rather than merely freed.
            let grown_to = self.0.capacity().saturating_mul(2).max(needed);
            let mut grown = Zeroizing::new(Vec::with_capacity(grown_to));
            grown.extend_from_slice(&self.0);
            self.0 = grown;
        }
        // Within capacity now, so this cannot reallocate behind our back.
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The JSON-RPC request envelope, serialized directly rather than built as a
/// `serde_json::Value` — see [`RpcSession::call`] for why that distinction is
/// a secret-handling one.
#[derive(Serialize)]
struct Request<'a, P> {
    jsonrpc: &'a str,
    id: u64,
    method: &'a str,
    params: P,
}

/// Request shapes for the calls that carry cleartext secrets.
///
/// **Every field is a borrowed `&str`, deliberately.** The caller holds the
/// secret in a `Zeroizing<String>` and lends it; serde copies the bytes
/// straight into the wiped payload buffer, so between the caller's wiped
/// `String` and the wiped request bytes there is no third allocation to
/// forget about. A field typed `String` here would silently reintroduce
/// exactly the copy this module exists to remove.
///
/// These live beside the transport rather than in each command file so the
/// set of secret-bearing requests is enumerable in one place — the thing the
/// original audit could not do, and the reason it undercounted its own work
/// list.
///
/// Rule 35 asks that a `Serialize` derive on a secret-bearing type carry an
/// explicit reason, so: these types exist **only** to be serialized, once,
/// into the wiped sink in [`RpcSession::call`], and that is the whole of
/// their lifetime. They borrow rather than own, so serializing one cannot
/// outlive the caller's secret; and none derives `Debug` or `Clone`, so
/// there is no second path by which a field could reach a log or a copy.
pub mod params {
    use serde::Serialize;

    /// `create_wallet` / `open_wallet`.
    #[derive(Serialize)]
    pub struct NamedPassword<'a> {
        pub name: &'a str,
        pub password: &'a str,
    }

    /// `restore_wallet` — carries the **mnemonic** as well, which is seed
    /// material and rode the same uncleared `Value` path as the password.
    #[derive(Serialize)]
    pub struct Restore<'a> {
        pub name: &'a str,
        pub password: &'a str,
        pub mnemonic: &'a str,
        pub restore_height: u64,
    }

    /// `change_password` — two secrets under two keys, which is why a fix
    /// keyed on the literal `"password"` would have skipped this one.
    #[derive(Serialize)]
    pub struct ChangePassword<'a> {
        pub old_password: &'a str,
        pub new_password: &'a str,
    }

    /// `stake` (market posture — the default).
    #[derive(Serialize)]
    pub struct Stake<'a> {
        pub password: &'a str,
    }

    /// `stake` with the Foundation posture and D-4's acknowledgment.
    #[derive(Serialize)]
    pub struct StakeFoundation<'a> {
        pub password: &'a str,
        pub posture: &'a str,
        pub acknowledge_non_earning_unbounded: bool,
    }
}

impl RpcSession {
    /// Spawn an in-process `shekyl-wallet-rpc` server over a private local
    /// endpoint (UDS on Unix, an owner-only named pipe on Windows) and connect
    /// to it (the Shape B self-hosted default).
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
        let transport = match &handle.listen {
            #[cfg(unix)]
            InProcessListen::Uds(path) => Transport::Uds(path.clone()),
            #[cfg(windows)]
            InProcessListen::NamedPipe(name) => Transport::NamedPipe(name.clone()),
            InProcessListen::Tcp(_) => {
                return Err("in-process wallet RPC did not expose a private local endpoint".into())
            }
        };
        Ok(Self {
            transport,
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
    /// Accepts `http://…` / `https://…` URLs or, on Unix, a
    /// `uds:///path/to.sock` socket path. `proxy` (a SOCKS address) applies
    /// **only** to the HTTP(S) transport; a `uds://` session is a local socket
    /// with no network path to route, so the argument is ignored for it.
    pub fn connect(rpc_url: &str, proxy: Option<&str>, debug: bool) -> Result<Self, String> {
        let transport = match parse_rpc_url(rpc_url)? {
            #[cfg(unix)]
            RpcUrlForm::Uds(path) => Transport::Uds(path),
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
    #[cfg(unix)]
    pub fn socket_path(&self) -> Option<&Path> {
        match &self.transport {
            Transport::Uds(path) => Some(path),
            Transport::Http { .. } => None,
        }
    }

    /// The named-pipe name requests go to, when this is a self-hosted
    /// Windows session.
    #[cfg(windows)]
    pub fn pipe_name(&self) -> Option<&str> {
        match &self.transport {
            Transport::NamedPipe(name) => Some(name),
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
    ///
    /// **Generic over the params rather than taking a `serde_json::Value`,
    /// and that is a secret-handling requirement, not ergonomics (rule 35).**
    /// A `Value` carrying a password or a mnemonic is a heap copy of
    /// cleartext this crate cannot wipe: `Value::String` owns a plain
    /// `String`, nothing zeroizes it on drop, and every call site that built
    /// one with `json!` left the secret in memory *after* its own
    /// `password.zeroize()` had run — the variable was wiped while the copy
    /// inside the `Value` survived.
    ///
    /// Taking `P: Serialize` lets a secret-bearing caller pass a borrowed
    /// struct from [`params`], whose fields are `&str` pointing at the
    /// caller's `Zeroizing<String>`. serde writes those bytes **straight
    /// into the wiped payload buffer below**, so no intermediate copy is
    /// allocated at all. Non-secret callers keep passing `json!(...)`
    /// unchanged — `Value` implements `Serialize`.
    pub fn call<P: Serialize>(&self, method: &str, params: P) -> Result<Value, RpcError> {
        let id = self.next_id.get();
        self.next_id.set(id.wrapping_add(1));
        let body = Request {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };

        // Serialized once, here, into a sink that wipes every buffer it
        // touches including any it outgrows (see `WipedBuf`) — the one place
        // the request's cleartext exists. On the error path the sink drops
        // with the partial request inside it, so that wipes too. The
        // transports take these bytes rather than re-serializing, so there is
        // exactly one copy to account for instead of one per transport.
        let mut sink = WipedBuf::with_capacity(REQUEST_BUF_CAPACITY);
        serde_json::to_writer(&mut sink, &body)
            .map_err(|e| RpcError::Transport(format!("serialize request: {e}")))?;
        let payload = sink.into_inner();

        // The response buffer holds cleartext secret material for some
        // methods (create_wallet returns the new BIP-39 mnemonic / raw seed).
        // Wrap it so the serialized bytes are wiped on drop (rule 35).
        let raw = Zeroizing::new(match &self.transport {
            #[cfg(unix)]
            Transport::Uds(path) => http_post_uds(path, &payload)?,
            #[cfg(windows)]
            Transport::NamedPipe(name) => http_post_pipe(name, &payload)?,
            Transport::Http { url, agent } => http_post_tcp(agent, url, &payload)?,
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
#[cfg(unix)]
fn http_post_uds(path: &Path, payload: &[u8]) -> Result<String, RpcError> {
    // Takes the caller's already-serialized bytes: `RpcSession::call` owns the
    // one `Zeroizing` buffer, so this helper cannot make a second copy of a
    // password or mnemonic even by accident.
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
    http_post_over(&mut stream, payload)
}

/// POST the JSON-RPC body over the self-hosted named pipe (HTTP/1.1,
/// `Connection: close`) and return the response body.
///
/// `open_verified` is the only pipe-open path this crate has. It runs the
/// owner + integrity check and hands back a handle only if it passed, so the
/// request bytes below cannot reach a pipe that is not ours — that ordering
/// is the dial-side half of containment (`WINDOWS_WALLET_SUPPORT.md` §8.1),
/// not a courtesy check. No timeout, for the reason at [`UDS_IO_TIMEOUT`].
#[cfg(windows)]
fn http_post_pipe(name: &str, payload: &[u8]) -> Result<String, RpcError> {
    let mut pipe = shekyl_win_sec::open_verified(name)
        .map_err(|e| RpcError::Transport(format!("cannot connect to the wallet RPC pipe: {e}")))?;
    http_post_over(&mut pipe, payload)
}

/// The `Connection: close` HTTP/1.1 exchange both local transports speak:
/// write the request, read to EOF, parse. Takes the caller's already-
/// serialized bytes and re-serializes nothing (see [`RpcSession::call`]).
fn http_post_over<S: Read + Write>(stream: &mut S, payload: &[u8]) -> Result<String, RpcError> {
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.write_all(payload))
        .map_err(|e| RpcError::Transport(format!("write request: {e}")))?;

    // The response can carry secret material (create_wallet returns the seed);
    // wipe the read buffer on drop.
    let mut raw = Zeroizing::new(Vec::new());
    stream
        .read_to_end(&mut raw)
        .map_err(|e| RpcError::Transport(format!("read response: {e}")))?;
    parse_http_response(&raw)
}

/// The accepted `--rpc-url` forms.
///
/// `Uds` exists only on Unix. That is the point, not a convenience: the
/// platform constraint used to live in the *implementation* of the transport
/// (`http_post_uds`), one layer below the type that selects it, so a `uds://`
/// URL parsed cleanly on Windows and failed later with something unhelpful.
/// With the variant gated, a Windows arm that returned `Uds` cannot compile
/// (`WINDOWS_WALLET_SUPPORT.md` §8.1, "the parse surface").
enum RpcUrlForm {
    /// A `uds://` socket path, guaranteed non-empty.
    #[cfg(unix)]
    Uds(PathBuf),
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
/// The host check reuses [`shekyl_rpc_transport::network_posture::host_of`] rather than a
/// second parser, for the same reason: one extractor cannot disagree with
/// itself about what a host is.
fn parse_rpc_url(rpc_url: &str) -> Result<RpcUrlForm, String> {
    if let Some(path) = rpc_url.strip_prefix("uds://") {
        return uds_form(path);
    }
    if rpc_url.starts_with("http://") || rpc_url.starts_with("https://") {
        if shekyl_rpc_transport::network_posture::host_of(rpc_url).is_empty() {
            return Err(format!(
                "invalid --rpc-url '{rpc_url}': missing host \
                 (expected http://host:port or https://host:port)"
            ));
        }
        return Ok(RpcUrlForm::Http);
    }
    Err(format!(
        "invalid --rpc-url '{rpc_url}': expected {ACCEPTED_RPC_URL_FORMS}"
    ))
}

/// What the rejection message offers, per platform.
#[cfg(unix)]
const ACCEPTED_RPC_URL_FORMS: &str = "http://host:port, https://host:port, or uds:///path/to.sock";
/// What the rejection message offers, per platform.
#[cfg(windows)]
const ACCEPTED_RPC_URL_FORMS: &str =
    "http://host:port or https://host:port (uds:// is Unix-only; omit --rpc-url to self-host)";

/// The `uds://` form on Unix: a non-empty socket path.
#[cfg(unix)]
fn uds_form(path: &str) -> Result<RpcUrlForm, String> {
    if path.is_empty() {
        return Err("--rpc-url uds:// path must not be empty".into());
    }
    Ok(RpcUrlForm::Uds(PathBuf::from(path)))
}

/// The `uds://` form on Windows: refused, naming the platform.
///
/// [`RpcUrlForm`] has no `Uds` variant here, so this arm *cannot* hand back a
/// transport the platform lacks — the parse surface that
/// `WINDOWS_WALLET_SUPPORT.md` §8.1 found invisible to the compiler is now a
/// compile error for anyone who adds one. The message says what works
/// instead (rule 82): there is no `npipe://`, by ruling, and self-hosting
/// needs no URL at all.
#[cfg(windows)]
fn uds_form(_path: &str) -> Result<RpcUrlForm, String> {
    Err(
        "--rpc-url uds:// is not available on Windows: a Unix domain socket has no \
         Windows form, and Shekyl ships no other local external form there. Omit \
         --rpc-url to self-host the wallet RPC in-process, or use http://host:port / \
         https://host:port against an external server."
            .into(),
    )
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

fn http_post_tcp(agent: &ureq::Agent, url: &str, payload: &[u8]) -> Result<String, RpcError> {
    // Same contract as `http_post_uds`: the bytes are the caller's, already
    // wiped-on-drop, and this path re-serializes nothing.
    let mut response = agent
        .post(url)
        .header("Content-Type", "application/json")
        .send(payload)
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
        #[cfg(unix)]
        assert!(RpcSession::connect("uds:///tmp/x.sock", None, false).is_ok());
        // Windows has no `uds://` form. The rejection must name the platform
        // — "parses fine, fails at connect with something unhelpful" is the
        // outcome `WINDOWS_WALLET_SUPPORT.md` §8.1 gated the variant against.
        #[cfg(windows)]
        {
            let err = RpcSession::connect("uds:///tmp/x.sock", None, false)
                .err()
                .expect("uds:// must be rejected on Windows");
            assert!(err.contains("Windows"), "{err}");
            assert!(
                err.contains("omit"),
                "the rejection must say what works: {err}"
            );
        }
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
        #[cfg(unix)]
        assert!(is_supported_rpc_url("uds:///tmp/x.sock"));
        #[cfg(windows)]
        assert!(!is_supported_rpc_url("uds:///tmp/x.sock"));
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

    /// **The reason this PR is not a nine-site edit.** Each secret-bearing
    /// call used to build a `serde_json::Value`, which allocates a `String`
    /// copy of the password (or mnemonic) on the heap and drops it without
    /// wiping — `Value` has no `Zeroize`, and nothing in the type system says
    /// it should. The nine sites were fixed by routing every one through a
    /// borrowed [`params`] shape; this test is what stops a tenth from
    /// appearing, because the next author will reach for `json!` exactly the
    /// way the first nine did.
    ///
    /// The needle is the JSON *key* form — `"password":` and friends — since
    /// that is what a `json!` object literal produces regardless of how the
    /// macro call is wrapped across lines. Needles are assembled with
    /// `concat!` so this test's own text cannot satisfy them.
    #[test]
    fn no_secret_ever_travels_through_a_json_value() {
        // Every file that sends a secret-bearing request. A new one must be
        // added here; the FOLLOWUPS entry undercounted precisely because no
        // such list existed.
        let senders = [
            (
                "commands/lifecycle.rs",
                include_str!("commands/lifecycle.rs"),
            ),
            ("commands/staking.rs", include_str!("commands/staking.rs")),
            ("commands/scripted.rs", include_str!("commands/scripted.rs")),
            ("main.rs", include_str!("main.rs")),
        ];

        // `change_password` carries two secrets under two keys, which is why a
        // gate written against the single literal "password" would have let
        // that site through.
        let forbidden_json_fields = [
            concat!("\"pass", "word\":"),
            concat!("\"old_pass", "word\":"),
            concat!("\"new_pass", "word\":"),
            concat!("\"mne", "monic\":"),
        ];

        for (name, src) in senders {
            for field in forbidden_json_fields {
                assert!(
                    !src.contains(field),
                    "{name} builds a JSON object with {field} — a secret in a \
                     serde_json::Value is a heap copy that never gets wiped. \
                     Send it through a borrowed rpc_client::params shape instead."
                );
            }
            assert!(
                src.contains(concat!("par", "ams::")),
                "{name} is listed as a secret-bearing sender but no longer uses \
                 a params shape — either it stopped sending secrets (drop it \
                 from this list) or it regressed"
            );
        }
    }

    /// The envelope must serialize once, into the wiped buffer. If `call`
    /// ever routes through `Value` again, every borrowed `params` shape above
    /// silently becomes decorative — the copy just moves one frame inward.
    #[test]
    fn call_serializes_the_request_straight_into_a_wiped_buffer() {
        // `split_once`, not `split(..).next()`: the latter cannot return
        // `None`, so its `expect` was decorative — if the delimiter ever
        // drifted, the whole file (this test module included) would flow into
        // the assertions and the gate would keep passing on its own text.
        // This form fails loudly on the drift instead.
        let (production, _tests) = include_str!("rpc_client.rs")
            .split_once("\n#[cfg(test)]\nmod tests {")
            .expect("rpc_client.rs must keep its production section separable from its tests");

        // Whitespace removed, so the pin describes the *code* and not one
        // rustfmt layout of it. Matching an exact indentation would fail the
        // day `call` moves out of the impl or a line settles differently —
        // and it would fail accusing the author of reintroducing a secret
        // copy they never touched. A gate that cries wolf gets deleted, and
        // then it guards nothing.
        let flat: String = production.chars().filter(|c| !c.is_whitespace()).collect();

        assert!(
            flat.contains(concat!("serde_json::", "to_writer(&mutsink,&body)")),
            "call must serialize *into* the wiped sink. Anything that returns a \
             buffer and wraps it afterwards leaves the secret in a bare \
             allocation first — which is what rule 35 forbids at point of \
             creation, and what leaves seed bytes in released heap when the \
             buffer grows"
        );
        // The two ways the destination gets lost. `to_vec` builds the buffer
        // bare and wraps it after; `to_value` reintroduces the `Value` copy
        // the params shapes exist to avoid. Note the prose above deliberately
        // never spells either path in full, so these needles cannot be
        // satisfied by a doc comment describing the very thing they forbid.
        for forbidden in [
            concat!("serde_json::", "to_vec"),
            concat!("serde_json::", "to_value"),
        ] {
            assert!(
                !flat.contains(forbidden),
                "the request must not travel through {forbidden} — that is an \
                 allocation this crate cannot wipe, and routing through it \
                 makes every borrowed params shape decorative"
            );
        }

        // Deliberately NOT asserted here: that the transport helpers take
        // `&[u8]` rather than `&Value`. The compiler already rejects that
        // change (`call` hands them a `Zeroizing<Vec<u8>>`), and a test that
        // restates a type error is noise that later readers must maintain.
    }

    /// Hand-rolled growth is the price of wiping what we outgrow, and the
    /// risk it introduces is a content bug rather than a leak — the wiping
    /// itself is `Zeroizing`'s contract, but copying the old buffer forward
    /// correctly is ours. Write in many small chunks so the buffer crosses
    /// several growths mid-stream.
    #[test]
    fn wiped_buf_preserves_content_across_repeated_growth() {
        let mut buf = WipedBuf::with_capacity(4);
        let mut expected = Vec::new();
        for i in 0..500u32 {
            let chunk = format!("{i},");
            buf.write_all(chunk.as_bytes()).expect("sink never fails");
            expected.extend_from_slice(chunk.as_bytes());
        }
        let got = buf.into_inner();
        assert_eq!(
            got.as_slice(),
            expected.as_slice(),
            "growth must carry every earlier byte forward intact"
        );
    }

    /// The sink must be usable as a serde_json destination, and must hold the
    /// request the transports are about to send — if `to_writer` and the sink
    /// disagreed about `write`'s contract, `call` would ship a truncated body.
    #[test]
    fn wiped_buf_round_trips_a_request_larger_than_its_capacity() {
        let long_mnemonic = vec!["abandon"; 25].join(" ");
        let body = Request {
            jsonrpc: "2.0",
            id: 7,
            method: "restore_wallet",
            params: params::Restore {
                name: "wallet",
                password: "hunter2",
                mnemonic: &long_mnemonic,
                restore_height: 0,
            },
        };

        // Deliberately smaller than the payload, so the growth path runs.
        let mut sink = WipedBuf::with_capacity(8);
        serde_json::to_writer(&mut sink, &body).expect("envelope serializes");
        let payload = sink.into_inner();

        assert!(
            payload.len() > 8,
            "the fixture must actually exercise growth"
        );
        let parsed: Value = serde_json::from_slice(&payload).expect("valid JSON out");
        assert_eq!(parsed["params"]["mnemonic"], long_mnemonic);
        assert_eq!(parsed["method"], "restore_wallet");
    }
}
