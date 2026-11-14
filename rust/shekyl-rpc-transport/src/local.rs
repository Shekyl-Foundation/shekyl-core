// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! "This computer": a client's dial of the daemon run as its own account,
//! on the owner's leg (`docs/design/RPC_CHANNEL.md` RT-15, §7.1).
//!
//! The target resolves through the daemon's own naming
//! ([`shekyl_rpc_channel::rendezvous_name`] over the network id and the
//! instance, and [`shekyl_rpc_channel::rendezvous`] for the file and the
//! directory), never a second copy of it. On Unix it dials the socket; on
//! Windows it reads the rendezvous record and opens the pipe it names through
//! the peer check (`shekyl_win_sec::open_verified`). Each call is one
//! connection, `Connection: close`: a call that fails or times out loses its
//! own connection and nothing else.
//!
//! RT-15's two failures stay apart ([`LocalFault`]). "Nothing there" (no
//! rendezvous, or nothing listening at it) is a plain "the node is not
//! running". "The wrong thing there" (a peer that fails the check: another
//! account's socket, a pipe that is not this user's, a file that is not a
//! rendezvous record) is a security failure: reported as one, never
//! retried, never routed around. That is why this target has its own
//! failure type and no conversion into the HTTP transport's: a fold into a
//! connection error would make the security failure retryable.
//!
//! The account's root (the session directory on Unix, the local
//! application data folder on Windows) and the peer's account on Unix come
//! from `shekyl_os_account`, the leaf the daemon's process crate reads the
//! same root from: one reader, and no network stack under it.

use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use shekyl_network::Network;
use shekyl_rpc_channel::{rendezvous, rendezvous_name, Instance};
use zeroize::Zeroizing;

use crate::JsonRpcError;

/// How long one call on the owner's leg may take, connect to last byte,
/// unless the caller names its own bound.
pub const CALL_WITHIN: Duration = Duration::from_secs(30);

/// Why a call on "this computer" did not reach the daemon. The two classes
/// RT-15 keeps apart: [`Self::is_security_failure`] is the wrong thing at
/// the rendezvous, and is never retried; everything else is the node not
/// running, or not answering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalFault {
    /// This account has no root for a rendezvous (Unix: no session
    /// directory), so no node of this account can be running here.
    NoPlace {
        /// The network and instance looked for.
        node: String,
    },
    /// No rendezvous: no node of this account runs for this network and
    /// instance.
    NotRunning {
        /// The network and instance looked for.
        node: String,
    },
    /// A rendezvous with nothing listening: the node stopped without
    /// cleaning up. Its next start replaces it.
    Stale {
        /// The network and instance looked for.
        node: String,
    },
    /// Windows: this account's node runs in another sign-in session, whose
    /// pipe admits that session alone. Known from the record, before any
    /// dial.
    OtherSession,
    /// Something other than this account's node is at the rendezvous: a
    /// peer that fails the check. A hard stop: never retried.
    PeerCheck(String),
    /// The node did not answer: a timeout, a busy pipe, a broken exchange.
    Unreachable(String),
}

impl LocalFault {
    /// The wrong thing at the rendezvous (RT-15): report it as a security
    /// failure and do not retry, here or on any other leg.
    #[must_use]
    pub fn is_security_failure(&self) -> bool {
        matches!(self, Self::PeerCheck(_))
    }
}

impl fmt::Display for LocalFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPlace { node } => write!(
                f,
                "No Shekyl node is running on this computer for {node}: this account has no \
                 session directory for one to run in."
            ),
            Self::NotRunning { node } => {
                write!(f, "No Shekyl node is running on this computer for {node}.")
            }
            Self::Stale { node } => write!(
                f,
                "The Shekyl node on this computer for {node} is not running (it stopped \
                 unexpectedly). Start it again."
            ),
            Self::OtherSession => f.write_str(
                "Your Shekyl node is running in another sign-in session and can only be \
                 reached from there.",
            ),
            Self::PeerCheck(detail) => write!(
                f,
                "Something other than your Shekyl node is answering at its local address. \
                 Not connecting. ({detail})"
            ),
            Self::Unreachable(detail) => {
                write!(
                    f,
                    "The Shekyl node on this computer did not answer: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for LocalFault {}

/// A run-as-me daemon's owner's leg: "this computer" (the default instance
/// in the account's own directory), or an instance or a directory named by
/// the caller.
#[derive(Clone, Debug)]
pub struct LocalTarget {
    node: String,
    path: PathBuf,
}

/// The connected owner's leg: the socket on Unix, the verified pipe on
/// Windows.
#[cfg(unix)]
pub type LocalStream = std::os::unix::net::UnixStream;

/// The connected owner's leg: the socket on Unix, the verified pipe on
/// Windows.
#[cfg(windows)]
pub type LocalStream = shekyl_win_sec::VerifiedPipe;

impl LocalTarget {
    /// "This computer" for `network`: the default instance, in this
    /// account's rendezvous directory.
    ///
    /// # Errors
    ///
    /// [`LocalFault::NoPlace`]: the account has no root for a rendezvous.
    pub fn this_computer(network: Network) -> Result<Self, LocalFault> {
        Self::resolve(network, &Instance::Default, None)
    }

    /// `instance` of `network`, in `dir` when given (a test host's
    /// `rpc-socket-dir`, which a client reaches only when told it, §7.1),
    /// otherwise in this account's rendezvous directory.
    ///
    /// # Errors
    ///
    /// [`LocalFault::NoPlace`]: no `dir`, and the account has no root.
    pub fn resolve(
        network: Network,
        instance: &Instance,
        dir: Option<&Path>,
    ) -> Result<Self, LocalFault> {
        let node = match instance {
            Instance::Default => network.name().to_owned(),
            Instance::Named(_) => format!("{} (instance {})", network.name(), instance.label()),
        };
        let dir = match dir {
            Some(dir) => dir.to_path_buf(),
            None => match shekyl_os_account::account_root() {
                Some(root) => rendezvous::account_dir(&root),
                None => return Err(LocalFault::NoPlace { node }),
            },
        };
        let name = rendezvous_name(&network.network_id(), instance);
        Ok(Self {
            node,
            path: dir.join(rendezvous::file_name(&name)),
        })
    }

    /// The rendezvous: the socket (Unix) or the record (Windows).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Connect to the owner's leg and check its peer.
    ///
    /// # Errors
    ///
    /// [`LocalFault`]: not running, stale, another session, a failed peer
    /// check, or a dial that failed otherwise.
    pub fn dial(&self) -> Result<LocalStream, LocalFault> {
        dial(&self.node, &self.path)
    }

    /// POST `body` to `route` on the owner's leg and return the reply's
    /// body: one connection, closed after the reply, bounded by `within`.
    ///
    /// # Errors
    ///
    /// [`LocalFault`], from the dial or the exchange.
    pub fn post(
        &self,
        route: &str,
        body: &[u8],
        within: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, LocalFault> {
        let path = format!("/{}", route.trim_start_matches('/'));
        let stream = self.dial()?;
        exchange(stream, &path, body, within)
    }

    /// One call of method `M`, the same envelope and checks
    /// [`crate::SyncDaemon::call`] makes, bounded by [`CALL_WITHIN`].
    ///
    /// # Errors
    ///
    /// The transport ([`LocalFault`]), a body that is not the reply, a
    /// method the daemon does not serve, or the daemon's refusal.
    pub fn call<M: shekyl_rpc_client::RpcMethod>(
        &self,
        request: &M::Request,
    ) -> Result<M::Reply, JsonRpcError<LocalFault>> {
        crate::call_via::<M, _>(request, |route, body| {
            self.post(route, &body, CALL_WITHIN)
                .map(|reply| reply.to_vec())
        })
    }

    /// One JSON-RPC call by name, its result decoded as `Reply`.
    ///
    /// # Errors
    ///
    /// As [`Self::call`].
    pub fn json_rpc<Req, Reply>(
        &self,
        method: &str,
        request: &Req,
    ) -> Result<Reply, JsonRpcError<LocalFault>>
    where
        Req: serde::Serialize,
        Reply: serde::de::DeserializeOwned,
    {
        crate::json_rpc_via(method, request, |route, body| {
            self.post(route, &body, CALL_WITHIN)
                .map(|reply| reply.to_vec())
        })
    }
}

#[cfg(unix)]
fn dial(node: &str, path: &Path) -> Result<LocalStream, LocalFault> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let me = shekyl_os_account::effective_uid();
    // What is at the path, before anything is sent to it: a socket of this
    // account, or the wrong thing.
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(LocalFault::NotRunning {
                node: node.to_owned(),
            })
        }
        Err(e) => {
            return Err(LocalFault::Unreachable(format!(
                "{} cannot be read: {e}",
                path.display()
            )))
        }
    };
    if !meta.file_type().is_socket() {
        return Err(LocalFault::PeerCheck(format!(
            "{} is not a socket",
            path.display()
        )));
    }
    if meta.uid() != me {
        return Err(LocalFault::PeerCheck(format!(
            "{} belongs to uid {}, not this account (uid {me})",
            path.display(),
            meta.uid()
        )));
    }
    let stream = match LocalStream::connect(path) {
        Ok(stream) => stream,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            return Err(LocalFault::Stale {
                node: node.to_owned(),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(LocalFault::NotRunning {
                node: node.to_owned(),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(LocalFault::PeerCheck(format!(
                "{} refuses this account: {e}",
                path.display()
            )))
        }
        Err(e) => return Err(LocalFault::Unreachable(e.to_string())),
    };
    // The peer is the process that answers: it must run as this account.
    let peer = shekyl_os_account::peer_uid(&stream)
        .map_err(|e| LocalFault::PeerCheck(format!("the peer's account cannot be read: {e}")))?;
    if peer != me {
        return Err(LocalFault::PeerCheck(format!(
            "the process answering at {} runs as uid {peer}, not this account (uid {me})",
            path.display()
        )));
    }
    Ok(stream)
}

#[cfg(windows)]
fn dial(node: &str, path: &Path) -> Result<LocalStream, LocalFault> {
    use shekyl_win_sec::DialError;

    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(LocalFault::NotRunning {
                node: node.to_owned(),
            })
        }
        Err(e) => {
            return Err(LocalFault::Unreachable(format!(
                "{} cannot be read: {e}",
                path.display()
            )))
        }
    };
    let Some(record) = rendezvous::Record::parse(&bytes) else {
        return Err(LocalFault::PeerCheck(format!(
            "{} is not a rendezvous record",
            path.display()
        )));
    };
    let session = shekyl_win_sec::current_logon_sid().map_err(|e| {
        LocalFault::Unreachable(format!("this sign-in session cannot be identified: {e}"))
    })?;
    if record.session != session.as_str() {
        return Err(LocalFault::OtherSession);
    }
    match shekyl_win_sec::open_verified(&record.pipe) {
        Ok(pipe) => Ok(pipe),
        Err(DialError::NotFound) => Err(LocalFault::Stale {
            node: node.to_owned(),
        }),
        Err(DialError::Refused(e)) => Err(LocalFault::PeerCheck(e.to_string())),
        Err(e @ (DialError::Busy | DialError::Open(_) | DialError::Sid(_))) => {
            Err(LocalFault::Unreachable(e.to_string()))
        }
    }
}

/// One `Connection: close` exchange on `stream`, bounded by `within`.
///
/// Unix bounds the socket's reads and writes. A Windows pipe has no such
/// bound, so the exchange runs on a thread of its own and the call returns
/// at the bound; the thread keeps that one connection until the daemon
/// answers or closes it.
#[cfg(unix)]
fn exchange(
    mut stream: LocalStream,
    path: &str,
    body: &[u8],
    within: Duration,
) -> Result<Zeroizing<Vec<u8>>, LocalFault> {
    stream
        .set_read_timeout(Some(within))
        .and_then(|()| stream.set_write_timeout(Some(within)))
        .map_err(|e| LocalFault::Unreachable(e.to_string()))?;
    post_over(&mut stream, path, body).map_err(LocalFault::Unreachable)
}

#[cfg(windows)]
fn exchange(
    mut stream: LocalStream,
    path: &str,
    body: &[u8],
    within: Duration,
) -> Result<Zeroizing<Vec<u8>>, LocalFault> {
    let (path, body) = (path.to_owned(), Zeroizing::new(body.to_vec()));
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("shekyl-local-call".to_owned())
        .spawn(move || {
            drop(send.send(post_over(&mut stream, &path, &body)));
        })
        .map_err(|e| LocalFault::Unreachable(e.to_string()))?;
    match receive.recv_timeout(within) {
        Ok(result) => result.map_err(LocalFault::Unreachable),
        Err(_) => Err(LocalFault::Unreachable(format!(
            "no reply within {} s",
            within.as_secs()
        ))),
    }
}

/// The `Connection: close` HTTP/1.1 exchange the local legs speak: write
/// the request for `path`, read to the end, and return the body of a 200.
/// The reply can carry secret material (a wallet's seed), so the buffers
/// are wiped on drop.
///
/// # Errors
///
/// The write or read failed, the reply is not HTTP, or its status is not
/// 200; the error says which.
pub fn post_over<S: Read + Write>(
    stream: &mut S,
    path: &str,
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.write_all(payload))
        .map_err(|e| format!("write request: {e}"))?;
    let mut raw = Zeroizing::new(Vec::new());
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read response: {e}"))?;
    http_body(&raw)
}

/// The body of an HTTP/1.1 reply read to its end: a 200's body, de-chunked
/// when it is chunked. Bytes until reassembled, so a multibyte character
/// across a chunk boundary survives.
///
/// # Errors
///
/// Not an HTTP reply, a status other than 200, or a broken chunk.
pub fn http_body(raw: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "truncated HTTP response".to_owned())?;
    let head = std::str::from_utf8(&raw[..sep]).map_err(|_| "non-UTF-8 HTTP header".to_owned())?;
    let body = &raw[sep + 4..];
    let status_line = head.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("bad HTTP status line: {status_line}"))?;
    if status != 200 {
        return Err(format!("the server answered HTTP {status}"));
    }
    let chunked = head.lines().skip(1).any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });
    if chunked {
        decode_chunked(body)
    } else {
        // `Connection: close`: the body runs to the end.
        Ok(Zeroizing::new(body.to_vec()))
    }
}

/// Decode a chunked body, byte for byte.
fn decode_chunked(body: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut out = Zeroizing::new(Vec::new());
    let mut rest = body;
    loop {
        let nl = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "truncated chunked body".to_owned())?;
        let size_hex = std::str::from_utf8(&rest[..nl])
            .ok()
            .and_then(|line| line.split(';').next())
            .map(str::trim)
            .ok_or_else(|| "bad chunk size line".to_owned())?;
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("bad chunk size: {size_hex:?}"))?;
        let after = &rest[nl + 2..];
        if size == 0 {
            return Ok(out);
        }
        if after.len() < size + 2 {
            return Err("truncated chunk".to_owned());
        }
        out.extend_from_slice(&after[..size]);
        rest = &after[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_content_length_reply_is_its_body() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(http_body(raw).unwrap().as_slice(), b"{}");
    }

    #[test]
    fn a_chunked_reply_is_reassembled() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert_eq!(http_body(raw).unwrap().as_slice(), b"{}");
    }

    /// Body `{"m":"—"}` (— is U+2014 = 0xE2 0x80 0x94) split so the em-dash
    /// straddles the chunk boundary: byte-wise reassembly keeps it whole.
    #[test]
    fn a_character_across_a_chunk_boundary_survives() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    7\r\n{\"m\":\"\xe2\r\n4\r\n\x80\x94\"}\r\n0\r\n\r\n";
        assert_eq!(
            std::str::from_utf8(&http_body(raw).unwrap()).unwrap(),
            "{\"m\":\"\u{2014}\"}"
        );
    }

    #[test]
    fn a_status_other_than_200_is_named() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
        let err = http_body(raw).unwrap_err();
        assert!(err.contains("401"), "{err}");
    }

    /// The target is the daemon's own naming: the directory, then
    /// `shekyl-<name>` with the platform's suffix.
    #[test]
    fn the_target_is_the_daemons_rendezvous() {
        let dir = Path::new("dir");
        let target = LocalTarget::resolve(Network::Regtest, &Instance::Default, Some(dir)).unwrap();
        let name = rendezvous_name(&Network::Regtest.network_id(), &Instance::Default);
        assert_eq!(target.path(), dir.join(rendezvous::file_name(&name)));
    }

    /// No daemon gives "not running", and an empty directory is not a
    /// security failure. Red edit: map a missing path to `PeerCheck`, and
    /// this fails.
    #[test]
    fn nothing_there_is_not_running_and_not_a_security_failure() {
        let dir = tempfile::tempdir().unwrap();
        let target =
            LocalTarget::resolve(Network::Regtest, &Instance::Default, Some(dir.path())).unwrap();
        let Err(fault) = target.dial() else {
            panic!("a dial with nothing there connected")
        };
        assert!(
            matches!(fault, LocalFault::NotRunning { ref node } if node == "regtest"),
            "{fault:?}"
        );
        assert!(!fault.is_security_failure());
        assert_eq!(
            fault.to_string(),
            "No Shekyl node is running on this computer for regtest."
        );
    }

    /// A socket left behind with nothing listening is stale, not a security
    /// failure; a file that is not a socket is the wrong thing there.
    #[cfg(unix)]
    #[test]
    fn a_stale_socket_is_stale_and_a_plain_file_is_the_wrong_thing() {
        let dir = tempfile::tempdir().unwrap();
        let target =
            LocalTarget::resolve(Network::Regtest, &Instance::Default, Some(dir.path())).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(target.path()).unwrap();
        drop(listener);
        assert!(
            matches!(target.dial(), Err(LocalFault::Stale { .. })),
            "{:?}",
            target.dial().err()
        );
        std::fs::remove_file(target.path()).unwrap();
        std::fs::write(target.path(), b"not a socket").unwrap();
        let fault = target.dial().unwrap_err();
        assert!(fault.is_security_failure(), "{fault:?}");
    }

    /// A socket of this account answered by a process of this account
    /// passes the peer check.
    #[cfg(unix)]
    #[test]
    fn a_socket_of_this_account_passes_the_peer_check() {
        let dir = tempfile::tempdir().unwrap();
        let target =
            LocalTarget::resolve(Network::Regtest, &Instance::Default, Some(dir.path())).unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(target.path()).unwrap();
        target.dial().expect("this account's socket");
    }
}
