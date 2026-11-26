// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! "This computer": a client's dial of the daemon run as its own account,
//! on the owner's leg (`docs/design/RPC_CHANNEL.md` RT-15, §7.1).
//!
//! The target resolves through the daemon's own naming
//! ([`shekyl_rpc_rendezvous::rendezvous_name`] over the network id and the
//! instance, and [`shekyl_rpc_rendezvous`]'s layout for the file and the
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
//! When no node of this account is there, "this computer" may be a service
//! (RT-16). A target that knows the service's rendezvous directory reads the
//! service's record only to say so ([`LocalFault::Service`], with the view
//! listener it names, if any). It dials nothing the record names: a wallet
//! reaches a service over the channel, from RT-W12 (Rick, 2026-11-17).
//!
//! [`LocalRpc`] is the target behind the async [`Rpc`] trait, for the wallet
//! engine: each call runs on the blocking pool, one connection each.
//!
//! The account's root (the session directory on Unix, the local
//! application data folder on Windows) and the peer's account on Unix come
//! from `shekyl_os_account`, the leaf the daemon's process crate reads the
//! same root from: one reader, and no network stack under it.

use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use shekyl_network::Network;
use shekyl_rpc_client::{Rpc, RpcError};
use shekyl_rpc_rendezvous::{rendezvous_name, Instance, ServiceRecord};
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
    /// No node of this account is there, and this computer's node is a
    /// service: its record says so. `view` is the service's view listener
    /// when it has one. Nothing was dialled.
    Service {
        /// The network and instance looked for.
        node: String,
        /// The service's view listener, as its record names it.
        view: Option<SocketAddr>,
    },
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
            Self::Service { view, .. } => f.write_str(&shekyl_rpc_client::service_refusal(*view)),
        }
    }
}

impl std::error::Error for LocalFault {}

/// A run-as-me daemon's owner's leg: "this computer" (the default instance
/// in the account's own directory), or an instance or a directory named by
/// the caller; and, when given, the service's rendezvous directory, read
/// only to say that this computer's node is a service.
#[derive(Clone, Debug)]
pub struct LocalTarget {
    node: String,
    /// The owner's rendezvous; `None` when the account has no root for one.
    path: Option<PathBuf>,
    /// The service's record for the same network and instance.
    service_record: Option<shekyl_rpc_rendezvous::ServiceRecordAt>,
}

/// The stream the owner's leg is.
#[cfg(unix)]
pub type LocalStream = std::os::unix::net::UnixStream;

/// The stream the owner's leg is: the pipe, opened through the peer check.
#[cfg(windows)]
pub type LocalStream = shekyl_win_sec::VerifiedPipe;

impl LocalTarget {
    /// "This computer" for `network`: the default instance in this
    /// account's rendezvous directory, and the service's record
    /// (`shekyl_rpc_rendezvous::service_record_at`: the file in the
    /// service's fixed rendezvous directory, or on Windows the registry
    /// value), consulted only when no node of this account is there.
    ///
    /// The one way a client names "this computer" (Rick, 2026-11-18): the
    /// network is all it gives. The directories are this account's and
    /// this platform's, read here, so no client assembles them and none can
    /// leave the service's out.
    #[must_use]
    pub fn this_computer(network: Network) -> Self {
        let service_record =
            shekyl_rpc_rendezvous::service_record_at(&network.network_id(), &Instance::Default);
        Self::at(network, &Instance::Default, None, service_record)
    }

    /// **A test's override.** `instance` of `network` in the directory
    /// `dir` (a test host's `rpc-socket-dir`), with the service's record
    /// looked for in `service_rendezvous`, each `None` for none: a test
    /// node lives in directories of its own, which "this computer" does not
    /// name. Behind the `test-override` feature, which
    /// `scripts/ci/check_test_only_features.py` holds to dev-dependency
    /// edges: a production client cannot name a directory, and so cannot
    /// name a wrong one.
    #[cfg(any(test, feature = "test-override"))]
    #[must_use]
    pub fn test_override(
        network: Network,
        instance: &Instance,
        dir: Option<&Path>,
        service_rendezvous: Option<&Path>,
    ) -> Self {
        let service_record = service_rendezvous.map(|dir| {
            shekyl_rpc_rendezvous::ServiceRecordAt::file(dir, &network.network_id(), instance)
        });
        Self::at(network, instance, dir, service_record)
    }

    /// `instance` of `network`, in `dir` when given, otherwise in this
    /// account's rendezvous directory; and the service's record at
    /// `service_record`, when given. An account with no root is
    /// [`LocalFault::NoPlace`] at the dial, unless a service is there.
    fn at(
        network: Network,
        instance: &Instance,
        dir: Option<&Path>,
        service_record: Option<shekyl_rpc_rendezvous::ServiceRecordAt>,
    ) -> Self {
        let node = match instance {
            Instance::Default => network.name().to_owned(),
            Instance::Named(_) => format!("{} (instance {})", network.name(), instance.label()),
        };
        let dir = match dir {
            Some(dir) => Some(dir.to_path_buf()),
            None => shekyl_os_account::account_root()
                .map(|root| shekyl_rpc_rendezvous::account_dir(&root)),
        };
        let network_id = network.network_id();
        let name = rendezvous_name(&network_id, instance);
        Self {
            node,
            path: dir.map(|dir| dir.join(shekyl_rpc_rendezvous::file_name(&name))),
            service_record,
        }
    }

    /// The rendezvous: the socket (Unix) or the record (Windows); `None`
    /// when the account has no root for one.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// The service published for this local target. An unreadable record
    /// is a refusal, so callers cannot fall through to another transport.
    pub(crate) fn service(&self) -> Result<Option<ServiceRecord>, super::channel::ChannelFault> {
        let Some(place) = &self.service_record else {
            return Ok(None);
        };
        let bytes = place.read().map_err(|e| {
            super::channel::ChannelFault::Local(format!("service record {place}: {e}"))
        })?;
        bytes
            .map(|bytes| {
                ServiceRecord::parse(&bytes).ok_or_else(|| {
                    super::channel::ChannelFault::Local(format!(
                        "invalid service record at {place}"
                    ))
                })
            })
            .transpose()
    }

    /// Resolve a local service's enrolled wallet channel from its published record.
    /// A run-as-me node without a service record uses the owner socket.
    ///
    /// # Errors
    ///
    /// A malformed or unreadable service record, unusable channel bundle, or an
    /// account identity that needs enrollment.
    pub fn wallet_channel(
        &self,
        network: Network,
        account: &crate::ChannelAccount,
    ) -> Result<Option<crate::channel::ChannelTarget>, crate::channel::ChannelFault> {
        use crate::{channel, listen};
        // Prefer this account's rendezvous when both records exist. The
        // owner dial verifies the peer, including when its socket is stale.
        if let Some(owner) = self.path() {
            match std::fs::symlink_metadata(owner) {
                Ok(_) => return Ok(None),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(channel::ChannelFault::Local(format!(
                        "cannot inspect the owner rendezvous {}: {error}",
                        owner.display()
                    )))
                }
            }
        }
        let Some(record) = self.service()? else {
            return Ok(None);
        };
        let service = record.channel.ok_or_else(|| channel::ChannelFault::Local(
            "the local service has no channel listener. Set rpc-listen on the node to a loopback address".into()
        ))?;
        if !listen::is_loopback_ip(service.address.ip()) {
            return Err(channel::ChannelFault::Local(
                "the service record must name a loopback channel".into(),
            ));
        }
        let bundle = channel::bundle_from_bytes(&service.bundle).ok_or_else(|| {
            channel::ChannelFault::Local(
                "the local service published an invalid channel bundle".into(),
            )
        })?;
        channel::account_target(
            network,
            channel::Leg::ip(service.address, None),
            bundle,
            account.key_file.as_deref(),
        )
        .map(Some)
    }

    /// Connect to the owner's leg and check its peer.
    ///
    /// # Errors
    ///
    /// [`LocalFault`]: not running (or a service is), stale, another
    /// session, a failed peer check, or a dial that failed otherwise.
    pub fn dial(&self) -> Result<LocalStream, LocalFault> {
        self.dial_by(None)
    }

    /// The dial, bounded by `deadline` when given. No node of this account
    /// at the rendezvous is the service's record's question.
    fn dial_by(&self, deadline: Option<Instant>) -> Result<LocalStream, LocalFault> {
        match &self.path {
            Some(path) => match dial(&self.node, path, deadline) {
                Err(LocalFault::NotRunning { .. }) => Err(self.nothing_here(false)),
                other => other,
            },
            None => Err(self.nothing_here(true)),
        }
    }

    /// No node of this account: a service, if its record is there, or
    /// [`LocalFault::NotRunning`] ([`LocalFault::NoPlace`] when the account
    /// has no root). The record is read and nothing it names is dialled.
    fn nothing_here(&self, no_place: bool) -> LocalFault {
        if let Some(record) = &self.service_record {
            match record.read() {
                Ok(Some(bytes)) => {
                    return match ServiceRecord::parse(&bytes) {
                        Some(found) => LocalFault::Service {
                            node: self.node.clone(),
                            view: found.view,
                        },
                        None => LocalFault::Unreachable(format!(
                            "{record} is not a service's rendezvous record this build reads"
                        )),
                    };
                }
                Ok(None) => {}
                Err(e) => {
                    return LocalFault::Unreachable(format!(
                        "the service's record {record} cannot be read: {e}"
                    ))
                }
            }
        }
        let node = self.node.clone();
        if no_place {
            LocalFault::NoPlace { node }
        } else {
            LocalFault::NotRunning { node }
        }
    }

    /// POST `body` to `route` on the owner's leg and return the reply's
    /// body: one connection, closed after the reply. `within` bounds the
    /// whole call, one deadline from before the dial to the reply's last
    /// byte: a daemon that answers slowly, or a byte at a time, cannot hold
    /// the caller past it. On Unix the connect itself returns at once
    /// unless the daemon's accept queue is full, and is the one step the
    /// deadline does not interrupt.
    ///
    /// # Errors
    ///
    /// [`LocalFault`], from the dial or the exchange; a call the deadline
    /// ends is [`LocalFault::Unreachable`].
    pub fn post(
        &self,
        route: &str,
        body: &[u8],
        within: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, LocalFault> {
        let deadline = Instant::now() + within;
        let path = format!("/{}", route.trim_start_matches('/'));
        let stream = self.dial_by(Some(deadline))?;
        exchange(stream, &path, body, deadline, within)
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

/// Dial the owner's leg at `path`. Unix: the connect to a local socket does
/// not wait on `_deadline` (see [`LocalTarget::post`]).
#[cfg(unix)]
fn dial(node: &str, path: &Path, _deadline: Option<Instant>) -> Result<LocalStream, LocalFault> {
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

/// Dial the owner's leg the record at `path` names. A busy pipe is waited
/// for no later than `deadline`.
#[cfg(windows)]
fn dial(node: &str, path: &Path, deadline: Option<Instant>) -> Result<LocalStream, LocalFault> {
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
    let Some(record) = shekyl_rpc_rendezvous::Record::parse(&bytes) else {
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
    let opened = match deadline {
        Some(deadline) => shekyl_win_sec::open_verified_by(&record.pipe, deadline),
        None => shekyl_win_sec::open_verified(&record.pipe),
    };
    match opened {
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

/// What a call the deadline ended says.
fn no_reply(within: Duration) -> LocalFault {
    LocalFault::Unreachable(format!("no reply within {:.1} s", within.as_secs_f64()))
}

/// One `Connection: close` exchange on `stream`, ending by `deadline`.
///
/// Unix: every read and write waits only for what is left of the deadline,
/// so the exchange as a whole ends by it ([`Deadlined`]).
#[cfg(unix)]
fn exchange(
    stream: LocalStream,
    path: &str,
    body: &[u8],
    deadline: Instant,
    within: Duration,
) -> Result<Zeroizing<Vec<u8>>, LocalFault> {
    let mut stream = Deadlined { stream, deadline };
    post_over(&mut stream, path, body).map_err(|e| {
        if Instant::now() >= deadline {
            no_reply(within)
        } else {
            LocalFault::Unreachable(e)
        }
    })
}

/// A Unix socket whose every read and write waits only for what is left of
/// one deadline. A per-operation timeout alone would let a peer that sends
/// a byte before each one runs out keep the call going without end.
#[cfg(unix)]
struct Deadlined {
    stream: LocalStream,
    deadline: Instant,
}

#[cfg(unix)]
impl Deadlined {
    /// What is left of the deadline; none left is the call timed out. The
    /// socket refuses a zero timeout, so a spent deadline never reaches it.
    fn left(&self) -> std::io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            Err(std::io::ErrorKind::TimedOut.into())
        } else {
            Ok(left)
        }
    }
}

/// A bound the socket refused because its peer has closed: macOS refuses
/// `SO_RCVTIMEO` and `SO_SNDTIMEO` (`EINVAL`) on such a socket. A read there
/// returns at once, with what is buffered or end of stream, and a write
/// fails at once, so the operation needs no bound and goes ahead.
#[cfg(unix)]
fn bounded(set: std::io::Result<()>) -> std::io::Result<()> {
    match set {
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
        other => other,
    }
}

#[cfg(unix)]
impl Read for Deadlined {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.left()?;
        bounded(self.stream.set_read_timeout(Some(left)))?;
        self.stream.read(buf)
    }
}

#[cfg(unix)]
impl Write for Deadlined {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let left = self.left()?;
        bounded(self.stream.set_write_timeout(Some(left)))?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

/// One `Connection: close` exchange on `stream`, ending by `deadline`.
///
/// Windows: a pipe has no read or write timeout, so the exchange runs on a
/// thread of its own. At the deadline the call cancels the I/O that thread
/// is blocked in, and again until the thread reports back (a cancel that
/// lands between two calls cancels nothing), then joins it: the thread and
/// its connection end with the call.
#[cfg(windows)]
fn exchange(
    mut stream: LocalStream,
    path: &str,
    body: &[u8],
    deadline: Instant,
    within: Duration,
) -> Result<Zeroizing<Vec<u8>>, LocalFault> {
    use std::sync::mpsc::RecvTimeoutError;

    /// How often a stopped call cancels the thread's I/O again.
    const CANCEL_AGAIN: Duration = Duration::from_millis(20);

    let (path, body) = (path.to_owned(), Zeroizing::new(body.to_vec()));
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("shekyl-local-call".to_owned())
        .spawn(move || {
            drop(send.send(post_over(&mut stream, &path, &body)));
        })
        .map_err(|e| LocalFault::Unreachable(e.to_string()))?;
    let left = deadline.saturating_duration_since(Instant::now());
    let outcome = match receive.recv_timeout(left) {
        Ok(result) => result.map_err(LocalFault::Unreachable),
        Err(RecvTimeoutError::Disconnected) => Err(LocalFault::Unreachable(
            "the call's thread ended without a reply".to_owned(),
        )),
        Err(RecvTimeoutError::Timeout) => {
            loop {
                if let Err(e) = shekyl_win_sec::cancel_synchronous_io(&worker) {
                    // The I/O cannot be cancelled: the thread keeps its one
                    // connection until the daemon answers or closes it.
                    return Err(LocalFault::Unreachable(format!(
                        "no reply within {:.1} s, and the call could not be stopped: {e}",
                        within.as_secs_f64()
                    )));
                }
                match receive.recv_timeout(CANCEL_AGAIN) {
                    Ok(_) | Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => {}
                }
            }
            Err(no_reply(within))
        }
    };
    // The thread has sent its result or ended; joining releases it.
    drop(worker.join());
    outcome
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

/// "This computer" behind the async [`Rpc`] trait: the wallet engine's
/// daemon when no address is named (RT-W10 step 5). Each call is one
/// connection on the blocking pool, bounded by its deadline; a blocking task
/// is not a cancellation point, so a call in flight at shutdown drains
/// within that bound.
#[derive(Clone, Debug)]
pub struct LocalRpc {
    target: Arc<LocalTarget>,
    within: Duration,
    /// A failed peer check or a service at this computer. The target does
    /// not change, so a later call on this client returns it without dialing.
    refused: Arc<std::sync::Mutex<Option<RpcError>>>,
}

impl LocalRpc {
    /// `target`, each call bounded by [`CALL_WITHIN`].
    #[must_use]
    pub fn new(target: LocalTarget) -> Self {
        Self::within(target, CALL_WITHIN)
    }

    /// `target`, each call bounded by `within`.
    #[must_use]
    pub fn within(target: LocalTarget, within: Duration) -> Self {
        Self {
            target: Arc::new(target),
            within,
            refused: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

impl Rpc for LocalRpc {
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
        let target = Arc::clone(&self.target);
        let route = route.to_owned();
        let within = self.within;
        let refused = Arc::clone(&self.refused);
        async move {
            if let Some(error) = refused
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
            {
                return Err(error);
            }
            let result = tokio::task::spawn_blocking(move || target.post(&route, &body, within))
                .await
                .map_err(|e| RpcError::InternalError(format!("the local call's task: {e}")))?
                .map(|reply| reply.to_vec())
                .map_err(rpc_error);
            if let Err(error) = &result {
                if error.fault().is_target_refusal() {
                    *refused
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error.clone());
                }
            }
            result
        }
    }
}

/// A local fault as the wallet's [`RpcError`]: the failed peer check and a
/// service at "this computer" keep their own variants, so neither reads as
/// a connection to retry; every other fault is the node not running or not
/// answering, in this module's words.
#[must_use]
pub fn rpc_error(fault: LocalFault) -> RpcError {
    match fault {
        LocalFault::PeerCheck(detail) => RpcError::PeerCheck(detail),
        LocalFault::Service { view, .. } => RpcError::Service(view),
        other @ (LocalFault::NoPlace { .. }
        | LocalFault::NotRunning { .. }
        | LocalFault::Stale { .. }
        | LocalFault::OtherSession
        | LocalFault::Unreachable(_)) => RpcError::ConnectionError(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **"This computer" names the service's record itself** (Rick,
    /// 2026-11-18). A client gives its network and nothing else, and the
    /// target it gets looks for the service's record where this platform
    /// keeps it (the file, or on Windows the registry value), under this
    /// network's name for the default instance. Pure: nothing is dialled and no host is needed.
    /// Red edit: have `this_computer` pass `None` for the service
    /// directory; every client then stops seeing a service, silently.
    #[test]
    fn this_computer_names_the_service_s_directory_itself() {
        let target = LocalTarget::this_computer(Network::Regtest);
        let expected = shekyl_rpc_rendezvous::service_record_at(
            &Network::Regtest.network_id(),
            &Instance::Default,
        );
        assert_eq!(target.service_record, expected);
        // Every platform with a row, and Windows' registry value, is a
        // place, so this is not a comparison of two absences there.
        if cfg!(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "macos",
            windows
        )) {
            assert!(target.service_record.is_some());
        }
    }

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
        let target =
            LocalTarget::test_override(Network::Regtest, &Instance::Default, Some(dir), None);
        let name = rendezvous_name(&Network::Regtest.network_id(), &Instance::Default);
        assert_eq!(
            target.path().expect("a named directory"),
            dir.join(shekyl_rpc_rendezvous::file_name(&name))
        );
    }

    /// No daemon gives "not running", and an empty directory is not a
    /// security failure. Red edit: map a missing path to `PeerCheck`, and
    /// this fails.
    #[test]
    fn nothing_there_is_not_running_and_not_a_security_failure() {
        let dir = tempfile::tempdir().unwrap();
        let target = LocalTarget::test_override(
            Network::Regtest,
            &Instance::Default,
            Some(dir.path()),
            None,
        );
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

    /// No node of this account here, and a service's record beside it
    /// (Rick, 2026-11-17): a record with a view listener names it as the
    /// `daemon-address` to set; one without says the node serves no wallet
    /// leg and names `rpc-view-listen`; no record is "not running"; and a
    /// record this build does not read is not taken for a service. Nothing
    /// the record names is dialled. Red edit: drop the record read in
    /// `nothing_here`, and both service cases are "not running".
    #[test]
    fn a_service_here_is_named_by_its_record_and_nothing_is_dialled() {
        let owner = tempfile::tempdir().unwrap();
        let service = tempfile::tempdir().unwrap();
        let target = LocalTarget::test_override(
            Network::Regtest,
            &Instance::Default,
            Some(owner.path()),
            Some(service.path()),
        );
        assert!(
            matches!(target.dial(), Err(LocalFault::NotRunning { .. })),
            "{:?}",
            target.dial().err()
        );

        // Listeners at the addresses the record names: neither is dialled.
        let view = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let channel = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let view_at = view.local_addr().unwrap();
        let record = shekyl_rpc_rendezvous::service_record_path(
            service.path(),
            &Network::Regtest.network_id(),
            &Instance::Default,
        );
        std::fs::write(
            &record,
            ServiceRecord {
                channel: Some(shekyl_rpc_rendezvous::ServiceChannel {
                    address: channel.local_addr().unwrap(),
                    bundle: vec![1, 2, 3],
                }),
                view: Some(view_at),
            }
            .bytes(),
        )
        .unwrap();
        let Err(fault) = target.dial() else {
            panic!("a node that runs as a service is not dialled");
        };
        assert_eq!(
            fault,
            LocalFault::Service {
                node: "regtest".to_owned(),
                view: Some(view_at),
            }
        );
        assert!(!fault.is_security_failure());
        assert_eq!(
            fault.to_string(),
            format!(
                "The node on this computer runs as a service. Until wallets reach a service \
                 over the channel, set daemon-address = {view_at}"
            )
        );
        for listener in [&view, &channel] {
            listener.set_nonblocking(true).unwrap();
            assert!(
                listener.accept().is_err(),
                "the record's address was dialled"
            );
        }

        std::fs::write(
            &record,
            ServiceRecord {
                channel: None,
                view: None,
            }
            .bytes(),
        )
        .unwrap();
        let Err(fault) = target.dial() else {
            panic!("a node that runs as a service is not dialled");
        };
        assert!(
            matches!(fault, LocalFault::Service { view: None, .. }),
            "{fault:?}"
        );
        let text = fault.to_string();
        assert!(text.contains("serves no wallet leg"), "{text}");
        assert!(text.contains("rpc-view-listen"), "{text}");

        std::fs::write(&record, b"shekyl-service-rendezvous 1\n").unwrap();
        assert!(
            matches!(target.dial(), Err(LocalFault::Unreachable(_))),
            "{:?}",
            target.dial().err()
        );
    }

    /// The failed peer check reaches the async client as its own error,
    /// whose fault is never retried. Red edit: fold `LocalFault::PeerCheck`
    /// into a connection error in `rpc_error`, and this fails.
    #[cfg(unix)]
    #[test]
    fn a_failed_peer_check_is_its_own_error_through_the_async_client() {
        let dir = tempfile::tempdir().unwrap();
        let target = LocalTarget::test_override(
            Network::Regtest,
            &Instance::Default,
            Some(dir.path()),
            None,
        );
        let path = target.path().expect("a named directory").to_path_buf();
        std::fs::write(&path, b"not a socket").unwrap();
        let client = LocalRpc::new(target);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let error = rt
            .block_on(client.post("json_rpc", b"{}".to_vec()))
            .unwrap_err();
        assert!(matches!(error, RpcError::PeerCheck(_)), "{error:?}");
        assert_eq!(error.fault(), shekyl_rpc_client::DaemonFault::PeerCheck);
        assert!(!error.fault().is_retryable());

        // The refusal is kept: replacing the file with this account's
        // socket does not earn a second dial. Red edit: do not store the
        // fault on `LocalRpc`, and the second call connects.
        std::fs::remove_file(&path).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::Write;
                drop(stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                ));
            }
        });
        let again = rt
            .block_on(client.post("json_rpc", b"{}".to_vec()))
            .unwrap_err();
        assert!(
            matches!(again, RpcError::PeerCheck(_)),
            "a kept refusal must not dial again: {again:?}"
        );
    }

    /// A socket left behind with nothing listening is stale, not a security
    /// failure; a file that is not a socket is the wrong thing there.
    /// A call's outcome and how long it took.
    #[cfg(unix)]
    type Timed = (Result<Zeroizing<Vec<u8>>, LocalFault>, Duration);

    /// `post` on a thread: its outcome and how long it took, or `None` if
    /// it is still running at `guard` (a call the bound did not end).
    #[cfg(unix)]
    fn post_guarded(target: LocalTarget, within: Duration, guard: Duration) -> Option<Timed> {
        let (sent, outcome) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let started = Instant::now();
            let result = target.post("json_rpc", b"{}", within);
            drop(sent.send((result, started.elapsed())));
        });
        outcome.recv_timeout(guard).ok()
    }

    /// A daemon at `target`'s socket that runs `serve` on the one
    /// connection it accepts.
    #[cfg(unix)]
    fn serve_once(
        target: &LocalTarget,
        serve: impl FnOnce(std::os::unix::net::UnixStream) + Send + 'static,
    ) -> std::thread::JoinHandle<()> {
        let listener =
            std::os::unix::net::UnixListener::bind(target.path().expect("a named directory"))
                .unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve(stream);
        })
    }

    /// **A daemon that never replies is given up at the bound.** The call
    /// is unreachable, not a security failure, and returns near its bound.
    #[cfg(unix)]
    #[test]
    fn a_daemon_that_never_replies_is_given_up_at_the_bound() {
        let dir = tempfile::tempdir().unwrap();
        let target = LocalTarget::test_override(
            Network::Regtest,
            &Instance::Default,
            Some(dir.path()),
            None,
        );
        let (release, held) = std::sync::mpsc::channel::<()>();
        let daemon = serve_once(&target, move |mut stream| {
            let mut request = [0u8; 1024];
            drop(stream.read(&mut request));
            // The call letting go drops the sender.
            held.recv().unwrap_err();
        });
        let (outcome, took) =
            post_guarded(target, Duration::from_millis(300), Duration::from_secs(10))
                .expect("the call returned");
        assert!(
            matches!(outcome, Err(LocalFault::Unreachable(_))),
            "{outcome:?}"
        );
        assert!(took < Duration::from_secs(3), "{took:?}");
        drop(release);
        daemon.join().unwrap();
    }

    /// **A reply the daemon sends whole and then closes is read whole.**
    /// The call reads on to the end of stream after the daemon has closed,
    /// where macOS refuses a read bound. Red edit (macOS): treat that
    /// refusal as an error, and the call fails after the reply arrived.
    #[cfg(unix)]
    #[test]
    fn a_reply_followed_by_the_close_is_read_whole() {
        let dir = tempfile::tempdir().unwrap();
        let target = LocalTarget::test_override(
            Network::Regtest,
            &Instance::Default,
            Some(dir.path()),
            None,
        );
        let daemon = serve_once(&target, |mut stream| {
            // The whole request, headers and the two-byte body, so the close
            // leaves nothing unread (an unread byte turns the close into a
            // reset).
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.ends_with(b"\r\n\r\n{}") {
                let n = stream.read(&mut chunk).unwrap();
                assert_ne!(n, 0, "the request ended early");
                request.extend_from_slice(&chunk[..n]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .unwrap();
        });
        let reply = target.post("json_rpc", b"{}", Duration::from_secs(5));
        daemon.join().unwrap();
        assert_eq!(&reply.expect("the reply")[..], b"{}");
    }

    /// **A daemon that answers a byte at a time is given up at the bound.**
    /// One deadline covers the whole call: a byte before each read's bound
    /// does not extend it. Red edit: give each read and write the whole of
    /// `within` instead of what is left of it, and the call runs past the
    /// guard.
    #[cfg(unix)]
    #[test]
    fn a_daemon_that_answers_a_byte_at_a_time_is_given_up_at_the_bound() {
        let dir = tempfile::tempdir().unwrap();
        let target = LocalTarget::test_override(
            Network::Regtest,
            &Instance::Default,
            Some(dir.path()),
            None,
        );
        let daemon = serve_once(&target, |mut stream| {
            let mut request = [0u8; 1024];
            drop(stream.read(&mut request));
            for byte in b"HTTP/1.1 200 OK\r\n".iter().cycle() {
                if stream.write_all(&[*byte]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let (outcome, took) =
            post_guarded(target, Duration::from_millis(400), Duration::from_secs(10))
                .expect("the call returned");
        assert!(
            matches!(outcome, Err(LocalFault::Unreachable(_))),
            "{outcome:?}"
        );
        assert!(took < Duration::from_secs(3), "{took:?}");
        daemon.join().unwrap();
    }

    /// **A call the bound ends releases its connection (Windows).** Three
    /// calls to a daemon that never replies each return at the bound, and
    /// the daemon sees each connection close: the call's thread is stopped
    /// and joined, not left holding the pipe. Red edit: leave the thread
    /// running at the bound (no cancel, no join), and the daemon's wait for
    /// the close runs out.
    #[cfg(windows)]
    #[test]
    fn a_call_the_bound_ends_releases_its_connection() {
        use tokio::io::AsyncReadExt;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let target = LocalTarget::test_override(
            Network::Regtest,
            &Instance::Default,
            Some(dir.path()),
            None,
        );
        let pipe = format!(
            "{}{:032x}",
            shekyl_rpc_rendezvous::PIPE_PREFIX,
            (u128::from(std::process::id()) << 16) | 0xb0d
        );
        let session = shekyl_win_sec::current_logon_sid().unwrap();
        std::fs::write(
            target.path().expect("a named directory"),
            shekyl_rpc_rendezvous::Record {
                pipe: pipe.clone(),
                session: session.as_str().to_owned(),
            }
            .bytes(),
        )
        .unwrap();
        let mut listener = {
            let _runtime = rt.enter();
            shekyl_win_sec::OwnerOnlyPipeListener::bind(pipe).unwrap()
        };
        const CALLS: usize = 3;
        let daemon = rt.spawn(async move {
            let mut closed = 0;
            for _ in 0..CALLS {
                let mut connection = listener.accept().await.unwrap();
                let mut buffer = vec![0u8; 4096];
                drop(connection.read(&mut buffer).await);
                // Never replies; waits for the caller to let go.
                let gone =
                    tokio::time::timeout(Duration::from_secs(5), connection.read(&mut buffer));
                if gone.await.is_ok() {
                    closed += 1;
                }
            }
            closed
        });
        for _ in 0..CALLS {
            let started = Instant::now();
            let outcome = target.post("json_rpc", b"{}", Duration::from_millis(300));
            assert!(
                matches!(outcome, Err(LocalFault::Unreachable(_))),
                "{outcome:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "{:?}",
                started.elapsed()
            );
        }
        assert_eq!(
            rt.block_on(daemon).unwrap(),
            CALLS,
            "each call released its connection"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_stale_socket_is_stale_and_a_plain_file_is_the_wrong_thing() {
        let dir = tempfile::tempdir().unwrap();
        let target = LocalTarget::test_override(
            Network::Regtest,
            &Instance::Default,
            Some(dir.path()),
            None,
        );
        let listener =
            std::os::unix::net::UnixListener::bind(target.path().expect("a named directory"))
                .unwrap();
        drop(listener);
        assert!(
            matches!(target.dial(), Err(LocalFault::Stale { .. })),
            "{:?}",
            target.dial().err()
        );
        std::fs::remove_file(target.path().expect("a named directory")).unwrap();
        std::fs::write(target.path().expect("a named directory"), b"not a socket").unwrap();
        let fault = target.dial().unwrap_err();
        assert!(fault.is_security_failure(), "{fault:?}");
    }

    /// A socket of this account answered by a process of this account
    /// passes the peer check.
    #[cfg(unix)]
    #[test]
    fn a_socket_of_this_account_passes_the_peer_check() {
        let dir = tempfile::tempdir().unwrap();
        let target = LocalTarget::test_override(
            Network::Regtest,
            &Instance::Default,
            Some(dir.path()),
            None,
        );
        let _listener =
            std::os::unix::net::UnixListener::bind(target.path().expect("a named directory"))
                .unwrap();
        target.dial().expect("this account's socket");
    }
}
