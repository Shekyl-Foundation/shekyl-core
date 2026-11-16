// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The RPC channel's client (`docs/design/RPC_CHANNEL.md` RT-W11): it dials
//! a daemon, runs the `hybridXK` handshake against the daemon's public
//! bundle, and carries HTTP over the record stream, behind the same calls
//! the transport's other targets offer ([`ChannelDaemon::call`],
//! [`ChannelDaemon::json_rpc`]).
//!
//! Four layers, each usable alone:
//!
//! - [`Leg`]: where the daemon is, an address or an onion (through a SOCKS
//!   proxy), a socket, or a Windows pipe; dialed into a [`LegStream`].
//! - [`handshake_over`]: the client's side of the handshake over any
//!   stream, ending in the record stream and the ceiling message 4 carried.
//!   [`ChannelTarget::open`] dials and runs it under §4.3's policy: the
//!   handshake deadline, one silent retry after a timeout, and a jittered
//!   back-off after a busy reply.
//! - [`Session`]: hyper's `client::conn::http1` over one record stream, a
//!   connection of its own (§13, RT-W11's client contracts). A submission
//!   is sent with the stream's [`SubmissionMark`] armed, as one complete
//!   body, and the session carries nothing else until its response.
//! - [`Pool`]: up to `SESSIONS_PER_CLIENT` sessions to one daemon under one
//!   grant (§8): opened on demand, one kept open and reopened when the
//!   daemon closes it, extras closed after [`EXTRA_SESSION_IDLE`]. A request
//!   beyond the cap waits for a session, bounded by the handshake deadline.
//!   A revocation stops the pool, which does not dial again.
//!
//! Every failure is a [`ChannelFault`], worded for the person who reads it
//! (§4.5, rule 81). What the client cannot tell apart, it names together and
//! points at the node's log.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use rand_core::OsRng;
use shekyl_rpc_channel::deadline::HANDSHAKE_DEADLINE;
use shekyl_rpc_channel::handshake::{
    Client, StaticKeypair, StaticPublic, MESSAGE2_LEN, MESSAGE4_LEN,
};
use shekyl_rpc_channel::retry::{AttemptEnd, HandshakeFailure, HandshakeRetry, Next};
use shekyl_rpc_channel::{NetworkId, BUSY_LEN, SESSIONS_PER_CLIENT};
use shekyl_rpc_grants::GrantSet;
use shekyl_rpc_stream::{RecordStream, SubmissionMark};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// How long a pool's extra session may sit idle before the pool closes it.
///
/// **Assumption** (Rick, 2026-11-15). Basis: a session costs each side
/// about 2.16 ms of CPU to open on the floor device (RT-P6), so an extra
/// closed after 30 s of quiet and opened again costs the daemon at most
/// 2.16 ms per 30 s, 0.0072 % of one core, for each extra. RT-P10 measures
/// the pool under load. The kept session idles at the record stream's own
/// limit (`shekyl_rpc_stream::RECORD_IDLE`), as the daemon's side does.
pub const EXTRA_SESSION_IDLE: Duration = Duration::from_secs(30);

/// How often a pool looks at its idle sessions.
const KEEPER_TICK: Duration = Duration::from_secs(1);

/// Why the channel did not carry a call. Each variant is one thing the
/// person reading it can act on (§4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelFault {
    /// Nothing accepted the connection at the leg.
    Unreachable {
        /// The leg, as the person named it.
        at: String,
        /// What the operating system or the proxy said.
        cause: String,
    },
    /// The node closed the connection after message 1 without answering:
    /// it does not hold this client's copy of its key, is on another
    /// network, or speaks another channel version. The node's log says
    /// which.
    NotRecognised {
        /// The leg.
        at: String,
    },
    /// Message 2 did not come from the node whose bundle this client holds.
    /// Not retried.
    NotTheDaemon {
        /// The leg.
        at: String,
    },
    /// The node answered and closed after message 3: this key is not
    /// enrolled there.
    NotEnrolled {
        /// This client's fingerprint, for the operator's `rpc client add`.
        fingerprint: [u8; 32],
    },
    /// The node revoked this client: a session it held was closed and the
    /// next one was refused at message 3. The pool does not dial again.
    Revoked,
    /// The handshake did not finish within its deadline, retried once.
    TimedOut,
    /// The node answered busy until the handshake deadline.
    Busy,
    /// No session came free within the handshake deadline: this client
    /// already holds `SESSIONS_PER_CLIENT`, each busy.
    PoolFull,
    /// The connection closed under a call.
    Closed,
    /// This client's own state failed: its key, or randomness.
    Local(String),
}

impl std::fmt::Display for ChannelFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable { at, cause } => {
                write!(f, "No Shekyl node answered at {at}: {cause}.")
            }
            Self::NotRecognised { at } => write!(
                f,
                "The node at {at} closed the connection without answering. It does not \
                 recognise this client's copy of its key, is on a different network, or runs \
                 a different version. The node's log records which."
            ),
            Self::NotTheDaemon { at } => write!(
                f,
                "Something answered at {at} that is not the node you enrolled with. Do not \
                 connect; check the address."
            ),
            Self::NotEnrolled { fingerprint } => write!(
                f,
                "The node answered but has not enrolled this client. Enrol it on the node \
                 with: shekyl-cli rpc client add {} --ceiling GRANTS",
                hex::encode(fingerprint)
            ),
            Self::Revoked => f.write_str("The node revoked this client's enrolment."),
            Self::TimedOut => f.write_str("The node did not complete the handshake in time."),
            Self::Busy => f.write_str(
                "The node is busy and did not accept the connection in time. Try again shortly.",
            ),
            Self::PoolFull => f.write_str(
                "Every connection this client may hold to the node is busy; none came free in \
                 time.",
            ),
            Self::Closed => f.write_str("The node closed the connection."),
            Self::Local(why) => write!(f, "This client could not use the channel: {why}."),
        }
    }
}

impl std::error::Error for ChannelFault {}

/// Where the daemon's channel is.
#[derive(Clone, Debug)]
pub enum Leg {
    /// An address or an onion, `host:port`, dialed directly or through a
    /// SOCKS5 proxy, which resolves the name (an onion needs one).
    Network {
        /// `host:port`: an IP address or an onion.
        endpoint: String,
        /// The SOCKS5 proxy, if any.
        socks: Option<SocketAddr>,
    },
    /// A Unix socket: a service's console leg (RT-O37).
    #[cfg(unix)]
    Socket(PathBuf),
    /// A Windows pipe: a service's console leg (RT-O37).
    #[cfg(windows)]
    Pipe(String),
}

impl std::fmt::Display for Leg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network { endpoint, .. } => f.write_str(endpoint),
            #[cfg(unix)]
            Self::Socket(path) => write!(f, "{}", path.display()),
            #[cfg(windows)]
            Self::Pipe(name) => f.write_str(name),
        }
    }
}

/// A dialed leg.
pub enum LegStream {
    /// TCP, direct or through SOCKS.
    Tcp(tokio::net::TcpStream),
    /// A Unix socket.
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    /// A Windows pipe.
    #[cfg(windows)]
    Pipe(tokio::net::windows::named_pipe::NamedPipeClient),
}

macro_rules! each_leg {
    ($self:ident, $io:ident => $body:expr) => {
        match $self.get_mut() {
            LegStream::Tcp($io) => $body,
            #[cfg(unix)]
            LegStream::Unix($io) => $body,
            #[cfg(windows)]
            LegStream::Pipe($io) => $body,
        }
    };
}

impl AsyncRead for LegStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        each_leg!(self, io => std::pin::Pin::new(io).poll_read(cx, buf))
    }
}

impl AsyncWrite for LegStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        each_leg!(self, io => std::pin::Pin::new(io).poll_write(cx, buf))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        each_leg!(self, io => std::pin::Pin::new(io).poll_flush(cx))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        each_leg!(self, io => std::pin::Pin::new(io).poll_shutdown(cx))
    }
}

impl Leg {
    /// Connect to the leg.
    ///
    /// # Errors
    ///
    /// [`ChannelFault::Unreachable`].
    pub async fn dial(&self) -> Result<LegStream, ChannelFault> {
        let unreachable = |cause: String| ChannelFault::Unreachable {
            at: self.to_string(),
            cause,
        };
        match self {
            Self::Network {
                endpoint,
                socks: None,
            } => {
                let addr: SocketAddr = endpoint
                    .parse()
                    .map_err(|_| unreachable("an onion is reached through a SOCKS proxy".into()))?;
                tokio::net::TcpStream::connect(addr)
                    .await
                    .map(LegStream::Tcp)
                    .map_err(|e| unreachable(e.to_string()))
            }
            Self::Network {
                endpoint,
                socks: Some(proxy),
            } => {
                let (host, port) = endpoint
                    .rsplit_once(':')
                    .and_then(|(host, port)| Some((host, port.parse::<u16>().ok()?)))
                    .ok_or_else(|| unreachable("not host:port".into()))?;
                let host = host.trim_start_matches('[').trim_end_matches(']');
                let mut tcp = tokio::net::TcpStream::connect(proxy)
                    .await
                    .map_err(|e| unreachable(format!("the SOCKS proxy {proxy}: {e}")))?;
                shekyl_socks::connect(
                    &mut tcp,
                    shekyl_socks::Isolation::Principal,
                    shekyl_socks::Destination::Name { host, port },
                )
                .await
                .map_err(|e| unreachable(format!("the SOCKS proxy {proxy}: {e}")))?;
                Ok(LegStream::Tcp(tcp))
            }
            #[cfg(unix)]
            Self::Socket(path) => tokio::net::UnixStream::connect(path)
                .await
                .map(LegStream::Unix)
                .map_err(|e| unreachable(e.to_string())),
            #[cfg(windows)]
            Self::Pipe(name) => tokio::net::windows::named_pipe::ClientOptions::new()
                .open(name)
                .map(LegStream::Pipe)
                .map_err(|e| unreachable(e.to_string())),
        }
    }
}

/// How one handshake attempt ended without a session.
#[derive(Debug)]
pub enum Attempt {
    /// The daemon's busy reply, in place of message 2.
    Busy,
    /// Closed after message 1 with nothing, or with fewer bytes than a
    /// message 2 that are not the busy reply.
    ClosedAfterMessage1,
    /// Message 2 did not authenticate the daemon.
    NotTheDaemon,
    /// Closed after message 3: the claim was refused.
    ClosedAfterMessage3,
    /// The stream failed before message 2 could be written or read.
    Io(String),
    /// This client could not build its messages.
    Local(String),
}

/// An opened channel: the record stream and the ceiling message 4 carried.
pub struct Opened<S> {
    /// The record stream, before anything is sent on it.
    pub stream: RecordStream<S>,
    /// This client's ceiling on the daemon.
    pub ceiling: GrantSet,
    /// What the connection holds: the request clamped to the ceiling (§6.2).
    pub granted: GrantSet,
}

/// The client's side of the handshake over `io`, any stream: messages 1 to
/// 4, then the record stream. No deadline of its own; the caller bounds it.
///
/// # Errors
///
/// [`Attempt`]: how this attempt ended.
pub async fn handshake_over<S>(
    mut io: S,
    network_id: &NetworkId,
    key: &StaticKeypair,
    daemon: &StaticPublic,
    request: GrantSet,
) -> Result<Opened<S>, Attempt>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (client, message1) =
        Client::start(network_id, key, daemon).map_err(|e| Attempt::Local(e.to_string()))?;
    io.write_all(&message1)
        .await
        .map_err(|e| Attempt::Io(e.to_string()))?;
    let mut message2 = vec![0u8; MESSAGE2_LEN];
    let read = read_up_to(&mut io, &mut message2)
        .await
        .map_err(|e| Attempt::Io(e.to_string()))?;
    if read < MESSAGE2_LEN {
        if read == BUSY_LEN && client.is_busy(&message2[..BUSY_LEN]) {
            return Err(Attempt::Busy);
        }
        return Err(Attempt::ClosedAfterMessage1);
    }
    let client = client
        .read_message2(&message2)
        .map_err(|_| Attempt::NotTheDaemon)?;
    let (client, message3) = client
        .write_message3(&request.to_payload())
        .map_err(|e| Attempt::Local(e.to_string()))?;
    io.write_all(&message3)
        .await
        .map_err(|_| Attempt::ClosedAfterMessage3)?;
    let mut message4 = vec![0u8; MESSAGE4_LEN];
    if io.read_exact(&mut message4).await.is_err() {
        return Err(Attempt::ClosedAfterMessage3);
    }
    let (established, ceiling) = client
        .read_message4(&message4)
        .map_err(|_| Attempt::NotTheDaemon)?;
    let ceiling = GrantSet::from_payload(&ceiling).map_err(|_| Attempt::NotTheDaemon)?;
    let (send, recv) = established.into_directions();
    Ok(Opened {
        stream: RecordStream::new(io, send, recv),
        ceiling,
        granted: request.intersection(ceiling),
    })
}

/// Read until `buf` is full or the stream ends; how many bytes were read.
async fn read_up_to<S: AsyncRead + Unpin>(io: &mut S, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = io.read(&mut buf[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// A daemon's channel, and this client's key for it.
#[derive(Clone)]
pub struct ChannelTarget {
    network_id: NetworkId,
    daemon: StaticPublic,
    key: Arc<StaticKeypair>,
    leg: Leg,
}

impl ChannelTarget {
    /// The daemon of `network_id` whose public bundle is `daemon`, reached
    /// at `leg`, with this client's `key`.
    #[must_use]
    pub fn new(network_id: NetworkId, daemon: StaticPublic, key: StaticKeypair, leg: Leg) -> Self {
        Self {
            network_id,
            daemon,
            key: Arc::new(key),
            leg,
        }
    }

    /// Where the daemon is.
    #[must_use]
    pub fn leg(&self) -> &Leg {
        &self.leg
    }

    /// This client's fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        *self.key.public().fingerprint().as_bytes()
    }

    /// Dial and run the handshake under §4.3's policy: each attempt within
    /// the handshake deadline, one silent retry after a timeout, and a
    /// jittered back-off after a busy reply until the deadline.
    ///
    /// # Errors
    ///
    /// [`ChannelFault`]: every way the channel can fail to open.
    pub async fn open(&self, request: GrantSet) -> Result<Opened<LegStream>, ChannelFault> {
        let at = self.leg.to_string();
        let mut retry = HandshakeRetry::new(std::time::Instant::now(), OsRng);
        loop {
            let deadline = tokio::time::Instant::from_std(retry.deadline_at());
            let attempt = tokio::time::timeout_at(deadline, async {
                let io = self.leg.dial().await?;
                Ok::<_, ChannelFault>(
                    handshake_over(io, &self.network_id, &self.key, &self.daemon, request).await,
                )
            })
            .await;
            let end = match attempt {
                Ok(Ok(Ok(opened))) => return Ok(opened),
                Ok(Err(unreachable)) => return Err(unreachable),
                Ok(Ok(Err(Attempt::Busy))) => AttemptEnd::Busy,
                Err(_elapsed) => AttemptEnd::TimedOut,
                Ok(Ok(Err(Attempt::ClosedAfterMessage1))) => {
                    return Err(ChannelFault::NotRecognised { at })
                }
                Ok(Ok(Err(Attempt::NotTheDaemon))) => {
                    return Err(ChannelFault::NotTheDaemon { at })
                }
                Ok(Ok(Err(Attempt::ClosedAfterMessage3))) => {
                    return Err(ChannelFault::NotEnrolled {
                        fingerprint: self.fingerprint(),
                    })
                }
                Ok(Ok(Err(Attempt::Io(cause)))) => {
                    return Err(ChannelFault::Unreachable { at, cause })
                }
                Ok(Ok(Err(Attempt::Local(why)))) => return Err(ChannelFault::Local(why)),
            };
            match retry.after(end, std::time::Instant::now()) {
                Next::StartAt(at) => tokio::time::sleep_until(at.into()).await,
                Next::Report(HandshakeFailure::TimedOut) => return Err(ChannelFault::TimedOut),
                Next::Report(HandshakeFailure::Busy) => return Err(ChannelFault::Busy),
            }
        }
    }
}

/// One HTTP connection over one record stream (§13, RT-W11's client
/// contracts): hyper's `client::conn::http1`, never a pooled client.
pub struct Session {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    mark: SubmissionMark,
    ceiling: GrantSet,
    granted: GrantSet,
}

/// Whether a JSON-RPC body calls `tx_submit`: the one method whose message
/// is padded to the submission's fixed size (RT-O28).
#[must_use]
pub fn is_submission(body: &[u8]) -> bool {
    use shekyl_rpc_types::method::RpcMethod;
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|request| {
            request
                .get("method")
                .and_then(serde_json::Value::as_str)
                .map(|method| method == shekyl_rpc_types::wire::TxSubmit::NAME)
        })
        .unwrap_or(false)
}

impl Session {
    /// Start HTTP over `opened`. `idle` is how long the session may wait
    /// between records before the stream closes it; `None` keeps the
    /// stream's own limit.
    ///
    /// # Errors
    ///
    /// [`ChannelFault::Closed`] when hyper cannot start on the stream.
    pub async fn start<S>(opened: Opened<S>, idle: Option<Duration>) -> Result<Self, ChannelFault>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Opened {
            mut stream,
            ceiling,
            granted,
        } = opened;
        if let Some(idle) = idle {
            stream.set_idle(idle);
        }
        let mark = stream.submission_mark();
        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| ChannelFault::Closed)?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!("channel session ended: {error}");
            }
        });
        Ok(Self {
            sender,
            mark,
            ceiling,
            granted,
        })
    }

    /// This client's ceiling on the daemon.
    #[must_use]
    pub fn ceiling(&self) -> GrantSet {
        self.ceiling
    }

    /// What this session holds.
    #[must_use]
    pub fn granted(&self) -> GrantSet {
        self.granted
    }

    /// Whether the daemon has closed the session.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    /// Send one request, its body whole, and read its whole response. A
    /// body that calls `tx_submit` is sent with the submission mark armed,
    /// as one complete body (`Full`); the session carries nothing else
    /// until the response.
    ///
    /// # Errors
    ///
    /// [`ChannelFault::Closed`] when the session ends under the request.
    pub async fn send(
        &mut self,
        request: hyper::Request<Bytes>,
    ) -> Result<hyper::Response<Bytes>, ChannelFault> {
        self.sender
            .ready()
            .await
            .map_err(|_| ChannelFault::Closed)?;
        if request.method() == hyper::Method::POST && is_submission(request.body()) {
            self.mark.arm();
        }
        let response = self
            .sender
            .send_request(request.map(Full::new))
            .await
            .map_err(|_| ChannelFault::Closed)?;
        let (parts, body) = response.into_parts();
        let body = body
            .collect()
            .await
            .map_err(|_| ChannelFault::Closed)?
            .to_bytes();
        Ok(hyper::Response::from_parts(parts, body))
    }

    /// POST `body` to `route` and return the response's body.
    ///
    /// # Errors
    ///
    /// [`ChannelFault::Closed`] when the session ends under the request.
    pub async fn post(&mut self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, ChannelFault> {
        let request = hyper::Request::post(format!("/{}", route.trim_start_matches('/')))
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .header(hyper::header::HOST, "localhost")
            .body(Bytes::from(body))
            .map_err(|e| ChannelFault::Local(e.to_string()))?;
        Ok(self.send(request).await?.into_body().to_vec())
    }
}

/// Up to `SESSIONS_PER_CLIENT` sessions to one daemon under one grant (§8).
pub struct Pool {
    target: ChannelTarget,
    request: GrantSet,
    slots: Arc<Semaphore>,
    state: Mutex<PoolState>,
}

#[derive(Default)]
struct PoolState {
    /// Idle sessions, the kept one first, each with when it went idle.
    idle: Vec<(Session, tokio::time::Instant)>,
    /// Whether a session has been held: a refusal at message 3 after one is
    /// a revocation.
    held: bool,
    /// Why the pool stopped; it does not dial again.
    stopped: Option<ChannelFault>,
    /// The grant the daemon gave, once known.
    granted: Option<(GrantSet, GrantSet)>,
}

/// A session lent by the pool; given back with [`Pool::give_back`].
pub struct Lent {
    session: Session,
    _slot: OwnedSemaphorePermit,
}

impl Lent {
    /// The session.
    pub fn session(&mut self) -> &mut Session {
        &mut self.session
    }
}

impl Pool {
    /// A pool to `target` asking for `request` on every session. Nothing is
    /// dialed until [`Self::open_kept`] or the first [`Self::lend`].
    #[must_use]
    pub fn new(target: ChannelTarget, request: GrantSet) -> Arc<Self> {
        Arc::new(Self {
            target,
            request,
            slots: Arc::new(Semaphore::new(SESSIONS_PER_CLIENT)),
            state: Mutex::new(PoolState::default()),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The target.
    #[must_use]
    pub fn target(&self) -> &ChannelTarget {
        &self.target
    }

    /// Why the pool stopped, if it has.
    #[must_use]
    pub fn stopped(&self) -> Option<ChannelFault> {
        self.state().stopped.clone()
    }

    /// The ceiling and the grant the daemon gave, once a session opened.
    #[must_use]
    pub fn granted(&self) -> Option<(GrantSet, GrantSet)> {
        self.state().granted
    }

    /// Open the kept session now, so the grant is known and reported at
    /// start (§8, §6.2).
    ///
    /// # Errors
    ///
    /// [`ChannelFault`], as [`Self::lend`].
    pub async fn open_kept(&self) -> Result<(GrantSet, GrantSet), ChannelFault> {
        let lent = self.lend().await?;
        let granted = (lent.session.ceiling(), lent.session.granted());
        self.give_back(lent);
        Ok(granted)
    }

    /// A session for one exchange: an idle one, or a new one while the
    /// pool holds fewer than the cap; otherwise wait for one, bounded by
    /// the handshake deadline.
    ///
    /// # Errors
    ///
    /// [`ChannelFault::PoolFull`] when none came free in time; the pool's
    /// stop; or why a new session did not open.
    pub async fn lend(&self) -> Result<Lent, ChannelFault> {
        if let Some(stopped) = self.stopped() {
            return Err(stopped);
        }
        let slot =
            tokio::time::timeout(HANDSHAKE_DEADLINE, Arc::clone(&self.slots).acquire_owned())
                .await
                .map_err(|_| ChannelFault::PoolFull)?
                .map_err(|_| ChannelFault::PoolFull)?;
        let idle = {
            let mut state = self.state();
            state.idle.retain(|(session, _)| !session.is_closed());
            state.idle.pop().map(|(session, _)| session)
        };
        let session = match idle {
            Some(session) => session,
            None => self.open_session().await?,
        };
        Ok(Lent {
            session,
            _slot: slot,
        })
    }

    /// Give a session back after its exchange. A closed one is dropped.
    pub fn give_back(&self, lent: Lent) {
        let Lent { session, _slot } = lent;
        if session.is_closed() {
            return;
        }
        self.state()
            .idle
            .push((session, tokio::time::Instant::now()));
    }

    async fn open_session(&self) -> Result<Session, ChannelFault> {
        let opened = self.target.open(self.request).await;
        let opened = match opened {
            Ok(opened) => opened,
            Err(ChannelFault::NotEnrolled { fingerprint }) => {
                let mut state = self.state();
                let fault = if state.held {
                    ChannelFault::Revoked
                } else {
                    ChannelFault::NotEnrolled { fingerprint }
                };
                state.stopped = Some(fault.clone());
                return Err(fault);
            }
            Err(fault @ ChannelFault::NotTheDaemon { .. }) => {
                self.state().stopped = Some(fault.clone());
                return Err(fault);
            }
            Err(fault) => return Err(fault),
        };
        let session = Session::start(opened, None).await?;
        let mut state = self.state();
        state.held = true;
        state.granted = Some((session.ceiling(), session.granted()));
        Ok(session)
    }

    /// One exchange on a lent session, given back after.
    ///
    /// # Errors
    ///
    /// [`ChannelFault`], from the lending or the exchange.
    pub async fn send(
        &self,
        request: hyper::Request<Bytes>,
    ) -> Result<hyper::Response<Bytes>, ChannelFault> {
        let mut lent = self.lend().await?;
        let response = lent.session.send(request).await;
        self.give_back(lent);
        response
    }

    /// Close extras idle longer than [`EXTRA_SESSION_IDLE`], keeping one,
    /// and open the kept session again when the daemon has closed it.
    /// Returns when the pool stops.
    pub async fn keep(self: Arc<Self>) {
        loop {
            tokio::time::sleep(KEEPER_TICK).await;
            if self.stopped().is_some() {
                return;
            }
            let reopen = {
                let mut state = self.state();
                state.idle.retain(|(session, _)| !session.is_closed());
                let now = tokio::time::Instant::now();
                let mut kept = 0usize;
                state.idle.retain(|(_, since)| {
                    kept += 1;
                    kept == 1 || now.duration_since(*since) < EXTRA_SESSION_IDLE
                });
                state.idle.is_empty() && self.slots.available_permits() == SESSIONS_PER_CLIENT
            };
            if reopen {
                match self.lend().await {
                    Ok(lent) => self.give_back(lent),
                    Err(fault) => {
                        tracing::warn!("the channel's kept session did not open again: {fault}");
                    }
                }
            }
        }
    }
}

/// A channel target a synchronous caller can hold: one session on a
/// current-thread runtime of its own, as [`crate::SyncDaemon`] holds one
/// for HTTP. `shekyl-cli` reaches a daemon on another host, or a service's
/// console leg, through it.
pub struct ChannelDaemon {
    runtime: tokio::runtime::Runtime,
    session: Mutex<Session>,
}

impl ChannelDaemon {
    /// Open a session to `target` asking for `request`.
    ///
    /// # Errors
    ///
    /// [`ChannelFault`]: the runtime, or why the channel did not open.
    pub fn connect(target: &ChannelTarget, request: GrantSet) -> Result<Self, ChannelFault> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(ChannelFault::Local(
                "the channel's client was made inside an async runtime".to_owned(),
            ));
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ChannelFault::Local(format!("runtime: {e}")))?;
        let session = runtime.block_on(async {
            let opened = target.open(request).await?;
            Session::start(opened, None).await
        })?;
        Ok(Self {
            runtime,
            session: Mutex::new(session),
        })
    }

    /// What the session holds.
    #[must_use]
    pub fn granted(&self) -> GrantSet {
        self.session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .granted()
    }

    /// POST `body` to `route` and return the response's body.
    ///
    /// # Errors
    ///
    /// [`ChannelFault::Closed`] when the session ends under the request.
    pub fn post(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, ChannelFault> {
        let mut session = self.session.lock().unwrap_or_else(PoisonError::into_inner);
        self.runtime.block_on(session.post(route, body))
    }

    /// One call of method `M`: the envelope and checks every target makes.
    ///
    /// # Errors
    ///
    /// The channel, a body that is not the reply, a method the daemon does
    /// not serve, or the daemon's refusal.
    pub fn call<M: shekyl_rpc_client::RpcMethod>(
        &self,
        request: &M::Request,
    ) -> Result<M::Reply, crate::JsonRpcError<ChannelFault>> {
        crate::call_via::<M, _>(request, |route, body| self.post(route, body))
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
    ) -> Result<Reply, crate::JsonRpcError<ChannelFault>>
    where
        Req: serde::Serialize,
        Reply: serde::de::DeserializeOwned,
    {
        crate::json_rpc_via(method, request, |route, body| self.post(route, body))
    }
}
