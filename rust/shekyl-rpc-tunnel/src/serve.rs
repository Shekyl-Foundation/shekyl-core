// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The tunnel at work (`RPC_CHANNEL.md` §8): a local listener a consumer
//! reaches in plaintext, and a pool of channel sessions to the node.
//!
//! - **The listener is local.** A loopback address (RT-14: never a
//!   wildcard; the table's endpoint rule refuses any other), or a socket in
//!   a directory only this account can enter. A socket another tunnel
//!   answers on is not taken over.
//! - **A request is carried whole.** The tunnel reads a consumer's request
//!   to its end, at most a submission's cap, and sends it on a pooled
//!   session as one complete body; a `tx_submit` goes padded, on a session
//!   that carries nothing else until its response (§13's client contracts,
//!   kept by `shekyl_rpc_transport::channel::Session`).
//! - **A revocation ends the tunnel.** The pool stops and does not dial
//!   again; the tunnel answers the request that met it, stops accepting,
//!   and exits with the node's reason, so a supervisor shows it.

use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use shekyl_rpc_channel::deadline::MESSAGE1_DEADLINE;
use shekyl_rpc_channel::SESSIONS_PER_CLIENT;
use shekyl_rpc_grants::GrantSet;
use shekyl_rpc_stream::{READ_STALL, WRITE_STALL};
use shekyl_rpc_transport::channel::{ChannelFault, ChannelTarget, Pool};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{watch, Semaphore};
use tokio::time::{sleep, Sleep};

use crate::config::{Config, Listen};
use shekyl_process::stop::{FirstStop, Inherited, Stops};

/// A grant set, as `rpc client list` names one.
fn names(set: GrantSet) -> String {
    let names: Vec<&str> = set.iter().map(shekyl_rpc_grants::Grant::name).collect();
    if names.is_empty() {
        "nothing".to_owned()
    } else {
        names.join(", ")
    }
}

/// Serve until a stop signal, or until the node revokes this tunnel.
///
/// `say` carries the lines the operator reads (the grants connected with,
/// the listener bound); the binary's `main` prints them.
///
/// # Errors
///
/// What ended the tunnel, in the words its operator acts on: the key, the
/// first session, the listener, or the node's revocation.
pub async fn run(
    config: Config,
    inherited: Inherited,
    key: shekyl_rpc_channel::handshake::StaticKeypair,
    say: fn(&str),
) -> Result<(), String> {
    let fingerprint = shekyl_rpc_transport::channel::fingerprint_hex(key.public());
    let target = ChannelTarget::new(
        config.network.network_id(),
        config.bundle.clone(),
        key,
        config.leg.clone(),
    );
    let pool = Pool::new(target, config.request);
    let (ceiling, granted) = pool.open_kept().await.map_err(|fault| fault.to_string())?;
    tracing::info!(
        target: "global",
        "connected to {} as {fingerprint} with {}; this client is enrolled for at most {}",
        config.leg,
        names(granted),
        names(ceiling)
    );
    say(&format!(
        "Connected with {}; this client is enrolled for at most {}.",
        names(granted),
        names(ceiling)
    ));
    let (ended_tx, ended_rx) = watch::channel(None::<ChannelFault>);
    let keeper = tokio::spawn(Arc::clone(&pool).keep(ended_tx.clone()));
    // One local connection per channel session. Another caller on this
    // host is closed: accepting it would hold a socket and a body with no
    // session to carry it.
    let local = Arc::new(Semaphore::new(SESSIONS_PER_CLIENT));
    // Armed before the listener exists: from "Listening on" a stop signal
    // is a clean stop that removes the socket, never the signal's default
    // death.
    let mut stops = Stops::arm(inherited)
        .map_err(|e| format!("the stop signals could not be registered: {e}"))?;
    let result = match &config.listen {
        Listen::Tcp(addr) => {
            listen_check(*addr)?;
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| format!("the listener {addr} could not be bound: {e}"))?;
            say(&format!(
                "Listening on {}.",
                listener.local_addr().map_or(*addr, |bound| bound)
            ));
            accept_loop(
                || async { listener.accept().await.map(|(io, _)| io) },
                &pool,
                &local,
                &mut stops,
                ended_tx,
                ended_rx,
            )
            .await
        }
        #[cfg(unix)]
        Listen::Socket(path) => {
            let listener = bind_socket(path)?;
            say(&format!("Listening on {}.", path.display()));
            let served = accept_loop(
                || async { listener.accept().await.map(|(io, _)| io) },
                &pool,
                &local,
                &mut stops,
                ended_tx,
                ended_rx,
            )
            .await;
            drop(std::fs::remove_file(path));
            served
        }
    };
    keeper.abort();
    result
}

async fn accept_loop<F, Fut, S>(
    mut accept: F,
    pool: &Arc<Pool>,
    local: &Arc<Semaphore>,
    stops: &mut Stops,
    ended_tx: watch::Sender<Option<ChannelFault>>,
    mut ended_rx: watch::Receiver<Option<ChannelFault>>,
) -> Result<(), String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<S>>,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ended_tx = Arc::new(ended_tx);
    let mut serving = tokio::task::JoinSet::new();
    let ended = loop {
        tokio::select! {
            accepted = accept() => {
                let io = match accepted {
                    Ok(io) => io,
                    Err(error) => {
                        tracing::warn!("the tunnel's listener: {error}");
                        continue;
                    }
                };
                let Ok(permit) = Arc::clone(local).try_acquire_owned() else {
                    tracing::debug!(
                        "a local connection was closed: every session this client may hold is \
                         already in use"
                    );
                    continue;
                };
                let pool = Arc::clone(pool);
                let ended = Arc::clone(&ended_tx);
                serving.spawn(async move {
                    let _permit = permit;
                    let service = hyper::service::service_fn(move |request| {
                        forward(Arc::clone(&pool), Arc::clone(&ended), request)
                    });
                    let io = StallWrite::new(io, WRITE_STALL);
                    if let Err(error) = local_builder()
                        .serve_connection(TokioIo::new(io), service)
                        .await
                    {
                        tracing::debug!("a local connection ended: {error}");
                    }
                });
            }
            ended = ended_rx.wait_for(Option::is_some) => {
                let fault = ended.ok().and_then(|value| value.clone());
                break Err(fault.map_or_else(String::new, |fault| fault.to_string()));
            }
            // `Replaced` does not complete: this tunnel armed once, and a
            // later arm is not a stop. The accept loop still ends on revocation.
            () = until_stop(stops) => break Ok(()),
            Some(_) = serving.join_next(), if !serving.is_empty() => {}
        }
    };
    // The requests in flight are answered before the tunnel ends, the one
    // that met a revocation among them, within the handshake deadline.
    drop(
        tokio::time::timeout(shekyl_rpc_channel::deadline::HANDSHAKE_DEADLINE, async {
            while serving.join_next().await.is_some() {}
        })
        .await,
    );
    ended
}

/// The first stop. A replaced arm does not end this wait: the accept loop
/// has the revocation to end on, and a replacement is not a stop.
async fn until_stop(stops: &mut Stops) {
    if let FirstStop::Replaced = stops.first().await {
        std::future::pending::<()>().await;
    }
}

/// One local request, carried whole to the node and its response back.
async fn forward(
    pool: Arc<Pool>,
    ended: Arc<watch::Sender<Option<ChannelFault>>>,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let (parts, body) = request.into_parts();
    let body = match tokio::time::timeout(
        READ_STALL,
        Limited::new(body, shekyl_rpc_stream::SUBMISSION_CAP).collect(),
    )
    .await
    {
        Ok(Ok(body)) => body.to_bytes(),
        Ok(Err(_)) => {
            return Ok(answer(
                StatusCode::PAYLOAD_TOO_LARGE,
                "the request is larger than the node accepts",
            ))
        }
        Err(_) => {
            return Ok(answer(
                StatusCode::REQUEST_TIMEOUT,
                "the request was not received in time",
            ))
        }
    };
    let mut forwarded = Request::new(body);
    *forwarded.method_mut() = parts.method;
    *forwarded.uri_mut() = parts.uri;
    if let Some(kind) = parts.headers.get(hyper::header::CONTENT_TYPE) {
        forwarded
            .headers_mut()
            .insert(hyper::header::CONTENT_TYPE, kind.clone());
    }
    match pool.send(forwarded).await {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            Ok(Response::from_parts(parts, Full::new(body)))
        }
        Err(fault) => {
            if pool.stopped().is_some() {
                ended.send_replace(Some(fault.clone()));
            }
            Ok(answer(StatusCode::BAD_GATEWAY, &fault.to_string()))
        }
    }
}

fn answer(status: StatusCode, text: &str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(text.to_owned())));
    *response.status_mut() = status;
    response
}

/// A socket at `path`, in a directory only this account can enter (R0
/// §1.1's construction), bound through the listeners' shared bind
/// (`shekyl_rpc_transport::listen::bind_owner_only_socket`): 0600 from
/// before it listens. A socket there that a tunnel answers on, or one whose
/// server cannot be shown gone, is not taken over; one left by a stopped
/// tunnel (the connection refused) is replaced.
#[cfg(unix)]
fn bind_socket(path: &std::path::Path) -> Result<tokio::net::UnixListener, String> {
    use shekyl_rpc_transport::listen::{
        bind_owner_only_socket, OwnerSocketRefusal, SocketDirRefusal, SocketRefusal,
    };
    let dir = || {
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."))
            .display()
    };
    match bind_owner_only_socket(path) {
        Ok(bound) => bound
            .into_tokio()
            .map_err(|e| format!("{}: {e}", path.display())),
        Err(OwnerSocketRefusal::NoDirectory) => {
            Err(format!("{} names no directory", path.display()))
        }
        Err(OwnerSocketRefusal::Directory(
            SocketDirRefusal::Missing | SocketDirRefusal::NotOwnerOnly,
        )) => Err(format!(
            "{} must be a directory only this account can enter (owned by uid {}, mode 0700)",
            dir(),
            shekyl_os_account::effective_uid()
        )),
        Err(OwnerSocketRefusal::Directory(SocketDirRefusal::Unreadable(why))) => {
            Err(format!("{}: {why}", dir()))
        }
        Err(OwnerSocketRefusal::Path(SocketRefusal::Answers)) => {
            Err(format!("another tunnel answers on {}", path.display()))
        }
        Err(OwnerSocketRefusal::Path(SocketRefusal::NotASocket)) => Err(format!(
            "{} is not a socket; it is not replaced",
            path.display()
        )),
        Err(OwnerSocketRefusal::Path(SocketRefusal::NotThisAccounts(uid))) => Err(format!(
            "{} is a socket another account owns (uid {uid}); it is not replaced",
            path.display()
        )),
        Err(OwnerSocketRefusal::Path(SocketRefusal::Unknown(why))) => Err(format!(
            "{}: whether a tunnel still holds this socket is not known ({why}); it is not \
             replaced",
            path.display()
        )),
        Err(OwnerSocketRefusal::Path(SocketRefusal::NotRemoved(why))) => {
            Err(format!("{}: {why}", path.display()))
        }
        Err(OwnerSocketRefusal::Socket(error)) => Err(format!("{}: {error}", path.display())),
    }
}

/// Header-read bound for a local consumer: the channel's message-1
/// deadline. Hyper arms it again while it waits for the next request, so
/// a connection that sends nothing does not hold a local slot.
fn local_builder() -> http1::Builder {
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Some(MESSAGE1_DEADLINE));
    builder
}

/// Closes a local connection whose response write makes no progress for
/// `bound`. The bound is [`WRITE_STALL`], the same one the daemon's
/// listeners use.
struct StallWrite<T> {
    inner: T,
    bound: Duration,
    wait: Option<Pin<Box<Sleep>>>,
}

impl<T> StallWrite<T> {
    fn new(inner: T, bound: Duration) -> Self {
        Self {
            inner,
            bound,
            wait: None,
        }
    }

    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Error> {
        if self.wait.is_none() {
            self.wait = Some(Box::pin(sleep(self.bound)));
        }
        let wait = self.wait.as_mut().expect("the stall sleep was just armed");
        if wait.as_mut().poll(cx).is_ready() {
            self.wait = None;
            Poll::Ready(io::Error::new(
                io::ErrorKind::TimedOut,
                "the response write made no progress",
            ))
        } else {
            Poll::Pending
        }
    }

    fn drive<R>(
        &mut self,
        cx: &mut Context<'_>,
        poll: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>>
    where
        T: Unpin,
    {
        match poll(Pin::new(&mut self.inner), cx) {
            Poll::Pending => match self.poll_pending(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(error) => Poll::Ready(Err(error)),
            },
            ready => {
                self.wait = None;
                ready
            }
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for StallWrite<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for StallWrite<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .drive(cx, |inner, cx| inner.poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().drive(cx, AsyncWrite::poll_flush)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().drive(cx, AsyncWrite::poll_shutdown)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .drive(cx, |inner, cx| inner.poll_write_vectored(cx, bufs))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// The one listen classifier every Shekyl listener passes (§8, RT-14),
/// beside the table's own loopback rule: loopback, the IPv4-mapped
/// spelling included, and nothing else.
fn listen_check(addr: std::net::SocketAddr) -> Result<(), String> {
    use shekyl_rpc_transport::listen::{classify_listen, ListenClass, WILDCARD_REASON};
    match classify_listen(addr) {
        ListenClass::Loopback => Ok(()),
        ListenClass::Wildcard => Err(format!(
            "the listener {addr} is a wildcard: {WILDCARD_REASON}"
        )),
        ListenClass::Addressed => Err(format!(
            "the listener {addr} is not loopback: the tunnel serves its consumers in \
             plaintext, on this host only"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Loopback is served, the IPv4-mapped spelling included; a wildcard
    /// and an addressed listener are refused. Red edit: accept
    /// `ListenClass::Addressed` in `listen_check`, and the LAN address is
    /// served.
    #[test]
    fn the_tunnel_listens_on_loopback_alone() {
        for good in ["127.0.0.1:1", "[::1]:1", "[::ffff:127.0.0.1]:1"] {
            assert!(listen_check(good.parse().unwrap()).is_ok(), "{good}");
        }
        for bad in ["0.0.0.0:1", "[::]:1", "192.0.2.7:1"] {
            assert!(listen_check(bad.parse().unwrap()).is_err(), "{bad}");
        }
    }

    /// **The tunnel's socket is never bound in a directory others can
    /// enter**, and the refusal names the directory; in an owner-only one
    /// it is bound 0600 (Rick, 2026-11-22). Red edit: bind without the
    /// shared bind's directory check.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_socket_is_bound_only_in_an_owner_only_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("a directory");
        let path = dir.path().join("tunnel.sock");
        for mode in [0o750, 0o755, 0o770] {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode))
                .expect("chmod");
            let refused = bind_socket(&path).expect_err("refused");
            assert!(
                refused.contains(&dir.path().display().to_string())
                    && refused.contains("only this account can enter"),
                "mode {mode:o}: {refused}"
            );
            assert!(!path.exists(), "nothing was bound under mode {mode:o}");
        }
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod 700");
        let _listener = bind_socket(&path).expect("bound in an owner-only directory");
        let mode = std::fs::metadata(&path)
            .expect("the socket")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the tunnel's socket is the owner's");
    }
}
