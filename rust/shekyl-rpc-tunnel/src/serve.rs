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

use std::sync::Arc;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use shekyl_rpc_grants::GrantSet;
use shekyl_rpc_transport::channel::{ChannelFault, ChannelTarget, Leg, Pool};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;

use crate::config::{Config, Listen};

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
/// # Errors
///
/// What ended the tunnel, in the words its operator acts on: the key, the
/// first session, the listener, or the node's revocation.
pub async fn run(
    config: Config,
    key: shekyl_rpc_channel::handshake::StaticKeypair,
) -> Result<(), String> {
    let fingerprint = shekyl_rpc_transport::channel::fingerprint_hex(key.public());
    let target = ChannelTarget::new(
        config.network.network_id(),
        config.bundle.clone(),
        key,
        Leg::Network {
            endpoint: config.endpoint.clone(),
            socks: config.socks,
        },
    );
    let pool = Pool::new(target, config.request);
    let (ceiling, granted) = pool.open_kept().await.map_err(|fault| fault.to_string())?;
    tracing::info!(
        target: "global",
        "connected to {} as {fingerprint} with {}; this client is enrolled for at most {}",
        config.endpoint,
        names(granted),
        names(ceiling)
    );
    println!(
        "Connected with {}; this client is enrolled for at most {}.",
        names(granted),
        names(ceiling)
    );
    let keeper = tokio::spawn(Arc::clone(&pool).keep());
    let (ended_tx, ended_rx) = watch::channel(None::<ChannelFault>);
    let result = match &config.listen {
        Listen::Tcp(addr) => {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| format!("the listener {addr} could not be bound: {e}"))?;
            println!(
                "Listening on {}.",
                listener.local_addr().map_or(*addr, |bound| bound)
            );
            accept_loop(
                || async { listener.accept().await.map(|(io, _)| io) },
                &pool,
                ended_tx,
                ended_rx,
            )
            .await
        }
        #[cfg(unix)]
        Listen::Socket(path) => {
            let listener = bind_socket(path)?;
            println!("Listening on {}.", path.display());
            let served = accept_loop(
                || async { listener.accept().await.map(|(io, _)| io) },
                &pool,
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
                let pool = Arc::clone(pool);
                let ended = Arc::clone(&ended_tx);
                serving.spawn(async move {
                    let service = hyper::service::service_fn(move |request| {
                        forward(Arc::clone(&pool), Arc::clone(&ended), request)
                    });
                    if let Err(error) = hyper::server::conn::http1::Builder::new()
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
            _ = tokio::signal::ctrl_c() => break Ok(()),
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

/// One local request, carried whole to the node and its response back.
async fn forward(
    pool: Arc<Pool>,
    ended: Arc<watch::Sender<Option<ChannelFault>>>,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let (parts, body) = request.into_parts();
    let body = match Limited::new(body, shekyl_rpc_stream::SUBMISSION_CAP)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(_) => {
            return Ok(answer(
                StatusCode::PAYLOAD_TOO_LARGE,
                "the request is larger than the node accepts",
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
/// §1.1's construction). A socket there that a tunnel answers on is not
/// taken over; one left by a stopped tunnel is replaced.
#[cfg(unix)]
fn bind_socket(path: &std::path::Path) -> Result<tokio::net::UnixListener, String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| format!("{} names no directory", path.display()))?;
    let meta = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let me = shekyl_os_account::effective_uid();
    if !meta.is_dir() || meta.uid() != me || meta.permissions().mode() & 0o077 != 0 {
        return Err(format!(
            "{} must be a directory only this account can enter (owned by uid {me}, mode 0700)",
            dir.display()
        ));
    }
    match std::fs::symlink_metadata(path) {
        Ok(existing) if existing.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(format!("another tunnel answers on {}", path.display()));
            }
            std::fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Ok(_) => {
            return Err(format!(
                "{} is not a socket; it is not replaced",
                path.display()
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    tokio::net::UnixListener::bind(path).map_err(|e| format!("{}: {e}", path.display()))
}
