// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The channel listener (`rpc-listen`; `RPC_CHANNEL.md` §4, §6.2, §7).
//!
//! Each accepted connection is admitted through the daemon's one connection
//! tracker, then runs the handshake under its deadlines from the instant
//! `accept` returned: message 1 whole within [`MESSAGE1_DEADLINE`], the
//! client's first record opened within [`HANDSHAKE_DEADLINE`]. Message 1 is
//! paid for from the daemon's one handshake budget, and an empty budget is
//! answered busy. After message 3 the claimed fingerprint is looked up: an
//! unenrolled client gets no message 4 and the connection closes (§4.5);
//! an admitted one gets its ceiling in message 4 (RT-O30, RT-O31). The
//! first record authenticates the client against both primitives; only
//! then is the request read, clamped to the ceiling, and the session
//! registered under the index's lock. The record stream then carries HTTP
//! into the router, every request stamped with the connection's authority
//! and its [`ChannelCall`] (RT-O32).
//!
//! What a failed handshake logs is uniform here: nothing, except an
//! unenrolled claim, which §4.5 names.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use shekyl_noise::ClassedOpener;
use shekyl_rpc_channel::deadline::{HANDSHAKE_DEADLINE, MESSAGE1_DEADLINE};
use shekyl_rpc_channel::handshake::{
    AuthenticatedSession, Daemon, Message1Admission, MESSAGE1_WIRE_LEN, MESSAGE3_LEN,
};
use shekyl_rpc_grants::GrantSet;
use shekyl_rpc_stream::{class_table, RecordStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;

use super::{Admitted, Channel, ChannelCall};
use crate::authority::Authority;

/// What the handshake hands the session.
struct Handshaken {
    session: AuthenticatedSession,
    first: shekyl_noise::Opened,
    admitted: Admitted,
    request: GrantSet,
}

/// Serve the channel on `listener` until `signal` completes. `router` is the
/// one router, not yet stamped: each connection stamps its own authority.
pub(crate) async fn serve<L>(
    mut listener: crate::conn_limit::LimitedListener<L>,
    channel: Arc<Channel>,
    router: Router,
    signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()>
where
    L: crate::conn_limit::AdmitAs<Addr = SocketAddr>,
    L::Io: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut signal = std::pin::pin!(signal);
    loop {
        let (io, peer) = tokio::select! {
            accepted = axum::serve::Listener::accept(&mut listener) => accepted,
            () = &mut signal => break,
        };
        let accepted_at = Instant::now();
        tokio::spawn(connection(
            io,
            peer,
            accepted_at,
            Arc::clone(&channel),
            router.clone(),
            stop_rx.clone(),
        ));
    }
    stop_tx.send_replace(true);
    Ok(())
}

async fn connection<S>(
    mut io: S,
    peer: SocketAddr,
    accepted_at: Instant,
    channel: Arc<Channel>,
    router: Router,
    mut stop: watch::Receiver<bool>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let deadline = tokio::time::Instant::from_std(accepted_at + HANDSHAKE_DEADLINE);
    let Ok(Some(handshaken)) =
        tokio::time::timeout_at(deadline, handshake(&mut io, &channel, accepted_at, peer)).await
    else {
        return;
    };
    let Handshaken {
        session,
        first,
        admitted,
        request,
    } = handshaken;
    let fingerprint = *session.client.fingerprint().as_bytes();
    // Registered under the index's lock, admitted again there: a removal
    // or a lowered ceiling since message 4 is seen, and the session closed
    // as it would have been (§5). A raised ceiling keeps it: the grant it
    // holds still lies within.
    let registering = Arc::clone(&channel);
    let Some(mut registered) = channel.sessions.register(fingerprint, move || {
        registering
            .admitted(&fingerprint)
            .ok()
            .flatten()
            .is_some_and(|now| still_admitted(admitted, now))
    }) else {
        return;
    };
    let console = admitted == Admitted::Console;
    let authority = Authority::channel(request.intersection(admitted.ceiling()), console);
    let Ok(stream) =
        RecordStream::after_first_opened(io, session.send, session.recv, first, Vec::new())
    else {
        return;
    };
    let call = ChannelCall {
        client: fingerprint,
        console,
        shape: stream.inbound_shape(),
    };
    let app = router.layer(axum::middleware::from_fn(move |request, next| {
        crate::authority::stamp_channel(authority, call.clone(), request, next)
    }));
    // No hyper timer: the record stream owns the idle and the stalls (§6.3,
    // step 2), so a session is not opened again through a new handshake.
    let mut served =
        std::pin::pin!(http1::Builder::new()
            .serve_connection(TokioIo::new(stream), TowerToHyperService::new(app)));
    let mut shutting_down = false;
    loop {
        tokio::select! {
            result = served.as_mut() => {
                if let Err(error) = result {
                    tracing::trace!("channel connection ended: {error:#}");
                }
                return;
            }
            () = registered.closed() => return,
            _stopped = stop.wait_for(|&stopped| stopped), if !shutting_down => {
                shutting_down = true;
                served.as_mut().graceful_shutdown();
            }
        }
    }
}

/// Whether a session admitted as `then` is still admitted as `now`: the
/// same kind of key, with a ceiling that still holds the one message 4
/// carried.
fn still_admitted(then: Admitted, now: Admitted) -> bool {
    match (then, now) {
        (Admitted::Console, Admitted::Console) => true,
        (Admitted::Client(then), Admitted::Client(now)) => then.within(now),
        _ => false,
    }
}

/// The handshake, through the client's first record. `None` closes the
/// connection: every refusal looks the same from outside.
async fn handshake<S>(
    io: &mut S,
    channel: &Channel,
    accepted_at: Instant,
    peer: SocketAddr,
) -> Option<Handshaken>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let message1_by = tokio::time::Instant::from_std(accepted_at + MESSAGE1_DEADLINE);
    let mut message1 = vec![0u8; MESSAGE1_WIRE_LEN];
    tokio::time::timeout_at(message1_by, io.read_exact(&mut message1))
        .await
        .ok()?
        .ok()?;
    let daemon = match Daemon::new(&channel.network_id, &channel.key).read_message1(
        &message1,
        &channel.budget,
        Instant::now(),
    ) {
        Ok(Message1Admission::Continue(daemon)) => daemon,
        Ok(Message1Admission::Busy(reply)) => {
            drop(io.write_all(&reply).await);
            return None;
        }
        Err(_) => return None,
    };
    let (daemon, message2) = daemon.write_message2().ok()?;
    io.write_all(&message2).await.ok()?;

    let mut message3 = vec![0u8; MESSAGE3_LEN];
    io.read_exact(&mut message3).await.ok()?;
    let daemon = daemon.read_message3(&message3).ok()?;
    let claim = *daemon.fingerprint().as_bytes();
    let admitted = match channel.admitted(&claim) {
        Ok(Some(admitted)) => admitted,
        Ok(None) => {
            // A claim, not an authenticated client: the operator's remedy
            // names it (§4.5).
            tracing::info!(
                target: "global",
                "refused unenrolled client {} from {peer}",
                hex::encode(claim)
            );
            return None;
        }
        Err(error) => {
            tracing::error!(target: "global", "the RPC channel's enrolled set: {error}");
            return None;
        }
    };
    let (pending, message4) = daemon
        .write_message4(&admitted.ceiling().to_payload())
        .ok()?;
    io.write_all(&message4).await.ok()?;

    // The first record: its header says its length; the rest follows.
    let (withheld, recv) = pending.lend();
    let mut opener = ClassedOpener::new(recv, class_table());
    let mut header = [0u8; 1];
    io.read_exact(&mut header).await.ok()?;
    let length = opener.record_len(header[0]).ok()?;
    let mut wire = vec![0u8; length];
    *wire.first_mut()? = header[0];
    io.read_exact(wire.get_mut(1..)?).await.ok()?;
    let opened = opener.open(&wire);
    let recv = opener.into_direction();
    let (session, first) = withheld.release(recv, opened).ok()?;
    let request = GrantSet::from_payload(&session.request).ok()?;
    Some(Handshaken {
        session,
        first,
        admitted,
        request,
    })
}
