// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Copy socket bytes through the cap.
//!
//! `encode` and `decode` are the connector's framing. An identity pair
//! copies the bytes. A seam seals and opens them. A full queue is
//! selected beside the socket write, so a peer that stops reading does
//! not keep the buffer.
//!
//! A grant is held only across the socket call. Drop returns whatever
//! the socket did not take, including when the call is cancelled.

use std::borrow::Cow;

use shekyl_transport_layer::{CloseCause, CloseKind, LinkDirection, MessageClass};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::gate::{HeldGrant, LinkGate};
use crate::queue::{ByteQueue, Overfull};
use crate::read::{read_granted, ReadStop, ReadyRead};
use crate::session::InboundEnd;
use crate::stall::WriteStall;

/// Write every byte of `bytes` under the up budget.
///
/// One message is recorded when the whole buffer has been accepted.
/// `false` is a socket that stopped first; the grant has already returned
/// what that socket did not take. Dropping this future does the same.
pub async fn write_granted<W>(
    write: &mut W,
    bytes: &[u8],
    gate: &LinkGate,
    conn: u64,
    class: MessageClass,
) -> bool
where
    W: AsyncWrite + Unpin,
{
    let mut off = 0usize;
    while off < bytes.len() {
        let grant = HeldGrant::acquire(
            gate,
            LinkDirection::Up,
            conn,
            class,
            u64::try_from(bytes.len() - off).unwrap_or(u64::MAX),
        )
        .await;
        match write_accepted(write, &bytes[off..], grant, || {}).await {
            Ok(0) => continue,
            Ok(n) => off += n,
            Err(()) => return false,
        }
    }
    gate.record_message(LinkDirection::Up, conn);
    true
}

/// Write every byte, and call `on_accept` with each slice the socket took.
///
/// The hook runs before the next attempt. A prefix is therefore counted
/// when a later write in the same grant fails, at the instant that slice
/// was accepted.
async fn write_counted<W, F>(write: &mut W, bytes: &[u8], mut on_accept: F) -> Result<(), usize>
where
    W: AsyncWrite + Unpin,
    F: FnMut(u64),
{
    let mut wrote = 0usize;
    while wrote < bytes.len() {
        match write.write(&bytes[wrote..]).await {
            Ok(0) | Err(_) => return Err(wrote),
            Ok(n) => {
                wrote += n;
                on_accept(u64::try_from(n).unwrap_or(u64::MAX));
            }
        }
    }
    Ok(())
}

/// Write `bytes` up to `grant`, and accept each slice the socket takes.
///
/// `Ok(0)` is a grant that covered nothing. `Ok(n)` is a grant that was
/// fully accepted. `Err` is a socket that stopped; the grant's drop
/// returns the tail.
async fn write_accepted<W, F>(
    write: &mut W,
    bytes: &[u8],
    mut grant: HeldGrant,
    mut on_accept: F,
) -> Result<usize, ()>
where
    W: AsyncWrite + Unpin,
    F: FnMut(),
{
    let room = grant.room(bytes.len());
    if room == 0 {
        return Ok(0);
    }
    write_counted(write, &bytes[..room], |n| {
        on_accept();
        grant.accept(n);
    })
    .await
    .map(|()| room)
    .map_err(|_| ())
}

/// Bytes read from the socket in one turn.
///
/// This is not a frame size. The connector's `decode` decides where a
/// frame ends. Both connectors share this buffer so the read size cannot
/// drift between them.
pub const READ_CHUNK_BYTES: usize = 8 * 1024;

/// Write queued bytes until the queue closes or the cap trips.
///
/// `encode` turns one queued buffer into the socket bytes. An empty
/// encoding is not written. The cap count is released when the write
/// finishes, or when it is cancelled.
pub async fn write_capped<W, F>(
    write: &mut W,
    outbound: &ByteQueue,
    overfull: &Overfull,
    gate: &LinkGate,
    stall: &mut WriteStall,
    mut encode: F,
) -> CloseCause
where
    W: AsyncWrite + Unpin,
    F: for<'a> FnMut(&'a [u8]) -> Result<Cow<'a, [u8]>, CloseKind>,
{
    let conn = stall.conn();
    let _lease = gate.lease(LinkDirection::Up, conn);
    let cause = write_queued(write, outbound, overfull, gate, stall, &mut encode).await;
    stall.fold();
    cause
}

async fn write_queued<W, F>(
    write: &mut W,
    outbound: &ByteQueue,
    overfull: &Overfull,
    gate: &LinkGate,
    stall: &mut WriteStall,
    encode: &mut F,
) -> CloseCause
where
    W: AsyncWrite + Unpin,
    F: for<'a> FnMut(&'a [u8]) -> Result<Cow<'a, [u8]>, CloseKind>,
{
    let conn = stall.conn();
    let stamp = gate.byte_stamp(LinkDirection::Up, conn);
    loop {
        if overfull.tripped() {
            shutdown(write).await;
            return CloseCause::new(CloseKind::SendQueueFull);
        }
        tokio::select! {
            biased;
            () = overfull.wait() => {
                shutdown(write).await;
                return CloseCause::new(CloseKind::SendQueueFull);
            }
            next = outbound.pop() => {
                let (class, bytes) = match next {
                    Ok(item) => item,
                    Err(closed) => {
                        shutdown(write).await;
                        return CloseCause::new(closed.kind());
                    }
                };
                let n = bytes.len();
                let wire = match encode(&bytes) {
                    Ok(wire) => wire,
                    Err(kind) => {
                        outbound.release(n);
                        shutdown(write).await;
                        return CloseCause::new(kind);
                    }
                };
                if wire.is_empty() {
                    outbound.release(n);
                    continue;
                }
                let mut off = 0usize;
                while off < wire.len() {
                    if overfull.tripped() {
                        outbound.release(n);
                        shutdown(write).await;
                        return CloseCause::new(CloseKind::SendQueueFull);
                    }
                    let grant = HeldGrant::acquire(
                        gate,
                        LinkDirection::Up,
                        conn,
                        class,
                        u64::try_from(wire.len() - off).unwrap_or(u64::MAX),
                    )
                    .await;
                    if grant.room(wire.len() - off) == 0 {
                        continue;
                    }
                    stall.begin();
                    // The pinned write owns the grant. The block ends, and
                    // drops that write, before anything else borrows the socket.
                    let result = {
                        let mut attempt = std::pin::pin!(write_accepted(
                            write,
                            &wire[off..],
                            grant,
                            || stamp.store(),
                        ));
                        tokio::select! {
                            biased;
                            () = overfull.wait() => Err(CloseKind::SendQueueFull),
                            result = &mut attempt => result.map_err(|()| CloseKind::IoError),
                        }
                    };
                    match result {
                        Ok(wrote) => {
                            stall.complete();
                            off += wrote;
                        }
                        Err(kind) => {
                            if kind == CloseKind::SendQueueFull {
                                stall.cancel();
                            } else {
                                stall.complete();
                            }
                            outbound.release(n);
                            shutdown(write).await;
                            return CloseCause::new(kind);
                        }
                    }
                }
                gate.record_message(LinkDirection::Up, conn);
                outbound.release(n);
            }
        }
    }
}

/// Read socket bytes until the peer, the cap, or the caller stops.
///
/// `decode` turns one read into session frames. A slow [`crate::Session::recv`]
/// stops this function on a full inbound queue, and TCP pushes back on
/// the peer. A tripped cap closes instead of waiting that out.
///
/// The returned cause is what this shared code observed. It is not stored
/// on `inbound`: the connector stamps it with its own table and seals the
/// session, so the first end a session holds is the connector's.
pub async fn read_capped<R, F>(
    read: &mut R,
    inbound: InboundEnd,
    overfull: &Overfull,
    gate: &LinkGate,
    conn: u64,
    mut decode: F,
) -> CloseCause
where
    R: ReadyRead + Unpin,
    F: FnMut(&[u8]) -> Result<Vec<Vec<u8>>, CloseKind>,
{
    let _lease = gate.lease(LinkDirection::Down, conn);
    read_queued(read, &inbound, overfull, gate, conn, &mut decode).await
}

async fn read_queued<R, F>(
    read: &mut R,
    inbound: &InboundEnd,
    overfull: &Overfull,
    gate: &LinkGate,
    conn: u64,
    decode: &mut F,
) -> CloseCause
where
    R: ReadyRead + Unpin,
    F: FnMut(&[u8]) -> Result<Vec<Vec<u8>>, CloseKind>,
{
    let mut buf = [0u8; READ_CHUNK_BYTES];
    let stamp = gate.byte_stamp(LinkDirection::Down, conn);
    loop {
        if overfull.tripped() {
            return CloseCause::new(CloseKind::SendQueueFull);
        }
        let mut cancel = std::pin::pin!(overfull.wait());
        let n = match read_granted(
            read,
            &mut buf,
            gate,
            conn,
            MessageClass::Session,
            &mut cancel,
        )
        .await
        {
            Ok(n) => n,
            Err(ReadStop::Cancel(())) => return CloseCause::new(CloseKind::SendQueueFull),
            Err(ReadStop::Eof) => return CloseCause::new(CloseKind::PeerClosed),
            Err(ReadStop::Failed) => return CloseCause::new(CloseKind::IoError),
        };
        stamp.store();
        gate.record_message(LinkDirection::Down, conn);
        let pieces = match decode(&buf[..n]) {
            Ok(pieces) => pieces,
            Err(kind) => return CloseCause::new(kind),
        };
        for piece in pieces {
            tokio::select! {
                biased;
                () = overfull.wait() => return CloseCause::new(CloseKind::SendQueueFull),
                result = inbound.send(piece) => {
                    if result.is_err() {
                        return CloseCause::new(CloseKind::LocalClose);
                    }
                }
            }
        }
    }
}

async fn shutdown<W: AsyncWrite + Unpin>(write: &mut W) {
    drop(write.shutdown().await);
}

#[cfg(test)]
#[path = "copy_tests.rs"]
mod tests;
