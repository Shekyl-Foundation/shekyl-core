// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The write-stall bound measures the peer.
//!
//! [`write_bounded`] times one [`tokio::io::AsyncWriteExt::write`] at a time.
//! Bytes accepted start [`WRITE_STALL_TIMEOUT`] over. A poll that finds the
//! socket writable writes, however late it is. The clock here is paused:
//! one peer drains across the bound, one poll arrives after the bound onto
//! a writable socket, and one peer stops reading.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

use super::super::{write_bounded, WRITE_STALL_TIMEOUT};

/// Duplex capacity for a stall test. One poll fills it, so the clock arms
/// before any later advance.
const STALL_PIPE_BYTES: usize = 1024;

/// Pipe-fulls one cross-bound write sends. More than
/// [`STALL_DRAINS_PER_BOUND`], so the write is still open when the whole
/// span passes [`WRITE_STALL_TIMEOUT`].
const STALL_PIPE_FILLS: usize = 8;

/// Pipe-fulls in the late-poll write. One fills the pipe and arms the
/// clock, one is what the late poll accepts, and one is still waiting, so
/// a `write_all` of the whole slice cannot finish on that poll.
const STALL_LATE_POLL_FILLS: usize = 3;
const _: () = assert!(
    STALL_LATE_POLL_FILLS > 2,
    "the late poll accepts one fill and still leaves bytes waiting"
);

/// Pipe-fulls offered to a peer that never reads. One fills the pipe; the
/// next write finds no room and is the one the clock times.
const STALL_NEVER_READS_FILLS: usize = 2;
const _: () = assert!(
    STALL_NEVER_READS_FILLS > 1,
    "one fill leaves the pipe full, so the next write is the one that stalls"
);

/// Drains that fit inside one stall bound. Two or more, so one gap is
/// strictly inside the bound.
const STALL_DRAINS_PER_BOUND: u32 = 3;

/// One millisecond past a bound. The paused clock moves in millisecond
/// ticks, so this is the smallest advance that is strictly later.
const STALL_BOUND_STEP: Duration = Duration::from_millis(1);

/// One drain's wait. [`STALL_PIPE_FILLS`] of them run past the bound.
fn stall_drain_gap() -> Duration {
    WRITE_STALL_TIMEOUT / STALL_DRAINS_PER_BOUND
}

/// Strictly past a clock armed at the previous poll.
fn past_the_stall_bound() -> Duration {
    WRITE_STALL_TIMEOUT + STALL_BOUND_STEP
}

/// Take one buffered pipe-full.
///
/// The bytes are already written, so this polls and does not wait: a
/// paused clock does not move.
fn take_full_pipe(client: &mut tokio::io::DuplexStream, cx: &mut Context<'_>, buf: &mut [u8]) {
    let mut read = ReadBuf::new(buf);
    match Pin::new(client).poll_read(cx, &mut read) {
        Poll::Ready(Ok(())) => {
            assert_eq!(
                read.filled().len(),
                STALL_PIPE_BYTES,
                "a full pipe was buffered"
            );
        }
        other => panic!("a full pipe was buffered, got {other:?}"),
    }
}

fn assert_stall_schedule_crosses_the_bound() {
    let gap = stall_drain_gap();
    assert!(
        gap < WRITE_STALL_TIMEOUT,
        "one drain waits inside the stall bound"
    );
    assert!(
        gap * u32::try_from(STALL_PIPE_FILLS).expect("fills fit u32") > WRITE_STALL_TIMEOUT,
        "the whole write runs past the stall bound"
    );
}

/// A peer that drains inside the bound, across a span longer than the
/// bound, keeps the write.
///
/// The edit that makes this red is a timeout around `write_all` of the
/// whole slice: the clock then starts at the first poll and is not cleared
/// when a later poll accepts bytes.
#[tokio::test(start_paused = true)]
async fn a_peer_that_drains_across_the_bound_keeps_the_write() {
    assert_stall_schedule_crosses_the_bound();
    let (mut server, mut client) = tokio::io::duplex(STALL_PIPE_BYTES);
    let bytes = vec![0xcdu8; STALL_PIPE_BYTES * STALL_PIPE_FILLS];
    let writer = tokio::spawn(async move { write_bounded(&mut server, &bytes).await });
    // The writer fills the pipe and blocks, which arms the clock, before
    // any advance.
    tokio::task::yield_now().await;

    let mut got = Vec::new();
    let mut buf = vec![0u8; STALL_PIPE_BYTES];
    for _ in 0..STALL_PIPE_FILLS {
        let n = client.read(&mut buf).await.expect("read");
        assert_eq!(n, STALL_PIPE_BYTES, "the writer had a full pipe buffered");
        got.extend_from_slice(&buf[..n]);
        tokio::time::advance(stall_drain_gap()).await;
    }
    writer
        .await
        .expect("join")
        .expect("drains inside the bound, across a span longer than it, are not a stall");
    assert_eq!(got.len(), STALL_PIPE_BYTES * STALL_PIPE_FILLS);
}

/// A poll that arrives after the bound, and finds the socket writable,
/// writes. That lateness is not a stall.
///
/// The first poll fills the pipe and arms the clock, with bytes still
/// waiting. One pipe-full is read back, so the next poll has room, and
/// the clock is moved past the bound before that poll. The poll accepts
/// one fill and still has one waiting. A timeout around `write_all` of
/// the whole slice stays pending on what is left and cuts. A clock that
/// starts over on the bytes just accepted writes the rest.
#[tokio::test(start_paused = true)]
async fn a_late_poll_of_a_writable_socket_is_not_a_stall() {
    let (mut server, mut client) = tokio::io::duplex(STALL_PIPE_BYTES);
    let bytes = vec![0xabu8; STALL_PIPE_BYTES * STALL_LATE_POLL_FILLS];
    // Polled here, not spawned: `advance` wakes a sleep and does not poll
    // it, so the late poll has to be this task's next poll of the write.
    let mut cx = Context::from_waker(Waker::noop());
    let mut write = std::pin::pin!(write_bounded(&mut server, &bytes));
    assert!(
        write.as_mut().poll(&mut cx).is_pending(),
        "the first poll fills the pipe and arms the clock"
    );

    let mut buf = [0u8; STALL_PIPE_BYTES];
    take_full_pipe(&mut client, &mut cx, &mut buf);
    let mut got = buf.to_vec();

    // Armed after the write's own clock, for the same duration. Once this
    // one has fired, that earlier clock has too.
    let mut stall_clock = std::pin::pin!(tokio::time::sleep(WRITE_STALL_TIMEOUT));
    assert!(stall_clock.as_mut().poll(&mut cx).is_pending());
    tokio::time::advance(past_the_stall_bound()).await;
    assert!(
        stall_clock.as_mut().poll(&mut cx).is_ready(),
        "the stall clock has fired before the late poll"
    );

    match write.as_mut().poll(&mut cx) {
        Poll::Pending => {}
        Poll::Ready(Ok(())) => panic!(
            "the late poll finished the whole slice, so a timeout around write_all would too"
        ),
        Poll::Ready(Err(e)) => {
            panic!("a poll that finds room writes that room, it does not cut ({e})")
        }
    }

    // The late poll accepted one fill and left one. Drain that fill, then
    // the last poll finds room and finishes.
    take_full_pipe(&mut client, &mut cx, &mut buf);
    got.extend_from_slice(&buf);
    match write.as_mut().poll(&mut cx) {
        Poll::Ready(result) => {
            result.expect("a poll that finds room writes, however late it is");
        }
        Poll::Pending => panic!("the last fill found no room"),
    }
    take_full_pipe(&mut client, &mut cx, &mut buf);
    got.extend_from_slice(&buf);
    assert_eq!(got, bytes);
}

/// A peer that stops reading is cut when the bound runs out. The clock
/// starts at the first poll that finds no room.
///
/// The edit that makes this red is a longer stall bound. Waiting on the
/// handle first lets the paused clock run on to whatever deadline the
/// write armed, so the cut would still arrive.
#[tokio::test(start_paused = true)]
async fn a_peer_that_stops_reading_is_cut_at_the_stall_bound() {
    let (mut server, _client_keeps_the_pipe_open_and_never_reads) =
        tokio::io::duplex(STALL_PIPE_BYTES);
    let bytes = vec![0xefu8; STALL_PIPE_BYTES * STALL_NEVER_READS_FILLS];
    let writer = tokio::spawn(async move { write_bounded(&mut server, &bytes).await });
    // The writer fills the pipe and arms the clock before any advance.
    // Without this yield the later `is_finished` is false, and an await
    // would auto-advance to a deadline that was never pinned.
    tokio::task::yield_now().await;
    tokio::time::advance(past_the_stall_bound()).await;
    // The advance wakes the writer; this yield polls it, so the cut is
    // observed here rather than by an await that moves the clock.
    tokio::task::yield_now().await;
    assert!(
        writer.is_finished(),
        "the stall bound has already cut a peer that never reads"
    );
    let err = writer
        .await
        .expect("join")
        .expect_err("a peer that never drains is cut");
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
}
