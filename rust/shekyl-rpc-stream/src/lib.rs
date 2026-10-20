// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! The RPC channel's stream adapter (`RPC_CHANNEL.md` §4.4, RT-W9 step 5b).
//!
//! hyper and axum expect a byte stream; the channel carries records.
//! [`RecordStream`] is `AsyncRead` and `AsyncWrite` over two
//! [`ClassedRecord`] halves and a transport:
//!
//! - **Writing combines bytes until a flush** (RT-P5's registered flush
//!   policy). A record is cut when the writer flushes, or when the buffer
//!   holds a full record's payload. A full record is the largest class; the
//!   bytes left at a flush go in the smallest class that holds them. A
//!   message larger than one record is so cut into full records and a tail.
//! - **Backpressure.** The adapter holds at most one record's payload and
//!   one sealed record waiting for the transport. It cuts no new record
//!   until the last one is written, so a slow reader holds the writer.
//! - **Reading** delivers each record's payload in order. A record with no
//!   payload (occupancy 0, the padding below) delivers nothing.
//! - **Half-close.** Shutting down the write side flushes, then shuts the
//!   transport's write side. A reader sees the end of the stream when the
//!   transport ends at a record boundary; an end inside a record is an
//!   error, since it is a truncation.
//! - **One class table in both directions** ([`class_table`], RT-O29):
//!   512, 16,384 and 65,535.
//! - **A submission is padded to a fixed size** (RT-O28): the client arms
//!   the [`SubmissionMark`] before it sends a `submit_transaction`
//!   request, and the message it flushes next goes out as exactly
//!   [`SUBMISSION_RECORDS`] records of the largest class, the last ones
//!   carrying no payload. A message that would need more is refused before
//!   a record past the count is sealed.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use shekyl_noise::{
    ClassId, ClassTable, ClassedError, ClassedRecord, Direction, MAX_RECORD_PLAINTEXT,
    OCCUPANCY_LEN,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The channel's class table, in both directions (RT-O6 re-ruled
/// 2026-10-18; RT-O29, 2026-10-20): plaintext lengths, occupancy included.
pub const CLASS_LENGTHS: [usize; 3] = [512, 16_384, MAX_RECORD_PLAINTEXT];

/// The most payload one record carries: a record of the largest class.
pub const MAX_PAYLOAD: usize = MAX_RECORD_PLAINTEXT - OCCUPANCY_LEN;

/// The records every `submit_transaction` upload takes, whatever the
/// transaction's size (RT-O28).
///
/// The largest admissible transaction is `TX_WEIGHT_LIMIT` = 149,400 bytes
/// (weight is size plus the Bp+ clawback). Its request body,
/// `{"tx_blob":"<hex>"}`, is at most 298,814 bytes: 4.56 records. Five
/// leave 28,851 bytes for the request head. A test pins this against
/// `shekyl-wire`'s `TX_WEIGHT_LIMIT`.
pub const SUBMISSION_RECORDS: usize = 5;

/// How much the adapter asks of the transport at once when reading.
const READ_CHUNK: usize = 16 * 1024;

/// The class table both directions pad to.
#[must_use]
pub fn class_table() -> ClassTable {
    ClassTable::new(&CLASS_LENGTHS).expect("the ruled table is strictly increasing")
}

/// The switch a client sets before it sends a submission: the next message
/// the stream flushes is padded to [`SUBMISSION_RECORDS`] records.
#[derive(Clone, Debug)]
pub struct SubmissionMark(Arc<AtomicBool>);

impl SubmissionMark {
    /// Pad the next flushed message as a submission. A flush with nothing
    /// written leaves the mark armed: the next message is the submission.
    pub fn arm(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A submission that does not fit its fixed record count. Nothing past the
/// count was sealed.
#[derive(Debug)]
pub struct SubmissionTooLarge;

impl std::fmt::Display for SubmissionTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "a submission needs more than its fixed {SUBMISSION_RECORDS} records"
        )
    }
}

impl std::error::Error for SubmissionTooLarge {}

fn record_error(error: ClassedError) -> io::Error {
    match error {
        ClassedError::Truncated => io::Error::from(io::ErrorKind::UnexpectedEof),
        other => io::Error::new(io::ErrorKind::InvalidData, format!("record: {other:?}")),
    }
}

/// What a test reads off a stream: records cut per class, flushes that
/// sent something, and the most the buffers ever held.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct Counters {
    pub(crate) sent: [u64; 3],
    pub(crate) received: [u64; 3],
    pub(crate) flushes_with_records: u64,
    pub(crate) max_pending: usize,
    pub(crate) max_out: usize,
}

/// A byte stream over the channel's records.
pub struct RecordStream<T> {
    io: T,
    send: ClassedRecord,
    recv: ClassedRecord,
    /// Payload written and not yet sealed. At most [`MAX_PAYLOAD`].
    pending: Vec<u8>,
    /// One sealed record not yet written to the transport, from `out_pos`.
    out: Vec<u8>,
    out_pos: usize,
    /// Records cut since the last flush ended.
    records_in_message: usize,
    submission: Arc<AtomicBool>,
    /// Wire bytes read and not yet opened.
    wire: Vec<u8>,
    /// The length of the record at the front of `wire`, once known.
    next_len: Option<usize>,
    /// An opened payload not yet read, from `plain_pos`.
    plain: Vec<u8>,
    plain_pos: usize,
    eof: bool,
    #[cfg(test)]
    counters: Arc<std::sync::Mutex<Counters>>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> RecordStream<T> {
    /// A stream over `io`, sealing with `send` and opening with `recv`.
    #[must_use]
    pub fn new(io: T, send: Direction, recv: Direction) -> Self {
        Self::after_first_record(io, send, recv, Vec::new(), Vec::new())
    }

    /// A stream whose first record the handshake already opened (a pending
    /// session is released by opening it): `first_payload` is read first,
    /// then `unread_wire`, bytes read past that record, then the transport.
    #[must_use]
    pub fn after_first_record(
        io: T,
        send: Direction,
        recv: Direction,
        first_payload: Vec<u8>,
        unread_wire: Vec<u8>,
    ) -> Self {
        Self {
            io,
            send: ClassedRecord::new(send, class_table()),
            recv: ClassedRecord::new(recv, class_table()),
            pending: Vec::with_capacity(MAX_PAYLOAD),
            out: Vec::new(),
            out_pos: 0,
            records_in_message: 0,
            submission: Arc::new(AtomicBool::new(false)),
            wire: unread_wire,
            next_len: None,
            plain: first_payload,
            plain_pos: 0,
            eof: false,
            #[cfg(test)]
            counters: Arc::default(),
        }
    }

    /// The switch that pads this stream's next message as a submission.
    #[must_use]
    pub fn submission_mark(&self) -> SubmissionMark {
        SubmissionMark(Arc::clone(&self.submission))
    }

    #[cfg(test)]
    pub(crate) fn counters(&self) -> Arc<std::sync::Mutex<Counters>> {
        Arc::clone(&self.counters)
    }

    /// Write out the sealed record waiting for the transport.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.out[self.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
            }
            self.out_pos += n;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }

    /// Seal `payload_len` bytes from the front of `pending` as one record of
    /// `class`. The caller has drained `out`.
    fn cut(&mut self, class: ClassId, payload_len: usize) -> io::Result<()> {
        debug_assert!(self.out.is_empty());
        if self.submission.load(Ordering::SeqCst) && self.records_in_message >= SUBMISSION_RECORDS {
            return Err(io::Error::other(SubmissionTooLarge));
        }
        let wire = self
            .send
            .seal(class, &self.pending[..payload_len])
            .map_err(record_error)?;
        self.pending.drain(..payload_len);
        self.out = wire;
        self.records_in_message += 1;
        #[cfg(test)]
        {
            let mut c = self.counters.lock().unwrap();
            c.sent[usize::from(class.0)] += 1;
            c.max_out = c.max_out.max(self.out.len());
        }
        Ok(())
    }

    fn largest(&self) -> ClassId {
        self.send.table().largest()
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RecordStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending.len() == MAX_PAYLOAD {
            ready!(this.poll_drain(cx))?;
            let largest = this.largest();
            this.cut(largest, MAX_PAYLOAD)?;
        }
        // Start the record on its way; if the transport is not ready, the
        // bytes below still fit in `pending`.
        if let Poll::Ready(result) = this.poll_drain(cx) {
            result?;
        }
        let n = buf.len().min(MAX_PAYLOAD - this.pending.len());
        this.pending.extend_from_slice(&buf[..n]);
        #[cfg(test)]
        {
            let mut c = this.counters.lock().unwrap();
            c.max_pending = c.max_pending.max(this.pending.len());
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            ready!(this.poll_drain(cx))?;
            let submission = this.submission.load(Ordering::SeqCst);
            if this.pending.len() == MAX_PAYLOAD {
                let largest = this.largest();
                this.cut(largest, MAX_PAYLOAD)?;
            } else if submission
                && (!this.pending.is_empty()
                    || (this.records_in_message > 0
                        && this.records_in_message < SUBMISSION_RECORDS))
            {
                // A submission's tail, then its padding: every record the
                // largest class, until the count is reached.
                let largest = this.largest();
                let len = this.pending.len();
                this.cut(largest, len)?;
            } else if !submission && !this.pending.is_empty() {
                let len = this.pending.len();
                let class = this
                    .send
                    .table()
                    .smallest_for(len)
                    .expect("pending never exceeds the largest class");
                this.cut(class, len)?;
            } else {
                break;
            }
        }
        if this.records_in_message > 0 {
            #[cfg(test)]
            {
                this.counters.lock().unwrap().flushes_with_records += 1;
            }
            this.records_in_message = 0;
            this.submission.store(false, Ordering::SeqCst);
        }
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for RecordStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.plain_pos < this.plain.len() {
                let n = buf.remaining().min(this.plain.len() - this.plain_pos);
                buf.put_slice(&this.plain[this.plain_pos..this.plain_pos + n]);
                this.plain_pos += n;
                if this.plain_pos == this.plain.len() {
                    this.plain.clear();
                    this.plain_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.next_len.is_none() {
                if let Some(&header) = this.wire.first() {
                    this.next_len = Some(this.recv.record_len(header).map_err(record_error)?);
                }
            }
            if let Some(len) = this.next_len {
                if this.wire.len() >= len {
                    let opened = this.recv.open(&this.wire).map_err(record_error)?;
                    this.wire.drain(..opened.consumed);
                    this.next_len = None;
                    #[cfg(test)]
                    {
                        this.counters.lock().unwrap().received[usize::from(opened.class.0)] += 1;
                    }
                    this.plain = opened.payload;
                    this.plain_pos = 0;
                    continue;
                }
            }
            if this.eof {
                if this.wire.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the transport ended inside a record",
                )));
            }
            let mut chunk = [0u8; READ_CHUNK];
            let mut read = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut this.io).poll_read(cx, &mut read))?;
            if read.filled().is_empty() {
                this.eof = true;
            } else {
                this.wire.extend_from_slice(read.filled());
            }
        }
    }
}

#[cfg(test)]
mod tests;
