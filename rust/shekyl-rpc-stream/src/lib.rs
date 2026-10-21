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
//!   policy). [`message`] decides the cut. An ordinary record is cut when
//!   the next byte would start another record, or at the flush. A full
//!   record is the largest class; the bytes left at a flush go in the
//!   smallest class that holds them.
//! - **A submission is padded to a fixed size** (RT-O28). The client arms
//!   the [`SubmissionMark`] before the message is classified. The mark is
//!   taken once, at classification: a further byte while one full record
//!   is buffered, or a flush that has bytes. The message then goes out as
//!   exactly [`SUBMISSION_RECORDS`] records of the largest class, padding
//!   first, so the HTTP body is a suffix and is not complete until the
//!   last record. A flush that seals nothing leaves the mark armed.
//! - **Backpressure.** An ordinary message holds at most one record's
//!   payload and one sealed record. A submission holds its payload until
//!   the flush, at most [`SUBMISSION_CAP`], and then one sealed record
//!   at a time. Either way a slow reader holds the writer.
//! - **Reading** delivers each record's payload in order. Only a padding
//!   record has occupancy 0, and it delivers nothing.
//! - **Half-close.** Shutting down the write side flushes, then shuts the
//!   transport's write side. A reader sees the end of the stream when the
//!   transport ends at a record boundary; an end inside a record is a
//!   truncation.
//! - **One class table in both directions** ([`class_table`], RT-O29):
//!   512, 16,384 and 65,535.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};

#[cfg(test)]
use shekyl_noise::ClassId;
use shekyl_noise::{ClassedError, ClassedRecord, Direction};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

mod message;

use message::{FlushPlan, Message, MessageKind, SealPlan, WritePlan};

pub use message::{class_table, CLASS_LENGTHS, MAX_PAYLOAD, SUBMISSION_CAP, SUBMISSION_RECORDS};

/// How much the adapter asks of the transport at once when reading.
const READ_CHUNK: usize = 16 * 1024;

/// The switch a client sets before a submission is classified.
///
/// hyper owns the stream on its own task, so the mark is shared. [`arm`](Self::arm)
/// publishes with [`Ordering::Release`]; the stream takes it with one
/// [`Ordering::AcqRel`] swap when the message is classified, and never
/// writes it back.
#[derive(Clone, Debug)]
pub struct SubmissionMark(Arc<AtomicBool>);

impl SubmissionMark {
    /// Arm the next message that has not been classified yet.
    ///
    /// Classification is when the kind first changes what is sealed: a
    /// further byte arrives while one full record is buffered, or a flush
    /// finds bytes waiting. An arm after that moment covers the following
    /// message. A flush that seals nothing does not take the mark.
    pub fn arm(&self) {
        self.0.store(true, Ordering::Release);
    }
}

/// A submission that does not fit [`SUBMISSION_CAP`]. The extra byte was
/// not accepted. The cap itself may already be sealed, as payload records,
/// because a message that large has no room to pad.
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

/// [`ClassedError`] stays the source. Truncation is an unexpected end;
/// every other failure is data the peer will not accept.
fn record_error(error: ClassedError) -> io::Error {
    let kind = match error {
        ClassedError::Truncated => io::ErrorKind::UnexpectedEof,
        ClassedError::Refused
        | ClassedError::Poisoned
        | ClassedError::UnknownClass
        | ClassedError::PayloadTooLarge
        | ClassedError::State => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, error)
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
    /// An ordinary write accepted payload while a sealed record was still
    /// leaving. That overlap is the one-record backpressure: the next
    /// payload fills during the write, and the seal after it waits.
    pub(crate) payload_while_record_in_flight: bool,
}

/// A byte stream over the channel's records.
pub struct RecordStream<T> {
    io: T,
    send: ClassedRecord,
    recv: ClassedRecord,
    /// The message being cut. The transport's in-flight record is `out`,
    /// not here: a seal commits in the message only after it succeeds,
    /// and `out` is that record until the transport takes it.
    message: Message,
    /// One sealed record not yet written to the transport, from `out_pos`.
    out: Vec<u8>,
    out_pos: usize,
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

    /// A stream whose first record the handshake already opened.
    ///
    /// The caller is the handshake's release of a pending session: it
    /// lends the receiving [`Direction`], opens the first record with a
    /// [`ClassedRecord`], and takes the direction back with
    /// [`ClassedRecord::into_direction`]. That direction has spent the
    /// first record's nonce. `first_payload` is read before anything
    /// else, then `unread_wire` (bytes already read past that record,
    /// which may be the next record or only the start of it), then the
    /// transport. The half built here derives its header key again for
    /// the epoch the direction is on.
    ///
    /// This is the handoff the session release will call. The release
    /// itself is not in this crate: the adapter does not depend on the
    /// handshake (RT-O19).
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
            message: Message::new(),
            out: Vec::new(),
            out_pos: 0,
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

    /// The switch that arms this stream's next unclassified message.
    #[must_use]
    pub fn submission_mark(&self) -> SubmissionMark {
        SubmissionMark(Arc::clone(&self.submission))
    }

    #[cfg(test)]
    pub(crate) fn counters(&self) -> Arc<std::sync::Mutex<Counters>> {
        Arc::clone(&self.counters)
    }

    /// The mark is taken once. A later [`SubmissionMark::arm`] is the
    /// next message, and this flush does not clear it.
    fn take_kind(&self) -> MessageKind {
        if self.submission.swap(false, Ordering::AcqRel) {
            MessageKind::Submission
        } else {
            MessageKind::Ordinary
        }
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

    /// Seal what `plan` names. The message keeps its bytes until the seal
    /// returns, so a failure is retried as the same record.
    fn seal(&mut self, plan: SealPlan) -> io::Result<()> {
        debug_assert!(
            self.out.is_empty(),
            "the previous record has not left; two sealed records would wait"
        );
        let wire = {
            let Self { send, message, .. } = self;
            send.seal(plan.class, message.prefix(plan.len))
                .map_err(record_error)?
        };
        self.message.commit_seal(plan);
        #[cfg(test)]
        self.note_sent(plan.class, wire.len());
        self.out = wire;
        Ok(())
    }

    #[cfg(test)]
    fn note_sent(&self, class: ClassId, wire_len: usize) {
        let mut counters = self.counters.lock().unwrap();
        let index = usize::from(class.0);
        debug_assert!(index < counters.sent.len(), "the table has three classes");
        counters.sent[index] += 1;
        counters.max_out = counters.max_out.max(wire_len);
    }

    #[cfg(test)]
    fn note_pending(&self) {
        let buffered = self.message.buffered_len();
        let mut counters = self.counters.lock().unwrap();
        counters.max_pending = counters.max_pending.max(buffered);
        if buffered > 0 && self.out_pos < self.out.len() {
            counters.payload_while_record_in_flight = true;
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RecordStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let largest = this.send.table().largest();
        loop {
            match this.message.plan_write(buf.len(), largest) {
                WritePlan::Accept(n) => {
                    debug_assert!(
                        n > 0 || buf.is_empty(),
                        "a non-empty write made no progress"
                    );
                    // A sealed record may already be in flight. Move what
                    // the transport will take, and accept these bytes
                    // either way: the message has room for them. Waiting
                    // here would hold the next payload until the record
                    // was gone, which is a second record of delay the
                    // ordinary path does not take. The next seal waits.
                    if let Poll::Ready(result) = this.poll_drain(cx) {
                        result?;
                    }
                    this.message.accept(&buf[..n]);
                    #[cfg(test)]
                    this.note_pending();
                    return Poll::Ready(Ok(n));
                }
                WritePlan::Classify => {
                    ready!(this.poll_drain(cx))?;
                    this.message.classify(this.take_kind());
                }
                WritePlan::Seal(plan) => {
                    ready!(this.poll_drain(cx))?;
                    this.seal(plan)?;
                }
                WritePlan::TooLarge => {
                    ready!(this.poll_drain(cx))?;
                    this.message.finish();
                    return Poll::Ready(Err(io::Error::other(SubmissionTooLarge)));
                }
                WritePlan::Sealing => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "a flush is already sealing this message",
                    )));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            ready!(this.poll_drain(cx))?;
            let plan = {
                let Self { send, message, .. } = this;
                message.plan_flush(send.table())
            };
            match plan {
                FlushPlan::Classify => this.message.classify(this.take_kind()),
                FlushPlan::Seal(plan) => this.seal(plan)?,
                FlushPlan::Done { counted } => {
                    if counted {
                        #[cfg(test)]
                        {
                            this.counters.lock().unwrap().flushes_with_records += 1;
                        }
                    }
                    // Idle, and the mark is untouched. An arm taken for
                    // the next message stays armed.
                    this.message.finish();
                    break;
                }
                FlushPlan::TooLarge => {
                    this.message.finish();
                    return Poll::Ready(Err(io::Error::other(SubmissionTooLarge)));
                }
            }
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
                        let index = usize::from(opened.class.0);
                        let mut counters = this.counters.lock().unwrap();
                        debug_assert!(index < counters.received.len());
                        counters.received[index] += 1;
                    }
                    // An empty payload is padding. It is not the end of
                    // the stream, and it delivers nothing, so the read
                    // continues into the next record.
                    this.plain = opened.payload;
                    this.plain_pos = 0;
                    continue;
                }
            }
            if this.eof {
                if this.wire.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(record_error(ClassedError::Truncated)));
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
