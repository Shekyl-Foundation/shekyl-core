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
//!   smallest class that holds them. A flush ends its message: a write
//!   that arrives while the flush is still pending finishes sealing that
//!   message first and never joins it.
//! - **A submission is padded to a fixed size** (RT-O28). The client arms
//!   the [`SubmissionMark`] before the message is classified. The mark is
//!   taken once, at classification: a further byte while one full record
//!   is buffered, or a flush that has bytes. The message then goes out as
//!   exactly [`SUBMISSION_RECORDS`] records of the largest class, padding
//!   first, so the HTTP body is a suffix and is not complete until the
//!   last record. A flush that seals nothing leaves the mark armed. A
//!   submission past [`SUBMISSION_CAP`] is discarded unsealed and refused.
//! - **Backpressure.** An ordinary message holds at most one record's
//!   payload and one sealed record. A submission holds its payload until
//!   the flush, at most [`SUBMISSION_CAP`], and then one sealed record
//!   at a time. Either way a slow reader holds the writer.
//! - **Reading** delivers each record's payload in order. An empty record
//!   is accepted only in the shapes a sender makes: padding, at most
//!   `SUBMISSION_RECORDS - 1` largest-class records followed by the rest of
//!   their submission, and the close record. Anything else is refused.
//!   [`InboundShape`] reports the shape of the records just read, for the
//!   daemon's `submit_transaction` route to check (RT-W10).
//! - **An authenticated end.** Shutting down the write side flushes, seals
//!   the close record (occupancy 0 in the smallest class, which nothing
//!   else sends), then shuts the transport's write side. A reader sees the
//!   end of the stream only at that record; a transport that ends without
//!   it is a truncation.
//! - **One refusal is final.** A refused record, a transport error and a
//!   refused submission poison the stream: every later call returns an
//!   error, on both sides.
//! - **One class table in both directions** ([`class_table`], RT-O29):
//!   512, 16,384 and 65,535.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{ready, Context, Poll};

use shekyl_noise::{ClassId, ClassedError, ClassedRecord, Direction};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

mod message;

use message::{EndPlan, Message, MessageKind, SealPlan, WritePlan};

pub use message::{class_table, CLASS_LENGTHS, MAX_PAYLOAD, SUBMISSION_CAP, SUBMISSION_RECORDS};

/// How much the adapter asks of the transport at once when reading.
const READ_CHUNK: usize = 16 * 1024;

/// Empty records opened in one read before the read yields, so a run of
/// them cannot hold the task.
const EMPTY_RECORDS_PER_POLL: usize = 2;

/// The class of the close record: the smallest.
const CLOSE_CLASS: ClassId = ClassId(0);

/// The switch a client sets before a submission is classified.
///
/// hyper owns the stream on its own task, so the mark is shared. [`arm`](Self::arm)
/// publishes with [`Ordering::Release`]; the stream takes it with one
/// [`Ordering::AcqRel`] swap when the message is classified, and never
/// writes it back.
///
/// The mark belongs to the stream, not to a request. A client arms it on
/// the connection it is about to send the submission on, and that
/// connection is its own: hyper's `client::conn::http1`, not a pool
/// (`RPC_CHANNEL.md` §13, RT-W11 and RT-W12).
#[derive(Clone, Debug)]
pub struct SubmissionMark(Arc<AtomicBool>);

impl SubmissionMark {
    /// Arm the next message that has not been classified yet.
    ///
    /// Classification is when the kind first changes what is sealed: a
    /// further byte arrives while one full record is buffered, or a flush
    /// finds bytes waiting. An arm after that moment covers the following
    /// message. A flush that seals nothing does not take the mark. Arming
    /// twice before classification arms one message.
    pub fn arm(&self) {
        self.0.store(true, Ordering::Release);
    }
}

/// A submission that does not fit [`SUBMISSION_CAP`]. Nothing of it was
/// sealed, and the stream is poisoned.
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

/// The stream refused once and refuses everything after.
#[derive(Debug)]
pub struct StreamPoisoned;

impl std::fmt::Display for StreamPoisoned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the record stream refused earlier and stays refused")
    }
}

impl std::error::Error for StreamPoisoned {}

/// A record in a shape no sender makes: padding out of place, too much of
/// it, an empty record in a middle class, or a record after the close.
#[derive(Debug)]
pub struct RecordShapeRefused;

impl std::fmt::Display for RecordShapeRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a record arrived in a shape no sender makes")
    }
}

impl std::error::Error for RecordShapeRefused {}

/// [`ClassedError`] stays the source. On the read side, truncation is an
/// unexpected end and every other failure is data the peer will not
/// accept.
fn read_error(error: ClassedError) -> io::Error {
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

/// On the write side, a direction that cannot advance is this side's
/// failure, not bad data from the peer.
fn seal_error(error: ClassedError) -> io::Error {
    let kind = match error {
        ClassedError::State => io::ErrorKind::Other,
        _ => io::ErrorKind::InvalidInput,
    };
    io::Error::new(kind, error)
}

/// The errors a transport gives when the other end has already gone.
fn peer_gone(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::NotConnected
    )
}

/// One record as the reader saw it: its class, and whether it carried
/// nothing (padding, or the close).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordShape {
    /// The record's class in [`class_table`].
    pub class: ClassId,
    /// The record carried no payload.
    pub empty: bool,
    /// The record is the last of a padded submission frame: the frame's
    /// padding announced how many records it has, and this is the last.
    pub ends_frame: bool,
}

/// The shapes of the records a stream has read most recently, shared so the
/// daemon's request handler can read them while hyper owns the stream.
///
/// The `submit_transaction` route (RT-W10) refuses a request unless
/// [`ends_in_submission`](Self::ends_in_submission) is true when the body
/// has been read: a client that did not arm its mark, or armed the wrong
/// connection, sent a size the padding exists to hide, and the daemon fails
/// closed rather than answer it.
#[derive(Clone, Debug, Default)]
pub struct InboundShape(Arc<Mutex<VecDeque<RecordShape>>>);

impl InboundShape {
    /// The records read most recently, oldest first: at most
    /// `SUBMISSION_RECORDS + 1`.
    #[must_use]
    pub fn last(&self) -> Vec<RecordShape> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .copied()
            .collect()
    }

    /// Whether the records read most recently are one submission as a
    /// sender pads it: [`SUBMISSION_RECORDS`] records of the largest class,
    /// the empty ones first, at least one carrying payload.
    ///
    /// A submission whose request fills all five records carries no
    /// padding, and nothing on the wire says where it began. It counts only
    /// when the record before it ends a message the reader can see the end
    /// of: a smaller class, an empty record, or the last record of a padded
    /// frame. So a longer ordinary message is never taken for one, and a
    /// real submission sent right after an ordinary message that ended on a
    /// full record is refused: the daemon fails closed and the client sends
    /// again.
    #[must_use]
    pub fn ends_in_submission(&self) -> bool {
        let records = self.last();
        let Some(start) = records.len().checked_sub(SUBMISSION_RECORDS) else {
            return false;
        };
        let largest = class_table().largest();
        let frame = &records[start..];
        if frame.iter().any(|r| r.class != largest) {
            return false;
        }
        let padding = frame.iter().take_while(|r| r.empty).count();
        if padding == SUBMISSION_RECORDS || frame[padding..].iter().any(|r| r.empty) {
            return false;
        }
        match start.checked_sub(1).map(|i| records[i]) {
            Some(before) if padding == 0 => {
                before.class != largest || before.empty || before.ends_frame
            }
            _ => true,
        }
    }

    fn push(&self, shape: RecordShape) {
        let mut log = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if log.len() == SUBMISSION_RECORDS + 1 {
            log.pop_front();
        }
        log.push_back(shape);
    }
}

/// Where the reader is in a submission frame (`RPC_CHANNEL.md` §4.4): a
/// run of padding, then the rest of its [`SUBMISSION_RECORDS`] records.
#[derive(Debug, Default)]
struct Frame {
    /// Padding records read in the current run.
    padding: usize,
    /// Payload records the open frame still owes.
    owed: usize,
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
    /// The kind of the first error, once one has happened.
    poisoned: Option<io::ErrorKind>,
    /// Shutdown has begun: no more writes.
    write_closed: bool,
    close_sealed: bool,
    /// Wire bytes read and not yet opened are `wire[..wire_len]`. The
    /// rest is room a read fills directly; it grows only when a read needs
    /// more, so a read does not zero a buffer each time.
    wire: Vec<u8>,
    wire_len: usize,
    /// The length of the record at the front of `wire`, once known.
    next_len: Option<usize>,
    /// An opened payload not yet read, from `plain_pos`.
    plain: Zeroizing<Vec<u8>>,
    plain_pos: usize,
    frame: Frame,
    shape: InboundShape,
    /// The peer's close record has been read.
    peer_closed: bool,
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
            poisoned: None,
            write_closed: false,
            close_sealed: false,
            wire_len: unread_wire.len(),
            wire: unread_wire,
            next_len: None,
            plain: Zeroizing::new(first_payload),
            plain_pos: 0,
            frame: Frame::default(),
            shape: InboundShape::default(),
            peer_closed: false,
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

    /// The shapes of the records this stream reads.
    #[must_use]
    pub fn inbound_shape(&self) -> InboundShape {
        self.shape.clone()
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

    fn poisoned_error(&self) -> Option<io::Error> {
        self.poisoned
            .map(|kind| io::Error::new(kind, StreamPoisoned))
    }

    /// Every error a call returns poisons the stream for the calls after it.
    fn guard<R>(&mut self, result: Poll<io::Result<R>>) -> Poll<io::Result<R>> {
        if let Poll::Ready(Err(error)) = &result {
            self.poisoned.get_or_insert(error.kind());
        }
        result
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
                .map_err(seal_error)?
        };
        self.message.commit_seal(plan);
        #[cfg(test)]
        self.note_sent(plan.class, wire.len());
        self.out = wire;
        Ok(())
    }

    /// The message's last record has left: count it and go idle.
    fn close_message(&mut self, counted: bool) {
        #[cfg(test)]
        if counted {
            self.counters.lock().unwrap().flushes_with_records += 1;
        }
        let _ = counted;
        self.message.finish();
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

    fn write_step(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if let Some(error) = self.poisoned_error() {
            return Poll::Ready(Err(error));
        }
        if self.write_closed {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        let table = class_table();
        loop {
            match self.message.plan_write(buf.len(), &table) {
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
                    if let Poll::Ready(result) = self.poll_drain(cx) {
                        result?;
                    }
                    self.message.accept(&buf[..n]);
                    #[cfg(test)]
                    self.note_pending();
                    return Poll::Ready(Ok(n));
                }
                WritePlan::Classify => self.message.classify(self.take_kind()),
                WritePlan::Seal(plan) => {
                    ready!(self.poll_drain(cx))?;
                    self.seal(plan)?;
                }
                WritePlan::Close { counted } => {
                    ready!(self.poll_drain(cx))?;
                    self.close_message(counted);
                }
                WritePlan::TooLarge => {
                    self.message.discard();
                    return Poll::Ready(Err(io::Error::other(SubmissionTooLarge)));
                }
            }
        }
    }

    fn flush_step(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.poisoned_error() {
            return Poll::Ready(Err(error));
        }
        let table = class_table();
        loop {
            match self.message.plan_flush(&table) {
                EndPlan::Nothing => {
                    ready!(self.poll_drain(cx))?;
                    break;
                }
                EndPlan::Classify => self.message.classify(self.take_kind()),
                EndPlan::Seal(plan) => {
                    ready!(self.poll_drain(cx))?;
                    self.seal(plan)?;
                }
                EndPlan::Close { counted } => {
                    // Idle afterwards, and the mark is untouched. An arm
                    // taken for the next message stays armed.
                    ready!(self.poll_drain(cx))?;
                    self.close_message(counted);
                    break;
                }
            }
        }
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn shutdown_step(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write_closed = true;
        ready!(self.flush_step(cx))?;
        if !self.close_sealed {
            let close = self.send.seal(CLOSE_CLASS, &[]).map_err(seal_error)?;
            #[cfg(test)]
            self.note_sent(CLOSE_CLASS, close.len());
            self.out = close;
            self.close_sealed = true;
        }
        // Once the peer's close has been read the session is over both ways,
        // and a transport that refuses ours because the peer has gone has
        // nothing left to deliver it to. Before that, the same error is a
        // failure: the peer has not been told the stream ended.
        let after_peer_close = |result: io::Result<()>, peer_closed: bool| match result {
            Err(error) if peer_closed && peer_gone(&error) => Ok(true),
            Err(error) => Err(error),
            Ok(()) => Ok(false),
        };
        let drained = ready!(self.poll_drain(cx));
        if after_peer_close(drained, self.peer_closed)? {
            return Poll::Ready(Ok(()));
        }
        let flushed = ready!(Pin::new(&mut self.io).poll_flush(cx));
        if after_peer_close(flushed, self.peer_closed)? {
            return Poll::Ready(Ok(()));
        }
        let shut = ready!(Pin::new(&mut self.io).poll_shutdown(cx));
        after_peer_close(shut, self.peer_closed)?;
        Poll::Ready(Ok(()))
    }

    /// Check an opened record's shape against what a sender makes, and log
    /// it. Returns whether it is the peer's close.
    fn admit_shape(&mut self, class: ClassId, empty: bool) -> io::Result<bool> {
        let largest = self.recv.table().largest();
        let refused = || io::Error::new(io::ErrorKind::InvalidData, RecordShapeRefused);
        let frame = &mut self.frame;
        let close = empty && class == CLOSE_CLASS;
        if close {
            if frame.padding > 0 || frame.owed > 0 {
                return Err(refused());
            }
            return Ok(true);
        }
        let mut ends_frame = false;
        if empty {
            // Padding: the largest class, before the frame's payload, and
            // at most SUBMISSION_RECORDS - 1 of it.
            if class != largest || frame.owed > 0 || frame.padding + 1 >= SUBMISSION_RECORDS {
                return Err(refused());
            }
            frame.padding += 1;
        } else if frame.padding > 0 {
            if class != largest {
                return Err(refused());
            }
            frame.owed = SUBMISSION_RECORDS - frame.padding - 1;
            frame.padding = 0;
            ends_frame = frame.owed == 0;
        } else if frame.owed > 0 {
            if class != largest {
                return Err(refused());
            }
            frame.owed -= 1;
            ends_frame = frame.owed == 0;
        }
        self.shape.push(RecordShape {
            class,
            empty,
            ends_frame,
        });
        Ok(false)
    }

    fn read_step(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = self.poisoned_error() {
            return Poll::Ready(Err(error));
        }
        let mut empty_run = 0;
        loop {
            if self.plain_pos < self.plain.len() {
                let n = buf.remaining().min(self.plain.len() - self.plain_pos);
                buf.put_slice(&self.plain[self.plain_pos..self.plain_pos + n]);
                self.plain_pos += n;
                if self.plain_pos == self.plain.len() {
                    self.plain.clear();
                    self.plain_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if self.peer_closed {
                return Poll::Ready(Ok(()));
            }
            if self.next_len.is_none() && self.wire_len > 0 {
                let header = self.wire[0];
                self.next_len = Some(self.recv.record_len(header).map_err(read_error)?);
            }
            if let Some(len) = self.next_len {
                if self.wire_len >= len {
                    let opened = self
                        .recv
                        .open(&self.wire[..self.wire_len])
                        .map_err(read_error)?;
                    self.wire.copy_within(opened.consumed..self.wire_len, 0);
                    self.wire_len -= opened.consumed;
                    self.next_len = None;
                    #[cfg(test)]
                    {
                        let index = usize::from(opened.class.0);
                        let mut counters = self.counters.lock().unwrap();
                        debug_assert!(index < counters.received.len());
                        counters.received[index] += 1;
                    }
                    let empty = opened.payload.is_empty();
                    if self.admit_shape(opened.class, empty)? {
                        self.peer_closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    self.plain = Zeroizing::new(opened.payload);
                    self.plain_pos = 0;
                    if empty {
                        // Padding delivers nothing and is not the end of
                        // the stream. A run of it yields now and then.
                        empty_run += 1;
                        if empty_run >= EMPTY_RECORDS_PER_POLL {
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                    }
                    continue;
                }
            }
            if self.eof {
                // The peer ends the stream with its close record. A
                // transport that ends without one was cut, at a record
                // boundary or inside one.
                return Poll::Ready(Err(read_error(ClassedError::Truncated)));
            }
            if self.wire.len() - self.wire_len < READ_CHUNK {
                self.wire.resize(self.wire_len + READ_CHUNK, 0);
            }
            let mut read = ReadBuf::new(&mut self.wire[self.wire_len..]);
            ready!(Pin::new(&mut self.io).poll_read(cx, &mut read))?;
            let got = read.filled().len();
            self.wire_len += got;
            if got == 0 {
                self.eof = true;
            }
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
        let result = this.write_step(cx, buf);
        this.guard(result)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = this.flush_step(cx);
        this.guard(result)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = this.shutdown_step(cx);
        this.guard(result)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for RecordStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = this.read_step(cx, buf);
        this.guard(result)
    }
}

#[cfg(test)]
mod tests;
