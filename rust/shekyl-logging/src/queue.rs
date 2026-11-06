// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Every sink behind a bounded queue with its own writer thread.
//!
//! A log call enqueues. It does not wait on the sink. *Records-was:* the
//! stderr layer wrote synchronously. One slow `stderr` write (a file on a
//! stalled disk, a slow journald) blocked the logging thread, and every
//! other thread that logged then waited on the process's `stderr` lock.
//! The P2P transport's workers were among them, so a peer's session timed
//! out while this node's own threads sat in a log call (the PR-3
//! cold-first-contact measurement, 2026-10-14: 18 s on one responder).
//!
//! Each sink has its own queue, so a stall on one does not hold the other.
//! A full queue drops the line and counts it. A write the sink refuses is
//! counted. A flush the sink refuses is counted only when that `flush`
//! call returns an error. The writer publishes one line naming the counts
//! since the last line that reached the sink, and only moves the watermark
//! after that line is written. A refused summary leaves the counts where
//! they are. It is not itself a failed flush.
//!
//! **Flushing.** A line reaches the sink some time after the call that
//! logged it returns. [`flush`] is the bounded wait for that: it puts a
//! marker behind every line already queued and returns when the writer has
//! written and flushed up to the marker, or when the deadline passes,
//! whichever is first. It never blocks on a full queue; it retries until the
//! deadline. A process that is about to exit, and a test that reads what a
//! sink wrote, call it. [`SinkGuard`]'s drop flushes the same way and then
//! stops the writer.

use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing_subscriber::fmt::MakeWriter;

/// Lines one sink's queue holds before a log call drops instead of waiting.
///
/// About 40 s of debug-level output at the ~200 lines/s a daemon with live
/// P2P sessions writes (the PR-3 measurement logs, 2026-10-14). A sink that
/// stalls longer than that drops and counts. Lines are a few hundred bytes,
/// so a full queue is a few MB per sink, inside the floor device's budget
/// (rule 76). *Records-was:* `tracing_appender`'s default, 128 000 lines and
/// lossy with no report, on the file sink only.
pub const SINK_QUEUE_LINES: usize = 8_192;

/// How long a flush waits for the writers before it gives up.
///
/// Provisioned at the floor device (rule 76): a full queue is
/// [`SINK_QUEUE_LINES`] lines of a few hundred bytes, about 3 MB per sink,
/// and the writer appends them through the page cache in one write per line.
/// On a Pi 4 that is about 8 000 `write` calls of a few microseconds each:
/// tens of milliseconds. Two seconds is a wide margin over that. A sink that
/// has not drained by then is stalled (a blocked terminal, a hung journald,
/// a disk that stopped answering), and waiting longer would hold the
/// daemon's exit on it.
pub const FLUSH_WITHIN: Duration = Duration::from_secs(2);

/// How often a flush retries a queue that was full when it tried to put its
/// marker in.
const FULL_RETRY: Duration = Duration::from_millis(1);

/// Which sink a queue writes to. The thread name and the summary label
/// both come from here, so a new sink is one variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sink {
    /// The process's standard error.
    Stderr,
    /// The configured log file.
    File,
}

impl Sink {
    const fn label(self) -> &'static str {
        match self {
            Self::Stderr => "stderr",
            Self::File => "file",
        }
    }

    const fn thread_name(self) -> &'static str {
        match self {
            Self::Stderr => "log-stderr",
            Self::File => "log-file",
        }
    }
}

/// What a queue carries to its writer.
enum Msg {
    /// One formatted line.
    Line(Vec<u8>),
    /// Every line before this one has been written: flush, then answer.
    Marker(SyncSender<()>),
    /// Flush, answer, and end the writer.
    Stop(SyncSender<()>),
}

/// Whether a flush reached its marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "a flush that passed its deadline left lines queued"]
pub enum Flushed {
    /// Every line queued before the call is written and flushed. A sink
    /// whose writer has already stopped counts here: it holds nothing.
    Done,
    /// The deadline passed first.
    DeadlinePassed,
}

/// The log-call side of one sink's queue: what the subscriber's layer
/// writes to. Cloned per event.
#[derive(Clone)]
pub(crate) struct Producer {
    tx: SyncSender<Msg>,
    dropped: Arc<AtomicUsize>,
}

impl Producer {
    /// Put a marker behind every queued line and wait for the writer to
    /// reach it, until `deadline`.
    fn flush_until(&self, deadline: Instant) -> Flushed {
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        if !self.send_until(Msg::Marker(ack_tx), deadline) {
            return Flushed::DeadlinePassed;
        }
        wait_until(&ack_rx, deadline)
    }

    /// Queue `msg`, retrying a full queue until `deadline`. `true` when it
    /// was queued or the writer has stopped (there is nothing to wait for).
    fn send_until(&self, mut msg: Msg, deadline: Instant) -> bool {
        loop {
            match self.tx.try_send(msg) {
                Ok(()) | Err(TrySendError::Disconnected(_)) => return true,
                Err(TrySendError::Full(back)) => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    msg = back;
                    std::thread::sleep(FULL_RETRY);
                }
            }
        }
    }
}

/// The answer to a marker or a stop, until `deadline`. A writer that ended
/// without answering has nothing left to write.
fn wait_until(ack: &Receiver<()>, deadline: Instant) -> Flushed {
    let left = deadline.saturating_duration_since(Instant::now());
    match ack.recv_timeout(left) {
        Ok(()) | Err(RecvTimeoutError::Disconnected) => Flushed::Done,
        Err(RecvTimeoutError::Timeout) => Flushed::DeadlinePassed,
    }
}

impl Write for Producer {
    /// Queue `buf` as one line, or drop and count it when the queue is
    /// full or the writer has stopped. Never waits.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.tx.try_send(Msg::Line(buf.to_vec())).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        Ok(buf.len())
    }

    /// Nothing to do on the log call's side: [`flush`] is the wait.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Producer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// One sink's writer thread. Dropping it flushes within [`FLUSH_WITHIN`] and
/// stops the writer; it never waits longer.
pub(crate) struct SinkGuard {
    producer: Producer,
}

impl Drop for SinkGuard {
    fn drop(&mut self) {
        let deadline = Instant::now() + FLUSH_WITHIN;
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        if self.producer.send_until(Msg::Stop(ack_tx), deadline) {
            let _flushed = wait_until(&ack_rx, deadline);
        }
    }
}

/// The sinks the installed subscriber writes to, for [`flush`].
static INSTALLED: Mutex<Vec<Producer>> = Mutex::new(Vec::new());

/// Record the installed subscriber's sinks.
pub(crate) fn install(producers: Vec<Producer>) {
    *INSTALLED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = producers;
}

/// Wait until every line logged before this call has reached its sink, or
/// `within` passes. One deadline covers every sink. With no subscriber
/// installed there is nothing queued: [`Flushed::Done`].
pub fn flush(within: Duration) -> Flushed {
    let deadline = Instant::now() + within;
    let producers = INSTALLED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let mut flushed = Flushed::Done;
    for producer in &producers {
        if producer.flush_until(deadline) == Flushed::DeadlinePassed {
            flushed = Flushed::DeadlinePassed;
        }
    }
    flushed
}

/// `writer` behind a bounded lossy queue of `lines` with its own thread.
///
/// `lines` is at least one. A full queue drops and counts. The thread
/// publishes the count.
///
/// # Errors
///
/// The writer thread could not be started.
pub(crate) fn queued<W: Write + Send + 'static>(
    writer: W,
    sink: Sink,
    lines: usize,
) -> io::Result<(Producer, SinkGuard)> {
    assert!(lines > 0, "a sink queue holds at least one line");
    let (tx, rx) = mpsc::sync_channel(lines);
    let dropped = Arc::new(AtomicUsize::new(0));
    let notice = DropNotice {
        inner: writer,
        loss: LossWindow::new(sink),
        dropped: Arc::clone(&dropped),
    };
    std::thread::Builder::new()
        .name(sink.thread_name().to_owned())
        .spawn(move || write_queue(&rx, notice))?;
    let producer = Producer { tx, dropped };
    Ok((producer.clone(), SinkGuard { producer }))
}

/// The writer thread: each line in order, a flush whenever the queue runs
/// empty, and an answer to each marker after the lines before it.
fn write_queue<W: Write>(rx: &Receiver<Msg>, mut notice: DropNotice<W>) {
    while let Ok(mut msg) = rx.recv() {
        loop {
            match msg {
                Msg::Line(line) => notice.write_line_queued(&line),
                Msg::Marker(ack) => {
                    notice.flush();
                    // A flush that gave up at its deadline dropped the
                    // receiver; nobody is left to answer.
                    ack.send(()).ok();
                }
                Msg::Stop(ack) => {
                    notice.flush();
                    ack.send(()).ok();
                    return;
                }
            }
            match rx.try_recv() {
                Ok(next) => msg = next,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        notice.flush();
    }
    notice.flush();
}

/// What one sink has lost since the last summary that reached it.
struct LossWindow {
    sink: Sink,
    /// Queue-drop total included in the last summary that reached the sink.
    reported_drops: usize,
    failed_lines: u64,
    failed_flushes: u64,
    /// When the last line or summary reached the sink.
    last_written: SystemTime,
}

/// The loss a summary is about to name. `dropped_total` is the counter
/// snapshot this summary describes. Drops after the snapshot stay for the
/// next summary.
struct Pending {
    dropped: usize,
    failed_lines: u64,
    failed_flushes: u64,
    since: SystemTime,
    sink: Sink,
}

impl LossWindow {
    fn new(sink: Sink) -> Self {
        Self {
            sink,
            reported_drops: 0,
            failed_lines: 0,
            failed_flushes: 0,
            last_written: SystemTime::now(),
        }
    }

    fn pending(&self, dropped_total: usize) -> Option<Pending> {
        let dropped = dropped_total.saturating_sub(self.reported_drops);
        if dropped == 0 && self.failed_lines == 0 && self.failed_flushes == 0 {
            return None;
        }
        Some(Pending {
            dropped,
            failed_lines: self.failed_lines,
            failed_flushes: self.failed_flushes,
            since: self.last_written,
            sink: self.sink,
        })
    }

    /// The summary that named `dropped_total` reached the sink.
    fn acknowledge(&mut self, dropped_total: usize, now: SystemTime) {
        self.reported_drops = dropped_total;
        self.failed_lines = 0;
        self.failed_flushes = 0;
        self.last_written = now;
    }

    fn note_failed_line(&mut self) {
        self.failed_lines = self.failed_lines.saturating_add(1);
    }

    fn note_failed_flush(&mut self) {
        self.failed_flushes = self.failed_flushes.saturating_add(1);
    }

    fn note_written(&mut self, now: SystemTime) {
        self.last_written = now;
    }
}

impl Pending {
    fn line(&self) -> String {
        let since = stamp(self.since);
        let sink = self.sink.label();
        let mut parts = Vec::new();
        if self.dropped > 0 {
            let dropped = self.dropped;
            parts.push(format!(
                "{dropped} lines dropped since {since} (the {sink} sink's queue was full)"
            ));
        }
        if self.failed_lines > 0 {
            let failed_lines = self.failed_lines;
            parts.push(format!(
                "{failed_lines} lines failed to write since {since} (the {sink} sink returned an error)"
            ));
        }
        if self.failed_flushes > 0 {
            let failed_flushes = self.failed_flushes;
            parts.push(format!(
                "{failed_flushes} flushes failed since {since} (the {sink} sink returned an error)"
            ));
        }
        let now = stamp(SystemTime::now());
        format!("{now}  WARN shekyl_logging: {}\n", parts.join("; "))
    }
}

/// Whether the sink can take the next write or flush.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Notice {
    /// Nothing was pending, or the summary reached the sink.
    Delivered,
    /// The summary was refused. The counts stay.
    Held,
}

/// The sink, as its writer thread sees it.
struct DropNotice<W> {
    inner: W,
    loss: LossWindow,
    /// Lines the log call's side dropped: a full queue, or a stopped writer.
    dropped: Arc<AtomicUsize>,
}

impl<W: Write> DropNotice<W> {
    fn dropped_total(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }

    /// One queued line: the summary first when there is one to give.
    fn write_line_queued(&mut self, buf: &[u8]) {
        match self.publish() {
            Notice::Delivered => self.write_line(buf),
            Notice::Held => self.loss.note_failed_line(),
        }
    }

    /// Write the summary when there is something to say.
    ///
    /// `Delivered` means the caller may touch the sink: there was nothing
    /// to say, or the summary is now on it. `Held` means the summary was
    /// refused and the counts are unchanged.
    fn publish(&mut self) -> Notice {
        let dropped_total = self.dropped_total();
        let Some(pending) = self.loss.pending(dropped_total) else {
            return Notice::Delivered;
        };
        if self.inner.write_all(pending.line().as_bytes()).is_err() {
            return Notice::Held;
        }
        self.loss.acknowledge(dropped_total, SystemTime::now());
        Notice::Delivered
    }

    fn write_line(&mut self, buf: &[u8]) {
        match self.inner.write_all(buf) {
            Ok(()) => self.loss.note_written(SystemTime::now()),
            Err(_) => self.loss.note_failed_line(),
        }
    }

    /// Flush the sink. A refused summary is not a flush, and it stays
    /// pending; a refused flush is counted and published in this call,
    /// because a marker or a stop may be the last chance before exit.
    fn flush(&mut self) {
        if self.publish() == Notice::Held {
            return;
        }
        if self.inner.flush().is_err() {
            self.loss.note_failed_flush();
            let _notice = self.publish();
        }
    }
}

fn stamp(at: SystemTime) -> String {
    OffsetDateTime::from(at)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "an unformattable time".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Record {
        refuse_writes: usize,
        fail_flushes: bool,
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for Record {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.refuse_writes > 0 {
                self.refuse_writes -= 1;
                return Err(io::Error::other("refused"));
            }
            self.buf.lock().expect("record").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flushes {
                Err(io::Error::other("flush refused"))
            } else {
                Ok(())
            }
        }
    }

    /// Enqueue `lines` copies of `line\n`, then drop the guard so the
    /// worker drains. The queue is larger than `lines`, so nothing is dropped.
    fn run(refuse_writes: usize, fail_flushes: bool, lines: usize) -> String {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let (mut non_blocking, guard) = queued(
            Record {
                refuse_writes,
                fail_flushes,
                buf: Arc::clone(&buf),
            },
            Sink::Stderr,
            lines + 1,
        )
        .expect("the writer thread");
        for _ in 0..lines {
            non_blocking.write_all(b"line\n").expect("enqueue");
        }
        drop(guard);
        let recorded = buf.lock().expect("record");
        String::from_utf8_lossy(&recorded).into_owned()
    }

    fn count_in(text: &str, phrase: &str) -> u64 {
        let line = text
            .lines()
            .find(|line| line.contains(phrase))
            .unwrap_or_else(|| panic!("no report containing {phrase}:\n{text}"));
        line.split("WARN shekyl_logging: ")
            .nth(1)
            .and_then(|rest| rest.split([' ', ';']).next())
            .and_then(|count| count.parse().ok())
            .unwrap_or_else(|| panic!("the report names a count: {line}"))
    }

    #[test]
    fn a_refused_write_is_not_a_failed_flush() {
        const REFUSALS: usize = 8;
        const LINES: usize = 32;
        let text = run(REFUSALS, false, LINES);
        let failed = count_in(&text, "lines failed to write since");
        let lines = u64::try_from(LINES).expect("line count");
        assert!(
            (1..=lines).contains(&failed),
            "the report counts refused lines, got {failed}:\n{text}"
        );
        assert!(
            !text.contains("flushes failed"),
            "a refused summary is not a flush:\n{text}"
        );
        assert!(
            !text.contains("lines dropped"),
            "the queue held every line:\n{text}"
        );
        assert!(
            text.contains("line"),
            "a line written after the refusals:\n{text}"
        );
    }

    #[test]
    fn a_refused_flush_is_not_a_failed_line() {
        let text = run(0, true, 4);
        let failed = count_in(&text, "flushes failed since");
        assert!(failed >= 1, "the sink refused a flush: {failed}:\n{text}");
        assert!(
            !text.contains("lines failed to write"),
            "the lines were written:\n{text}"
        );
    }

    /// A sink that takes `pause` per write, or blocks until opened.
    struct Slow {
        pause: Duration,
        gate: Gate,
        buf: Arc<Mutex<Vec<u8>>>,
        /// Writes begun: a test waits on it to know the writer holds a line.
        entered: Arc<AtomicUsize>,
    }

    impl Write for Slow {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.entered.fetch_add(1, Ordering::SeqCst);
            let (open, opened) = &*self.gate;
            let mut is_open = open.lock().expect("gate");
            while !*is_open {
                is_open = opened.wait(is_open).expect("gate");
            }
            drop(is_open);
            std::thread::sleep(self.pause);
            self.buf.lock().expect("slow").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A gate the slow sink's writes wait on.
    type Gate = Arc<(Mutex<bool>, std::sync::Condvar)>;

    /// A slow sink behind a queue of `lines`: its producer, guard, gate,
    /// what it wrote, and how many writes it has begun.
    struct SlowQueue {
        producer: Producer,
        guard: SinkGuard,
        gate: Gate,
        buf: Arc<Mutex<Vec<u8>>>,
        entered: Arc<AtomicUsize>,
    }

    fn slow(pause: Duration, open: bool, lines: usize) -> SlowQueue {
        let gate = Arc::new((Mutex::new(open), std::sync::Condvar::new()));
        let buf = Arc::new(Mutex::new(Vec::new()));
        let entered = Arc::new(AtomicUsize::new(0));
        let (producer, guard) = queued(
            Slow {
                pause,
                gate: Arc::clone(&gate),
                buf: Arc::clone(&buf),
                entered: Arc::clone(&entered),
            },
            Sink::Stderr,
            lines,
        )
        .expect("the writer thread");
        SlowQueue {
            producer,
            guard,
            gate,
            buf,
            entered,
        }
    }

    /// Wait until the writer has begun `writes` writes.
    fn wait_entered(entered: &AtomicUsize, writes: usize) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while entered.load(Ordering::SeqCst) < writes {
            assert!(Instant::now() < deadline, "the writer never took a line");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn open_gate(gate: &(Mutex<bool>, std::sync::Condvar)) {
        *gate.0.lock().expect("gate") = true;
        gate.1.notify_all();
    }

    /// A flush returns only once every line queued before it is on the sink.
    #[test]
    fn a_flush_returns_after_every_line_before_it_is_written() {
        const LINES: usize = 50;
        let SlowQueue {
            mut producer,
            buf,
            guard: _guard,
            ..
        } = slow(Duration::from_millis(2), true, LINES + 1);
        for _ in 0..LINES {
            producer.write_all(b"line\n").expect("enqueue");
        }
        assert_eq!(
            producer.flush_until(Instant::now() + Duration::from_secs(30)),
            Flushed::Done
        );
        let written = buf.lock().expect("slow").len();
        assert_eq!(
            written,
            LINES * b"line\n".len(),
            "every line before the marker"
        );
    }

    /// A stalled sink holds a flush to its deadline, not past it and not short
    /// of it.
    #[test]
    fn a_flush_on_a_stalled_sink_returns_at_its_deadline() {
        const WITHIN: Duration = Duration::from_millis(200);
        let SlowQueue {
            mut producer,
            guard,
            gate,
            ..
        } = slow(Duration::ZERO, false, 4);
        producer.write_all(b"held\n").expect("enqueue");
        let started = Instant::now();
        assert_eq!(
            producer.flush_until(started + WITHIN),
            Flushed::DeadlinePassed
        );
        let waited = started.elapsed();
        assert!(waited >= WITHIN, "returned before the deadline: {waited:?}");
        assert!(waited < WITHIN * 10, "held past the deadline: {waited:?}");
        open_gate(&gate);
        drop(guard);
    }

    /// A queue too full to take the marker is retried until the deadline,
    /// never waited on.
    #[test]
    fn a_flush_on_a_full_queue_returns_at_its_deadline() {
        const WITHIN: Duration = Duration::from_millis(100);
        let SlowQueue {
            mut producer,
            guard,
            gate,
            entered,
            ..
        } = slow(Duration::ZERO, false, 1);
        // One line in the writer's hands, one in the queue: full.
        producer.write_all(b"a\n").expect("enqueue");
        wait_entered(&entered, 1);
        producer.write_all(b"b\n").expect("enqueue");
        let started = Instant::now();
        assert_eq!(
            producer.flush_until(started + WITHIN),
            Flushed::DeadlinePassed
        );
        assert!(
            started.elapsed() < WITHIN * 10,
            "the full queue was waited on"
        );
        open_gate(&gate);
        drop(guard);
    }

    /// Dropping the guard of a stalled sink returns within [`FLUSH_WITHIN`].
    #[test]
    fn the_guard_of_a_stalled_sink_returns_within_the_drain_bound() {
        let SlowQueue {
            mut producer,
            guard,
            gate,
            ..
        } = slow(Duration::ZERO, false, 4);
        producer.write_all(b"held\n").expect("enqueue");
        let started = Instant::now();
        drop(guard);
        let waited = started.elapsed();
        assert!(
            waited < FLUSH_WITHIN * 2,
            "the stop waited past its bound: {waited:?}"
        );
        open_gate(&gate);
    }

    /// After the writer stopped, a flush has nothing to wait for.
    #[test]
    fn a_flush_after_the_stop_is_done_at_once() {
        let SlowQueue {
            producer, guard, ..
        } = slow(Duration::ZERO, true, 4);
        drop(guard);
        let started = Instant::now();
        assert_eq!(
            producer.flush_until(started + Duration::from_secs(30)),
            Flushed::Done
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
