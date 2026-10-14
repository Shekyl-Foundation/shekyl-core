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
//! `tracing_appender`'s worker keeps running when a write returns an error,
//! and it discards the error. Returning `Err` from this writer still ends
//! the current batch before `flush`, so a drained queue would not publish.
//! [`DropNotice`] therefore returns `Ok` and keeps the counts itself.

use std::io::{self, Write};
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing_appender::non_blocking::{ErrorCounter, NonBlocking, NonBlockingBuilder, WorkerGuard};

/// Lines one sink's queue holds before a log call drops instead of waiting.
///
/// About 40 s of debug-level output at the ~200 lines/s a daemon with live
/// P2P sessions writes (the PR-3 measurement logs, 2026-10-14). A sink that
/// stalls longer than that drops and counts. Lines are a few hundred bytes,
/// so a full queue is a few MB per sink, inside the floor device's budget
/// (rule 76). *Records-was:* `tracing_appender`'s default, 128 000 lines and
/// lossy with no report, on the file sink only.
pub const SINK_QUEUE_LINES: usize = 8_192;

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

/// `writer` behind a bounded lossy queue of `lines` with its own thread.
///
/// `lines` is at least one. A full queue drops and counts. The thread
/// publishes the count.
pub(crate) fn queued<W: Write + Send + 'static>(
    writer: W,
    sink: Sink,
    lines: usize,
) -> (NonBlocking, WorkerGuard) {
    assert!(lines > 0, "a sink queue holds at least one line");
    let counter = Arc::new(OnceLock::new());
    let (non_blocking, guard) = NonBlockingBuilder::default()
        .lossy(true)
        .buffered_lines_limit(lines)
        .thread_name(sink.thread_name())
        .finish(DropNotice {
            inner: writer,
            loss: LossWindow::new(sink),
            counter: Arc::clone(&counter),
        });
    // The worker blocks in `recv` until a line exists, and the subscriber
    // that produces lines is installed after this returns. The counter has
    // to be published before either. A missed publish would report every
    // drop as zero, which is the failure this queue exists to close.
    counter
        .set(non_blocking.error_counter())
        .expect("the drop counter is published once");
    (non_blocking, guard)
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
    counter: Arc<OnceLock<ErrorCounter>>,
}

impl<W: Write> DropNotice<W> {
    fn dropped_total(&self) -> usize {
        self.counter
            .get()
            .expect("the drop counter is published before any line")
            .dropped_lines()
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
}

impl<W: Write> Write for DropNotice<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.publish() {
            Notice::Delivered => self.write_line(buf),
            Notice::Held => self.loss.note_failed_line(),
        }
        // `Ok` so the worker finishes this batch and reaches `flush`.
        // That flush is what publishes a queue that just drained.
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // A refused summary is not a flush, and it stays pending.
        if self.publish() == Notice::Held {
            return Ok(());
        }
        if self.inner.flush().is_err() {
            self.loss.note_failed_flush();
            // Publish in this call. The worker's batch flush is the last
            // chance before shutdown releases the guard; a later line
            // would be too late.
            let _notice = self.publish();
        }
        Ok(())
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
        );
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
}
