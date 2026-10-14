// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Every sink behind a bounded queue with its own writer thread (Rick,
//! 2026-10-14): a log call never waits on a sink.
//!
//! *Records-was:* the stderr layer wrote synchronously. One slow `stderr`
//! write (a file on a stalled disk, a slow journald) blocked the logging
//! thread, and every other thread that logged then waited on the process's
//! `stderr` lock: the P2P transport's workers among them, so a peer's
//! session timed out while this node's own threads sat in a log call (the
//! PR-3 cold-first-contact measurement, 2026-10-14: 18 s on one responder).
//!
//! A full queue drops the line and counts it, per sink. A write or flush
//! the sink refuses is counted too, and the writer thread carries on:
//! `tracing_appender`'s worker discards a writer's error, so without the
//! count a dead stderr pipe (`EPIPE`; the daemon ignores `SIGPIPE`), a full
//! disk or a failing file would lose lines silently. On its next successful
//! write, or when it has drained the queue, the writer thread writes one
//! line with both counts since the last line it had written. The loss is
//! never silent.

use std::io::{self, Write};
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing_appender::non_blocking::{ErrorCounter, NonBlocking, NonBlockingBuilder, WorkerGuard};

/// Lines one sink's queue holds before a log call drops instead of waiting.
///
/// About 40 s of debug-level output at the ~200 lines/s a daemon with live
/// P2P sessions writes (the PR-3 measurement logs, 2026-10-14); a sink that
/// stalls longer than that drops and counts. Lines are a few hundred bytes,
/// so a full queue is a few MB per sink, inside the floor device's budget
/// (rule 76). *Records-was:* `tracing_appender`'s default, 128 000 lines and
/// lossy with no report, on the file sink only.
pub const SINK_QUEUE_LINES: usize = 8_192;

/// `writer` behind a bounded queue of `lines` with its own thread,
/// `log-<sink>`. A full queue drops and counts; the thread reports the count.
pub(crate) fn queued<W: Write + Send + 'static>(
    writer: W,
    sink: &str,
    lines: usize,
) -> (NonBlocking, WorkerGuard) {
    let counter = Arc::new(OnceLock::new());
    let (non_blocking, guard) = NonBlockingBuilder::default()
        .lossy(true)
        .buffered_lines_limit(lines)
        .thread_name(&format!("log-{sink}"))
        .finish(DropNotice {
            inner: writer,
            sink: sink.to_owned(),
            counter: Arc::clone(&counter),
            reported: 0,
            failed_lines: 0,
            failed_flushes: 0,
            last_written: SystemTime::now(),
        });
    // Set before any event can reach the queue: the subscriber that writes
    // to it is installed after this returns.
    let _unset = counter.set(non_blocking.error_counter());
    (non_blocking, guard)
}

/// The sink, as its writer thread sees it: before each line and after each
/// drain, what was lost since the last line it wrote, as one line.
struct DropNotice<W> {
    inner: W,
    sink: String,
    counter: Arc<OnceLock<ErrorCounter>>,
    /// The queue's drop count at the last report that reached the sink.
    reported: usize,
    /// Lines the sink refused since the last report that reached it.
    failed_lines: u64,
    /// Flushes the sink refused since the last report that reached it.
    failed_flushes: u64,
    last_written: SystemTime,
}

impl<W: Write> DropNotice<W> {
    /// Writes what was lost, if anything, and reports whether the sink is
    /// taking writes. The counts are cleared only once the report is
    /// written, so a sink that refuses the report keeps them.
    fn report(&mut self) -> bool {
        let dropped_total = self.counter.get().map_or(0, ErrorCounter::dropped_lines);
        let dropped = dropped_total.saturating_sub(self.reported);
        if dropped == 0 && self.failed_lines == 0 && self.failed_flushes == 0 {
            return true;
        }
        let since = stamp(self.last_written);
        let sink = &self.sink;
        let mut parts = Vec::new();
        if dropped > 0 {
            parts.push(format!(
                "{dropped} lines dropped since {since} (the {sink} sink's queue was full)"
            ));
        }
        if self.failed_lines > 0 {
            parts.push(format!(
                "{} lines failed to write since {since} (the {sink} sink returned an error)",
                self.failed_lines
            ));
        }
        if self.failed_flushes > 0 {
            parts.push(format!(
                "{} flushes failed since {since} (the {sink} sink returned an error)",
                self.failed_flushes
            ));
        }
        let now = stamp(SystemTime::now());
        let line = format!("{now}  WARN shekyl_logging: {}\n", parts.join("; "));
        if self.inner.write_all(line.as_bytes()).is_err() {
            return false;
        }
        self.reported = dropped_total;
        self.failed_lines = 0;
        self.failed_flushes = 0;
        self.last_written = SystemTime::now();
        true
    }
}

/// Never returns an error: `tracing_appender`'s worker would discard it.
/// A refused write is counted and reported once the sink takes writes
/// again.
impl<W: Write> Write for DropNotice<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.report() && self.inner.write_all(buf).is_ok() {
            self.last_written = SystemTime::now();
        } else {
            self.failed_lines = self.failed_lines.saturating_add(1);
        }
        Ok(buf.len())
    }

    /// The writer thread flushes when it has drained the queue: that is
    /// when it has caught up, so the report is written then too.
    fn flush(&mut self) -> io::Result<()> {
        if !self.report() || self.inner.flush().is_err() {
            self.failed_flushes = self.failed_flushes.saturating_add(1);
        }
        Ok(())
    }
}

fn stamp(at: SystemTime) -> String {
    OffsetDateTime::from(at)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "an unformattable time".to_owned())
}
