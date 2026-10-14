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
//! A full queue drops the line and counts it, per sink. The sink's writer
//! thread, on its next write or when it has drained the queue, writes one
//! line saying how many were dropped since the last line it had written.
//! The loss is never silent.

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
            last_written: SystemTime::now(),
        });
    // Set before any event can reach the queue: the subscriber that writes
    // to it is installed after this returns.
    let _unset = counter.set(non_blocking.error_counter());
    (non_blocking, guard)
}

/// The sink, as its writer thread sees it: before each line and after each
/// drain, the lines the queue dropped since the last report, as one line.
struct DropNotice<W> {
    inner: W,
    sink: String,
    counter: Arc<OnceLock<ErrorCounter>>,
    reported: usize,
    last_written: SystemTime,
}

impl<W: Write> DropNotice<W> {
    fn report_drops(&mut self) -> io::Result<()> {
        let Some(counter) = self.counter.get() else {
            return Ok(());
        };
        let dropped = counter.dropped_lines();
        if dropped <= self.reported {
            return Ok(());
        }
        let count = dropped - self.reported;
        self.reported = dropped;
        let now = stamp(SystemTime::now());
        let since = stamp(self.last_written);
        writeln!(
            self.inner,
            "{now}  WARN shekyl_logging: {count} lines dropped since {since} (the {} sink's queue was full)",
            self.sink
        )
    }
}

impl<W: Write> Write for DropNotice<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.report_drops()?;
        self.inner.write_all(buf)?;
        self.last_written = SystemTime::now();
        Ok(buf.len())
    }

    /// The writer thread flushes when it has drained the queue: that is
    /// when it has caught up, so the report is written then too.
    fn flush(&mut self) -> io::Result<()> {
        self.report_drops()?;
        self.inner.flush()
    }
}

fn stamp(at: SystemTime) -> String {
    OffsetDateTime::from(at)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "an unformattable time".to_owned())
}
