// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A sink's write errors are counted and reported.
//!
//! The sink refuses the first [`REFUSALS`] writes, then accepts. The
//! report that follows names the refused lines and does not call them
//! failed flushes: a summary the sink refuses is held and retried, and
//! `flush` is counted only when `flush` itself fails.
//! *Records-was:* `tracing_appender`'s worker discards a writer's error,
//! so a dead stderr pipe, a full disk, or a failing file lost lines with
//! nothing said.

use std::io::Write;
use std::sync::{Arc, Mutex};

use shekyl_logging::{Config, __test_only_init_with_stderr};
use tracing::Level;

/// Writes the sink refuses before it accepts. Enough that a summary
/// attempted in between is refused too, and fewer than [`LINES`] so a
/// later line still lands.
const REFUSALS: usize = 8;
/// Lines logged through the subscriber. The queue holds all of them, so
/// a loss in the report is a refused write.
const LINES: u32 = 32;
const QUEUE_LINES: usize = 64;

/// A sink that returns an error for the first `refusals_left` writes,
/// then records what it gets. Flushes succeed, so a "flushes failed"
/// clause would be the writer counting a summary it did not flush.
struct RefusingSink {
    refusals_left: usize,
    written: Arc<Mutex<Vec<u8>>>,
}

impl Write for RefusingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.refusals_left > 0 {
            self.refusals_left -= 1;
            return Err(std::io::Error::other("the sink refuses writes"));
        }
        self.written.lock().expect("sink").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_sink_that_refuses_writes_reports_them_once_it_accepts() {
    let written = Arc::new(Mutex::new(Vec::new()));
    let sink = RefusingSink {
        refusals_left: REFUSALS,
        written: Arc::clone(&written),
    };
    let guard = __test_only_init_with_stderr(Config::stderr_only(Level::DEBUG), sink, QUEUE_LINES)
        .expect("init");

    for logged in 1..=LINES {
        tracing::debug!(logged, "a line");
    }
    drop(guard);

    let text = String::from_utf8_lossy(&written.lock().expect("sink")).into_owned();
    let report = text
        .lines()
        .find(|line| line.contains("lines failed to write since"))
        .unwrap_or_else(|| panic!("no write-error report once the sink accepts:\n{text}"));
    let refused: u64 = report
        .split("WARN shekyl_logging: ")
        .nth(1)
        .and_then(|rest| rest.split([' ', ';']).next())
        .and_then(|count| count.parse().ok())
        .unwrap_or_else(|| panic!("the report names a count: {report}"));
    assert!(
        (1..=u64::from(LINES)).contains(&refused),
        "the report counts refused lines and not more than were logged: {refused}"
    );
    assert!(
        !text.contains("flushes failed"),
        "the sink accepted every flush; a refused summary is not one:\n{text}"
    );
    assert!(
        !text.contains("lines dropped since"),
        "nothing was dropped: the queue held every line:\n{text}"
    );
    assert!(
        text.contains("a line"),
        "lines logged after the sink accepted reach it:\n{text}"
    );
}
