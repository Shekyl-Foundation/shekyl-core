// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A log call returns while its sink is stalled.
//!
//! The sink's first writes block until `STALL` has passed. Each `tracing`
//! call in that window must return within [`ON_TIME`]. Once the sink
//! catches up it carries one line saying how many lines were dropped.
//! *Records-was:* the stderr layer wrote synchronously, and a stalled
//! stderr held the caller for as long as the write took (18 s on one
//! responder in the PR-3 measurement).

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use shekyl_logging::{Config, __test_only_init_with_stderr};
use tracing::Level;

/// How long a write that starts inside the window waits.
const STALL: Duration = Duration::from_secs(1);
/// Small, so the queue fills and drops while the sink is stalled.
const QUEUE_LINES: usize = 16;
/// Calls issued while the sink is stalled. More than the queue, so a drop
/// is required.
const CALLS: usize = QUEUE_LINES * 4;
/// A log call that waits on the sink takes the rest of [`STALL`], which is
/// longer than this.
const ON_TIME: Duration = Duration::from_millis(500);
/// How long to wait, after the stall, for the writer to publish the drop.
const REPORT_WAIT: Duration = Duration::from_secs(2);

const DROPPED: &[u8] = b"lines dropped since";

/// A sink that stalls every write until `until`, then records what it gets.
struct StallingSink {
    until: Instant,
    written: Arc<Mutex<Vec<u8>>>,
}

impl Write for StallingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let now = Instant::now();
        if now < self.until {
            thread::sleep(self.until - now);
        }
        self.written.lock().expect("sink").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn contains_dropped(written: &Mutex<Vec<u8>>) -> bool {
    let buf = written.lock().expect("sink");
    buf.windows(DROPPED.len()).any(|window| window == DROPPED)
}

#[test]
fn a_stalled_sink_does_not_hold_the_log_call_and_reports_its_drops() {
    let written = Arc::new(Mutex::new(Vec::new()));
    let start = Instant::now();
    let sink = StallingSink {
        until: start + STALL,
        written: Arc::clone(&written),
    };
    let guard = __test_only_init_with_stderr(Config::stderr_only(Level::DEBUG), sink, QUEUE_LINES)
        .expect("init");

    for call in 0..CALLS {
        let started = Instant::now();
        tracing::debug!(call, "tick");
        let took = started.elapsed();
        assert!(
            took < ON_TIME,
            "log call {call} took {took:?} while the sink was stalled"
        );
    }

    let deadline = start + STALL + REPORT_WAIT;
    while Instant::now() < deadline && !contains_dropped(&written) {
        thread::sleep(Duration::from_millis(10));
    }
    drop(guard);

    let text = String::from_utf8_lossy(&written.lock().expect("sink")).into_owned();
    let report = text
        .lines()
        .find(|line| line.contains("lines dropped since"))
        .unwrap_or_else(|| panic!("the sink carries the drop report once it catches up:\n{text}"));
    let dropped: u64 = report
        .split("WARN shekyl_logging: ")
        .nth(1)
        .and_then(|rest| rest.split([' ', ';']).next())
        .and_then(|count| count.parse().ok())
        .unwrap_or_else(|| panic!("the report names a count: {report}"));
    assert!(
        dropped > 0,
        "the queue dropped at least one of the {CALLS} calls: {report}"
    );
}
