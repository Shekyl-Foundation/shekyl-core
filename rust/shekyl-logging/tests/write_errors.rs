// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A sink's write errors are counted and reported (Rick's review of #1069,
//! 2026-10-14). A sink that refuses every write for 5 s and then accepts:
//! once it accepts, it carries one line saying how many lines failed to
//! write. *Records-was:* `tracing_appender`'s worker discards a writer's
//! error, so a dead stderr pipe, a full disk or a failing file lost lines
//! with nothing said.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use shekyl_logging::{Config, __test_only_init_with_stderr};
use tracing::Level;

/// How long the sink refuses every write.
const REFUSING: Duration = Duration::from_secs(5);
/// Large, so nothing is dropped and every loss counted is a refused write.
const QUEUE_LINES: usize = 8_192;

/// A sink that returns an error until `until`, then records what it gets.
struct RefusingSink {
    until: Instant,
    written: Arc<Mutex<Vec<u8>>>,
}

impl Write for RefusingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if Instant::now() < self.until {
            return Err(std::io::Error::other("the sink refuses writes"));
        }
        self.written.lock().expect("sink").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if Instant::now() < self.until {
            return Err(std::io::Error::other("the sink refuses flushes"));
        }
        Ok(())
    }
}

#[test]
fn a_sink_that_refuses_writes_reports_them_once_it_accepts() {
    let written = Arc::new(Mutex::new(Vec::new()));
    let start = Instant::now();
    let sink = RefusingSink {
        until: start + REFUSING,
        written: Arc::clone(&written),
    };
    let guard = __test_only_init_with_stderr(Config::stderr_only(Level::DEBUG), sink, QUEUE_LINES)
        .expect("init");

    let mut logged = 0u32;
    while start.elapsed() < REFUSING + Duration::from_secs(1) {
        logged += 1;
        tracing::debug!(logged, "a line");
        thread::sleep(Duration::from_millis(50));
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
        .and_then(|rest| rest.split(' ').next())
        .and_then(|count| count.parse().ok())
        .unwrap_or_else(|| panic!("the report names a count: {report}"));
    assert!(
        refused >= 50,
        "about 100 lines were logged while the sink refused; the report counts {refused}"
    );
    assert!(
        !text.contains("lines dropped since"),
        "nothing was dropped: the queue held every line"
    );
    assert!(
        text.contains("a line"),
        "lines logged after the sink accepted reach it"
    );
}
