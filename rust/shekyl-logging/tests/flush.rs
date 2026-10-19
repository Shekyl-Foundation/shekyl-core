// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `flush` through the installed subscriber: it returns once every line
//! logged before it is on the sink, and a stalled sink holds it to its
//! deadline and no longer. The FFI's `shekyl_log_flush` answers the same.

use std::io::Write;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use shekyl_logging::{flush, Config, Flushed, LineColour, __test_only_init_with_stderr};
use tracing::Level;

/// Lines logged before the first flush.
const LINES: usize = 64;
/// Each write's cost while the gate is open: the lines are still queued
/// when the flush is called.
const PER_WRITE: Duration = Duration::from_millis(1);
/// The stalled arm's deadline.
const WITHIN: Duration = Duration::from_millis(200);
/// A flush that should have finished long before this did not.
const GENEROUS: Duration = Duration::from_secs(30);

/// Writes block while the gate is closed.
struct GatedSink {
    gate: Arc<(Mutex<bool>, Condvar)>,
    written: Arc<Mutex<Vec<u8>>>,
}

impl Write for GatedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let (open, opened) = &*self.gate;
        let mut is_open = open.lock().expect("gate");
        while !*is_open {
            is_open = opened.wait(is_open).expect("gate");
        }
        drop(is_open);
        std::thread::sleep(PER_WRITE);
        self.written.lock().expect("sink").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn set_gate(gate: &(Mutex<bool>, Condvar), open: bool) {
    *gate.0.lock().expect("gate") = open;
    gate.1.notify_all();
}

fn count(written: &Mutex<Vec<u8>>, marker: &str) -> usize {
    let text = String::from_utf8_lossy(&written.lock().expect("sink")).into_owned();
    text.matches(marker).count()
}

#[test]
fn a_flush_waits_for_every_earlier_line_and_no_longer_than_its_deadline() {
    let gate = Arc::new((Mutex::new(true), Condvar::new()));
    let written = Arc::new(Mutex::new(Vec::new()));
    let _guard = __test_only_init_with_stderr(
        Config::stderr_only(Level::INFO),
        GatedSink {
            gate: Arc::clone(&gate),
            written: Arc::clone(&written),
        },
        LINES * 2,
        LineColour::Plain,
    )
    .expect("init");

    for i in 0..LINES {
        tracing::info!("flush-marker-{i}");
    }
    assert_eq!(flush(GENEROUS), Flushed::Done);
    assert_eq!(
        count(&written, "flush-marker-"),
        LINES,
        "every line logged before the flush is on the sink"
    );

    // A stalled sink: the flush returns at its deadline.
    set_gate(&gate, false);
    tracing::info!("flush-held");
    let started = Instant::now();
    assert_eq!(flush(WITHIN), Flushed::DeadlinePassed);
    let waited = started.elapsed();
    assert!(waited >= WITHIN, "returned before the deadline: {waited:?}");
    assert!(waited < GENEROUS, "held past the deadline: {waited:?}");

    // The C entry point, on the same sinks.
    set_gate(&gate, true);
    // SAFETY: no pointer parameters.
    let code = unsafe { shekyl_logging::ffi::shekyl_log_flush(30_000) };
    assert_eq!(code, shekyl_logging::ffi::SHEKYL_LOG_OK);
    assert_eq!(count(&written, "flush-held"), 1);
}
