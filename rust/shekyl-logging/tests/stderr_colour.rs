// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Plain stderr lines from the installed subscriber carry no colour codes.
//!
//! `LineColour::stderr` decides when lines are plain. This test installs
//! `LineColour::Plain` through the test hook and checks the subscriber
//! actually writes that way. `NO_COLOR` is removed first: tracing-subscriber
//! colours by default when that variable is unset, so a layer that forgot
//! `with_ansi` fails here.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use shekyl_logging::{Config, LineColour, __test_only_init_with_stderr};
use tracing::Level;

/// How long to wait for the queued writer to deliver the line.
const DELIVERY_WAIT: Duration = Duration::from_secs(2);

const MARKER: &str = "stderr-colour-marker";
const ESCAPE: u8 = 0x1b;

/// A sink that records every byte it is given.
struct Recorder(Arc<Mutex<Vec<u8>>>);

impl Write for Recorder {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("sink").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn plain_stderr_lines_carry_no_escape_bytes() {
    // SAFETY: this file is its own process, and this is its only test.
    unsafe { std::env::remove_var(shekyl_logging::SHEKYL_LOG_ENV) };
    unsafe { std::env::remove_var("NO_COLOR") };

    let written = Arc::new(Mutex::new(Vec::new()));
    let guard = __test_only_init_with_stderr(
        Config::stderr_only(Level::INFO),
        Recorder(Arc::clone(&written)),
        shekyl_logging::SINK_QUEUE_LINES,
        LineColour::Plain,
    )
    .expect("init");

    tracing::warn!(target: "global", "{MARKER}");

    let deadline = Instant::now() + DELIVERY_WAIT;
    let delivered = || String::from_utf8_lossy(&written.lock().expect("sink")).contains(MARKER);
    while Instant::now() < deadline && !delivered() {
        thread::sleep(Duration::from_millis(10));
    }
    drop(guard);

    let bytes = written.lock().expect("sink").clone();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    assert!(
        text.contains(MARKER),
        "the line reached the sink (subject present):\n{text:?}"
    );
    assert!(
        text.contains(" WARN global: "),
        "level and target are plain text:\n{text:?}"
    );
    assert!(
        !bytes.contains(&ESCAPE),
        "no escape byte in what the sink received:\n{text:?}"
    );
}
