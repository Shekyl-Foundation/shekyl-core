// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Log capture for a test binary: one global subscriber, a buffer per
//! thread.
//!
//! `tracing` caches each callsite's interest globally. A capture that
//! installs a thread-local subscriber (`with_default`) races every test
//! that reaches the same callsite with no subscriber: whichever gets there
//! first can cache the callsite as "never", for every thread, and the
//! capture then sees nothing. Here the one subscriber is global from the
//! first capture on, at `TRACE`, so no callsite is cached as never; the
//! writer routes each line to the calling thread's buffer, and only while
//! that thread is inside [`log_text`]. The dialer's wakes in these tests
//! run on the test thread, so per-thread routing holds.

use std::cell::RefCell;
use std::io::{self, Write};
use std::sync::Once;

use tracing_subscriber::fmt::MakeWriter;

thread_local! {
    /// The level this thread is capturing at, and what it has captured.
    static CAPTURE: RefCell<Option<(tracing::Level, Vec<u8>)>> = const { RefCell::new(None) };
}

/// Writes a line into the calling thread's capture, or nowhere.
struct ThreadBuf {
    capture: bool,
}

impl Write for ThreadBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.capture {
            CAPTURE.with(|slot| {
                if let Some((_, bytes)) = slot.borrow_mut().as_mut() {
                    bytes.extend_from_slice(buf);
                }
            });
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ThreadRouting;

impl<'a> MakeWriter<'a> for ThreadRouting {
    type Writer = ThreadBuf;

    fn make_writer(&'a self) -> Self::Writer {
        ThreadBuf { capture: false }
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        let capture = CAPTURE.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|(level, _)| meta.level() <= level)
        });
        ThreadBuf { capture }
    }
}

/// Install the one subscriber, once per binary.
fn install() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(ThreadRouting)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("no other global subscriber in this test binary");
    });
}

/// Everything logged at `level` or above on this thread while `run` runs.
pub fn log_text(level: tracing::Level, run: impl FnOnce()) -> String {
    install();
    CAPTURE.with(|slot| *slot.borrow_mut() = Some((level, Vec::new())));
    run();
    let bytes = CAPTURE
        .with(|slot| slot.borrow_mut().take())
        .map(|(_, bytes)| bytes)
        .unwrap_or_default();
    String::from_utf8(bytes).expect("utf-8")
}
