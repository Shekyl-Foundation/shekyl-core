// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's panic hook (`DAEMON_CONFIG_CUTOVER.md` §2.2 step 1).
//!
//! The workspace builds with `panic = "abort"`, so a panic cannot be caught
//! and turned into an exit status, and an unwind across the C++ frames
//! would be undefined anyway. What can be done is to make the panic never
//! silent: the hook records the panicking thread's name, the message and
//! the location, writes them to standard error first, directly and with no
//! lock taken, then offers them to the log through a call that never
//! blocks (every log sink is queued, #1069), and returns; the abort
//! follows. The abort's status is distinct from the configuration
//! refusal's 2 and the runtime failure's 1, so a supervisor tells the three
//! apart.

use std::panic::PanicHookInfo;

/// Installs the hook. Called once, first thing in the daemon's entry.
pub fn install() {
    std::panic::set_hook(Box::new(report));
}

/// The one line the hook writes.
fn describe(info: &PanicHookInfo<'_>) -> String {
    let thread = std::thread::current();
    let name = thread.name().unwrap_or("<unnamed>");
    let message = info
        .payload()
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| info.payload().downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "<no message>".to_owned());
    let location = info.location().map_or_else(
        || "<unknown>".to_owned(),
        |l| format!("{}:{}", l.file(), l.line()),
    );
    format!("shekyld: panic in thread '{name}' at {location}: {message}; aborting\n")
}

fn report(info: &PanicHookInfo<'_>) {
    let line = describe(info);
    write_stderr_raw(line.as_bytes());
    // Queued sinks: this call hands the line to a writer thread and returns.
    tracing::error!(target: "daemon", "{}", line.trim_end());
}

/// A write that takes no lock: the panicking thread may hold the standard
/// library's stderr lock.
#[cfg(unix)]
fn write_stderr_raw(bytes: &[u8]) {
    let mut rest = bytes;
    while !rest.is_empty() {
        // SAFETY: `rest` is a live slice; `write(2)` reads at most its
        // length and writes nothing of ours.
        let n = unsafe { libc::write(libc::STDERR_FILENO, rest.as_ptr().cast(), rest.len()) };
        if n <= 0 {
            return;
        }
        let Ok(n) = usize::try_from(n) else { return };
        rest = &rest[n.min(rest.len())..];
    }
}

#[cfg(windows)]
fn write_stderr_raw(bytes: &[u8]) {
    shekyl_win_sec::console::write_stderr_raw(bytes);
}
