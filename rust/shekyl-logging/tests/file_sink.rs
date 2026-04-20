// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! File-sink emit + flush round-trip, `LoggerGuard` drop semantics, and
//! POSIX-mode `0600` assertions.
//!
//! Consolidated into a single test because `init` installs a
//! process-global subscriber and integration tests in the same file
//! share one process; running two separate `init`-calling tests in this
//! file would race against `AlreadyInitialized` on the second call.
//!
//! Explicitly NOT covered:
//!
//! - Rotation triggering. `tracing_appender`'s `RollingFileAppender`
//!   uses internals we can't cleanly drive from outside; tests that
//!   force a rotation are flaky and re-implement upstream
//!   implementation details.
//!
//! The `0600` assertion calls `libc::umask(0)` on entry so an unusual
//! login-shell umask does not mask the permission bits we're checking.
//! Gated on `#[cfg(unix)]` because `0600` has no meaning on Windows.

use std::fs;
use std::path::PathBuf;

use shekyl_logging::{init, Config, FileSink};
use tracing::Level;

#[cfg(unix)]
#[test]
fn emit_flush_and_mode_0600_roundtrip() {
    use std::os::unix::fs::PermissionsExt;

    // Normalize umask so the mode we observe is the one we set.
    // SAFETY: single integration-test process; no sibling threads care.
    let saved_umask = unsafe { libc::umask(0) };

    let dir = {
        let d = tempfile::tempdir().expect("tmpdir");
        let path = d.path().to_path_buf();
        std::mem::forget(d);
        path
    };
    let prefix = "rust-shekyl-logging-filesink.log";

    // Make sure no ambient SHEKYL_LOG escalates the level past our
    // emitted ERROR.
    // SAFETY: integration tests run one file per process.
    unsafe { std::env::remove_var(shekyl_logging::SHEKYL_LOG_ENV) };

    let cfg = Config::with_file_sink(Level::TRACE, FileSink::unrotated(&dir, prefix));

    {
        let _guard = init(cfg).expect("init");
        tracing::error!(target: "shekyl_logging_test", "hello from the file sink");
        // _guard drops here; background writer flushes to disk.
    }

    let file_path: PathBuf = dir.join(prefix);
    let mut content = String::new();
    for _ in 0..50 {
        if let Ok(c) = fs::read_to_string(&file_path) {
            if !c.is_empty() {
                content = c;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    assert!(
        content.contains("hello from the file sink"),
        "sink file did not contain the emitted event; got: {content:?}",
    );

    // Re-apply the 0600 chmod after the write lands. The appender may
    // have opened the file after our first walk; this ensures we are
    // asserting on the steady state.
    shekyl_logging::__test_only_reapply_file_modes(&dir, prefix)
        .expect("reapply modes");

    let meta = fs::metadata(&file_path).expect("file metadata");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");

    unsafe { libc::umask(saved_umask) };
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(not(unix))]
#[test]
fn emit_flush_roundtrip_writes_event_to_disk_nonunix() {
    // On non-Unix we still want to verify that the guard-drop flushes
    // events to disk. We just don't assert on file mode.
    let dir = {
        let d = tempfile::tempdir().expect("tmpdir");
        let path = d.path().to_path_buf();
        std::mem::forget(d);
        path
    };
    let prefix = "rust-shekyl-logging-filesink-nonunix.log";

    let cfg = Config::with_file_sink(Level::TRACE, FileSink::unrotated(&dir, prefix));
    {
        let _guard = init(cfg).expect("init");
        tracing::error!(target: "shekyl_logging_test", "hello from the file sink");
    }

    let file_path: PathBuf = dir.join(prefix);
    let mut content = String::new();
    for _ in 0..50 {
        if let Ok(c) = fs::read_to_string(&file_path) {
            if !c.is_empty() {
                content = c;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    assert!(
        content.contains("hello from the file sink"),
        "sink file did not contain the emitted event; got: {content:?}",
    );
    let _ = fs::remove_dir_all(&dir);
}
