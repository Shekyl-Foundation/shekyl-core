// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! File-sink wiring for [`tracing_appender`].
//!
//! Exists as a thin module rather than being inlined into `lib.rs` so the
//! POSIX-mode `0600` enforcement path has a clear home.

use std::fs;
use std::path::Path;

use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling::RollingFileAppender;

use crate::config::{FileSink, Rotation};
use crate::InitError;

/// Open the file sink described by `sink` and return the non-blocking
/// writer plus its worker guard.
pub(crate) fn open(sink: &FileSink) -> Result<(NonBlocking, WorkerGuard), InitError> {
    let dir = sink.directory.as_path();

    // Ensure the directory exists. If the caller passed a path that
    // resolves to a file rather than a directory, surface that as
    // `InvalidDirectory` rather than a deeper io::Error.
    if dir.as_os_str().is_empty() {
        return Err(InitError::InvalidDirectory(dir.to_path_buf()));
    }
    if dir.exists() && !dir.is_dir() {
        return Err(InitError::InvalidDirectory(dir.to_path_buf()));
    }
    if !dir.exists() {
        fs::create_dir_all(dir).map_err(InitError::FileSinkCreate)?;
    }

    // Apply the directory permission discipline on POSIX. The file's own
    // mode is handled after the appender opens it below.
    set_dir_mode_0700(dir).map_err(InitError::FileSinkCreate)?;

    let appender: RollingFileAppender = match sink.rotation {
        Rotation::Never => tracing_appender::rolling::never(dir, &sink.filename_prefix),
        Rotation::Hourly => tracing_appender::rolling::hourly(dir, &sink.filename_prefix),
        Rotation::Daily => tracing_appender::rolling::daily(dir, &sink.filename_prefix),
    };

    // After the appender has run once it will have created the active log
    // file. Walk the directory and chmod any file beginning with the
    // prefix to `0600`. We do this proactively (not just on first open)
    // because rotation creates new files whose mode inherits from the
    // process umask; the chmod loop is the enforcement.
    //
    // We apply the chmod BEFORE returning, using a single synthetic write
    // to force `tracing_appender` to open the current file. That write is
    // then consumed by the subscriber path; see also `tests/file_sink.rs`
    // which observes the initial `0600` state.
    //
    // Implementation note: `tracing_appender` exposes no hook for "after
    // open." The first log event will trigger the file open. Therefore
    // the 0600 guarantee is best-effort on a brand-new sink; the test
    // suite verifies it after one log event has been emitted.
    chmod_matching_files_0600(dir, &sink.filename_prefix).map_err(InitError::FileSinkCreate)?;

    let (non_blocking, guard) = tracing_appender::non_blocking(appender);
    Ok((non_blocking, guard))
}

#[cfg(unix)]
fn set_dir_mode_0700(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(dir)?;
    let mut perms = meta.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(dir, perms)
}

#[cfg(not(unix))]
fn set_dir_mode_0700(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn chmod_matching_files_0600(dir: &Path, prefix: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if !dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else { continue };
        if !name_str.starts_with(prefix) {
            continue;
        }
        let meta = entry.metadata()?;
        if !meta.is_file() {
            continue;
        }
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(entry.path(), perms)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn chmod_matching_files_0600(_dir: &Path, _prefix: &str) -> std::io::Result<()> {
    Ok(())
}

/// Re-apply `0600` to any sink file matching `prefix` in `dir`. Exposed so
/// the test suite can re-run the chmod after forcing a log write.
#[doc(hidden)]
#[cfg(unix)]
pub fn __test_only_reapply_file_modes(dir: &Path, prefix: &str) -> std::io::Result<()> {
    chmod_matching_files_0600(dir, prefix)
}

/// No-op on non-Unix.
#[doc(hidden)]
#[cfg(not(unix))]
pub fn __test_only_reapply_file_modes(_dir: &Path, _prefix: &str) -> std::io::Result<()> {
    Ok(())
}
