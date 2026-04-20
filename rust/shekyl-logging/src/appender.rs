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
    // Only apply the `0700` directory discipline to directories this code
    // path creates. Chmod'ing an operator-managed directory that happened
    // to already exist is dangerous: `--log-file /tmp/wallet.log` would
    // otherwise try to chmod `/tmp` to `0700`, which either fails with
    // `EPERM` (breaking startup) or, if the binary happens to run
    // privileged, restricts every other process using `/tmp`.
    let created_dir = if dir.exists() {
        false
    } else {
        fs::create_dir_all(dir).map_err(InitError::FileSinkCreate)?;
        true
    };
    if created_dir {
        set_dir_mode_0700(dir).map_err(InitError::FileSinkCreate)?;
    }

    // For `Rotation::Never` we know the exact filename the appender will
    // open (`dir/filename_prefix`), so pre-create it with `0600` before
    // `tracing_appender` opens it in append mode. This closes the
    // brand-new-sink race where the first emitted event would otherwise
    // land in a file whose mode was set by the process umask.
    //
    // For rotating policies the filename carries a date/hour suffix
    // chosen by `tracing_appender` at first write; we can't race it to
    // the exact path. The `chmod_matching_files_0600` sweep below keeps
    // us honest for files that already exist at init time and for
    // subsequent test reapplications via `__test_only_reapply_file_modes`.
    // A future size-rolling appender (Chore #2) will re-enforce `0600`
    // as part of its rename/prune pass.
    if matches!(sink.rotation, Rotation::Never) {
        precreate_file_mode_0600(&dir.join(&sink.filename_prefix))
            .map_err(InitError::FileSinkCreate)?;
    }

    let appender: RollingFileAppender = match sink.rotation {
        Rotation::Never => tracing_appender::rolling::never(dir, &sink.filename_prefix),
        Rotation::Hourly => tracing_appender::rolling::hourly(dir, &sink.filename_prefix),
        Rotation::Daily => tracing_appender::rolling::daily(dir, &sink.filename_prefix),
    };

    // Sweep any existing sink files to `0600` so a reopen against files
    // left behind by a prior run normalizes their mode.
    chmod_matching_files_0600(dir, &sink.filename_prefix).map_err(InitError::FileSinkCreate)?;

    let (non_blocking, guard) = tracing_appender::non_blocking(appender);
    Ok((non_blocking, guard))
}

#[cfg(unix)]
fn precreate_file_mode_0600(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    // `create(true)` + `append(true)` is idempotent: existing files are
    // opened without truncation. `.mode(0o600)` applies only on creation;
    // for the existing-file path we `set_permissions` explicitly below.
    let _file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn precreate_file_mode_0600(path: &Path) -> std::io::Result<()> {
    let _file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    Ok(())
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
