// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! File-sink wiring for [`tracing_appender`].
//!
//! Exists as a thin module rather than being inlined into `lib.rs` so the
//! POSIX-mode `0600` enforcement path and the custom [`SizeRollingWriter`]
//! (the C++ daemon's size-based rotation replacement) have a clear home.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};

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

    // For `Rotation::Never` and `Rotation::Size` we know the exact
    // filename the writer will open (`dir/filename_prefix`), so
    // pre-create it with `0600` before first write. This closes the
    // brand-new-sink race where the first emitted event would
    // otherwise land in a file whose mode was set by the process
    // umask.
    //
    // For `Rotation::Hourly` / `Rotation::Daily` the filename carries
    // a date/hour suffix chosen by `tracing_appender` at first write;
    // we can't race it to the exact path. The
    // `chmod_matching_files_0600` sweep below keeps us honest for
    // files that already exist at init time.
    if matches!(sink.rotation, Rotation::Never | Rotation::Size { .. }) {
        precreate_file_mode_0600(&dir.join(&sink.filename_prefix))
            .map_err(InitError::FileSinkCreate)?;
    }

    // Normalize permissions on any sink files left behind by a prior
    // run. The sweep is gated on the rotation policy:
    //
    // - `Rotation::Never` uses a fixed, exact filename that was
    //   pre-created at `0600` above. A prefix sweep would incorrectly
    //   chmod unrelated siblings (e.g. `shekyld.log.old`).
    // - `Rotation::Size` also uses a fixed, exact live filename; its
    //   rotated siblings are named `{prefix}-{UTC}` and the writer
    //   enforces `0600` on them per-rotation, so an init-time sweep
    //   is redundant and risks the same unrelated-sibling issue.
    // - `Rotation::Hourly` / `Rotation::Daily` need the prefix sweep
    //   because `tracing_appender` appends a runtime-generated suffix
    //   to the active filename.
    match sink.rotation {
        Rotation::Never | Rotation::Size { .. } => {}
        Rotation::Hourly | Rotation::Daily => {
            chmod_matching_files_0600(dir, &sink.filename_prefix)
                .map_err(InitError::FileSinkCreate)?;
        }
    }

    let (non_blocking, guard) = match sink.rotation {
        Rotation::Never => {
            let appender = tracing_appender::rolling::never(dir, &sink.filename_prefix);
            tracing_appender::non_blocking(appender)
        }
        Rotation::Hourly => {
            let appender = tracing_appender::rolling::hourly(dir, &sink.filename_prefix);
            tracing_appender::non_blocking(appender)
        }
        Rotation::Daily => {
            let appender = tracing_appender::rolling::daily(dir, &sink.filename_prefix);
            tracing_appender::non_blocking(appender)
        }
        Rotation::Size {
            max_bytes,
            max_files,
        } => {
            let writer = SizeRollingWriter::new(dir, &sink.filename_prefix, max_bytes, max_files)
                .map_err(InitError::FileSinkCreate)?;
            tracing_appender::non_blocking(writer)
        }
    };
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
        // Skip symlinks (and anything else that isn't a regular file).
        //
        // `DirEntry::file_type()` does *not* follow symlinks — it returns
        // the type of the entry itself. That matters because
        // `fs::set_permissions(path, …)` on a symlink on Linux follows
        // the link and chmods the *target*. If the log directory is
        // writable by more than one principal (e.g. an operator points
        // `--log-file` at a shared `/tmp/shekyl.log` and runs elevated,
        // or a daemon shares its log dir with a less-privileged user),
        // an attacker who can create a prefix-matching symlink inside
        // that directory — `shekyld.log.evil` → `/etc/ssh/sshd_config`,
        // say — would trick us into clobbering the target's mode to
        // `0600`. Skipping non-regular entries here closes the direct
        // symlink vector. A fuller defense (`openat` + `O_NOFOLLOW` +
        // `fchmod`) isn't available in stable `std::fs`; the
        // `DirEntry::metadata()` call below is still scoped to entries
        // we just verified are regular files, so the TOCTOU window
        // between that check and `set_permissions` shrinks to a
        // regular-file → regular-file swap, which isn't the planted-
        // symlink attack we're closing here.
        let file_type = entry.file_type()?;
        if !file_type.is_file() {
            continue;
        }
        let meta = entry.metadata()?;
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

/// Size-based rolling writer.
///
/// Replaces the legacy easylogging++ `MaxLogFileSize` +
/// `installPreRollOutCallback` pair from `contrib/epee/src/mlog.cpp`.
/// Unlike `tracing_appender`'s upstream `RollingFileAppender` — which
/// only supports time-based policies (hourly/daily/never) — this writer
/// owns the rename path itself, so the `0600` POSIX discipline holds
/// across every rotation.
///
/// ## Wire behavior
///
/// 1. `new()` opens (or creates) `dir/prefix` at mode `0600`. Existing
///    files are opened in append mode so a restart doesn't clobber
///    prior content; their mode is re-enforced to `0600`. The initial
///    `bytes_written` is primed from the on-disk size so a restart
///    against a near-full file rolls on the next write rather than
///    waiting for a full `max_bytes` of fresh content.
/// 2. Every `write` increments the byte counter. When the counter
///    reaches `max_bytes` (and `max_bytes > 0`), a rollover is
///    attempted best-effort:
///    a. `flush()` on the live file.
///    b. `rename` live → `{prefix}-{UTC %Y-%m-%d-%H-%M-%S}` in the
///    same directory. This format matches `generate_log_filename`
///    in `contrib/epee/src/mlog.cpp`.
///    c. Re-enforce `0600` on the rotated file (the legacy C++ only
///    relied on the live file's mode carrying across rename, which
///    is implementation-defined across kernels).
///    d. Reopen a fresh live file at the original path, also `0600`.
///    e. If `max_files > 0`, run `prune_oldest` so the total count
///    (live + rotated) never exceeds `max_files` — matching the
///    steady-state disk footprint the C++ daemon targets today.
/// 3. If any rollover step fails *after* the rename, subsequent writes
///    continue landing on the renamed inode (Unix semantics). The
///    byte counter is not reset until the new live file is open, so
///    the next write attempts a rollover again; the writer recovers
///    as soon as the underlying issue clears. If the rename itself
///    fails, the live file is untouched and writes keep going there.
///
/// ## Collision handling
///
/// When two rotations land in the same UTC second (a small
/// `max_bytes` + high-throughput log can do this), the naive legacy
/// rename would silently clobber the earlier rotation. We disambiguate
/// with a `.N` counter suffix — the rotated name stays
/// `{prefix}-{UTC}` as long as it's unique, falling back to
/// `{prefix}-{UTC}.1`, `.2`, … as needed.
///
/// ## `Send + 'static`
///
/// `tracing_appender::non_blocking` moves the writer onto a dedicated
/// worker thread and serializes all access through an mpsc channel.
/// Only the worker ever calls `write`/`flush`, so no `Mutex` is
/// required around the file handle.
struct SizeRollingWriter {
    file: File,
    dir: PathBuf,
    prefix: String,
    bytes_written: u64,
    max_bytes: u64,
    max_files: u32,
}

impl SizeRollingWriter {
    fn new(dir: &Path, prefix: &str, max_bytes: u64, max_files: u32) -> io::Result<Self> {
        let path = dir.join(prefix);
        let file = open_with_0600_append(&path)?;
        let bytes_written = file.metadata()?.len();
        Ok(Self {
            file,
            dir: dir.to_path_buf(),
            prefix: prefix.to_owned(),
            bytes_written,
            max_bytes,
            max_files,
        })
    }

    fn rollover(&mut self) -> io::Result<()> {
        self.file.flush()?;

        let live = self.dir.join(&self.prefix);
        let suffix = utc_rotation_suffix();
        let rotated = pick_nonexistent_rotated_path(&self.dir, &self.prefix, &suffix)?;

        fs::rename(&live, &rotated)?;

        // From here, `self.file` still points at the renamed inode on
        // Unix (write-while-renamed is fine). If the following steps
        // fail, writes keep landing on the rotated file until the next
        // rollover attempt succeeds; we deliberately don't try to
        // "unrename" because that would race a concurrent reader.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&rotated, fs::Permissions::from_mode(0o600))?;
        }

        let new_live = open_with_0600_append(&live)?;
        self.file = new_live;
        self.bytes_written = 0;

        if self.max_files > 0 {
            // Prune is best-effort; a filesystem error during the
            // walk shouldn't brick subsequent writes. The legacy C++
            // swallows per-file errors (see `mlog.cpp` lines 215-223).
            // `drop(...)` instead of `let _ = ...;` so the
            // `clippy::let_underscore_must_use` lint (secondary
            // defense for `LoggerGuard` drop hygiene) keeps firing
            // on unintentional ignores elsewhere in the crate.
            drop(self.prune_oldest());
        }
        Ok(())
    }

    /// Prune prefix-matching siblings so the total on-disk count
    /// (live file + rotated files) stays at or below `self.max_files`.
    ///
    /// The live file is always retained. Everything else matching the
    /// prefix and surviving the symlink filter is sorted by mtime
    /// ascending and the oldest are deleted until the invariant holds.
    fn prune_oldest(&self) -> io::Result<()> {
        if self.max_files == 0 {
            return Ok(());
        }
        let mut rotated: Vec<(PathBuf, std::time::SystemTime)> = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else { continue };
            // Rotated files all start with `{prefix}-`. Using the
            // exact `{prefix}-` separator instead of a bare
            // `starts_with(prefix)` avoids matching the live file
            // itself (`name == prefix`, no dash) and also avoids
            // pulling in unrelated siblings like `{prefix}rotate.conf`.
            let Some(rest) = name_str.strip_prefix(&self.prefix) else {
                continue;
            };
            if !rest.starts_with('-') {
                continue;
            }
            // Apply the same symlink-safety we use in
            // `chmod_matching_files_0600`: an attacker who can plant a
            // prefix-matching symlink in a shared log dir must not be
            // able to trick us into deleting the link's target.
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                continue;
            }
            let mtime = entry.metadata()?.modified()?;
            rotated.push((entry.path(), mtime));
        }

        // Target: total on-disk count (live + rotated) <= max_files.
        // The live file is always retained, so the rotated slice must
        // fit within `max_files - 1`. `saturating_sub(1)` pins
        // `max_files == 1` to "0 rotated allowed" (keep live only),
        // which matches the legacy C++ behavior where
        // `found_files.size() >= max_log_files` with `max_log_files ==
        // 1` deletes every rotated sibling.
        let cap = self.max_files.saturating_sub(1) as usize;
        if rotated.len() > cap {
            rotated.sort_by_key(|(_, t)| *t);
            let to_delete = rotated.len() - cap;
            for (path, _) in rotated.iter().take(to_delete) {
                // Per-file remove errors are swallowed to match
                // `mlog.cpp`'s loop, which logs-then-continues on
                // `boost::filesystem::remove` failure. `drop(...)`
                // instead of `let _ = ...;` keeps the
                // `clippy::let_underscore_must_use` lint's signal
                // intact crate-wide.
                drop(fs::remove_file(path));
            }
        }
        Ok(())
    }
}

impl Write for SizeRollingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.file.write(buf)?;
        self.bytes_written += n as u64;
        if self.max_bytes > 0 && self.bytes_written >= self.max_bytes {
            // Rollover errors are swallowed — matching `mlog.cpp`'s
            // `installPreRollOutCallback` (which returns void and
            // explicitly comments "can't log a failure"). If the
            // rollover actually failed, `bytes_written` is still at
            // or above the threshold, so the next write triggers
            // another attempt; the writer recovers on its own.
            // `drop(...)` instead of `let _ = ...;` preserves the
            // `clippy::let_underscore_must_use` lint's signal.
            drop(self.rollover());
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// Open `path` for appending, creating it at mode `0600` and
/// re-enforcing `0600` if the file already existed.
fn open_with_0600_append(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// Produce a UTC `%Y-%m-%d-%H-%M-%S` suffix matching the legacy C++
/// `generate_log_filename` format.
fn utc_rotation_suffix() -> String {
    use time::format_description::FormatItem;
    use time::macros::format_description;
    use time::OffsetDateTime;

    const FMT: &[FormatItem<'static>] =
        format_description!("[year]-[month]-[day]-[hour]-[minute]-[second]");
    // `now_utc()` is infallible on modern systems; `format` only
    // errors on a malformed description, which is compile-time
    // enforced by `format_description!`.
    OffsetDateTime::now_utc()
        .format(FMT)
        .unwrap_or_else(|_| String::from("unknown-time"))
}

/// Return a rotated path that doesn't already exist in `dir`.
///
/// The legacy C++ rename would silently clobber an earlier rotation
/// when two rollovers landed in the same UTC second. We append a `.N`
/// disambiguator instead. Bounded to 1024 attempts so a pathological
/// state can't spin forever.
fn pick_nonexistent_rotated_path(
    dir: &Path,
    prefix: &str,
    suffix: &str,
) -> io::Result<PathBuf> {
    let base = dir.join(format!("{prefix}-{suffix}"));
    if !base.exists() {
        return Ok(base);
    }
    for n in 1..=1024_u32 {
        let candidate = dir.join(format!("{prefix}-{suffix}.{n}"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "too many rotation collisions in one second; refusing to rename",
    ))
}

#[cfg(test)]
mod size_rolling_tests {
    //! Unit tests for the size-based rolling writer.
    //!
    //! These exercise `SizeRollingWriter` directly rather than going
    //! through `crate::init`, because each integration-test binary
    //! installs a process-global `tracing` subscriber and we need
    //! multiple independent scenarios (overflow, prune, restart,
    //! collision) without tripping `AlreadyInitialized`.

    use super::*;

    /// Helper: count files in `dir` whose name starts with `prefix`.
    /// Includes the live file (`name == prefix`) and all rotated
    /// siblings (`name.starts_with("{prefix}-")`). Skips non-regular
    /// files and non-UTF-8 names — matching the production code's
    /// filters.
    fn count_prefix_files(dir: &Path, prefix: &str) -> usize {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                let Some(name) = e.file_name().to_str().map(str::to_owned) else {
                    return false;
                };
                if name != prefix && !name.starts_with(&format!("{prefix}-")) {
                    return false;
                }
                e.file_type().map(|t| t.is_file()).unwrap_or(false)
            })
            .count()
    }

    #[test]
    fn write_under_max_bytes_does_not_rotate() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let prefix = "under.log";

        let mut writer =
            SizeRollingWriter::new(dir.path(), prefix, 1024, 10).expect("construct writer");
        writer.write_all(b"just a little").expect("write");
        writer.flush().expect("flush");

        assert_eq!(
            count_prefix_files(dir.path(), prefix),
            1,
            "sub-threshold write must not produce a rotated sibling"
        );
    }

    #[test]
    fn overflow_triggers_rename_and_fresh_live_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let prefix = "rolls.log";

        // max_bytes = 16 so the first 32-byte write trips the
        // threshold immediately and rolls.
        let mut writer =
            SizeRollingWriter::new(dir.path(), prefix, 16, 10).expect("construct writer");
        writer
            .write_all(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .expect("first write");
        // After the first write, bytes_written >= max_bytes triggers
        // rollover *inside* the same write call. The second write
        // should land in the fresh live file.
        writer.write_all(b"B").expect("second write");
        writer.flush().expect("flush");

        let live = dir.path().join(prefix);
        assert!(live.exists(), "live file must exist after rollover");

        // One live + one rotated = 2 files total.
        assert_eq!(
            count_prefix_files(dir.path(), prefix),
            2,
            "expected live + exactly one rotated sibling",
        );

        // The rotated file should carry the A's; the fresh live file
        // should hold only the B.
        let live_content = fs::read(&live).expect("read live");
        assert_eq!(
            live_content, b"B",
            "fresh live file must only contain post-rollover bytes, got {live_content:?}",
        );
    }

    #[cfg(unix)]
    #[test]
    fn rotated_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        // Normalize umask so the observed mode is what we set, not
        // what the test runner's shell happens to mask.
        // SAFETY: unit tests run serially within this module's
        // #[test] harness; no sibling threads mutate the process
        // umask.
        let saved_umask = unsafe { libc::umask(0) };
        struct UmaskRestore(libc::mode_t);
        impl Drop for UmaskRestore {
            fn drop(&mut self) {
                unsafe { libc::umask(self.0) };
            }
        }
        let _restore = UmaskRestore(saved_umask);

        let dir = tempfile::tempdir().expect("tmpdir");
        let prefix = "perms.log";

        let mut writer =
            SizeRollingWriter::new(dir.path(), prefix, 8, 10).expect("construct writer");
        writer.write_all(b"overflow!!").expect("first write");
        writer.write_all(b"post").expect("second write");
        writer.flush().expect("flush");

        // Live file must be 0600.
        let live = dir.path().join(prefix);
        let live_mode = fs::metadata(&live).unwrap().permissions().mode() & 0o777;
        assert_eq!(live_mode, 0o600, "live file mode must be 0600, got {live_mode:o}");

        // Rotated sibling must be 0600.
        let rotated = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .find(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n != prefix && n.starts_with(&format!("{prefix}-")))
                    .unwrap_or(false)
            })
            .expect("one rotated sibling");
        let rotated_mode = rotated.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(
            rotated_mode, 0o600,
            "rotated file mode must be 0600, got {rotated_mode:o}"
        );
    }

    #[test]
    fn prune_keeps_total_within_max_files() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let prefix = "prune.log";

        // max_bytes = 4 so every write rolls. max_files = 3 means the
        // steady-state disk footprint is 3 total (1 live + 2 rotated).
        let mut writer =
            SizeRollingWriter::new(dir.path(), prefix, 4, 3).expect("construct writer");

        // Drive enough rollovers to exceed the cap. We emit 8 >4-byte
        // writes in sequence. Between writes we sleep 1.1 seconds to
        // make the rotation suffix (%Y-%m-%d-%H-%M-%S, 1-second
        // resolution) unique — otherwise the collision fallback
        // (`.N` counter) still works correctly, but mtimes can tie
        // and make the "oldest first" assertion brittle on some
        // filesystems. Two sleep+write pairs are enough to exercise
        // the prune path; the total runtime stays under a couple
        // seconds.
        for i in 0..6 {
            writer.write_all(format!("roll{i}AAAA").as_bytes()).expect("write");
            writer.flush().expect("flush");
            std::thread::sleep(std::time::Duration::from_millis(1100));
        }

        let total = count_prefix_files(dir.path(), prefix);
        assert!(
            total <= 3,
            "prune must cap total on-disk count at max_files=3; got {total}"
        );
        assert!(
            dir.path().join(prefix).exists(),
            "live file must be retained across prune pass"
        );
    }

    #[test]
    fn restart_reopens_existing_file_without_truncating() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let prefix = "restart.log";

        // First "session": write 10 bytes into a writer with a 1-MB
        // cap. No rollover happens; the file ends with 10 bytes.
        {
            let mut w = SizeRollingWriter::new(dir.path(), prefix, 1024 * 1024, 0)
                .expect("first open");
            w.write_all(b"session-01").expect("write");
            w.flush().expect("flush");
            drop(w);
        }

        // Second "session": a fresh writer opens the same path. The
        // initial `bytes_written` must be primed from the on-disk
        // size so the next write doesn't silently reset the counter
        // and overshoot `max_bytes`.
        {
            let mut w = SizeRollingWriter::new(dir.path(), prefix, 1024 * 1024, 0)
                .expect("second open");
            w.write_all(b"-02").expect("write");
            w.flush().expect("flush");
            drop(w);
        }

        let content = fs::read(dir.path().join(prefix)).expect("read");
        assert_eq!(
            content, b"session-01-02",
            "restart must append, not truncate; got {content:?}"
        );
    }

    #[test]
    fn max_files_zero_disables_prune() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let prefix = "noprune.log";

        let mut writer =
            SizeRollingWriter::new(dir.path(), prefix, 4, 0).expect("construct writer");
        for i in 0..5 {
            writer.write_all(format!("roll{i}").as_bytes()).expect("write");
            writer.flush().expect("flush");
            // Sleep so each rotation lands in a distinct UTC second
            // and the rename collision path isn't exercised.
            std::thread::sleep(std::time::Duration::from_millis(1100));
        }

        // With max_files = 0, nothing is pruned. We expect at least
        // 2 rotated siblings + 1 live = 3+ files.
        let total = count_prefix_files(dir.path(), prefix);
        assert!(
            total >= 3,
            "max_files=0 must disable prune entirely; got only {total} files"
        );
    }

    #[test]
    fn same_second_rollovers_use_dot_counter_fallback() {
        // Two rollovers inside the same second must not clobber each
        // other. The second rollover's rename target gets disambiguated
        // with a `.1` suffix by `pick_nonexistent_rotated_path`.
        let dir = tempfile::tempdir().expect("tmpdir");
        let prefix = "clash.log";

        let mut writer =
            SizeRollingWriter::new(dir.path(), prefix, 4, 0).expect("construct writer");
        // Two overflow writes back-to-back. Total elapsed time is a
        // handful of microseconds, well within one UTC second on
        // every supported runner.
        writer.write_all(b"firstA").expect("first roll");
        writer.write_all(b"secondB").expect("second roll");
        writer.flush().expect("flush");

        // Expect 3 files: live + 2 rotated siblings. The collision
        // path guarantees distinct rotated filenames even at 1-second
        // suffix resolution.
        let total = count_prefix_files(dir.path(), prefix);
        assert_eq!(
            total, 3,
            "same-second rollovers must produce 2 distinct rotated siblings, got {total} total"
        );
    }
}
