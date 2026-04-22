// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Configuration types for [`crate::init`].
//!
//! A [`Config`] bundles a binary's default filter level, optional file
//! sink, and rotation policy. Binaries build one via the helper
//! constructors ([`Config::stderr_only`] and [`Config::with_file_sink`])
//! or by assembling the struct directly.

use std::path::PathBuf;

use tracing::Level;

/// Rotation policy for the file sink.
///
/// Four shapes:
///
/// - [`Rotation::Never`] — no rotation, `0600` held end-to-end. Intended
///   for `--log-file` opt-ins where the operator owns file management.
/// - [`Rotation::Hourly`] / [`Rotation::Daily`] — time-based rotation
///   driven by `tracing_appender` upstream. See the "`0600` caveat"
///   section below.
/// - [`Rotation::Size`] — size-based rotation driven by `shekyl-logging`
///   itself. Preserves the legacy C++ behavior installed by the
///   easylogging++ `MaxLogFileSize` + `installPreRollOutCallback` pair
///   (see `contrib/epee/src/mlog.cpp`). `0600` is re-enforced across
///   every rename and every newly opened live file.
///
/// # POSIX `0600` discipline and rotation
///
/// `shekyl-logging` enforces mode `0600` on sink files at [`crate::init`]
/// time by sweeping the directory for anything matching the prefix. For
/// [`Rotation::Never`] and [`Rotation::Size`] the active file is also
/// pre-created with mode `0600` before any event is written, so the
/// mode is guaranteed end-to-end.
///
/// For [`Rotation::Hourly`] and [`Rotation::Daily`], the active filename
/// is chosen by `tracing_appender` at first write with a date/hour
/// suffix we can't race. Files created by *rotation after* startup
/// therefore inherit the process umask (typically `0644`) until another
/// init, another sweep, or a rotation-aware wrapper runs. **Do not use
/// these variants when the `0600` discipline must hold for the lifetime
/// of the process;** prefer [`Rotation::Size`] (which is the variant
/// the C++ daemon default sink uses) or [`Rotation::Never`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotation {
    /// No automatic rotation. The file grows unboundedly, and
    /// `shekyl-logging` can guarantee mode `0600` on the active file
    /// from first write onward.
    Never,
    /// Rotate every hour. See the variant-group doc comment for the
    /// caveat about mode `0600` on rotation-created files.
    Hourly,
    /// Rotate every day. See the variant-group doc comment for the
    /// caveat about mode `0600` on rotation-created files.
    Daily,
    /// Size-based rotation. When the active file reaches `max_bytes`
    /// the writer closes it, renames it to `{filename_prefix}-{UTC}`
    /// using the `%Y-%m-%d-%H-%M-%S` format (matching the legacy C++
    /// `generate_log_filename`), re-enforces `0600` on the rotated
    /// file, and opens a fresh active file (also `0600`).
    ///
    /// When `max_files > 0`, the rename step is followed by a prune
    /// pass that sorts every prefix-matching file (excluding the live
    /// file itself) by mtime and removes the oldest so that the total
    /// on-disk count — live file plus rotated siblings — does not
    /// exceed `max_files`. Steady state: `max_files` total files
    /// resident in the directory.
    ///
    /// `max_bytes == 0` disables the size check entirely and is
    /// accepted for symmetry with the legacy C++ API; callers that
    /// want "no cap" should prefer [`Rotation::Never`] which is a
    /// cheaper code path.
    Size {
        /// Byte count at which the writer rolls. `0` disables.
        max_bytes: u64,
        /// Maximum total file count (live + rotated). `0` disables
        /// pruning.
        max_files: u32,
    },
}

/// File-sink configuration.
///
/// When present in a [`Config`], events are written to
/// `directory / filename_prefix[-<rotation-suffix>]` with a
/// [`tracing_appender`] non-blocking writer.
///
/// On POSIX, the sink file is chmod'd to `0600` at init and, for
/// [`Rotation::Never`] and [`Rotation::Size`], pre-created with mode
/// `0600` before first write *and* re-enforced on every rotation. For
/// [`Rotation::Hourly`]/[`Rotation::Daily`] the mode is re-enforced
/// only on files that exist at init time — see the [`Rotation`] docs
/// for the post-rotation gap.
#[derive(Debug, Clone)]
pub struct FileSink {
    /// Directory the log file lives in. Created with `0700` perms if
    /// missing.
    pub directory: PathBuf,
    /// Filename prefix (rotation appends a date/hour suffix when enabled).
    pub filename_prefix: String,
    /// Rotation policy.
    pub rotation: Rotation,
}

impl FileSink {
    /// A file sink rotated daily.
    ///
    /// `tracing_appender` opens files under `directory/` with names of the
    /// form `filename_prefix.YYYY-MM-DD` (UTC). The `filename_prefix`
    /// argument is therefore a stem, not a full filename — callers that
    /// want the active file to end in `.log` should pass
    /// `filename_prefix = "something.log"` and accept the resulting
    /// `something.log.YYYY-MM-DD` on-disk filename.
    ///
    /// **Mode `0600` caveat.** See [`Rotation::Daily`]: files created by
    /// post-startup rotation inherit the process umask and are not
    /// re-chmod'd by this crate yet. Use [`FileSink::unrotated`] if the
    /// `0600` discipline must hold for the process lifetime.
    pub fn daily(directory: impl Into<PathBuf>, filename_prefix: impl Into<String>) -> Self {
        Self {
            directory: directory.into(),
            filename_prefix: filename_prefix.into(),
            rotation: Rotation::Daily,
        }
    }

    /// A file sink with no rotation. Intended for explicit `--log-file`
    /// opt-ins where the user owns file management.
    pub fn unrotated(directory: impl Into<PathBuf>, filename_prefix: impl Into<String>) -> Self {
        Self {
            directory: directory.into(),
            filename_prefix: filename_prefix.into(),
            rotation: Rotation::Never,
        }
    }

    /// A file sink with size-based rotation. Intended for the C++
    /// daemon default (100 MB per file, 50 files total) and other
    /// long-running binaries where the operator wants bounded
    /// on-disk footprint.
    ///
    /// Rotation semantics mirror the legacy easylogging++ behavior:
    /// when the active file reaches `max_bytes`, it is renamed to
    /// `{filename_prefix}-{UTC %Y-%m-%d-%H-%M-%S}`, the sibling-count
    /// is capped at `max_files - 1`, and a fresh active file is
    /// opened at `{filename_prefix}`. See [`Rotation::Size`] for the
    /// full contract.
    pub fn size_rolling(
        directory: impl Into<PathBuf>,
        filename_prefix: impl Into<String>,
        max_bytes: u64,
        max_files: u32,
    ) -> Self {
        Self {
            directory: directory.into(),
            filename_prefix: filename_prefix.into(),
            rotation: Rotation::Size {
                max_bytes,
                max_files,
            },
        }
    }
}

/// Top-level logging configuration passed to [`crate::init`].
///
/// See [`Config::stderr_only`] and [`Config::with_file_sink`] for the two
/// common shapes.
#[derive(Debug, Clone)]
pub struct Config {
    /// Filter level applied when no `SHEKYL_LOG` env var is set.
    ///
    /// Passed through to the legacy translator's `fallback_default`
    /// argument so that unset `SHEKYL_LOG` at startup produces an explicit
    /// bare-level directive instead of the "empty directive => no filter"
    /// landmine described in the crate README.
    pub fallback_default: Level,

    /// Optional file sink.
    ///
    /// `None` means stderr-only. This struct is consumed by the Rust
    /// binary crates that call [`crate::init`] directly:
    ///
    /// * `shekyl-cli` — always `None` (stderr-only).
    /// * `shekyl-wallet-rpc` (Rust variant) — `None` by default;
    ///   populated with `Some(FileSink::unrotated(...))` when the user
    ///   passes `--log-file <path>`. See
    ///   `rust/shekyl-wallet-rpc/src/main.rs` for the exact mapping.
    ///
    /// The C++ daemon (`shekyld`) does **not** consume this struct. It
    /// routes through the raw FFI entry point `shekyl_log_init_file`
    /// (see `rust/shekyl-logging/src/ffi.rs`), which constructs a
    /// [`FileSink::size_rolling`] sink from the `MAX_LOG_FILE_SIZE` /
    /// `MAX_LOG_FILES` constants in `contrib/epee/include/misc_log_ex.h`
    /// — not a [`FileSink::daily`]. Integrators mirroring the daemon's
    /// defaults should therefore construct
    /// `FileSink::size_rolling(directory, filename_prefix, max_bytes,
    /// max_files)` with a directory under `~/.shekyl/logs/` rather than
    /// reaching for `FileSink::daily`.
    pub file_sink: Option<FileSink>,
}

impl Config {
    /// stderr-only, no file sink.
    ///
    /// Correct for CLI tools and for wallet-rpc in its
    /// "no `--log-file` passed" default state.
    pub fn stderr_only(fallback_default: Level) -> Self {
        Self {
            fallback_default,
            file_sink: None,
        }
    }

    /// stderr + rotating file sink.
    ///
    /// Correct for daemons whose default is a file on disk. Callers that
    /// want to honor a user-provided path pass the directory explicitly.
    pub fn with_file_sink(fallback_default: Level, file_sink: FileSink) -> Self {
        Self {
            fallback_default,
            file_sink: Some(file_sink),
        }
    }
}

impl Default for Config {
    /// Safe default: `INFO`, stderr-only. Chosen so that a caller that
    /// forgets to pass a config still gets a usable logger.
    fn default() -> Self {
        Self::stderr_only(Level::INFO)
    }
}
