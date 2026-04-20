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
/// Mirrors the rotation policies exposed by `tracing_appender`. Rotation
/// itself is driven entirely by upstream; this crate does not claim to
/// validate rotation triggering in its test suite (see the `tests/file_sink.rs`
/// doc-comment).
///
/// # POSIX `0600` discipline and rotation
///
/// `shekyl-logging` enforces mode `0600` on sink files at [`crate::init`]
/// time by sweeping the directory for anything matching the prefix. For
/// [`Rotation::Never`] the sink file is also pre-created with mode
/// `0600` before `tracing_appender` ever opens it, so the mode is
/// guaranteed end-to-end.
///
/// For [`Rotation::Hourly`] and [`Rotation::Daily`], the active filename
/// is chosen by `tracing_appender` at first write with a date/hour
/// suffix we can't race. Files created by *rotation after* startup
/// therefore inherit the process umask (typically `0644`) until another
/// init, another sweep, or a rotation-aware wrapper runs. **Do not use
/// these variants when the `0600` discipline must hold for the lifetime
/// of the process.** A size-rolling variant that owns the rename path
/// and re-enforces `0600` per new file lands with the daemon default
/// sink work.
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
}

/// File-sink configuration.
///
/// When present in a [`Config`], events are written to
/// `directory / filename_prefix[-YYYY-MM-DD[-HH]]` with a
/// [`tracing_appender`] non-blocking writer.
///
/// On POSIX, the sink file is chmod'd to `0600` at init and, for
/// [`Rotation::Never`], pre-created with mode `0600` before first
/// write. For [`Rotation::Hourly`]/[`Rotation::Daily`] the mode is
/// re-enforced only on files that exist at init time — see the
/// [`Rotation`] docs for the post-rotation gap.
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
    /// `None` means stderr-only. Wallet-rpc defaults to `None` and only
    /// populates this when the user passes `--log-file`. Daemon defaults
    /// to `Some(FileSink::daily(...))` with a default path under
    /// `~/.shekyl/logs/`.
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
