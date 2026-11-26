// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Configuration types for [`crate::init`].
//!
//! A [`Config`] bundles a binary's filter, optional file sink, and rotation
//! policy. Binaries build one via the helper
//! constructors ([`Config::stderr_only`] and [`Config::with_file_sink`])
//! or by assembling the struct directly.

use std::path::PathBuf;

use tracing::Level;

use crate::filter::Directive;

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
///   itself. `0600` is re-enforced across every rename and every newly
///   opened live file.
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
/// of the process;** prefer [`Rotation::Size`] (the daemon's sink,
/// through [`FileSink::within_budget`]) or [`Rotation::Never`].
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
    /// using the `%Y-%m-%d-%H-%M-%S` format, re-enforces `0600` on the
    /// rotated file, and opens a fresh active file (also `0600`).
    ///
    /// When `max_files > 0`, the rename step is followed by a prune
    /// pass that sorts every prefix-matching file (excluding the live
    /// file itself) by mtime and removes the oldest so that the total
    /// on-disk count — live file plus rotated siblings — does not
    /// exceed `max_files`. Steady state: `max_files` total files
    /// resident in the directory.
    ///
    /// `max_bytes == 0` disables the size check entirely; callers that
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
    /// Bytes the live file and its archives may occupy together.
    ///
    /// Set by [`FileSink::within_budget`]. [`FileSink::size_rolling`],
    /// [`FileSink::daily`] and [`FileSink::unrotated`] leave this `None`,
    /// so their rotation stays a file count.
    pub retained_bytes: Option<u64>,
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
            retained_bytes: None,
        }
    }

    /// A file sink with no rotation. Intended for explicit `--log-file`
    /// opt-ins where the user owns file management.
    pub fn unrotated(directory: impl Into<PathBuf>, filename_prefix: impl Into<String>) -> Self {
        Self {
            directory: directory.into(),
            filename_prefix: filename_prefix.into(),
            rotation: Rotation::Never,
            retained_bytes: None,
        }
    }

    /// A file sink with size-based rotation, for long-running binaries
    /// where the operator wants a bounded on-disk footprint
    /// ([`Self::within_budget`] builds the daemon's).
    ///
    /// When the active file reaches `max_bytes`, it is renamed to
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
            retained_bytes: None,
        }
    }
}

/// Top-level logging configuration passed to [`crate::init`].
///
/// See [`Config::stderr_only`] and [`Config::with_file_sink`] for the two
/// common shapes.
#[derive(Debug, Clone)]
pub struct Config {
    /// The filter. It comes from the binary's configuration and never from
    /// the environment (`INPUT_GRAMMAR.md` IG-13). It is a [`Directive`], so
    /// a retired target was refused when it was parsed.
    pub directive: Directive,

    /// Optional file sink; `None` is stderr only. Every binary builds it
    /// from its `log-file` and `log-size-max` rows with
    /// [`FileSink::within_budget`], so the live file and its archives share
    /// one byte budget. `shekyld` and `shekyl-rpc-tunnel` default to a file;
    /// `shekyl-cli` and `shekyl-wallet-rpc` write one only when `log-file`
    /// names it, so nothing about wallet activity lands on disk unasked.
    pub file_sink: Option<FileSink>,
}

impl Config {
    /// stderr only, every target at `level`.
    pub fn stderr_only(level: Level) -> Self {
        Self {
            directive: Directive::level(level),
            file_sink: None,
        }
    }

    /// The same configuration with an explicit filter directive, built by
    /// [`crate::subsystem::directive`] or its words form.
    #[must_use]
    pub fn with_directive(mut self, directive: Directive) -> Self {
        self.directive = directive;
        self
    }

    /// stderr and a file sink, every target at `level`.
    pub fn with_file_sink(level: Level, file_sink: FileSink) -> Self {
        Self {
            directive: Directive::level(level),
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

/// The split of one disk budget into a rotation (`log-size-max`, IG-Q19:
/// the budget is the operator's, the rotation inside it is this crate's).
pub const FILES_WITHIN_BUDGET: u32 = 8;

impl FileSink {
    /// A size-rolling sink whose live file and archives together stay
    /// within `budget_bytes`. The rotation is [`FILES_WITHIN_BUDGET`]
    /// files of an equal share; the share floors at one byte. The byte
    /// budget is [`Self::retained_bytes`], so a record larger than its
    /// share is pruned back to the budget. [`Self::size_rolling`] does
    /// not set that budget: its cap stays a file count.
    pub fn within_budget(
        directory: impl Into<PathBuf>,
        filename_prefix: impl Into<String>,
        budget_bytes: u64,
    ) -> Self {
        let share = (budget_bytes / u64::from(FILES_WITHIN_BUDGET)).max(1);
        let mut sink = Self::size_rolling(directory, filename_prefix, share, FILES_WITHIN_BUDGET);
        sink.retained_bytes = Some(budget_bytes);
        sink
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[test]
    fn a_budget_is_split_into_equal_shares_that_sum_within_it() {
        let sink = FileSink::within_budget("/var/log", "shekyld", 1 << 30);
        assert_eq!(sink.retained_bytes, Some(1 << 30));
        match sink.rotation {
            Rotation::Size {
                max_bytes,
                max_files,
            } => {
                assert_eq!(max_files, FILES_WITHIN_BUDGET);
                assert!(max_bytes * u64::from(max_files) <= 1 << 30);
                assert_eq!(max_bytes, (1 << 30) / u64::from(FILES_WITHIN_BUDGET));
            }
            other => panic!("not size-rolling: {other:?}"),
        }
        let tiny = FileSink::within_budget("/var/log", "shekyld", 3);
        assert_eq!(tiny.retained_bytes, Some(3));
        assert!(matches!(tiny.rotation, Rotation::Size { max_bytes: 1, .. }));
        assert!(
            FileSink::size_rolling("/var/log", "shekyld", 100, 2)
                .retained_bytes
                .is_none(),
            "a count rotation carries no byte budget"
        );
    }
}
