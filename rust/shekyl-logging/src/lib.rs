// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `shekyl-logging` — unified `tracing`-based logger initialization for
//! Shekyl Rust binaries.
//!
//! # What this crate is
//!
//! A small facade over [`tracing_subscriber`] and [`tracing_appender`] that
//! centralizes the discipline every Shekyl Rust binary needs:
//!
//! - One env var — `SHEKYL_LOG` — controls filter directives. `RUST_LOG` is
//!   intentionally not honored in release builds (see [`filter`]).
//! - File sinks are optional, per-binary, and POSIX-mode `0600` on the
//!   active file at init time (see [`config::FileSink`] for the
//!   rotation caveat).
//! - A translator ([`filter::directives_from_legacy_categories`]) converts
//!   the legacy C++ easylogging++ `log-levels=` grammar to EnvFilter
//!   directives so the unified logger can absorb configuration shipped by
//!   the soon-to-be-retired C++ shim.
//!
//! # What this crate is not
//!
//! - **Not a PII scrubber.** Whatever your call sites log, `shekyl-logging`
//!   will faithfully emit. PII discipline lives at the `tracing::debug!` /
//!   `tracing::trace!` call site, not here. If `SHEKYL_LOG=debug` is set
//!   against a wallet-rpc binary, the logger will surface everything any
//!   module chose to log at that level.
//! - **Not `no_std`.** Requires `std`, a filesystem, and (on POSIX) `libc`.
//! - **Not async-safe beyond `tracing`'s own guarantees.** The non-blocking
//!   writer buffers in-memory; if the binary exits before the returned
//!   [`LoggerGuard`] is dropped, buffered events are lost.
//!
//! # The [`LoggerGuard`] footgun
//!
//! [`init`] returns a `LoggerGuard` that must outlive the process's
//! interesting work. Binding it to `_` or letting it drop at a `;` defeats
//! the purpose. See the guard's own docs for the defense hierarchy.
//!
//! # Quick-start
//!
//! ```no_run
//! use shekyl_logging::{init, Config};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Bind the guard to a named local; it flushes buffered file-sink
//!     // events when `main` returns.
//!     let _guard = init(Config::stderr_only(tracing::Level::INFO))?;
//!     tracing::info!("wallet-rpc starting");
//!     Ok(())
//! }
//! ```

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod config;
pub mod ffi;
pub mod filter;

mod appender;
mod legacy;

pub use config::{Config, FileSink, Rotation};
pub use filter::{
    directives_from_legacy_categories, FilterError, TranslationReport, SHEKYL_LOG_ENV,
};

use std::sync::atomic::{AtomicBool, Ordering};

use thiserror::Error;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Registry;

/// Tracks whether [`init`] has installed a global subscriber.
///
/// A process-global flag is correct here because
/// `tracing::subscriber::set_global_default` is itself process-global.
/// Guarding the call prevents the second-init panic path from leaking into
/// binaries that accidentally call `init` twice.
///
/// `pub(crate)` so the FFI init path in [`crate::ffi`] can coordinate
/// against the same flag — only one subscriber per process, whether
/// it was installed from Rust or from C.
pub(crate) static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Handle for the process-global reload layer wrapping the `EnvFilter`.
///
/// Needed by the FFI path so `shekyl_log_set_categories` (called from
/// the C++ RPC `on_set_log_*` handlers via the shim) can swap the
/// filter at runtime without tearing down the subscriber.
///
/// The handle is `Clone` and cheap, so `init` stashes a copy here and
/// also returns the caller its [`LoggerGuard`]. The FFI module is the
/// only consumer of this alias; keeping it `pub(crate)` keeps the
/// Rust public API surface unchanged.
pub(crate) type FilterReloadHandle = reload::Handle<EnvFilter, Registry>;

/// RAII guard for the non-blocking writer thread(s) spawned by [`init`].
///
/// # The guard is not optional
///
/// Dropping this guard too early silently loses buffered log events. The
/// correct idiom is:
///
/// ```no_run
/// # use shekyl_logging::{init, Config};
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let _guard = init(Config::stderr_only(tracing::Level::WARN))?;
///     // ... do work ...
///     Ok(())
/// } // _guard drops here, flushing any buffered events.
/// ```
///
/// # Defense hierarchy, in decreasing order of effectiveness
///
/// 1. **`#[must_use]` on this type (primary).** Fires on the common wrong
///    idiom `shekyl_logging::init(cfg)?;` where the guard is dropped at the
///    semicolon with no binding.
/// 2. **`clippy::let_underscore_must_use = "deny"` at the workspace root
///    (secondary).** Fires on the narrower `let _ = init(...)` shape. This
///    lint does *not* catch the unbound-`?` case above.
/// 3. **This docblock.** Neither lint catches
///    `let _guard = init(...)?;` followed by code that moves `_guard` into
///    a scope that ends mid-`main`. Only code review catches that.
/// 4. **A compile-fail test under `tests/trybuild/`.** Regression guard
///    against someone removing `#[must_use]` in a future refactor.
#[must_use = "dropping LoggerGuard without binding flushes buffered events \
              and may silently lose logs; bind to a named local such as `_guard`"]
pub struct LoggerGuard {
    // `Option` because stderr-only configs have no worker thread; the
    // guard is still `#[must_use]` to keep the type-level discipline
    // uniform regardless of which sinks the caller chose. `pub(crate)`
    // so the FFI path in [`crate::ffi`] can build a guard when the C
    // caller owns the init — it holds the guard in global state and
    // drops it on `shekyl_log_shutdown`.
    pub(crate) _worker_guard: Option<WorkerGuard>,
}

/// Errors returned from [`init`].
#[derive(Debug, Error)]
pub enum InitError {
    /// [`init`] has already been called in this process.
    #[error("shekyl-logging has already been initialized in this process")]
    AlreadyInitialized,

    /// The configured file-sink directory could not be prepared or the log
    /// file could not be opened for appending.
    #[error("failed to open file sink: {0}")]
    FileSinkCreate(#[source] std::io::Error),

    /// The resolved `EnvFilter` directive string was rejected by the
    /// filter parser.
    #[error("failed to parse resolved filter directive: {0}")]
    FilterParse(String),

    /// Installing the global [`tracing`] subscriber failed.
    ///
    /// The most common cause is another subscriber already being
    /// installed in this process (for example, by a test harness or by
    /// an embedding binary that also calls `try_init` directly).
    /// Distinguishes "cannot install" from `FilterParse` so operators
    /// aren't misled by errors that have nothing to do with filter
    /// directive parsing.
    #[error("failed to install global tracing subscriber: {0}")]
    SubscriberInstall(String),

    /// The configured file-sink directory path is invalid (empty, not a
    /// directory, etc.).
    #[error("invalid file-sink directory: {0}")]
    InvalidDirectory(std::path::PathBuf),
}

/// Install the global [`tracing`] subscriber described by `config`.
///
/// Returns a [`LoggerGuard`] that keeps the background writer thread alive
/// for any configured file sink. The guard must be held until the binary
/// is ready to shut down.
///
/// Subsequent calls in the same process return
/// [`InitError::AlreadyInitialized`].
pub fn init(config: Config) -> Result<LoggerGuard, InitError> {
    let (guard, reload_handle) = install_subscriber(config)?;
    // Rust callers don't currently need the reload handle; stash a
    // clone for the FFI path in case a C caller wants to drive
    // `shekyl_log_set_categories` against a subscriber that was
    // installed from the Rust side (e.g. an integration test that
    // links both paths).
    ffi::__register_reload_handle(reload_handle);
    Ok(guard)
}

/// Install the subscriber and hand back both the guard *and* the
/// reload handle. The `INITIALIZED` flag coordination lives here so
/// both [`init`] and the FFI path stay in lockstep.
pub(crate) fn install_subscriber(
    config: Config,
) -> Result<(LoggerGuard, FilterReloadHandle), InitError> {
    if INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(InitError::AlreadyInitialized);
    }

    // Release the flag on hard failure so a follow-up init with a
    // fixed config can succeed; on success the flag stays set for
    // the process lifetime.
    let result = install_subscriber_inner(config);
    if result.is_err() {
        INITIALIZED.store(false, Ordering::SeqCst);
    }
    result
}

fn install_subscriber_inner(
    config: Config,
) -> Result<(LoggerGuard, FilterReloadHandle), InitError> {
    let filter = filter::resolve_env_filter(config.fallback_default)
        .map_err(|e| InitError::FilterParse(e.to_string()))?;

    // Wrap the resolved `EnvFilter` in a reload layer so later
    // `shekyl_log_set_categories` calls from C (via the FFI) can
    // swap filters without tearing the subscriber down.
    let (reloadable_filter, reload_handle) = reload::Layer::new(filter);

    let stderr_layer = fmt::layer().with_writer(std::io::stderr);

    if let Some(file_sink) = config.file_sink {
        let (non_blocking, worker_guard) = appender::open(&file_sink)?;
        let file_layer = fmt::layer().with_writer(non_blocking).with_ansi(false);

        tracing_subscriber::registry()
            .with(reloadable_filter)
            .with(stderr_layer)
            .with(file_layer)
            .try_init()
            .map_err(|e| InitError::SubscriberInstall(e.to_string()))?;

        Ok((
            LoggerGuard {
                _worker_guard: Some(worker_guard),
            },
            reload_handle,
        ))
    } else {
        tracing_subscriber::registry()
            .with(reloadable_filter)
            .with(stderr_layer)
            .try_init()
            .map_err(|e| InitError::SubscriberInstall(e.to_string()))?;

        Ok((
            LoggerGuard {
                _worker_guard: None,
            },
            reload_handle,
        ))
    }
}

/// Test-only hook: clear the init flag so a fresh `init` call can run.
///
/// The global subscriber itself is *not* reset — tracing's
/// `set_global_default` installs one for the process lifetime. This helper
/// only lets tests exercise the guard-flag path independently of the
/// subscriber path.
#[doc(hidden)]
pub fn __test_only_reset_init_flag() {
    INITIALIZED.store(false, Ordering::SeqCst);
}

/// Test-only hook: re-apply `0600` POSIX mode to any file in `dir`
/// starting with `prefix`.
///
/// Exposed so `tests/file_sink.rs` can assert the mode after a known
/// write has landed. Timing-sensitive tests that run before the
/// appender has opened the file can call this once the file exists.
///
/// No-op on non-Unix targets.
#[doc(hidden)]
pub fn __test_only_reapply_file_modes(dir: &std::path::Path, prefix: &str) -> std::io::Result<()> {
    appender::__test_only_reapply_file_modes(dir, prefix)
}
