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
//! # Every sink is queued
//!
//! Every sink, stderr included, sits behind a bounded queue with its own
//! writer thread (`log-stderr`, `log-file`), so a log call never waits on
//! a sink. A full queue drops and counts. A write the sink refuses is
//! counted. A flush is counted only when that `flush` returns an error.
//! The writer thread reports the counts in one line once the sink takes
//! writes again; a summary the sink refuses stays pending and is not itself
//! a failed flush. What that leaves, on the record (Rick's review
//! of #1069, 2026-10-14):
//!
//! - **Shutdown.** Dropping the [`LoggerGuard`] queues a shutdown (waiting
//!   at most 100 ms for room) and then waits at most 1 s for the writer
//!   thread to drain, and returns either way: about a second. Lines still
//!   queued then are lost. A sink still stalled at that point can hold the
//!   process's exit anyway: a writer thread inside a write the kernel
//!   cannot interrupt (a stalled disk) keeps the process from exiting, and
//!   anything else writing to the same stalled stderr blocks with it. The
//!   service manager's stop timeout is the bound.
//! - **Before init.** The FFI's pre-init passthrough (WARNING and above,
//!   straight to stderr; see [`ffi`]) stays synchronous: a stalled stderr
//!   blocks those calls. It serves only the lines logged before the
//!   subscriber is installed.
//! - **The bound is lines, not bytes.** [`SINK_QUEUE_LINES`] counts lines,
//!   so a queue of long lines holds more memory than the figure suggests.
//! - **The thread ledger does not count them.** `tracing_appender` spawns
//!   the two writer threads itself, not through `shekyl-thread-ledger`, so
//!   the daemon's ledger print leaves them out.
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
mod queue;

pub use queue::SINK_QUEUE_LINES;

pub use config::{Config, FileSink, Rotation};
pub use filter::{
    directives_from_legacy_categories, FilterError, TranslationReport, SHEKYL_LOG_ENV,
};

use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

use thiserror::Error;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Registry;

/// First-caller reservation for [`install_subscriber`].
///
/// Flipped true at the *start* of an install attempt so a concurrent
/// second caller gets [`InitError::AlreadyInitialized`] rather than
/// racing `try_init`. Cleared if the attempt fails, so a later call
/// can retry. This is not "the subscriber is live" — that is
/// [`SUBSCRIBER_INSTALLED`]. The two facts have different lifetimes:
/// a reservation can unwind, a successful `set_global_default` cannot.
///
/// `pub(crate)` so the FFI init path in [`crate::ffi`] can coordinate
/// against the same flag — only one subscriber per process, whether
/// it was installed from Rust or from C.
pub(crate) static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Whether [`install_reserved`] has successfully called `try_init`.
///
/// Set only after `try_init` returns Ok, and never cleared —
/// `set_global_default` has no uninstall. FFI emit, enabled, and the
/// tracing-forwarder pin consult this flag. Consulting [`INITIALIZED`]
/// instead would treat the reservation window (filter parse, file
/// open, `try_init`) as "already live" and dispatch WARNING+ against
/// the still-empty default dispatcher, dropping the events the
/// pre-init passthrough exists to keep audible.
pub(crate) static SUBSCRIBER_INSTALLED: AtomicBool = AtomicBool::new(false);

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
    // One field per sink. Drop flushes that sink's queue. The fields are
    // never read: moving a guard out would take the writer thread out of
    // the value that shuts it down. `pub(crate)` so the FFI path in
    // [`crate::ffi`] can hold the guard and drop it on
    // `shekyl_log_shutdown`.
    /// stderr's writer thread. stderr is always queued.
    #[allow(dead_code)]
    pub(crate) stderr: WorkerGuard,
    /// The file sink's writer thread, when a file sink is configured.
    #[allow(dead_code)]
    pub(crate) file: Option<WorkerGuard>,
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
/// reload handle. [`init`], the FFI path, and the test hook all enter
/// through [`install_reserved`], so the reservation ([`INITIALIZED`])
/// and the successful install ([`SUBSCRIBER_INSTALLED`]) stay one protocol.
pub(crate) fn install_subscriber(
    config: Config,
) -> Result<(LoggerGuard, FilterReloadHandle), InitError> {
    let stderr = std::io::stderr();
    let ansi = stderr.is_terminal();
    install_reserved(config, stderr, queue::SINK_QUEUE_LINES, ansi)
}

/// Reserve the process subscriber, then install `config` with `stderr`
/// queued at `lines`, colouring stderr's lines only when `ansi` is set.
///
/// One reservation for every caller. A failed attempt clears
/// [`INITIALIZED`] so a later call can retry. Success leaves the
/// reservation set for the process lifetime and flips
/// [`SUBSCRIBER_INSTALLED`], so emit, enabled, and the forwarder stop
/// using the pre-init stderr passthrough.
fn install_reserved<W: std::io::Write + Send + 'static>(
    config: Config,
    stderr: W,
    lines: usize,
    ansi: bool,
) -> Result<(LoggerGuard, FilterReloadHandle), InitError> {
    if INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(InitError::AlreadyInitialized);
    }

    let result = install_subscriber_with_stderr(config, stderr, lines, ansi);
    if result.is_err() {
        INITIALIZED.store(false, Ordering::SeqCst);
    } else {
        SUBSCRIBER_INSTALLED.store(true, Ordering::SeqCst);
    }
    result
}

/// The subscriber itself. `stderr` is the stderr sink. Every sink is
/// queued at `lines`. Production passes the process's `stderr` and
/// [`SINK_QUEUE_LINES`]; the never-blocks test passes a sink that stalls.
///
/// `ansi` is whether stderr's lines carry colour codes. Production sets it
/// only when stderr is a terminal. Under systemd, a pipe or a redirect the
/// codes would land in the journal or the file as escape bytes, and every
/// `grep` over them would have to strip them first. It is always set
/// explicitly, so the `NO_COLOR` variable that `tracing-subscriber`'s
/// default consults does not decide it: the daemon takes no environment
/// input (`83-input-grammar`). The file sink never carries colour.
fn install_subscriber_with_stderr<W: std::io::Write + Send + 'static>(
    config: Config,
    stderr: W,
    lines: usize,
    ansi: bool,
) -> Result<(LoggerGuard, FilterReloadHandle), InitError> {
    let filter = filter::resolve_env_filter(config.fallback_default)
        .map_err(|e| InitError::FilterParse(e.to_string()))?;

    // Wrap the resolved `EnvFilter` in a reload layer so later
    // `shekyl_log_set_categories` calls from C (via the FFI) can
    // swap filters without tearing the subscriber down.
    let (reloadable_filter, reload_handle) = reload::Layer::new(filter);

    // Queued like every sink: a log call never waits on stderr. What
    // stderr carries (levels, format) is unchanged; that is IG-14's.
    let (stderr_writer, stderr_guard) = queue::queued(stderr, queue::Sink::Stderr, lines);
    let stderr_layer = fmt::layer().with_writer(stderr_writer).with_ansi(ansi);

    let (file_layer, file_guard) = if let Some(file_sink) = config.file_sink {
        let (writer, guard) = appender::open(&file_sink, lines)?;
        (
            Some(fmt::layer().with_writer(writer).with_ansi(false)),
            Some(guard),
        )
    } else {
        (None, None)
    };

    tracing_subscriber::registry()
        .with(reloadable_filter)
        .with(stderr_layer)
        .with(file_layer)
        .try_init()
        .map_err(|e| InitError::SubscriberInstall(e.to_string()))?;

    Ok((
        LoggerGuard {
            stderr: stderr_guard,
            file: file_guard,
        },
        reload_handle,
    ))
}

/// Test-only hook: [`init`] with `stderr` standing in for the process's
/// stderr and every sink's queue at `lines`, so a test can stall the sink
/// and watch the queue drop and report instead of blocking the caller.
/// A stand-in is never a terminal, so its lines carry no colour codes, as
/// the process's stderr does not when it is a pipe or the journal.
///
/// Enters through [`install_reserved`], the same reservation as [`init`]
/// and the FFI path.
#[doc(hidden)]
pub fn __test_only_init_with_stderr<W: std::io::Write + Send + 'static>(
    config: Config,
    stderr: W,
    lines: usize,
) -> Result<LoggerGuard, InitError> {
    let (guard, reload_handle) = install_reserved(config, stderr, lines, false)?;
    ffi::__register_reload_handle(reload_handle);
    Ok(guard)
}

/// Test-only hook: raise the reservation flag without installing a subscriber.
///
/// This is the window inside [`install_subscriber`] after the first-caller
/// CAS and before `try_init` returns. Pre-init emit / enabled / forwarder
/// must stay on the stderr passthrough; if they consult [`INITIALIZED`]
/// they silently drop WARNING+. Pair with [`__test_only_reset_init_flag`]
/// before a real init or the reservation will make that init return
/// [`InitError::AlreadyInitialized`].
#[doc(hidden)]
pub fn __test_only_reserve_init() {
    INITIALIZED.store(true, Ordering::SeqCst);
}

/// Test-only hook: clear the reservation flag so a fresh `init` call can
/// run the first-caller CAS.
///
/// Does **not** clear [`SUBSCRIBER_INSTALLED`] and does **not** uninstall
/// the subscriber — `set_global_default` has no un-install. A follow-up
/// `init` will still fail at `try_init` if a subscriber is already live;
/// this helper only re-opens the reservation path.
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
