// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! C ABI exposed by `shekyl-logging` for the C++ shim that replaces
//! `external/easylogging++/`.
//!
//! The surface mirrors `src/shekyl/shekyl_log.h` verbatim. Every
//! function is `extern "C"`, `#[no_mangle]`, and only takes C-safe
//! types — raw pointers plus length-prefixed slices rather than
//! `CStr` round-trips, so a caller can pass a non-terminated buffer
//! out of `std::string::data()` without first copying to a
//! NUL-terminated bag.
//!
//! # Wire shape
//!
//! - **Init**: idempotent. The first `shekyl_log_init_stderr` or
//!   `shekyl_log_init_file` call in a process wins and registers a
//!   global subscriber whose filter layer is wrapped in
//!   [`tracing_subscriber::reload::Layer`] so later category toggles
//!   can swap filters without tearing down the subscriber. Subsequent
//!   init calls return [`SHEKYL_LOG_ERR_ALREADY_INIT`].
//! - **Shutdown**: drops the stashed [`crate::LoggerGuard`], which
//!   flushes the non-blocking writer thread. Safe to call multiple
//!   times; additional calls are no-ops.
//! - **Emit**: the hot path for C++ `MINFO` / `MDEBUG` / etc. macros.
//!   Every emit takes an `(target, file, func, msg)` bag of length-
//!   prefixed byte slices. Targets (the legacy category string, e.g.
//!   `"net.p2p"`) are interned once per (target, level) pair into a
//!   leaked `DynCallsite` so `EnvFilter`'s target-matching lines up
//!   naturally against the translator output from
//!   `directives_from_legacy_categories`.
//! - **Enabled**: the gate the shim calls before building the C++
//!   `std::stringstream`. Short-circuits ~1,345 suppressed C++ call
//!   sites before they allocate. Internally routes through
//!   [`tracing::dispatcher::get_default`] against the same interned
//!   callsite pool.
//! - **Set-categories**: applies a legacy `log-levels=` spec through
//!   the stateful translator (`current_spec` = last-applied
//!   directive), then hands the resulting EnvFilter directive to the
//!   stashed reload handle.
//!
//! # Thread-safety
//!
//! The global state ([`OnceLock`] of [`Mutex<FfiState>`]) is safe to
//! call from any C thread concurrently. The last-error text is a
//! per-thread `RefCell`, so a failed call from thread A never
//! clobbers thread B's diagnostic text.
//!
//! # Memory safety contract
//!
//! Every function below is `unsafe extern "C"`. The C caller promises
//! that every non-null `(ptr, len)` pair it passes describes a valid,
//! readable byte region for the duration of the call. The Rust side
//! never stashes the pointer past return — it either copies the bytes
//! into the interned callsite pool (`shekyl_log_emit`) or parses them
//! into owned `String` values and drops them (`shekyl_log_set_*`).
//!
//! # Not implemented here
//!
//! File initialization with a split `directory + filename_prefix` is
//! the *only* supported shape — the C++ side already splits
//! `filename_base` into dir + base before calling us. Callers that
//! have a single path must split it themselves; we don't accept a
//! combined path to avoid reproducing boost-filesystem-style splitting
//! on the Rust side.

use std::cell::RefCell;
use std::collections::HashMap;
use std::os::raw::c_char;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Mutex, OnceLock, RwLock};

use tracing::Level;
use tracing_core::callsite::{Callsite, Identifier};
use tracing_core::field::{FieldSet, ValueSet};
use tracing_core::metadata::Kind;
use tracing_core::subscriber::Interest;
use tracing_core::{Event, Metadata};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::reload::Error as ReloadError;

use crate::{filter as legacy_filter, FilterReloadHandle};
use crate::{Config, FileSink, InitError, LoggerGuard};

/// C-visible log-level constants matching `src/shekyl/shekyl_log.h`.
///
/// Numeric values match `el::Level` from the legacy easylogging++
/// tree so the existing C++ call-site macros (`MINFO` → level 3,
/// `MDEBUG` → level 4, etc.) translate 1:1 without renumbering
/// ~1,345 sites.
pub const SHEKYL_LOG_LEVEL_FATAL: u8 = 0;
/// See [`SHEKYL_LOG_LEVEL_FATAL`].
pub const SHEKYL_LOG_LEVEL_ERROR: u8 = 1;
/// See [`SHEKYL_LOG_LEVEL_FATAL`].
pub const SHEKYL_LOG_LEVEL_WARNING: u8 = 2;
/// See [`SHEKYL_LOG_LEVEL_FATAL`].
pub const SHEKYL_LOG_LEVEL_INFO: u8 = 3;
/// See [`SHEKYL_LOG_LEVEL_FATAL`].
pub const SHEKYL_LOG_LEVEL_DEBUG: u8 = 4;
/// See [`SHEKYL_LOG_LEVEL_FATAL`].
pub const SHEKYL_LOG_LEVEL_TRACE: u8 = 5;

// -----------------------------------------------------------------
// Error codes
// -----------------------------------------------------------------

/// Success.
pub const SHEKYL_LOG_OK: i32 = 0;
/// The logger was already initialized in this process.
pub const SHEKYL_LOG_ERR_ALREADY_INIT: i32 = -1;
/// The resolved filter directive failed to parse.
pub const SHEKYL_LOG_ERR_FILTER_PARSE: i32 = -2;
/// A suffix-glob (`*y.z:LEVEL`) was rejected. See
/// [`crate::FilterError::UnsupportedGlob`].
pub const SHEKYL_LOG_ERR_UNSUPPORTED_GLOB: i32 = -3;
/// A level token was unrecognized.
pub const SHEKYL_LOG_ERR_UNKNOWN_LEVEL: i32 = -4;
/// A bare-numeric level was outside `0..=4`.
pub const SHEKYL_LOG_ERR_NUMERIC_LEVEL_OUT_OF_RANGE: i32 = -5;
/// The legacy spec was syntactically malformed.
pub const SHEKYL_LOG_ERR_MALFORMED_SPEC: i32 = -6;
/// Opening the file sink failed.
pub const SHEKYL_LOG_ERR_FILE_SINK_CREATE: i32 = -7;
/// The file-sink directory was invalid.
pub const SHEKYL_LOG_ERR_INVALID_DIRECTORY: i32 = -8;
/// The logger was not initialized when the call was made.
pub const SHEKYL_LOG_ERR_NOT_INITIALIZED: i32 = -9;
/// A length-prefixed byte slice was not valid UTF-8.
pub const SHEKYL_LOG_ERR_INVALID_UTF8: i32 = -10;
/// Installing the global subscriber failed.
pub const SHEKYL_LOG_ERR_SUBSCRIBER_INSTALL: i32 = -11;

// -----------------------------------------------------------------
// Global state
// -----------------------------------------------------------------

struct FfiState {
    reload_handle: FilterReloadHandle,
    /// Kept behind `Option` so `shekyl_log_shutdown` can `.take()`
    /// and drop the guard while leaving the rest of the state in
    /// place for idempotent subsequent calls.
    guard: Option<LoggerGuard>,
    /// Last-applied filter directive. Fed into the stateful
    /// translator as `current_spec` on the next
    /// `shekyl_log_set_categories` call.
    current_directive: String,
}

static FFI_STATE: OnceLock<Mutex<FfiState>> = OnceLock::new();

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn set_last_error(msg: impl Into<String>) {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = msg.into();
    });
}

/// Called by the Rust-side `crate::init` so a Rust caller's install
/// also registers its reload handle for the FFI `set_categories`
/// path. `crate::INITIALIZED` has already flipped at this point,
/// so `FFI_STATE::set()` is racing only against the narrow case
/// where a C caller concurrently tries to init — which would have
/// already failed at the atomic exchange.
pub(crate) fn __register_reload_handle(handle: FilterReloadHandle) {
    let state = FfiState {
        reload_handle: handle,
        guard: None,
        current_directive: String::new(),
    };
    // If another init path already populated `FFI_STATE`, keep the
    // existing state — it holds the authoritative guard. Swallow
    // the returned `Mutex<FfiState>` rather than replacing.
    drop(FFI_STATE.set(Mutex::new(state)));
}

// -----------------------------------------------------------------
// Init / shutdown
// -----------------------------------------------------------------

/// Initialize the logger with an stderr-only subscriber.
///
/// Idempotent: subsequent calls return
/// [`SHEKYL_LOG_ERR_ALREADY_INIT`].
///
/// # Safety
///
/// No pointer parameters, so no pointer-validity obligations. The
/// `fallback_level` byte must be one of the `SHEKYL_LOG_LEVEL_*`
/// constants; other values return [`SHEKYL_LOG_ERR_UNKNOWN_LEVEL`].
#[no_mangle]
pub unsafe extern "C" fn shekyl_log_init_stderr(fallback_level: u8) -> i32 {
    let Some(level) = level_from_u8(fallback_level) else {
        set_last_error(format!(
            "shekyl_log_init_stderr: unknown fallback level {fallback_level}"
        ));
        return SHEKYL_LOG_ERR_UNKNOWN_LEVEL;
    };
    install_for_ffi(Config::stderr_only(level))
}

/// Initialize the logger with an stderr layer *and* a file sink.
///
/// `max_bytes == 0` installs a non-rotating sink (equivalent to
/// `FileSink::unrotated`). `max_bytes > 0` installs a size-rolling
/// sink with `max_files` total on-disk retention (live + rotated),
/// matching the legacy easylogging++ `MaxLogFileSize` +
/// `installPreRollOutCallback` pair.
///
/// # Safety
///
/// `dir_ptr` / `dir_len` and `prefix_ptr` / `prefix_len` must
/// describe valid, readable byte regions for the duration of the
/// call, or be `(null, 0)`. Non-UTF-8 content returns
/// [`SHEKYL_LOG_ERR_INVALID_UTF8`]. The Rust side never stashes
/// the pointer.
#[no_mangle]
pub unsafe extern "C" fn shekyl_log_init_file(
    dir_ptr: *const c_char,
    dir_len: usize,
    prefix_ptr: *const c_char,
    prefix_len: usize,
    fallback_level: u8,
    max_bytes: u64,
    max_files: u32,
) -> i32 {
    // SAFETY: forwarded to caller's contract documented above.
    let dir = match unsafe { str_from_raw(dir_ptr, dir_len) } {
        Ok(s) => s,
        Err(code) => {
            set_last_error("shekyl_log_init_file: directory argument is not valid UTF-8");
            return code;
        }
    };
    // SAFETY: forwarded to caller's contract documented above.
    let prefix = match unsafe { str_from_raw(prefix_ptr, prefix_len) } {
        Ok(s) => s,
        Err(code) => {
            set_last_error("shekyl_log_init_file: filename_prefix argument is not valid UTF-8");
            return code;
        }
    };
    let Some(level) = level_from_u8(fallback_level) else {
        set_last_error(format!(
            "shekyl_log_init_file: unknown fallback level {fallback_level}"
        ));
        return SHEKYL_LOG_ERR_UNKNOWN_LEVEL;
    };
    if dir.is_empty() {
        set_last_error("shekyl_log_init_file: directory argument is empty");
        return SHEKYL_LOG_ERR_INVALID_DIRECTORY;
    }
    if prefix.is_empty() {
        set_last_error("shekyl_log_init_file: filename_prefix argument is empty");
        return SHEKYL_LOG_ERR_INVALID_DIRECTORY;
    }

    let sink = if max_bytes == 0 {
        FileSink::unrotated(Path::new(dir).to_path_buf(), prefix.to_owned())
    } else {
        FileSink::size_rolling(
            Path::new(dir).to_path_buf(),
            prefix.to_owned(),
            max_bytes,
            max_files,
        )
    };
    install_for_ffi(Config::with_file_sink(level, sink))
}

fn install_for_ffi(config: Config) -> i32 {
    let fallback_level = config.fallback_default;
    let (guard, reload_handle) = match crate::install_subscriber(config) {
        Ok(pair) => pair,
        Err(e) => {
            let code = init_error_to_code(&e);
            set_last_error(e.to_string());
            return code;
        }
    };

    // Determine the directive the subscriber was installed with
    // (`resolve_env_filter` already applied `SHEKYL_LOG` /
    // `dev-env-fallback` / fallback-level precedence). Mirroring the
    // same resolution here keeps `current_directive` honest as the
    // translator's `current_spec`.
    let current_directive = match legacy_filter::resolve_env_filter(fallback_level) {
        Ok(f) => f.to_string(),
        Err(_) => crate::filter::level_directive(fallback_level),
    };

    let state = FfiState {
        reload_handle,
        guard: Some(guard),
        current_directive,
    };
    // Replace any bootstrap state that `__register_reload_handle`
    // may have stashed (happens only if something bizarre ran Rust
    // init before the C init and they landed in the same address
    // space — vanishingly rare, but handle it cleanly).
    match FFI_STATE.set(Mutex::new(state)) {
        Ok(()) => SHEKYL_LOG_OK,
        Err(mutex_with_state) => {
            // The `OnceLock` already held state from an earlier
            // init. Merge: replace the guard/directive inside the
            // existing Mutex with ours, dropping the old guard so
            // its worker thread shuts down cleanly. This branch is
            // only reachable when `__register_reload_handle` ran
            // first — which means `install_subscriber` above has
            // already bumped `INITIALIZED`, so we're the real init.
            let fresh = mutex_with_state
                .into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(cell) = FFI_STATE.get() {
                let mut existing = match cell.lock() {
                    Ok(g) => g,
                    Err(e) => e.into_inner(),
                };
                *existing = fresh;
                SHEKYL_LOG_OK
            } else {
                SHEKYL_LOG_ERR_SUBSCRIBER_INSTALL
            }
        }
    }
}

/// Drop the stashed `LoggerGuard` so the non-blocking writer thread
/// flushes. Safe to call multiple times; subsequent calls are no-ops.
///
/// After `shutdown` the filter-reload path is still callable — the
/// subscriber stays installed for the process lifetime (tracing's
/// `set_global_default` has no un-install). This function only
/// releases the background writer.
///
/// # Safety
///
/// No pointer parameters.
#[no_mangle]
pub unsafe extern "C" fn shekyl_log_shutdown() {
    if let Some(cell) = FFI_STATE.get() {
        if let Ok(mut state) = cell.lock() {
            let _ = state.guard.take();
        }
    }
}

// -----------------------------------------------------------------
// Hot path: enabled gate + emit
// -----------------------------------------------------------------

/// Return `true` when an event with `level` and `target` would pass
/// the current filter, `false` otherwise.
///
/// The shim calls this before building the C++ `std::stringstream`
/// so suppressed events short-circuit before any allocation.
///
/// Returns `false` when the logger is uninitialized or the target
/// bytes are not valid UTF-8.
///
/// # Safety
///
/// `target_ptr` / `target_len` must describe a valid, readable
/// byte region for the duration of the call, or be `(null, 0)`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_log_level_enabled(
    level: u8,
    target_ptr: *const c_char,
    target_len: usize,
) -> bool {
    let Some(level) = level_from_u8(level) else {
        return false;
    };
    // SAFETY: forwarded to caller's contract documented above.
    let Ok(target) = (unsafe { str_from_raw(target_ptr, target_len) }) else {
        return false;
    };
    let cs = callsite_for(target, level);
    let meta = cs.static_metadata();
    tracing::dispatcher::get_default(|d| d.enabled(meta))
}

/// Emit one event.
///
/// All pointer+length pairs except `msg_ptr`/`msg_len` may be
/// `(null, 0)` — the event then lands with the corresponding field
/// unset.
///
/// # Safety
///
/// Every non-null `(ptr, len)` pair must describe a valid, readable
/// byte region for the duration of the call. The Rust side never
/// stashes the pointer past return; target strings are copied into
/// the interned callsite pool, and the message / file / func bytes
/// land inside the dispatcher's own event buffer.
#[no_mangle]
pub unsafe extern "C" fn shekyl_log_emit(
    level: u8,
    target_ptr: *const c_char,
    target_len: usize,
    file_ptr: *const c_char,
    file_len: usize,
    line: u32,
    func_ptr: *const c_char,
    func_len: usize,
    msg_ptr: *const c_char,
    msg_len: usize,
) {
    let Some(level) = level_from_u8(level) else {
        return;
    };
    // SAFETY: forwarded to caller's contract documented above.
    let Ok(target) = (unsafe { str_from_raw(target_ptr, target_len) }) else {
        return;
    };
    // SAFETY: as above.
    let file = unsafe { str_from_raw(file_ptr, file_len) }.unwrap_or("");
    // SAFETY: as above.
    let func = unsafe { str_from_raw(func_ptr, func_len) }.unwrap_or("");
    // SAFETY: as above.
    let msg = unsafe { str_from_raw(msg_ptr, msg_len) }.unwrap_or("");

    let cs = callsite_for(target, level);
    let meta = cs.static_metadata();

    tracing::dispatcher::get_default(|dispatcher| {
        if !dispatcher.enabled(meta) {
            return;
        }
        let fields = meta.fields();
        let message_field = fields.field("message").expect("'message' field registered");
        let file_field = fields
            .field("log.file")
            .expect("'log.file' field registered");
        let line_field = fields
            .field("log.line")
            .expect("'log.line' field registered");
        let func_field = fields
            .field("log.func")
            .expect("'log.func' field registered");

        let line_u64 = u64::from(line);
        let values: [(
            &tracing_core::field::Field,
            Option<&dyn tracing_core::field::Value>,
        ); 4] = [
            (
                &message_field,
                Some(&msg as &dyn tracing_core::field::Value),
            ),
            (&file_field, Some(&file as &dyn tracing_core::field::Value)),
            (
                &line_field,
                Some(&line_u64 as &dyn tracing_core::field::Value),
            ),
            (&func_field, Some(&func as &dyn tracing_core::field::Value)),
        ];
        let value_set: ValueSet<'_> = fields.value_set(&values);
        let event = Event::new(meta, &value_set);
        dispatcher.event(&event);
    });
}

// -----------------------------------------------------------------
// Set / get categories
// -----------------------------------------------------------------

/// Apply a legacy `log-levels=` spec, routed through the stateful
/// translator and the reload handle.
///
/// `fallback_level` is consulted only for the empty-spec startup
/// branch inside the translator; runtime toggles with a non-empty
/// `current_directive` ignore it.
///
/// # Safety
///
/// `spec_ptr` / `spec_len` must describe a valid, readable byte
/// region for the duration of the call, or be `(null, 0)`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_log_set_categories(
    spec_ptr: *const c_char,
    spec_len: usize,
    fallback_level: u8,
) -> i32 {
    // SAFETY: forwarded to caller's contract documented above.
    let spec = match unsafe { str_from_raw(spec_ptr, spec_len) } {
        Ok(s) => s,
        Err(code) => {
            set_last_error("shekyl_log_set_categories: spec is not valid UTF-8");
            return code;
        }
    };
    let Some(fallback) = level_from_u8(fallback_level) else {
        set_last_error(format!(
            "shekyl_log_set_categories: unknown fallback level {fallback_level}"
        ));
        return SHEKYL_LOG_ERR_UNKNOWN_LEVEL;
    };

    let Some(cell) = FFI_STATE.get() else {
        set_last_error("shekyl_log_set_categories: logger not initialized");
        return SHEKYL_LOG_ERR_NOT_INITIALIZED;
    };
    let mut state = cell
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let current_spec = if state.current_directive.is_empty() {
        None
    } else {
        Some(state.current_directive.as_str())
    };
    let translation =
        match legacy_filter::directives_from_legacy_categories(current_spec, spec, fallback) {
            Ok(t) => t,
            Err(e) => {
                let code = filter_error_to_code(&e);
                set_last_error(e.to_string());
                return code;
            }
        };

    let new_filter = match EnvFilter::try_new(&translation.directive) {
        Ok(f) => f,
        Err(e) => {
            set_last_error(format!(
                "shekyl_log_set_categories: translator emitted directive {:?} that EnvFilter rejected: {e}",
                translation.directive
            ));
            return SHEKYL_LOG_ERR_FILTER_PARSE;
        }
    };

    match state.reload_handle.reload(new_filter) {
        Ok(()) => {
            state.current_directive = translation.directive;
            SHEKYL_LOG_OK
        }
        Err(e) => {
            set_last_error(format!(
                "shekyl_log_set_categories: reload handle rejected the filter: {}",
                reload_error_text(&e)
            ));
            SHEKYL_LOG_ERR_SUBSCRIBER_INSTALL
        }
    }
}

/// Apply a numeric preset (0..=4), equivalent to calling
/// [`shekyl_log_set_categories`] with the corresponding preset
/// string.
///
/// # Safety
///
/// No pointer parameters.
#[no_mangle]
pub unsafe extern "C" fn shekyl_log_set_level(numeric_level: u8) -> i32 {
    if numeric_level > 4 {
        set_last_error(format!(
            "shekyl_log_set_level: numeric level {numeric_level} out of range 0..=4"
        ));
        return SHEKYL_LOG_ERR_NUMERIC_LEVEL_OUT_OF_RANGE;
    }
    // The translator accepts a bare numeric string as a preset; go
    // through `shekyl_log_set_categories` so the full `current_spec`
    // bookkeeping fires. We use the bytes of a short stack buffer to
    // avoid depending on `format!` for a single-digit string.
    let digit = [b'0' + numeric_level];
    // SAFETY: `digit` is a 1-byte stack buffer of ASCII, always
    // valid UTF-8, and the slice outlives this call.
    unsafe { shekyl_log_set_categories(digit.as_ptr() as *const c_char, 1, SHEKYL_LOG_LEVEL_INFO) }
}

/// Copy the current EnvFilter directive into `out_ptr` (up to
/// `out_cap` bytes) and return the total number of bytes that would
/// have been written, *not* including a terminating NUL (the Rust
/// side does not NUL-terminate).
///
/// A return value greater than `out_cap` means truncation occurred
/// and the caller should re-invoke with a larger buffer.
///
/// # Safety
///
/// If `out_cap > 0`, `out_ptr` must be non-null and point at a
/// writable byte region of at least `out_cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_log_get_categories(out_ptr: *mut c_char, out_cap: usize) -> usize {
    let Some(cell) = FFI_STATE.get() else {
        return 0;
    };
    let state = match cell.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let bytes = state.current_directive.as_bytes();
    let total = bytes.len();
    if out_cap > 0 && !out_ptr.is_null() {
        let to_copy = total.min(out_cap);
        // SAFETY: caller's contract guarantees `out_ptr..out_ptr+out_cap`
        // is writable; `to_copy` ≤ `out_cap`.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr as *mut u8, to_copy);
        }
    }
    total
}

/// Build the per-binary default log path
/// (`~/.shekyl/logs/<binary_name>`).
///
/// Writes up to `out_cap` bytes and returns the total number of
/// bytes that would have been written (caller re-invokes with a
/// larger buffer on truncation).
///
/// On platforms where a home directory can't be resolved (no
/// `HOME`, no passwd entry) the function writes no bytes and
/// returns `0`.
///
/// # Safety
///
/// `binary_name_ptr` / `binary_name_len` must describe a valid,
/// readable byte region, or be `(null, 0)`. `out_ptr` / `out_cap`
/// has the same writable-region contract as
/// [`shekyl_log_get_categories`].
#[no_mangle]
pub unsafe extern "C" fn shekyl_log_default_path(
    binary_name_ptr: *const c_char,
    binary_name_len: usize,
    out_ptr: *mut c_char,
    out_cap: usize,
) -> usize {
    // SAFETY: forwarded to caller's contract documented above.
    let Ok(binary_name) = (unsafe { str_from_raw(binary_name_ptr, binary_name_len) }) else {
        return 0;
    };
    let Some(home) = home_dir() else {
        return 0;
    };
    let path = home.join(".shekyl").join("logs").join(binary_name);
    let Some(path_str) = path.to_str() else {
        return 0;
    };
    let bytes = path_str.as_bytes();
    let total = bytes.len();
    if out_cap > 0 && !out_ptr.is_null() {
        let to_copy = total.min(out_cap);
        // SAFETY: caller's contract guarantees `out_ptr..out_ptr+out_cap`
        // is writable; `to_copy` ≤ `out_cap`.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr as *mut u8, to_copy);
        }
    }
    total
}

/// Copy the per-thread last-error message into `out_ptr` (up to
/// `out_cap` bytes) and return the total length that would have
/// been written.
///
/// Last-error is set whenever a function returns a negative code.
/// It is *not* cleared between calls — callers must read it
/// immediately after the failing call. Each thread has its own
/// last-error buffer, so concurrent failures on separate C
/// threads do not race.
///
/// # Safety
///
/// Same as [`shekyl_log_get_categories`].
#[no_mangle]
pub unsafe extern "C" fn shekyl_log_last_error_message(
    out_ptr: *mut c_char,
    out_cap: usize,
) -> usize {
    LAST_ERROR.with(|cell| {
        let msg = cell.borrow();
        let bytes = msg.as_bytes();
        let total = bytes.len();
        if out_cap > 0 && !out_ptr.is_null() {
            let to_copy = total.min(out_cap);
            // SAFETY: caller's contract guarantees `out_ptr..out_ptr+out_cap`
            // is writable; `to_copy` ≤ `out_cap`.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr as *mut u8, to_copy);
            }
        }
        total
    })
}

// -----------------------------------------------------------------
// Shutdown-flag reset, exposed only for tests that run inside the
// same Rust process as the global subscriber install. The C FFI
// does *not* expose this — production callers go through
// `shekyl_log_shutdown`, which leaves `INITIALIZED` set (tracing's
// `set_global_default` has no un-install), and any follow-up init
// attempt correctly returns `SHEKYL_LOG_ERR_ALREADY_INIT`.
// -----------------------------------------------------------------

#[doc(hidden)]
pub fn __test_only_reset_ffi_state() {
    if let Some(cell) = FFI_STATE.get() {
        if let Ok(mut state) = cell.lock() {
            state.guard.take();
            state.current_directive.clear();
        }
    }
    crate::INITIALIZED.store(false, Ordering::SeqCst);
}

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

fn level_from_u8(level: u8) -> Option<Level> {
    match level {
        // tracing has no FATAL; map both FATAL and ERROR to ERROR so
        // the C++ side doesn't need to down-cast on its own.
        SHEKYL_LOG_LEVEL_FATAL | SHEKYL_LOG_LEVEL_ERROR => Some(Level::ERROR),
        SHEKYL_LOG_LEVEL_WARNING => Some(Level::WARN),
        SHEKYL_LOG_LEVEL_INFO => Some(Level::INFO),
        SHEKYL_LOG_LEVEL_DEBUG => Some(Level::DEBUG),
        SHEKYL_LOG_LEVEL_TRACE => Some(Level::TRACE),
        _ => None,
    }
}

/// SAFETY: caller must ensure `ptr..ptr+len` is a valid, readable
/// byte region for the duration of the call, or that `len == 0`.
unsafe fn str_from_raw<'a>(ptr: *const c_char, len: usize) -> Result<&'a str, i32> {
    if len == 0 {
        return Ok("");
    }
    if ptr.is_null() {
        return Err(SHEKYL_LOG_ERR_INVALID_UTF8);
    }
    // SAFETY: forwarded to this function's own contract.
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
    std::str::from_utf8(slice).map_err(|_| SHEKYL_LOG_ERR_INVALID_UTF8)
}

fn init_error_to_code(e: &InitError) -> i32 {
    match e {
        InitError::AlreadyInitialized => SHEKYL_LOG_ERR_ALREADY_INIT,
        InitError::FileSinkCreate(_) => SHEKYL_LOG_ERR_FILE_SINK_CREATE,
        InitError::FilterParse(_) => SHEKYL_LOG_ERR_FILTER_PARSE,
        InitError::SubscriberInstall(_) => SHEKYL_LOG_ERR_SUBSCRIBER_INSTALL,
        InitError::InvalidDirectory(_) => SHEKYL_LOG_ERR_INVALID_DIRECTORY,
    }
}

fn filter_error_to_code(e: &crate::FilterError) -> i32 {
    match e {
        crate::FilterError::UnknownLevel { .. } => SHEKYL_LOG_ERR_UNKNOWN_LEVEL,
        crate::FilterError::NumericLevelOutOfRange { .. } => {
            SHEKYL_LOG_ERR_NUMERIC_LEVEL_OUT_OF_RANGE
        }
        crate::FilterError::UnsupportedGlob { .. } => SHEKYL_LOG_ERR_UNSUPPORTED_GLOB,
        crate::FilterError::MalformedSpec { .. } => SHEKYL_LOG_ERR_MALFORMED_SPEC,
    }
}

fn reload_error_text(e: &ReloadError) -> String {
    e.to_string()
}

/// Resolve the operator's home directory, falling back to `$HOME`
/// and then to passwd when unset. Kept off the `dirs` crate so we
/// don't add another dependency just for one call path.
fn home_dir() -> Option<std::path::PathBuf> {
    if let Ok(val) = std::env::var("HOME") {
        if !val.is_empty() {
            return Some(std::path::PathBuf::from(val));
        }
    }
    #[cfg(unix)]
    {
        // SAFETY: `getpwuid` is thread-safe on glibc/musl when
        // called without concurrent mutators of the passwd file;
        // the returned pointer lives until the next libc call
        // modifies the internal buffer, which we don't make in this
        // scope. The resulting `pw_dir` bytes are a C string we
        // copy out before returning, so no dangling reference
        // escapes.
        let uid = unsafe { libc::getuid() };
        let pw = unsafe { libc::getpwuid(uid) };
        if !pw.is_null() {
            let dir_ptr = unsafe { (*pw).pw_dir };
            if !dir_ptr.is_null() {
                let cstr = unsafe { std::ffi::CStr::from_ptr(dir_ptr) };
                if let Ok(s) = cstr.to_str() {
                    if !s.is_empty() {
                        return Some(std::path::PathBuf::from(s));
                    }
                }
            }
        }
    }
    None
}

// -----------------------------------------------------------------
// Interned dynamic callsites
// -----------------------------------------------------------------

/// A tracing callsite whose `Metadata` is populated at runtime.
///
/// `tracing_core::Metadata` requires `&'static` target / field / name
/// strings because the dispatcher stores borrows into these across
/// threads. We satisfy the `'static` bound by leaking a `Box<DynCallsite>`
/// (plus the target string) on first use. Leak is bounded by the
/// number of unique `(target, level)` pairs the C++ side ever emits
/// under — small and fixed for Shekyl's category set.
struct DynCallsite {
    /// The metadata ends up pointing to `&self` via `Identifier`, so
    /// we can only construct it once `self` has been placed at its
    /// final `'static` address. `OnceLock` lets us install the
    /// metadata exactly once after the box is leaked.
    meta: OnceLock<Metadata<'static>>,
}

impl Callsite for DynCallsite {
    fn set_interest(&self, _interest: Interest) {}
    fn metadata(&self) -> &Metadata<'_> {
        self.meta
            .get()
            .expect("DynCallsite metadata was not initialized before first use")
    }
}

impl DynCallsite {
    fn static_metadata(&'static self) -> &'static Metadata<'static> {
        self.meta
            .get()
            .expect("DynCallsite metadata was not initialized before first use")
    }
}

type CallsiteKey = (String, Level);

/// Normalize a caller-supplied target string into the
/// `tracing`-idiomatic `::` module-path form.
///
/// The legacy easylogging++ grammar addresses categories with `.`
/// separators (`net.p2p`, `daemon.rpc.payment`). The translator in
/// [`crate::legacy`] rewrites those to `::` when producing EnvFilter
/// directives (`net::p2p=trace`, `daemon::rpc::payment=error`), so
/// the emit-time target string must use the same convention or
/// EnvFilter's string-equality comparison silently fails and every
/// category-scoped emit falls through to the default clause — the
/// exact regression `TEST(logging, category_filter_routes_emits)`
/// surfaces when the FFI passes dotted names through untouched.
///
/// Normalization is a plain `.` → `::` rewrite; it is idempotent
/// (already-colon-separated targets round-trip unchanged) and
/// cheap (allocation-free when the target contains no dots). The
/// interned callsite pool keys on the normalized form so a single
/// target sees one `DynCallsite` regardless of which separator the
/// caller spelled it with.
fn normalize_target(target: &str) -> std::borrow::Cow<'_, str> {
    if target.contains('.') {
        std::borrow::Cow::Owned(target.replace('.', "::"))
    } else {
        std::borrow::Cow::Borrowed(target)
    }
}

/// Intern pool for `(target, level)` → callsite mappings.
///
/// Reads take the read-lock only; on the rare miss we take the
/// write-lock, re-check, and allocate. The inner `HashMap` is cloned
/// only once per process (bounded growth).
fn callsite_for(target: &str, level: Level) -> &'static DynCallsite {
    static CACHE: OnceLock<RwLock<HashMap<CallsiteKey, &'static DynCallsite>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| RwLock::new(HashMap::new()));

    let normalized = normalize_target(target);
    let key = (normalized.into_owned(), level);
    {
        let guard = match cache.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(&cs) = guard.get(&key) {
            return cs;
        }
    }
    let mut guard = match cache.write() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(&cs) = guard.get(&key) {
        return cs;
    }

    let target_static: &'static str = Box::leak(key.0.clone().into_boxed_str());
    // Leak the callsite first so `Identifier` has a stable address.
    let cs: &'static DynCallsite = Box::leak(Box::new(DynCallsite {
        meta: OnceLock::new(),
    }));
    let fields = FieldSet::new(
        &["message", "log.file", "log.line", "log.func"],
        Identifier(cs),
    );
    let level_static: tracing_core::Level = level;
    let meta = Metadata::new(
        "shekyl_log_emit",
        target_static,
        level_static,
        None,
        None,
        None,
        fields,
        Kind::EVENT,
    );
    cs.meta
        .set(meta)
        .unwrap_or_else(|_| panic!("DynCallsite metadata set twice"));
    tracing_core::callsite::register(cs);

    guard.insert(key, cs);
    cs
}

#[cfg(test)]
mod tests {
    use super::normalize_target;

    /// Dotted legacy targets (`net.p2p`, `daemon.rpc.payment`) must
    /// be rewritten into the `::` module-path form the translator
    /// emits in EnvFilter directives; otherwise every category-
    /// scoped emit from the C++ shim falls through to the default
    /// clause. Regression guard for the
    /// `category_filter_routes_emits` unit test on the C++ side.
    #[test]
    fn normalize_target_rewrites_dots_to_double_colons() {
        assert_eq!(normalize_target("net.p2p"), "net::p2p");
        assert_eq!(
            normalize_target("daemon.rpc.payment"),
            "daemon::rpc::payment"
        );
    }

    /// Already-colonized targets round-trip unchanged (idempotent).
    /// Matters because the Rust-side callers in
    /// `tests/presets.rs` exercise the enablement matrix with
    /// `net::p2p` directly — we must not re-process it into
    /// `net::::p2p` or similar.
    #[test]
    fn normalize_target_is_idempotent_on_colon_form() {
        assert_eq!(normalize_target("net::p2p"), "net::p2p");
        assert_eq!(normalize_target("global"), "global");
    }

    /// Empty targets survive the rewrite; the FFI treats them as
    /// "no target scope" (events land under the default clause).
    #[test]
    fn normalize_target_accepts_empty() {
        assert_eq!(normalize_target(""), "");
    }
}
