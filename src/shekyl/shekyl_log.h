// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

/// @file shekyl_log.h
/// @brief C declarations for the Rust shekyl-logging crate (libshekyl_log.a).
///
/// This header is the FFI boundary between the C++ logging shim
/// (`contrib/epee/include/misc_log_ex.h`, `contrib/epee/src/mlog.cpp`)
/// and the Rust `tracing` subscriber that replaces `external/easylogging++/`.
/// Every function here has a matching `#[no_mangle] pub extern "C"` in
/// `rust/shekyl-logging/src/ffi.rs`.
///
/// ## Linking
///
/// Link against `libshekyl_log.a` (static archive produced by
/// `cargo build -p shekyl-logging`). The CMake integration is in
/// `cmake/BuildRust.cmake`; every C++ target that already links
/// `shekyl_ffi` also picks up `shekyl_log` transitively.
///
/// ## Initialization & shutdown
///
/// `shekyl_log_init_stderr` / `shekyl_log_init_file` are idempotent:
/// the first caller in the process wins and installs a global
/// subscriber whose filter layer is wrapped in
/// `tracing_subscriber::reload::Layer` so `shekyl_log_set_categories`
/// can swap filters at runtime without tearing the subscriber down.
/// Subsequent init calls return `SHEKYL_LOG_ERR_ALREADY_INIT`.
///
/// `shekyl_log_shutdown` drops the writer guard so the non-blocking
/// appender thread flushes pending output. It is safe (and common)
/// to call it multiple times; extra calls are no-ops.
///
/// ## Memory model
///
/// All `(ptr, len)` pairs are borrowed — the Rust side never stashes
/// the pointer past the call return. The caller owns every buffer
/// it passes in or receives. No allocations cross this FFI in either
/// direction.
///
/// ## Buffer-sizing convention for read-side helpers
///
/// `shekyl_log_get_categories`, `shekyl_log_default_path`, and
/// `shekyl_log_last_error_message` all return the total byte length
/// of the answer *regardless of* whether it fit in the caller's
/// buffer. The caller checks `return_value > out_cap` to detect
/// truncation and, if desired, retries with a larger buffer. No NUL
/// terminator is written — callers must use the returned length.
///
/// ## Thread safety
///
/// Every function below is safe to call concurrently from any C
/// thread. Internal state uses `OnceLock<Mutex<…>>` for the global
/// subscriber handle and a thread-local `RefCell<String>` for
/// last-error text, so failed calls on one thread do not clobber
/// diagnostic strings on another.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#include <cstdbool>
extern "C" {
#else
#include <stdbool.h>
#endif

// -----------------------------------------------------------------
// Level constants
// -----------------------------------------------------------------
//
// Numeric values match `el::Level` from the retired easylogging++
// tree so the existing `MINFO` / `MDEBUG` / etc. macros translate
// 1:1 without renumbering ~1,345 call sites.

#define SHEKYL_LOG_LEVEL_FATAL   0
#define SHEKYL_LOG_LEVEL_ERROR   1
#define SHEKYL_LOG_LEVEL_WARNING 2
#define SHEKYL_LOG_LEVEL_INFO    3
#define SHEKYL_LOG_LEVEL_DEBUG   4
#define SHEKYL_LOG_LEVEL_TRACE   5

// -----------------------------------------------------------------
// Error codes
// -----------------------------------------------------------------
//
// Functions that return `int32_t` use 0 for success and a negative
// code for failure. Matches `SHEKYL_LOG_*` constants in
// `rust/shekyl-logging/src/ffi.rs`.

#define SHEKYL_LOG_OK                              0
#define SHEKYL_LOG_ERR_ALREADY_INIT               -1
#define SHEKYL_LOG_ERR_FILTER_PARSE               -2
#define SHEKYL_LOG_ERR_UNSUPPORTED_GLOB           -3
#define SHEKYL_LOG_ERR_UNKNOWN_LEVEL              -4
#define SHEKYL_LOG_ERR_NUMERIC_LEVEL_OUT_OF_RANGE -5
#define SHEKYL_LOG_ERR_MALFORMED_SPEC             -6
#define SHEKYL_LOG_ERR_FILE_SINK_CREATE           -7
#define SHEKYL_LOG_ERR_INVALID_DIRECTORY          -8
#define SHEKYL_LOG_ERR_NOT_INITIALIZED            -9
#define SHEKYL_LOG_ERR_INVALID_UTF8              -10
#define SHEKYL_LOG_ERR_SUBSCRIBER_INSTALL        -11

// -----------------------------------------------------------------
// Init / shutdown
// -----------------------------------------------------------------

/// Install a stderr-only tracing subscriber.
/// `fallback_level` must be one of `SHEKYL_LOG_LEVEL_*`; it is used
/// only when neither the `SHEKYL_LOG` env var nor a build-time
/// development fallback is set.
/// Returns `SHEKYL_LOG_OK` on first-caller success, `SHEKYL_LOG_ERR_*`
/// otherwise.
int32_t shekyl_log_init_stderr(uint8_t fallback_level);

/// Install a subscriber with both stderr output and a file sink.
///
/// `dir_ptr/dir_len` and `prefix_ptr/prefix_len` describe length-
/// prefixed UTF-8 byte slices (no NUL required). The active log
/// file is written as `<dir>/<prefix>`; rotated archives are
/// renamed to `<dir>/<prefix>-YYYY-MM-DD-HH-MM-SS` on overflow.
///
/// `max_bytes == 0` disables rotation (single unbounded file).
/// `max_bytes > 0` enables size-based rotation; `max_files` caps
/// total on-disk retention (live + rotated) — the oldest archive is
/// pruned when the count would exceed this limit.
///
/// Both the live file and every rotated archive are forced to
/// POSIX mode `0600` on Unix before the filename becomes visible.
int32_t shekyl_log_init_file(
    const char* dir_ptr,
    size_t dir_len,
    const char* prefix_ptr,
    size_t prefix_len,
    uint8_t fallback_level,
    uint64_t max_bytes,
    uint32_t max_files);

/// Flush the non-blocking writer and drop its worker-thread guard.
/// The subscriber itself remains installed — `tracing`'s global
/// default has no un-install — so filter and emit calls continue to
/// function after shutdown, they just write to stderr/the file
/// without the async buffer. Safe to call multiple times.
void shekyl_log_shutdown(void);

// -----------------------------------------------------------------
// Hot path: enabled gate + emit
// -----------------------------------------------------------------

/// Gate called by the C++ `MCLOG_TYPE` macro body *before* the
/// `stringstream` is built. Returns `true` when an event at the
/// given level and target would pass the current filter.
///
/// `target_ptr/target_len` is the legacy easylogging++ "category"
/// string (e.g. `"net.p2p"`). Passing `(NULL, 0)` is allowed and
/// matches the global default target.
///
/// Returns `false` when the logger is not yet initialized or the
/// target bytes are not valid UTF-8.
bool shekyl_log_level_enabled(
    uint8_t level,
    const char* target_ptr,
    size_t target_len);

/// Emit a single formatted log event to the installed subscriber.
///
/// `target_ptr/target_len` — legacy category string.
/// `file_ptr/file_len`    — `__FILE__` at the call site.
/// `line`                 — `__LINE__` at the call site.
/// `func_ptr/func_len`    — function/context marker (e.g. `ELPP_FUNC`).
/// `msg_ptr/msg_len`      — already-formatted message body.
///
/// Any `(ptr, len)` pair may be `(NULL, 0)` to omit that field.
/// Targets are interned once per `(target, level)` pair into a
/// leaked `'static` callsite so `tracing`'s `EnvFilter` can match
/// runtime-discovered categories. Unknown levels and non-UTF-8
/// buffers are silently dropped.
void shekyl_log_emit(
    uint8_t level,
    const char* target_ptr,
    size_t target_len,
    const char* file_ptr,
    size_t file_len,
    uint32_t line,
    const char* func_ptr,
    size_t func_len,
    const char* msg_ptr,
    size_t msg_len);

// -----------------------------------------------------------------
// Filter management
// -----------------------------------------------------------------

/// Apply a legacy `log-levels=` style spec (e.g. `"*:WARNING,net:INFO"`)
/// through the stateful translator. The translator combines this
/// call with the previously-applied directive so `mlog_set_log`
/// semantics (additive overrides) are preserved.
///
/// `fallback_level` seeds the resolution when the spec reduces to
/// the empty string.
///
/// Returns `SHEKYL_LOG_OK` on success, `SHEKYL_LOG_ERR_*` on
/// translator or filter-reload failure. Call
/// `shekyl_log_last_error_message` for diagnostic text.
int32_t shekyl_log_set_categories(
    const char* spec_ptr,
    size_t spec_len,
    uint8_t fallback_level);

/// Apply a bare-numeric level preset (0..=4). Convenience wrapper
/// for the legacy `mlog_set_log_level(int)` API; routed through
/// `shekyl_log_set_categories` internally so `current_spec`
/// bookkeeping stays consistent.
///
/// Returns `SHEKYL_LOG_ERR_NUMERIC_LEVEL_OUT_OF_RANGE` when
/// `numeric_level > 4`.
int32_t shekyl_log_set_level(uint8_t numeric_level);

// -----------------------------------------------------------------
// Read-side helpers
// -----------------------------------------------------------------

/// Copy the currently-active filter directive into
/// `out_ptr[0 .. min(total, out_cap)]`. Returns the total byte
/// length of the directive regardless of truncation. Callers that
/// want a C string must size their buffer for `return_value + 1`
/// and append the NUL terminator themselves — this FFI never
/// writes one.
/// Returns 0 when the logger is not initialized.
size_t shekyl_log_get_categories(char* out_ptr, size_t out_cap);

/// Resolve the default log-file path for a given binary name.
/// Produces `"<home>/.shekyl/logs/<binary_name>.log"` on Unix;
/// falls back to a current-directory path when `$HOME` is unset.
/// `binary_name_ptr/binary_name_len` must be a valid UTF-8 slice.
/// Uses the same truncation convention as
/// `shekyl_log_get_categories`. Returns 0 on UTF-8 failure or
/// when the home directory cannot be resolved.
size_t shekyl_log_default_path(
    const char* binary_name_ptr,
    size_t binary_name_len,
    char* out_ptr,
    size_t out_cap);

/// Copy the last error message produced by the calling thread
/// into `out_ptr[0 .. min(total, out_cap)]`. Returns the total
/// byte length regardless of truncation. Error text is
/// thread-local, so failed calls on one thread never clobber
/// diagnostics on another.
size_t shekyl_log_last_error_message(char* out_ptr, size_t out_cap);

#ifdef __cplusplus
} // extern "C"
#endif
