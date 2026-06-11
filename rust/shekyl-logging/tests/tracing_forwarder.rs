// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! State-machine coverage for `shekyl_log_install_tracing_forwarder`.
//!
//! The forwarder export is the runtime half of the single-Rust-image
//! logging contract (decision log 2026-04-25, amended 2026-06-10):
//! `shekyl-daemon-rpc` compiles `shekyl-logging` into its own
//! staticlib so the daemon carries exactly one `tracing-core`
//! dispatcher, and this export pins the C++ call ordering
//! (`shekyl_log_init_*` first) plus install idempotency.
//!
//! This is an integration test (own process) rather than a unit test
//! because the install pin and `INITIALIZED` flag are process-global
//! one-shots: the before-init arm is only observable in a process
//! where nothing else has initialized the logger yet. Keep this file
//! to this single `#[test]` — a second test in the same binary could
//! race the global state.
//!
//! The link-time half of the contract — exactly one `GLOBAL_DISPATCH`
//! symbol in `shekyld` — is asserted by the post-link `nm` gate on
//! the `daemon` CMake target, not here; no Rust-side test can observe
//! a foreign image's dispatcher.

use shekyl_logging::ffi::{
    shekyl_log_init_stderr, shekyl_log_install_tracing_forwarder, SHEKYL_LOG_ERR_ALREADY_INSTALLED,
    SHEKYL_LOG_ERR_NOT_INITIALIZED, SHEKYL_LOG_LEVEL_INFO, SHEKYL_LOG_OK,
};

#[test]
fn forwarder_install_state_machine() {
    // An ambient SHEKYL_LOG (e.g. `off`) would override the
    // stderr_only(INFO) fallback below and break the final
    // `enabled!(ERROR)` assertion. Clear it for determinism, matching
    // the sibling integration tests (file_sink.rs, defaults.rs).
    // SAFETY: integration tests run one file per process.
    unsafe { std::env::remove_var(shekyl_logging::SHEKYL_LOG_ENV) };

    // Before any init: typed failure, and the one-shot pin must not
    // be consumed (the post-init install below must still succeed).
    // SAFETY: no pointer parameters on any call in this test.
    let pre = unsafe { shekyl_log_install_tracing_forwarder() };
    assert_eq!(pre, SHEKYL_LOG_ERR_NOT_INITIALIZED);

    let init = unsafe { shekyl_log_init_stderr(SHEKYL_LOG_LEVEL_INFO) };
    assert_eq!(init, SHEKYL_LOG_OK);

    // First install after a successful init.
    let first = unsafe { shekyl_log_install_tracing_forwarder() };
    assert_eq!(first, SHEKYL_LOG_OK);

    // Second install: idempotent typed signal, not a panic and not a
    // silent success — shekyld's SIGHUP-style re-configure path keys
    // off this distinction.
    let second = unsafe { shekyl_log_install_tracing_forwarder() };
    assert_eq!(second, SHEKYL_LOG_ERR_ALREADY_INSTALLED);

    // Within this (single-image) test binary, the dispatcher that
    // `tracing` macros dispatch through must be the init-installed
    // subscriber: an ERROR-level event passes any filter the
    // stderr_only(INFO) config can have produced.
    assert!(tracing::enabled!(tracing::Level::ERROR));
}
