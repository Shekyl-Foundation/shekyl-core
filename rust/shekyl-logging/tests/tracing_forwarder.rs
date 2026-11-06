// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! State-machine coverage for `install_tracing_forwarder`, the pin the
//! daemon's `run` sets right after `init` (DC-Q22).
//!
//! The pin is the runtime half of the single-Rust-image logging contract
//! (decision log 2026-04-25, amended 2026-06-10 and 2026-06-11): every
//! binary links exactly one Rust image — `libshekyl_ffi.a` for the C++
//! binaries, and `shekyld`'s own cargo graph (DC-Q19) — so each carries
//! exactly one `tracing-core` dispatcher, and the pin holds the call
//! ordering (`init` first) plus install idempotency. It has no C export:
//! no C++ called one (deleted 2026-11-02, `DAEMON_CONFIG_CUTOVER.md`
//! DC-F19).
//!
//! This is an integration test (own process) rather than a unit test
//! because the install pin and `INITIALIZED` flag are process-global
//! one-shots: the before-init arm is only observable in a process where
//! nothing else has initialized the logger yet. Keep this file to this
//! single `#[test]` — a second test in the same binary could race the
//! global state.
//!
//! The link-time half of the contract — exactly one `GLOBAL_DISPATCH`
//! symbol in `shekyld` — holds by the link: one cargo build, one
//! `tracing-core` in `Cargo.lock`. No Rust-side test can observe a foreign
//! image's dispatcher.

use shekyl_logging::ffi::{shekyl_log_init_stderr, SHEKYL_LOG_LEVEL_INFO, SHEKYL_LOG_OK};
use shekyl_logging::{install_tracing_forwarder, ForwarderError};

#[test]
fn forwarder_install_state_machine() {
    // An ambient SHEKYL_LOG (e.g. `off`) would override the
    // stderr_only(INFO) fallback below and break the final
    // `enabled!(ERROR)` assertion. Clear it for determinism, matching
    // the sibling integration tests (file_sink.rs, defaults.rs).
    // SAFETY: integration tests run one file per process.
    unsafe { std::env::remove_var(shekyl_logging::SHEKYL_LOG_ENV) };

    // Before any init: typed failure, and the one-shot pin must not be
    // consumed (the post-init install below must still succeed).
    assert_eq!(
        install_tracing_forwarder(),
        Err(ForwarderError::NotInitialized)
    );

    // SAFETY: no pointer parameters.
    let init = unsafe { shekyl_log_init_stderr(SHEKYL_LOG_LEVEL_INFO) };
    assert_eq!(init, SHEKYL_LOG_OK);

    // First install after a successful init.
    assert_eq!(install_tracing_forwarder(), Ok(()));

    // Second install: idempotent typed signal, not a panic and not a
    // silent success — a re-configure path keys off this distinction.
    assert_eq!(
        install_tracing_forwarder(),
        Err(ForwarderError::AlreadyInstalled)
    );

    // Within this (single-image) test binary, the dispatcher that
    // `tracing` macros dispatch through must be the init-installed
    // subscriber: an ERROR-level event passes any filter the
    // stderr_only(INFO) config can have produced.
    assert!(tracing::enabled!(tracing::Level::ERROR));
}
