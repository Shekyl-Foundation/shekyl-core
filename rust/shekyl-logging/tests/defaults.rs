// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `Config::default()` shape and `init` idempotence.
//!
//! Each integration-test file is its own process, so a first `init` in
//! this file does not collide with `init` calls from `file_sink.rs`.
//! That lets us assert the `AlreadyInitialized` diagnostic path cleanly.

use shekyl_logging::{init, Config, InitError};
use tracing::Level;

#[test]
fn config_default_is_stderr_only_info() {
    let cfg = Config::default();
    assert!(cfg.file_sink.is_none());
    assert_eq!(cfg.fallback_default, Level::INFO);
}

#[test]
fn config_stderr_only_has_no_file_sink() {
    let cfg = Config::stderr_only(Level::WARN);
    assert!(cfg.file_sink.is_none());
    assert_eq!(cfg.fallback_default, Level::WARN);
}

#[test]
fn double_init_returns_already_initialized() {
    // Remove SHEKYL_LOG so the fallback path is the one under test.
    // SAFETY: integration tests get their own process.
    unsafe { std::env::remove_var(shekyl_logging::SHEKYL_LOG_ENV) };

    let _guard = match init(Config::stderr_only(Level::WARN)) {
        Ok(g) => g,
        Err(e) => panic!("first init should succeed: {e:?}"),
    };

    match init(Config::stderr_only(Level::WARN)) {
        Ok(_) => panic!("second init should have failed"),
        Err(InitError::AlreadyInitialized) => {}
        Err(other) => panic!("wrong error variant: {other:?}"),
    }
}
