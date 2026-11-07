// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `SHEKYL_LOG` resolution: a set variable is the directive, and an unset
//! one resolves to the caller's fallback level.

use tracing::Level;

use shekyl_logging::filter::resolve_env_filter;
use shekyl_logging::SHEKYL_LOG_ENV;

// -----------------------------------------------------------------------
// SHEKYL_LOG env-var behavior.
// -----------------------------------------------------------------------

// `std::env::set_var` is `unsafe` since Rust 1.80 because it races with
// other threads' env-var reads. We accept the risk here because:
//   - Integration tests run one test file per process on the default
//     test runner.
//   - Within this file we serialize SHEKYL_LOG reads by running the
//     env-touching tests sequentially via a mutex.
//
// If the `resolve_env_filter` return value later needs to be tested
// under multi-threaded reads, move to a shared-state pattern with an
// explicit "spec string" argument and drop the env-var serialization.
use std::sync::Mutex;
static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// RAII guard that snapshots the requested env vars on construction
/// and restores them on drop, so a panic inside a `with_env` body does
/// not leak mutated env state into subsequent tests in the same
/// integration-test process.
///
/// Field order matters: `_lock` is listed last because struct fields
/// drop in declaration order, so the saved values are restored before
/// we release the serialization lock. That ordering keeps another
/// waiting test from observing a half-restored env.
struct EnvGuard<'a> {
    saved: Vec<(String, Option<String>)>,
    _lock: std::sync::MutexGuard<'a, ()>,
}

impl<'a> EnvGuard<'a> {
    fn apply(lock: std::sync::MutexGuard<'a, ()>, vars: &[(&str, Option<&str>)]) -> Self {
        let saved: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(k, _)| ((*k).to_owned(), std::env::var(*k).ok()))
            .collect();
        for (k, v) in vars {
            match v {
                // SAFETY: serialized by the lock owned by this guard;
                // we own all env reads in this test file.
                Some(val) => unsafe { std::env::set_var(k, val) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
        Self { saved, _lock: lock }
    }
}

impl Drop for EnvGuard<'_> {
    fn drop(&mut self) {
        for (k, v) in &self.saved {
            // SAFETY: same as `EnvGuard::apply`; the lock is still held
            // until `_lock` drops after this function returns.
            match v {
                Some(val) => unsafe { std::env::set_var(k, val) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
    }
}

fn with_env<F: FnOnce()>(vars: &[(&str, Option<&str>)], body: F) {
    let lock = ENV_MUTEX.lock().unwrap_or_else(|poisoned| {
        // If a previous test panicked holding the lock, the saved env
        // has already been restored by that test's EnvGuard::drop, so
        // it is safe to acquire the lock on the poisoned mutex.
        poisoned.into_inner()
    });
    let _guard = EnvGuard::apply(lock, vars);
    body();
    // `_guard` drops here, restoring env vars and releasing the lock
    // on every exit path (normal return or unwinding panic).
}

#[test]
fn unset_shekyl_log_uses_fallback_default() {
    with_env(&[(SHEKYL_LOG_ENV, None), ("RUST_LOG", None)], || {
        let filter = resolve_env_filter(Level::INFO).expect("a level directive parses");
        assert_eq!(filter.to_string(), "info");
    });
}

#[test]
fn a_set_shekyl_log_is_the_directive() {
    with_env(&[(SHEKYL_LOG_ENV, Some("shekyl_relay=debug"))], || {
        let filter = resolve_env_filter(Level::WARN).expect("the directive parses");
        assert_eq!(filter.to_string(), "shekyl_relay=debug");
    });
}
