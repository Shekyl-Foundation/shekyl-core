// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tests for `SHEKYL_LOG` env-var parsing and translator fixture coverage.

use tracing::Level;

use shekyl_logging::{
    directives_from_legacy_categories, FilterError, TranslationReport, SHEKYL_LOG_ENV,
};

// -----------------------------------------------------------------------
// Fixture-driven table tests (the broadest coverage of the translator's
// edge-case contract).
// -----------------------------------------------------------------------

const FIXTURE: &str = include_str!("fixtures/legacy_categories.txt");

enum Expect {
    Ok(String),
    OkContains(String),
    ErrVariant(String),
}

fn parse_line(line: &str) -> Option<(Expect, String)> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    // Split at the FIRST `|` only; spec side may contain further chars.
    let (expect_part, spec_part) = line.split_once('|')?;
    let spec = spec_part.to_owned();

    let expect_trim = expect_part.trim();
    if let Some(rest) = expect_trim.strip_prefix("ok:") {
        Some((Expect::Ok(rest.to_owned()), spec))
    } else if let Some(rest) = expect_trim.strip_prefix("ok-contains:") {
        Some((Expect::OkContains(rest.to_owned()), spec))
    } else if let Some(rest) = expect_trim.strip_prefix("err:") {
        Some((Expect::ErrVariant(rest.trim().to_owned()), spec))
    } else {
        panic!("malformed fixture line {line:?}");
    }
}

fn err_variant(err: &FilterError) -> &'static str {
    match err {
        FilterError::UnknownLevel { .. } => "UnknownLevel",
        FilterError::NumericLevelOutOfRange { .. } => "NumericLevelOutOfRange",
        FilterError::UnsupportedGlob { .. } => "UnsupportedGlob",
        FilterError::MalformedSpec { .. } => "MalformedSpec",
    }
}

#[test]
fn legacy_categories_fixture_passes() {
    let mut checked = 0usize;
    for (lineno, raw) in FIXTURE.lines().enumerate() {
        let Some((expect, spec)) = parse_line(raw) else {
            continue;
        };
        let result = directives_from_legacy_categories(None, &spec, Level::WARN);
        match (expect, result) {
            (Expect::Ok(expected), Ok(report)) => {
                assert_eq!(
                    report.directive,
                    expected,
                    "line {} spec {:?}: expected directive {:?}, got {:?}",
                    lineno + 1,
                    spec,
                    expected,
                    report.directive,
                );
            }
            (Expect::OkContains(needle), Ok(report)) => {
                assert!(
                    report.directive.contains(&needle),
                    "line {} spec {:?}: directive {:?} does not contain {:?}",
                    lineno + 1,
                    spec,
                    report.directive,
                    needle,
                );
            }
            (Expect::ErrVariant(expected), Err(err)) => {
                assert_eq!(
                    err_variant(&err),
                    expected.as_str(),
                    "line {} spec {:?}: wrong error variant",
                    lineno + 1,
                    spec,
                );
            }
            (Expect::Ok(expected), Err(err)) => panic!(
                "line {} spec {:?}: expected Ok({:?}), got Err({:?})",
                lineno + 1,
                spec,
                expected,
                err,
            ),
            (Expect::OkContains(needle), Err(err)) => panic!(
                "line {} spec {:?}: expected Ok(contains {:?}), got Err({:?})",
                lineno + 1,
                spec,
                needle,
                err,
            ),
            (Expect::ErrVariant(expected), Ok(report)) => panic!(
                "line {} spec {:?}: expected Err({}), got Ok({:?})",
                lineno + 1,
                spec,
                expected,
                report,
            ),
        }
        checked += 1;
    }
    assert!(checked > 0, "no fixture lines were exercised");
}

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
        // resolve_env_filter is crate-internal; we exercise it via init
        // indirectly in defaults.rs. Here, verify the translator
        // fallback at least does what we promise when called manually.
        let report = directives_from_legacy_categories(None, "", Level::INFO).unwrap();
        assert_eq!(report.directive, "info");
    });
}

#[test]
fn shekyl_log_value_roundtrips_through_translator() {
    with_env(&[(SHEKYL_LOG_ENV, Some("wallet.wallet2:DEBUG"))], || {
        let spec = std::env::var(SHEKYL_LOG_ENV).unwrap();
        let report: TranslationReport =
            directives_from_legacy_categories(None, &spec, Level::WARN).unwrap();
        assert_eq!(report.directive, "wallet::wallet2=debug");
    });
}

// NOTE: No test currently exercises `dev-env-fallback` end-to-end.
// `filter::resolve_env_filter` is crate-internal and the only public
// path through it (`init`) installs a process-global subscriber, which
// makes a "does RUST_LOG still work under the feature?" test brittle
// against integration-test file-sharing. Rather than carry an empty
// placeholder that would lie about coverage, we intentionally leave
// the feature to be covered by a dedicated harness once one of the
// binaries actually ships the flag behind a conditional compile.
