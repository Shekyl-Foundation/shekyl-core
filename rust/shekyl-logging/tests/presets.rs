// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! End-to-end integration harness for the five numeric-preset strings.
//!
//! Without this test a translator could produce a syntactically-valid
//! directive that `EnvFilter` parses but that silently filters nothing
//! (or everything), and every translator unit test would still pass.
//! Here we actually run the subscriber path: for each preset, we install
//! an `EnvFilter` with the directive string from the matching fixture
//! file, then query `tracing::enabled!` for each `(target, level)` pair
//! in a fixed matrix and assert the expected suppression pattern.
//!
//! Chore #1 substitutes this for the stressnet coverage that only
//! arrives in Chore #2 when the C++ shim pipes logs through the
//! translator.

use tracing::{Level, Subscriber};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;

/// The exhaustive list of tracing targets this test queries.
///
/// **Deliberately static.** Sourced from the corpus dump of every
/// `SHEKYL_DEFAULT_LOG_CATEGORY` definition under `src/` at Chore #1
/// authorship time, plus the preset-embedded names (`global`,
/// `logging`, `msgwriter`, `stacktrace`, `verify`, `serialization`,
/// `perf`, and the `net`/`daemon.rpc` children).
///
/// Do NOT regenerate this list from a live `rg` — that would let a
/// brand-new module's tracing target silently change preset-conformance
/// test behavior. Updating this list is an explicit diff-review event.
///
/// The `tracing::enabled!` macro requires a string-literal target, so
/// the list has to live in the `check_enabled!` macro below. The
/// constant here exists for review convenience.
#[allow(dead_code)]
const CATEGORIES: &[&str] = &[
    "global",
    "net",
    "net::http",
    "net::ssl",
    "net::p2p",
    "net::cn",
    "daemon::rpc",
    "daemon::rpc::payment",
    "verify",
    "serialization",
    "stacktrace",
    "logging",
    "msgwriter",
    "perf",
    "perf::build_tree",
    "blockchain",
    "blockchain::db",
    "blockchain::db::lmdb",
    "wallet",
    "wallet::wallet2",
    "wallet::mms",
    "txpool",
    "daemon",
    "rpc",
    "cn",
    "levin",
    "p2p",
    "miner",
    "hardfork",
    "mnemonic",
];

fn build_subscriber(directive: &str) -> impl Subscriber + Send + Sync + 'static {
    let env_filter = EnvFilter::try_new(directive)
        .unwrap_or_else(|e| panic!("directive {directive:?} failed to parse: {e}"));
    tracing_subscriber::registry().with(env_filter)
}

// `tracing::enabled!` needs a literal target. We expand checks via
// hand-rolled calls for each entry in CATEGORIES. Tedious, but honest.
macro_rules! check_enabled {
    ($results:expr, $level:expr) => {{
        check_enabled!(@target $results, $level, "global");
        check_enabled!(@target $results, $level, "net");
        check_enabled!(@target $results, $level, "net::http");
        check_enabled!(@target $results, $level, "net::ssl");
        check_enabled!(@target $results, $level, "net::p2p");
        check_enabled!(@target $results, $level, "net::cn");
        check_enabled!(@target $results, $level, "daemon::rpc");
        check_enabled!(@target $results, $level, "daemon::rpc::payment");
        check_enabled!(@target $results, $level, "verify");
        check_enabled!(@target $results, $level, "serialization");
        check_enabled!(@target $results, $level, "stacktrace");
        check_enabled!(@target $results, $level, "logging");
        check_enabled!(@target $results, $level, "msgwriter");
        check_enabled!(@target $results, $level, "perf");
        check_enabled!(@target $results, $level, "perf::build_tree");
        check_enabled!(@target $results, $level, "blockchain");
        check_enabled!(@target $results, $level, "blockchain::db");
        check_enabled!(@target $results, $level, "blockchain::db::lmdb");
        check_enabled!(@target $results, $level, "wallet");
        check_enabled!(@target $results, $level, "wallet::wallet2");
        check_enabled!(@target $results, $level, "wallet::mms");
        check_enabled!(@target $results, $level, "txpool");
        check_enabled!(@target $results, $level, "daemon");
        check_enabled!(@target $results, $level, "rpc");
        check_enabled!(@target $results, $level, "cn");
        check_enabled!(@target $results, $level, "levin");
        check_enabled!(@target $results, $level, "p2p");
        check_enabled!(@target $results, $level, "miner");
        check_enabled!(@target $results, $level, "hardfork");
        check_enabled!(@target $results, $level, "mnemonic");
    }};
    (@target $results:expr, $level:expr, $target:literal) => {
        $results.push((
            $target,
            $level,
            tracing::enabled!(target: $target, $level),
        ));
    };
}

fn collect_matrix() -> Vec<(&'static str, Level, bool)> {
    let mut out = Vec::with_capacity(CATEGORIES.len() * 5);
    check_enabled!(out, Level::ERROR);
    check_enabled!(out, Level::WARN);
    check_enabled!(out, Level::INFO);
    check_enabled!(out, Level::DEBUG);
    check_enabled!(out, Level::TRACE);
    out
}

fn matrix_under(directive: &str) -> Vec<(&'static str, Level, bool)> {
    let subscriber = build_subscriber(directive);
    let mut result = Vec::new();
    tracing::subscriber::with_default(subscriber, || {
        result = collect_matrix();
    });
    result
}

fn enabled_for(matrix: &[(&'static str, Level, bool)], target: &str, level: Level) -> bool {
    matrix
        .iter()
        .find(|(t, l, _)| *t == target && *l == level)
        .map(|(_, _, enabled)| *enabled)
        .unwrap_or_else(|| panic!("target/level not in matrix: {target:?}/{level:?}"))
}

// The match arms for LEVEL 3 and LEVEL 4 currently point at fixture
// files whose contents are identical (both degenerate to `trace`); the
// files are kept distinct so that Chore #2 can diverge LEVEL 3 without
// a rename. Silence the clippy complaint accordingly.
#[allow(clippy::match_same_arms)]
fn load_fixture(level: u8) -> String {
    let content = match level {
        0 => include_str!("fixtures/preset_level_0.expected"),
        1 => include_str!("fixtures/preset_level_1.expected"),
        2 => include_str!("fixtures/preset_level_2.expected"),
        3 => include_str!("fixtures/preset_level_3.expected"),
        4 => include_str!("fixtures/preset_level_4.expected"),
        _ => panic!("level out of range"),
    };
    content.trim().to_owned()
}

// -----------------------------------------------------------------------
// Behavioral tests
// -----------------------------------------------------------------------

/// LEVEL 0 — the wallet-rpc / daemon production default.
#[test]
fn preset_level_0_behavior() {
    let m = matrix_under(&load_fixture(0));

    // Un-overridden targets: WARN and above emit.
    assert!(enabled_for(&m, "blockchain", Level::WARN));
    assert!(!enabled_for(&m, "blockchain", Level::INFO));

    // Net overrides: only ERROR emits.
    assert!(enabled_for(&m, "net", Level::ERROR));
    assert!(!enabled_for(&m, "net", Level::WARN));
    assert!(enabled_for(&m, "net::p2p", Level::ERROR));
    assert!(!enabled_for(&m, "net::p2p", Level::WARN));

    // `global` opts up to INFO.
    assert!(enabled_for(&m, "global", Level::INFO));
    assert!(!enabled_for(&m, "global", Level::DEBUG));

    // Preset self-instrumentation at INFO.
    assert!(enabled_for(&m, "logging", Level::INFO));
    assert!(enabled_for(&m, "msgwriter", Level::INFO));
}

/// LEVEL 1 — general info tier, perf subtree at DEBUG.
#[test]
fn preset_level_1_behavior() {
    let m = matrix_under(&load_fixture(1));

    assert!(enabled_for(&m, "blockchain", Level::INFO));
    assert!(!enabled_for(&m, "blockchain", Level::DEBUG));
    assert!(enabled_for(&m, "perf", Level::DEBUG));
    assert!(enabled_for(&m, "perf::build_tree", Level::DEBUG));
    assert!(!enabled_for(&m, "perf", Level::TRACE));
}

/// LEVEL 2 — bare `debug`.
#[test]
fn preset_level_2_behavior() {
    let m = matrix_under(&load_fixture(2));

    assert!(enabled_for(&m, "wallet", Level::DEBUG));
    assert!(!enabled_for(&m, "wallet", Level::TRACE));
    assert!(enabled_for(&m, "logging", Level::DEBUG));
}

/// LEVEL 3 / LEVEL 4 — bare `trace` for Chore #1.
#[test]
fn preset_levels_3_and_4_behavior() {
    for level in [3u8, 4u8] {
        let m = matrix_under(&load_fixture(level));
        for target in ["wallet", "net::p2p", "logging"] {
            assert!(
                enabled_for(&m, target, Level::TRACE),
                "LEVEL {level}: {target} TRACE should be enabled",
            );
        }
    }
}

// -----------------------------------------------------------------------
// Structural tests
// -----------------------------------------------------------------------

/// Preset fixture contents must all parse through `EnvFilter::try_new`.
#[test]
fn all_preset_fixtures_parse_as_envfilter() {
    for level in 0..=4u8 {
        let d = load_fixture(level);
        EnvFilter::try_new(&d).unwrap_or_else(|e| {
            panic!("preset_level_{level}.expected directive {d:?} failed to parse: {e}")
        });
    }
}

/// The translator's numeric-preset output must equal the expected-file
/// contents byte-for-byte.
#[test]
fn translator_numeric_presets_equal_fixtures() {
    for level in 0..=4u8 {
        let spec = level.to_string();
        let report = shekyl_logging::directives_from_legacy_categories(None, &spec, Level::WARN)
            .unwrap_or_else(|e| panic!("LEVEL {level} failed: {e:?}"));

        let expected = load_fixture(level);
        assert_eq!(
            report.directive.as_str(),
            expected,
            "LEVEL {level} directive drifted from fixture"
        );
    }
}
