// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared C2-R3 boundary vectors for the ruled timestamp rule
//! (`docs/completed/CONSENSUS_C2_R3_TIMESTAMPS.md` §4.3, ratified
//! 2026-09-01), consumed from
//! `docs/test_vectors/MTP_BOUNDARY_V1.json`.
//!
//! The same file drives the C++ unit test
//! (`tests/unit_tests/mtp_boundary.cpp`) against the live C++ validator's
//! rule function — two implementations of one consensus rule that do not
//! share vectors drift silently. This side pins the rewrite's predicates:
//! [`shekyl_difficulty::is_above_mtp`] (`predicate_cases`) and
//! [`shekyl_difficulty::is_timestamp_below_ftl`] (`ftl_cases`).
//! `assembly_cases` (genesis-timestamp window padding) gain their Rust
//! consumer when the rewrite grows window assembly at the C3 cutover; the
//! C++ side consumes them today.

use shekyl_difficulty::consts::MTP_WINDOW_USIZE;
use shekyl_difficulty::{is_above_mtp, is_timestamp_below_ftl};

const VECTOR_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/test_vectors/MTP_BOUNDARY_V1.json"
);

fn load_vectors() -> serde_json::Value {
    let raw = std::fs::read_to_string(VECTOR_PATH)
        .unwrap_or_else(|e| panic!("missing boundary vectors at {VECTOR_PATH}: {e}"));
    serde_json::from_str(&raw).expect("MTP_BOUNDARY_V1.json is not valid JSON")
}

fn window_from(case: &serde_json::Value) -> [u64; MTP_WINDOW_USIZE] {
    let raw: Vec<u64> = case["window"]
        .as_array()
        .expect("window is an array")
        .iter()
        .map(|v| v.as_u64().expect("window entries are u64"))
        .collect();
    raw.try_into().unwrap_or_else(|v: Vec<u64>| {
        panic!("predicate windows are exactly 11 wide, got {}", v.len())
    })
}

/// Every `predicate_cases` row must match `is_above_mtp` exactly —
/// including the `== median` boundary rows, which are the consensus fork
/// line this round ruled.
#[test]
fn predicate_cases_match_is_above_mtp() {
    let doc = load_vectors();
    let cases = doc["predicate_cases"]["cases"]
        .as_array()
        .expect("predicate_cases.cases");
    assert!(!cases.is_empty(), "vector file lost its predicate cases");

    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let window = window_from(case);
        let candidate = case["candidate"].as_u64().expect("candidate");
        let expected = case["verdict"].as_bool().expect("verdict");

        assert_eq!(
            is_above_mtp(candidate, &window),
            expected,
            "predicate case `{name}`: candidate {candidate} vs window {window:?}"
        );

        // The vector file also pins the median itself (sorted index 5);
        // assert the pin is self-consistent with the strict boundary so a
        // vector edit cannot silently decouple `median` from `verdict`.
        let median = case["median"].as_u64().expect("median");
        assert_eq!(
            expected,
            candidate > median,
            "predicate case `{name}`: verdict/median self-consistency"
        );
    }
}

/// Every `ftl_cases` row must match `is_timestamp_below_ftl` exactly,
/// including the `local_clock + 540` boundary row.
#[test]
fn ftl_cases_match_is_timestamp_below_ftl() {
    let doc = load_vectors();
    let cases = doc["ftl_cases"]["cases"]
        .as_array()
        .expect("ftl_cases.cases");
    assert!(!cases.is_empty(), "vector file lost its FTL cases");

    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let candidate = case["candidate"].as_u64().expect("candidate");
        let local_clock = case["local_clock"].as_u64().expect("local_clock");
        let expected = case["verdict"].as_bool().expect("verdict");

        assert_eq!(
            is_timestamp_below_ftl(candidate, local_clock),
            expected,
            "FTL case `{name}`: candidate {candidate} vs local clock {local_clock}"
        );
    }
}

// ---------------------------------------------------------------------------
// Combined-rule coverage (C2-R3 crossing): `check_timestamp_rule` is the ONE
// implementation of the ruled sentence, exported to the C++ validator via
// shekyl-ffi. Every vector section gets its native consumer here — including
// `assembly_cases` (genesis padding), which previously had only the C++ side.

use shekyl_difficulty::{check_timestamp_rule, TimestampRuleVerdict};

/// Predicate cases through the combined rule: exact 11-window, FTL held out
/// of play (local_clock = candidate), verdict Ok / NotAboveMedian per the
/// pinned bool, and the pinned median must round-trip.
#[test]
fn predicate_cases_match_combined_rule() {
    let doc = load_vectors();
    let cases = doc["predicate_cases"]["cases"]
        .as_array()
        .expect("predicate_cases.cases");
    assert!(!cases.is_empty());

    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let window = window_from(case);
        let candidate = case["candidate"].as_u64().expect("candidate");
        let expected = case["verdict"].as_bool().expect("verdict");

        let (verdict, median) = check_timestamp_rule(candidate, &window, 0, candidate);
        assert_eq!(case["median"].as_u64().expect("median"), median, "{name}");
        let want = if expected {
            TimestampRuleVerdict::Ok
        } else {
            TimestampRuleVerdict::NotAboveMedian
        };
        assert_eq!(want, verdict, "{name}");
    }
}

/// Assembly cases natively: fewer than 11 predecessors are right-padded
/// with the genesis timestamp inside the rule (C2-R3-Q2).
#[test]
fn assembly_cases_pad_with_genesis_timestamp() {
    let doc = load_vectors();
    let cases = doc["assembly_cases"]["cases"]
        .as_array()
        .expect("assembly_cases.cases");
    assert!(!cases.is_empty());

    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let history: Vec<u64> = case["history_newest_first"]
            .as_array()
            .expect("history is an array")
            .iter()
            .map(|v| v.as_u64().expect("history entries are u64"))
            .collect();
        let genesis_ts = case["genesis_ts"].as_u64().expect("genesis_ts");
        let candidate = case["candidate"].as_u64().expect("candidate");
        let expected = case["verdict"].as_bool().expect("verdict");

        let (verdict, median) = check_timestamp_rule(candidate, &history, genesis_ts, candidate);
        assert_eq!(case["median"].as_u64().expect("median"), median, "{name}");
        let want = if expected {
            TimestampRuleVerdict::Ok
        } else {
            TimestampRuleVerdict::NotAboveMedian
        };
        assert_eq!(want, verdict, "{name}");
    }
}

/// FTL cases through the combined rule: `AboveFtl` iff the FTL half fails
/// (zero window keeps the MTP half out of the way for future candidates),
/// and the median out-value is the padded window's on the FTL arm too.
#[test]
fn ftl_cases_match_combined_rule() {
    let doc = load_vectors();
    let cases = doc["ftl_cases"]["cases"]
        .as_array()
        .expect("ftl_cases.cases");
    assert!(!cases.is_empty());

    let zero_window = [0u64; 11];
    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let candidate = case["candidate"].as_u64().expect("candidate");
        let local_clock = case["local_clock"].as_u64().expect("local_clock");
        let ftl_ok = case["verdict"].as_bool().expect("verdict");

        let (verdict, median) = check_timestamp_rule(candidate, &zero_window, 0, local_clock);
        assert_eq!(!ftl_ok, verdict == TimestampRuleVerdict::AboveFtl, "{name}");
        assert_eq!(0, median, "{name}");
    }
}

/// A window wider than 11 is refused with a zero median — the newest-11
/// selection is the caller's job (C2-R3-Q1 sub-a).
#[test]
fn wider_window_is_refused() {
    let too_wide = [5u64; 12];
    let (verdict, median) = check_timestamp_rule(999, &too_wide, 0, 999);
    assert_eq!(TimestampRuleVerdict::WindowTooWide, verdict);
    assert_eq!(0, median);
}

/// The template-edge premise on the one implementation: at
/// `median == local_clock + FTL` no timestamp satisfies both bounds, and
/// one clock tick later the same bump is valid (the refusal arm in the C++
/// template orchestration rests on exactly this).
#[test]
fn template_edge_no_timestamp_satisfies_both_bounds() {
    let clock = 1_000_000u64;
    let edge_median = clock + 540;
    let edge_window = [edge_median; 11];

    let (v1, m1) = check_timestamp_rule(clock, &edge_window, 0, clock);
    assert_eq!(TimestampRuleVerdict::NotAboveMedian, v1);
    assert_eq!(edge_median, m1);
    let (v2, _) = check_timestamp_rule(edge_median + 1, &edge_window, 0, clock);
    assert_eq!(TimestampRuleVerdict::AboveFtl, v2);
    let (v3, _) = check_timestamp_rule(edge_median + 1, &edge_window, 0, clock + 1);
    assert_eq!(TimestampRuleVerdict::Ok, v3);
}
