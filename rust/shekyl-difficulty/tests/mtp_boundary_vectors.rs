// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared C2-R3 boundary vectors for the ruled timestamp rule
//! (`docs/design/CONSENSUS_C2_R3_TIMESTAMPS.md` §4.3, ratified
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
