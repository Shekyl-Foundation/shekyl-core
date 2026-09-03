// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared C2-R1b vectors for the ruled fork-choice comparison and the
//! CEN-D5 alt-window selection
//! (`docs/design/CONSENSUS_C2_R1_REORG.md` §4b, ratified 2026-09-03),
//! consumed from `docs/test_vectors/FORK_CHOICE_V1.json`.
//!
//! There is ONE implementation of each rule —
//! [`shekyl_difficulty::fork_choice`] and
//! [`shekyl_difficulty::alt_window_plan`], which the C++ block-connect
//! machinery consumes through `shekyl_difficulty_fork_choice` /
//! `shekyl_difficulty_alt_window_plan`. This file pins both natively
//! over every vector section; the C++ suite
//! (`tests/unit_tests/fork_choice_vectors.cpp`) pins the same sections
//! end-to-end through the FFI boundary. Two consumers, one
//! implementation, one vector file — drift between the native and
//! boundary views cannot pass both.

use shekyl_difficulty::{alt_window_plan, fork_choice, ForkChoiceVerdict};

const VECTOR_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/test_vectors/FORK_CHOICE_V1.json"
);

fn load_vectors() -> serde_json::Value {
    let raw = std::fs::read_to_string(VECTOR_PATH)
        .unwrap_or_else(|e| panic!("missing fork-choice vectors at {VECTOR_PATH}: {e}"));
    serde_json::from_str(&raw).expect("FORK_CHOICE_V1.json is not valid JSON")
}

fn u64_field(case: &serde_json::Value, key: &str) -> u64 {
    case[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is a u64 in every case"))
}

fn u128_of(case: &serde_json::Value, lo_key: &str, hi_key: &str) -> u128 {
    (u128::from(u64_field(case, hi_key)) << 64) | u128::from(u64_field(case, lo_key))
}

#[test]
fn fork_choice_cases_pin_the_rule() {
    let v = load_vectors();
    let cases = v["fork_choice_cases"]["cases"]
        .as_array()
        .expect("fork_choice_cases.cases is an array");
    assert!(!cases.is_empty(), "vector file lost its fork-choice cases");
    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let verdict = fork_choice(
            u128_of(case, "current_lo", "current_hi"),
            u128_of(case, "alternative_lo", "alternative_hi"),
            case["checkpoint_match"]
                .as_bool()
                .expect("checkpoint_match"),
        );
        let expected = match u64_field(case, "verdict") {
            0 => ForkChoiceVerdict::KeepCurrent,
            1 => ForkChoiceVerdict::Switch,
            other => panic!("{name}: unknown expected verdict {other}"),
        };
        assert_eq!(verdict, expected, "case {name}");
    }
}

#[test]
fn alt_window_cases_pin_the_selection() {
    let v = load_vectors();
    let window = v["constants"]["window_entries"]
        .as_u64()
        .expect("window_entries");
    let cases = v["alt_window_cases"]["cases"]
        .as_array()
        .expect("alt_window_cases.cases is an array");
    assert!(!cases.is_empty(), "vector file lost its alt-window cases");
    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let bei_height = u64_field(case, "bei_height");
        let plan = alt_window_plan(
            bei_height,
            u64_field(case, "alt_len"),
            u64_field(case, "first_alt_height"),
        );
        if case["refused"].as_bool().expect("refused flag") {
            assert!(plan.is_err(), "case {name}: expected refusal");
            continue;
        }
        let plan = plan.unwrap_or_else(|e| panic!("case {name}: unexpected refusal {e}"));
        assert_eq!(
            plan.main_start,
            u64_field(case, "main_start"),
            "case {name}"
        );
        assert_eq!(plan.main_stop, u64_field(case, "main_stop"), "case {name}");
        assert_eq!(
            plan.alt_take_newest,
            u64_field(case, "alt_take"),
            "case {name}"
        );
        // The window invariant, re-asserted on the vector's own arithmetic.
        assert_eq!(
            (plan.main_stop - plan.main_start) + plan.alt_take_newest,
            window.min(bei_height),
            "case {name}: plan violates the window invariant"
        );
    }
}
