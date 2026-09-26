// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The retry bound is a type, not a counter: `MAX_FORM_ATTEMPTS` attempts
//! exist and the last one's successor is the terminal state.

use super::*;

#[test]
fn the_attempt_sequence_is_exactly_max_long_and_ends_in_exhausted() {
    let mut attempt = FormAttempt::FIRST;
    let mut seen = vec![attempt.number()];
    while let Retry::Again(next) = attempt.next() {
        assert_eq!(next.number(), attempt.number() + 1);
        seen.push(next.number());
        attempt = next;
    }
    assert_eq!(attempt.next(), Retry::Exhausted);
    assert_eq!(seen, (1..=MAX_FORM_ATTEMPTS).collect::<Vec<_>>());
}

#[test]
fn first_is_attempt_one() {
    assert_eq!(FormAttempt::FIRST.number(), 1);
}

#[test]
fn the_bound_is_small_and_positive() {
    // Two consecutive ≥ 64-block reorgs during one admission is not organic;
    // the value is a DoS bound, not a liveness knob (rule 75 rationale on
    // the constant). A bound of 1 would make a single reorg terminal.
    assert!((2..=8).contains(&MAX_FORM_ATTEMPTS));
}

#[test]
fn display_names_the_remedy() {
    let stale = Stale::Seed {
        claimed: shekyl_types::BlockHash::NULL,
        expected: shekyl_types::BlockHash::from_bytes([1; 32]),
        retry: Retry::Exhausted,
    };
    let text = stale.to_string();
    assert!(text.contains("stale seed"), "{text}");
    assert!(text.contains("exhausted"), "{text}");
}
