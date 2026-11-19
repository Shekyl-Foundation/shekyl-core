// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! DEMO ONLY (Brief C): this scratch pull request relies on the base's
//! value; a merge that changes it leaves this pull request red against
//! the new base, which the freshness re-test must report.

#[test]
fn the_demo_value_is_one() {
    assert_eq!(shekyl_sp_t3_spike::FRESHNESS_DEMO, 1);
}
