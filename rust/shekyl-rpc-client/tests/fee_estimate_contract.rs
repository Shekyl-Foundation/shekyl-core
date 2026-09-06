// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `get_fee_estimate`'s reply, read through the shared wire type.
//!
//! **Why this file exists.** `Rpc::get_fee_rate` used to declare its own
//! `FeeResponse` with a required scalar `fee`. RK-5b removed that field from
//! the wire — the handler had set it to `fees[0]`, so it carried nothing —
//! and nothing failed: the daemon's oracle vectors and parity tests all live
//! in `shekyl-rpc-types` and `shekyl-daemon-rpc`, and a hand-rolled struct in
//! a third crate is invisible to every one of them. It would have broken the
//! wallet's fee path at runtime against a 3.27 daemon.
//!
//! The structural fix is that `get_fee_rate` now reads
//! `shekyl_rpc_types::GetFeeEstimateResponse`, so the next field change is a
//! compile error rather than a parse failure. This file pins what a shared
//! type does not: that the *captured daemon reply* — the same vector the
//! daemon's own parity suite reads — parses through the client's type, and
//! that a reply still carrying the retired scalar is refused rather than
//! tolerated. The priority-to-tier mapping is a private function covered by
//! a unit test in `lib.rs`; this file claims neither more nor less than it
//! asserts, which the first draft of this comment did not.

use shekyl_rpc_types::{FeeTier, GetFeeEstimateResponse};

/// The vector the daemon's own parity suite pins, parsed by the client's
/// type. Same file, both directions — which is the only reason this is a
/// contract rather than two crates agreeing with themselves.
const V2: &str = include_str!("../../shekyl-rpc-types/tests/vectors/rpc/get_fee_estimate_v2.json");

#[test]
fn the_daemons_captured_reply_parses_and_carries_four_tiers() {
    let reply: GetFeeEstimateResponse =
        serde_json::from_str(V2).expect("the 3.27 reply must parse through the shared type");
    assert!(reply.status.is_ok());
    let tiers = [
        FeeTier::Low,
        FeeTier::Normal,
        FeeTier::Medium,
        FeeTier::High,
    ];
    // Ascending and distinct: a mapping that collapsed two tiers, or an
    // estimator that returned the same number four times, would make the
    // tier choice unobservable in every other test.
    let values: Vec<u64> = tiers.iter().map(|t| reply.fees.get(*t)).collect();
    assert!(
        values.windows(2).all(|w| w[0] < w[1]),
        "tiers must ascend: {values:?}"
    );
}

/// A reply still carrying the retired `fee` scalar is refused.
///
/// `GetFeeEstimateResponse` is `deny_unknown_fields`, so a daemon that had
/// not taken RK-5b is a named parse error rather than a field silently
/// ignored. This is the assertion that makes the removal real in both
/// directions: the client cannot quietly keep talking to a 3.26 daemon and
/// compute from a scalar the tiers were supposed to replace.
#[test]
fn a_reply_still_carrying_the_retired_scalar_is_refused() {
    let mut doc: serde_json::Value = serde_json::from_str(V2).unwrap();
    doc.as_object_mut()
        .unwrap()
        .insert("fee".to_owned(), serde_json::json!(20));
    let err = serde_json::from_value::<GetFeeEstimateResponse>(doc)
        .expect_err("the retired scalar must not deserialize");
    assert!(err.to_string().contains("fee"), "{err}");
}
