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
const V4: &str = include_str!("../../shekyl-rpc-types/tests/vectors/rpc/get_fee_estimate_v4.json");

#[test]
fn the_daemons_captured_reply_parses_and_carries_three_tiers() {
    let reply: GetFeeEstimateResponse =
        serde_json::from_str(V4).expect("the 3.57 reply must parse through the shared type");
    assert!(reply.status.is_ok());
    let tiers = [FeeTier::Low, FeeTier::Normal, FeeTier::High];
    // Every named tier buys a different rate. A mapping that collapsed two
    // of them would make the tier choice unobservable in every other test.
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
    // Built from V4, not V2: a V2 base would be refused for its four-slot
    // array as well as the scalar, and this test would pass while no
    // longer isolating the subject it names.
    let mut doc: serde_json::Value = serde_json::from_str(V4).unwrap();
    doc.as_object_mut()
        .unwrap()
        .insert("fee".to_owned(), serde_json::json!(20));
    let err = serde_json::from_value::<GetFeeEstimateResponse>(doc)
        .expect_err("the retired scalar must not deserialize");
    assert!(err.to_string().contains("fee"), "{err}");
}

/// A reply still carrying the retired `quantization_mask` is refused
/// (3.57). The lattice is `shekyl_economics::FEE_QUANTIZATION_MASK`, read
/// by this client's fee arithmetic and by the daemon's admission alike; a
/// daemon that still serves one is not read as a lattice to pay on.
#[test]
fn a_reply_still_carrying_the_retired_mask_is_refused() {
    let mut doc: serde_json::Value = serde_json::from_str(V4).unwrap();
    doc.as_object_mut()
        .unwrap()
        .insert("quantization_mask".to_owned(), serde_json::json!(8));
    let err = serde_json::from_value::<GetFeeEstimateResponse>(doc)
        .expect_err("the retired mask must not deserialize");
    assert!(err.to_string().contains("quantization_mask"), "{err}");
}
