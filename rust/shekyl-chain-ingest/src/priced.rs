// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a forged transaction pays (`CHAIN_FORGE.md` §11.4).
//!
//! The fee is the one the daemon would ask of it: the economy rung it
//! serves for the block that lists it ([`Scenario::connecting_economy_rate`](crate::scenario::Scenario::connecting_economy_rate)),
//! on the fee lattice, over the transaction's own weight, the weight
//! carrying the fee's varint (`shekyl_tx_weight::converge_fee_by`, the
//! wallet's loop).
//!
//! A seeded transaction is built **once**. Its randomness is keyed to the
//! plan, so building it again at another fee would sign a second message
//! with the same nonces, which the spender's seeds forbid
//! (`shekyl_harness_spender::SpendSeeds`). The weight is measured instead
//! on a sizing build of the same shape from the OS's randomness, which is
//! never listed: proof, key and signature sizes are fixed by the shape, so
//! the two weigh the same at one fee, and [`assert_priced`] holds the
//! seeded build to it.

use shekyl_wire::Transaction;

/// The fee a sizing build is built at. Any fee would do: it reaches the
/// weight only through its varint, which [`fee_at`] accounts for.
pub const SIZING_FEE: u64 = 0;

/// The fee a transaction shaped as `sized` pays at `rate` per weight:
/// the lattice price of its weight at that fee (`sized` was built at its
/// own fee, which reaches the weight only through its varint).
///
/// # Panics
///
/// If the price does not fit in `u64`: no forged transaction weighs that
/// much at any rate a chain serves.
#[must_use]
pub fn fee_at(sized: &Transaction, rate: u64) -> u64 {
    let measured = u64::try_from(sized.weight()).expect("a weight fits u64");
    shekyl_tx_weight::converge_fee_by(
        |fee| shekyl_tx_weight::weight_at_fee(measured, sized.fee(), fee),
        0,
        |weight| shekyl_economics::quantized_fee(weight, rate),
    )
    .expect("a forged transaction's fee is priceable")
}

/// Hold `built`, the seeded transaction listed, to the price its sizing
/// build set at `rate`: it pays [`fee_at`] and weighs what `sized` weighs
/// at that fee.
///
/// # Panics
///
/// If either does not hold: the seeded build's shape is not the sizing
/// build's, so its fee was priced for another weight.
pub fn assert_priced(built: &Transaction, sized: &Transaction, rate: u64) {
    let fee = fee_at(sized, rate);
    let measured = u64::try_from(sized.weight()).expect("a weight fits u64");
    assert_eq!(built.fee(), fee, "the listed transaction pays its price");
    assert_eq!(
        u64::try_from(built.weight()).ok(),
        shekyl_tx_weight::weight_at_fee(measured, sized.fee(), fee),
        "the listed transaction weighs what its sizing build weighs at its fee"
    );
}
