// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Served fee ladder: raw `C` times three rungs, relay admission, and the
//! fee lattice.
//!
//! ```text
//! F(h)      = max(1, R · C(h) · w_ref / M²)   // economy == relay floor
//! standard  = 4F
//! priority  = max(2 · R · C / M, 4F)
//! C(h)      = (1−σ) · M_r / (1−b)             // raw, SCALE units
//! M         = max(long-term median, Zm)
//! paid      = quantized_fee(weight, rung)      // the lattice, once
//! ```
//!
//! [`relay_floor_from`] and [`fee_ladder_from`] are the one composition of
//! these from a block's operands ([`FeeOperands`]); the chain-rules crate
//! reads the operands off the chain. The daemon multiplies by raw `C`
//! (FL-R20) and nothing on the served path rounds (FL-R21). The one rounding a payer meets is the lattice
//! ([`FEE_QUANTIZATION_MASK`]): the wallet rounds `weight × rate` up to it,
//! and [`relay_floor_admits`] requires the same multiple of the window's
//! lowest floor.

pub mod correction;
pub mod floor;
pub mod ladder;
pub mod quantization;
pub mod relay;

pub use correction::{fee_correction, FeeCorrection};
pub use floor::{
    fee_correction_at, fee_ladder_from, relay_floor_from, FeeOperands,
    RELAY_FLOOR_REFERENCE_TX_WEIGHT,
};
pub use ladder::{
    checked_corrected_fee_ladder, corrected_fee_ladder, FeeLadder, EMISSION_CLAIM_FEE_FLOOR,
};
pub use quantization::{quantized_fee, FEE_DECIMAL_PLACES, FEE_QUANTIZATION_MASK};
pub use relay::{
    checked_relay_fee_floor, relay_fee_floor, relay_floor_admits, RELAY_ADMISSION_SLACK_BP,
    RELAY_FLOOR_LOOKBACK, RELAY_FLOOR_WINDOW,
};
