// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Served fee ladder: raw `C` times three rungs, plus relay admission.
//!
//! ```text
//! F(h)      = max(1, R · C(h) · w_ref / M²)   // economy == relay floor
//! standard  = 4F
//! priority  = max(2 · R · C / M, 4F)
//! C(h)      = (1−σ) · M_r / (1−b)             // raw, SCALE units
//! M         = max(long-term median, Zm)
//! ```
//!
//! Quantized `C_q` / hysteresis live in [`correction`] for the wallet-cap
//! bound and the derivation instrument. They are not the served scalar
//! (FL-R20). PR C deletes them from the instrument.

pub mod correction;
pub mod ladder;
pub mod relay;

pub use correction::{
    fee_correction, fee_correction_quantized, hysteresis_fold, hysteresis_settled, hysteresis_step,
    quantize_pow2_ceil, FeeCorrection,
};
pub use ladder::{
    checked_corrected_fee_ladder, corrected_fee_ladder, round_money_up_2, FeeLadder,
    EMISSION_CLAIM_FEE_FLOOR,
};
pub use relay::{
    checked_relay_fee_floor, relay_fee_floor, relay_floor_admits, RELAY_ADMISSION_SLACK_BP,
    RELAY_FLOOR_LOOKBACK, RELAY_FLOOR_WINDOW,
};
