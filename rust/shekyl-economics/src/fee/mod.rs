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
//! [`quantize_pow2_ceil`] is the wallet-cap ceiling (`C_q ≥ C`). The daemon
//! multiplies by raw `C` (FL-R20). The §7 hysteresis band was deleted with
//! FL-R21.

pub mod correction;
pub mod ladder;
pub mod relay;

pub use correction::{fee_correction, quantize_pow2_ceil, FeeCorrection};
pub use ladder::{
    checked_corrected_fee_ladder, corrected_fee_ladder, round_money_up_2, FeeLadder,
    EMISSION_CLAIM_FEE_FLOOR,
};
pub use relay::{
    checked_relay_fee_floor, relay_fee_floor, relay_floor_admits, RELAY_ADMISSION_SLACK_BP,
    RELAY_FLOOR_LOOKBACK, RELAY_FLOOR_WINDOW,
};
