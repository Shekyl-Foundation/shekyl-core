// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Re-export shim for the staker pool accrual types.
//!
//! See [`shekyl_engine_state::staker_pool`] for the canonical implementation.
//! This shim exists only to keep `crate::staker_pool::…` import paths working
//! during the migration; it is removed in Commit 2n.

pub use shekyl_engine_state::staker_pool::{AccrualRecord, ConservationCheck, StakerPoolState};
