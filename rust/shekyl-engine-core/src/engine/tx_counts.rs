// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bounded transaction input/output counts — **re-export shim**.
//!
//! [`InputCount`] / [`OutputCount`] were hoisted to `shekyl-tx-weight` alongside
//! the weight predictor they bound (§12.3 D-1, so `shekyl-economics-sim` shares
//! one single-sourced weight model). This module re-exports them so every
//! in-crate `use super::tx_counts::{InputCount, OutputCount}` and the crate's
//! public re-export (`lib.rs`) stay byte-identical — the move is invisible to
//! every consumer outside the hoist commit (wallet-rpc's fee methods, the FFI).
//! Their semantics (`1..=MAX_INPUTS` / `1..=MAX_OUTPUTS`, `clamped` at the
//! fee-path boundary) are documented at their new home.

pub use shekyl_tx_weight::{InputCount, OutputCount};
