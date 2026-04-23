// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Re-export shim for [`TransferDetails`] and friends.
//!
//! The canonical type now lives in [`shekyl_wallet_state::transfer`] so that the
//! wallet-file orchestrator can persist ledger blocks without pulling in the scanner.
//! The scanner-specific constructor `TransferDetails::from_wallet_output` is provided
//! by the [`TransferDetailsExt`] extension trait in [`crate::runtime_ext`], which
//! must be in scope for `TransferDetails::from_wallet_output(&out, h)` to resolve.

pub use shekyl_wallet_state::transfer::{FcmpPrecomputedPath, TransferDetails, SPENDABLE_AGE};
