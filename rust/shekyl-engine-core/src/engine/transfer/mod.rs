// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transfer / pending-tx workflow ([`LocalPendingTx`]).
//!
//! Extracted from the former monofile `engine/local_pending_tx.rs` per
//! `docs/design/ENGINE_COMPOSITION_DECOMPOSITION.md`. The compatibility
//! shim at [`crate::engine::local_pending_tx`] re-exports the surface that
//! other modules historically imported from that path.
//!
//! Per [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`] §5.0.1 and
//! `V3_ENGINE_TRAIT_BOUNDARIES.md` §2.4, [`LocalPendingTx`] aggregates
//! a `Signer`, an `OutputSelector`, a `FeeEstimator`, a `LedgerEngine`
//! handle, the diagnostic sink, and reservation state under a `Mutex`.

mod types;
mod support;
mod engine;
mod trait_impl;

#[cfg(test)]
mod transfer_pending_tx_tests;

pub use engine::LocalPendingTx;
pub(crate) use types::{
    ConsumerHeldEntry, RescanRequest,
};
