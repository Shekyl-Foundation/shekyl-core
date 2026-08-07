// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! # Transfer workflow (ownership pin)
//!
//! **This module *is* the transfer / pending-tx workflow.** There is no
//! separate `TransferWorkflow` type yet — and none is required for ownership.
//! Multi-step send logic (select → assemble → sign → reserve → submit →
//! re-anchor → discard / mempool-evict) lives here as
//! [`LocalPendingTx`] + [`PendingTxEngine`](super::traits::PendingTxEngine).
//!
//! | Role | Where |
//! |------|--------|
//! | Production implementor | [`LocalPendingTx`] in this module |
//! | Trait surface | [`PendingTxEngine`](super::traits::PendingTxEngine) |
//! | Engine ownership | [`Engine`](super::Engine) holds `pending: P` (`P: PendingTxEngine`) |
//! | Compat import path | [`crate::engine::local_pending_tx`] re-exports |
//!
//! **Do not re-inflate send orchestration onto `Engine` or `lifecycle`.**
//! New multi-step transfer code lands under `engine/transfer/`. Thin
//! Engine delegates that only call `self.pending.…` are fine; new bodies
//! for `build_select_sync` / `finalize_submit_*` / `reanchor_consumer_held`
//! outside this tree fail `scripts/ci/check_engine_decomposition.sh`.
//!
//! Inside the tree the split is by phase: `engine` holds the type,
//! selection, commit, re-anchor and submit orchestration; `submit_finalize`
//! holds the §2.5 verdict dispositions (`finalize_submit_*`); `trait_impl`
//! holds the `PendingTxEngine` / `WatchdogHost` surfaces; `support` and
//! `types` hold the shared helpers and state.
//!
//! Extracted from the former monofile `engine/local_pending_tx.rs` per
//! `docs/design/ENGINE_COMPOSITION_DECOMPOSITION.md`. Policy + ratchet:
//! same doc, §"Transfer workflow ownership".
//!
//! Per [`docs/design/STAGE_1_PR_5_PENDING_TX_ENGINE.md`] §5.0.1 and
//! `V3_ENGINE_TRAIT_BOUNDARIES.md` §2.4, [`LocalPendingTx`] aggregates
//! a `Signer`, an `OutputSelector`, a `FeeEstimator`, a `LedgerEngine`
//! handle, the diagnostic sink, and reservation state under a `Mutex`.

mod engine;
mod submit_finalize;
mod support;
mod trait_impl;
mod types;

#[cfg(test)]
mod transfer_pending_tx_tests;

pub use engine::LocalPendingTx;
pub(crate) use types::{ConsumerHeldEntry, RescanRequest};
