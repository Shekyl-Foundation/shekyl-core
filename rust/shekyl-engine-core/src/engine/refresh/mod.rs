// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Snapshot-merge refresh **orchestrator**.
//!
//! Split by concern so the FILE ratchet measures workflow modules, not a
//! mixed types+handle+task+driver blob:
//!
//! - `types` — snapshot, options, summary, progress, merge-retry budget
//! - `handle` — [`RefreshHandle`]
//! - `task` — the spawned producer (`run_refresh_task`)
//! - `driver` — [`crate::engine::Engine::refresh`] / [`crate::engine::Engine::start_refresh`]
//!
//! Per C5 of `docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md` §7.X, the
//! producer body lives in `LocalRefresh::produce_scan_result` (the
//! production `RefreshEngine` implementor). This module owns the
//! **orchestration** layer:
//!
//! - [`crate::engine::Engine::refresh`] (the sync entry point) and
//!   [`crate::engine::Engine::start_refresh`] / [`RefreshHandle`] (the async entry
//!   point) drive the producer behind the trait surface;
//! - the snapshot-merge-with-retry loop in `Engine::refresh_with`
//!   takes a fresh [`LedgerSnapshot`] per attempt, hands it to the
//!   producer, and merges the result via
//!   [`crate::engine::Engine::apply_scan_result`] under the merge guard;
//! - the merge surfaces [`crate::engine::RefreshError::ConcurrentMutation`] on
//!   snapshot race; the retry loop pulls a fresh snapshot and tries
//!   again up to `opts.max_retries` times. Exhaustion always carries
//!   the race that spent the budget ([`MergeRetry`] makes a
//!   race-less fall-through unrepresentable);
//! - [`crate::engine::RefreshError::InternalInvariantViolation`] surfaces
//!   orchestrator control-flow contract failures (e.g. the producer
//!   task dropped the completion oneshot without delivery);
//! - producer-side terminal errors (cancellation, daemon-IO budget,
//!   malformed-block rejection) propagate to the caller via the
//!   trait's per-implementor `Self::Error` mapped through
//!   `From<LocalRefreshError> for RefreshError` (see
//!   `crate::engine::local_refresh`).
//!
//! See `docs/V3_WALLET_DECISION_LOG.md`
//! (`Snapshot-merge-with-retry semantics for Engine::refresh`,
//! 2026-04-26) for the substrate the orchestrator is built on.
//!
//! The producer does not mutate wallet state. The merge is the single
//! audited mutation point; see the merge module's docstring for the
//! invariant gates.

mod driver;
mod handle;
mod task;
mod types;

pub use handle::RefreshHandle;
pub use types::{
    LedgerSnapshot, RefreshOptions, RefreshPhase, RefreshProgress, RefreshReorgEvent,
    RefreshSummary,
};

pub(crate) use types::{derive_snapshot_id, membership_rebuilding, summarize, MergeRetry};

#[cfg(test)]
pub(crate) use types::{snapshot_id_preimage, SNAPSHOT_ID_CUSTOMIZATION};

// The single-flight primitive lives in its own module now that
// `start_refresh` and `start_rescan` both claim it; re-exported here so
// existing `refresh::RefreshSlot` paths (notably `Engine`'s field type in
// `engine/mod.rs`) keep resolving.
pub(crate) use super::refresh_slot::{RefreshSlot, SlotGuard};

#[cfg(test)]
#[path = "refresh_driver_tests.rs"]
mod refresh_driver_tests;

#[cfg(test)]
#[path = "refresh_handle_tests.rs"]
mod refresh_handle_tests;

#[cfg(test)]
#[path = "start_refresh_integration_tests.rs"]
mod start_refresh_integration_tests;
