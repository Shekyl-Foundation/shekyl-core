// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Stage 1 trait surfaces extracted from `Engine<S>`.
//!
//! Per [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`] §2, Stage 1 extracts seven
//! crate-internal traits from the monolithic [`Engine<S>`](super::Engine):
//! `KeyEngine`, `LedgerEngine`, `EconomicsEngine`, `DaemonEngine`,
//! `RefreshEngine`, `PendingTxEngine`, `PersistenceEngine`. Each trait
//! lands in its own per-trait PR per the §8.1 ordering; this module is
//! the home of the trait surfaces as they land.
//!
//! # Visibility (Round 4a — Item 13)
//!
//! Traits ship `pub(crate)` until the JSON-RPC server cutover at V3.2
//! (per the `wallet_rpc_server` follow-up in
//! [`docs/FOLLOWUPS.md`]). The traits are internal contracts of
//! `shekyl-engine-core`; consumers reach functionality via
//! [`Engine<S>`](super::Engine)'s inherent methods, not via direct
//! trait dispatch. Promoting to `pub` later is additive and does not
//! require trait-surface changes — only visibility relaxation.
//!
//! # Why traits live together rather than next to their primary
//!   implementor
//!
//! The seven trait surfaces share two cross-cutting concerns —
//! cancellation classification per §3.4.3 and the §1.6 documentation
//! discipline — that are easier to apply uniformly when the surfaces
//! are colocated. Per-trait files under `engine/traits/` keep each
//! surface independently reviewable while the colocation lets each
//! trait's contract sit alongside its siblings rather than scattered
//! across implementor crates.
//!
//! Per the §6.4 no-Mock test-substrate decision, the trait
//! implementors used in tests are the production types
//! (`LocalLedger`, `LocalKeys`, etc.) configured through their
//! `from_test_seed` / fixture constructors — **not** generated
//! `Mock*` shims. The surfaces colocate to make the shared trait
//! contract one read away from each test, not to support a
//! `Mock*`-based test substrate.
//!
//! [`Engine<S>`]: super::Engine
//! [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`]: ../../../../../docs/V3_ENGINE_TRAIT_BOUNDARIES.md
//! [`docs/FOLLOWUPS.md`]: ../../../../../docs/FOLLOWUPS.md

pub(crate) mod daemon;
pub(crate) mod key;
pub(crate) mod ledger;
pub(crate) mod pending_tx;
pub(crate) mod persistence;
pub(crate) mod refresh;

pub(crate) use daemon::{DaemonEngine, FeeEstimates, TxSubmitOutcome};
pub(crate) use ledger::LedgerEngine;
pub(crate) use pending_tx::PendingTxEngine;
pub(crate) use persistence::PersistenceEngine;
// C5 (`7140f726a`) lands the first orchestrator-side consumer of
// `RefreshEngine` per the `Engine<S, D, L, R>` parameterization in
// PR 4 §7.X; C1 (`d3edc1abb`) had landed the re-export ahead of
// C5 so subsequent commits do not pay for trait-surface access by
// absolute path. The `#[allow(unused_imports)]` C1 carried at that
// time has been live consumers since C5, so the suppression has
// been removed per `15-deletion-and-debt.mdc`'s "Default: delete"
// rule (the annotation now masks future regressions rather than
// suppressing a justified warning).
pub(crate) use refresh::RefreshEngine;
