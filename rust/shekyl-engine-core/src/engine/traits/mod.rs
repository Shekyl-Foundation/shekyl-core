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
//! surface independently reviewable while the colocation lets §6.1
//! `Mock*` test-support implementors find their contract in one place.
//!
//! [`Engine<S>`]: super::Engine
//! [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`]: ../../../../docs/V3_ENGINE_TRAIT_BOUNDARIES.md
//! [`docs/FOLLOWUPS.md`]: ../../../../docs/FOLLOWUPS.md

pub(crate) mod daemon;

pub(crate) use daemon::{DaemonEngine, FeeEstimates, TxSubmitOutcome};
