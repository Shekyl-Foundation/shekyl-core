// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! User-authored, crash-atomic ledger mutations that are **not** transfer,
//! scan, or stake pipelines (`ENGINE_COMPOSITION_DECOMPOSITION.md` §2).
//!
//! These ops share a mechanical shape (one ledger write guard → mutate →
//! `drive_persistence` → fail-closed rollback) and a product shape (local
//! UX / journal intent the chain cannot reconstruct). They are grouped here
//! so the composition root (`engine/mod.rs`) registers **one** workflow
//! tree rather than accreting a top-level `pub mod` per small operation.
//!
//! | Module | Surface |
//! |--------|---------|
//! | [`abandon_tx`] | Send-journal abandon (P3-4 / SJ-DQ-8) |
//! | [`set_tx_note`] | Per-txid annotation (SJ-DQ-7) |
//!
//! Inherent `Engine` methods still live on the orchestrator type (same as
//! `payment_requests` / `message_signing`'s thin façade); this directory is
//! ownership of the **workflow code**, not a second type parameter on
//! `Engine`.

pub mod abandon_tx;
pub mod set_tx_note;

pub use abandon_tx::{AbandonTxError, AbandonTxOutcome};
pub use set_tx_note::SetTxNoteError;
