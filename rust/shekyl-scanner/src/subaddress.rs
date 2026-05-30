// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Re-export shim for the canonical `SubaddressIndex` type.
//!
//! The type was promoted to [`shekyl_engine_state::subaddress`] so it can be shared
//! between the scanner (runtime state) and the wallet-file orchestrator (persisted
//! ledger blocks). This module exists only to keep the old `crate::subaddress::…`
//! import paths working during the migration; the transitional alias is removed in
//! Commit 2n together with any remaining `use crate::subaddress::…` call sites.

pub use shekyl_engine_state::subaddress::SubaddressIndex;
