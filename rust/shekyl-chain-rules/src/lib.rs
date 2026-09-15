// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Consensus validation (`shekyl-chain-rules`, DRS-E6).
//!
//! One crate, one home for every consensus rule the C++ spread across
//! `blockchain.cpp`, `tx_pool.cpp`, `cryptonote_core.cpp` and the LMDB layer.
//! Input: a candidate block, a `ChainView<'id>` (narrow, read-only trait over
//! **recorded** chain facts), a `RuleSet`. Output: `ChainValid<'id>` or
//! `InvalidBlock { rule: CenRow, .. }` — or the view's own fault, which is
//! neither. Ruled in
//! [`CONSENSUS_C2_R8_STORE_PLACEMENT.md`](../../docs/completed/CONSENSUS_C2_R8_STORE_PLACEMENT.md)
//! §9; designed in
//! [`CHAIN_RULES_CRATE.md`](../../docs/design/CHAIN_RULES_CRATE.md).
//!
//! # No store handle
//!
//! This crate reaches neither `shekyl-chain-store` nor `redb`, directly or
//! transitively, in any dependency section. Every rule is unit-testable
//! against a mock view with no database — the capability the C++ never had
//! and the reason CEN-L11-class defects survived. The property is held three
//! ways: the two doctests below refuse a direct `use`; the coverage gate
//! refuses either token in `Cargo.toml`; the `build.yml` `cargo tree -i` belt
//! refuses either package anywhere in the resolved graph (the only one of
//! the three that sees *transitive* arrival).
//!
//! ```compile_fail
//! use redb::Database; // shekyl-chain-rules has no store engine
//! ```
//!
//! ```compile_fail
//! use shekyl_chain_store::store::ChainStore; // and no store crate
//! ```
//!
//! # Staging (rule 23: STAGED, consumer named)
//!
//! Increment 1 is the scaffold: the census registry ([`CenRow`],
//! [`PolicyRow`]) and the gate that holds it to the census. **Zero consensus
//! rules land here** (DRS-D12); every registry entry is `pending`, so the
//! gate prints `implemented 0 / enforced 153` and `0 / 9`, and only complete
//! coverage is parity evidence. The named consumer is **S-CHAIN-W**
//! (`DAEMON_REDB_STORE.md` §3.6.2): it projects a `ChainView<'id>` from the
//! store's `WriteBatch<'_, 'id>` and takes a `ChainValid<'id>` into `connect`.
//! Increments 2+ port the 141 surface-free rules one census subsystem at a
//! time (`DAEMON_REDB_STORE.md` §7.5.2 table 3), flipping entries to
//! `implemented(...)` as they land.

#![deny(unsafe_code)]

mod census;

pub use census::{CenRow, Flag, PolicyRow, Row, RowStatus};

#[cfg(test)]
#[path = "census_tests.rs"]
mod census_tests;
