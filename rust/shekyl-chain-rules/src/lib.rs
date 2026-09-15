// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Consensus validation (`shekyl-chain-rules`, DRS-E6).
//!
//! One crate, one home for every consensus rule the C++ spread across
//! `blockchain.cpp`, `tx_pool.cpp`, `cryptonote_core.cpp` and the LMDB layer.
//! Input: a candidate block, a `ChainView<'id>` (narrow, read-only trait over
//! **recorded** chain facts), a `RuleSet`. Output: `ChainValid<'id, V>` or
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
//! refuses either token in `Cargo.toml`; `check_chain_rules_no_store.sh`
//! (`rust-audit-test.yml`) refuses either package anywhere in the resolved
//! `cargo tree` closure (the only one of the three that sees *transitive*
//! arrival).
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
//! store's `WriteBatch<'_, 'id>` and takes a `ChainValid<'id, V>` — `V` its
//! own view type — into `connect`.
//! Increments 2+ port the 141 surface-free rules one census subsystem at a
//! time (`DAEMON_REDB_STORE.md` §7.5.2 table 3), flipping entries to
//! `implemented(...)` as they land.
//!
//! # Consumers
//!
//! * **Block connect** (S-CHAIN-W): [`validate`] over the store's projected
//!   `ChainView<'id>`; the `ChainValid<'id, V>` it mints is the only thing
//!   `connect` accepts, branded with both the batch `'id` and the view type
//!   `V` so an unbranded impl cannot satisfy `connect`.
//! * **Pool admission** (DRS-E5): the *same* [`tx_form`] / [`tx_against`]
//!   over a `PoolView` the pool defines by decorating a `ChainView` with its
//!   unconfirmed set. There is no second validator
//!   (`CONSENSUS_C2_R8_STORE_PLACEMENT.md` §9.1).
//! * **Replay** (DRS-E2): every C++-accepted block through [`validate`]. A
//!   disagreement is routed through `shekyl_chain_store::conformance::grade`
//!   keyed by [`Row::as_str`] — where a Rust refusal of a canonical block on
//!   a DIVERGENT row is the *expected* outcome and agreement is the failure.
//!   This crate never imports the grader; the harness that does lives with
//!   the replay.
//!
//! # Faults are not verdicts
//!
//! A view's substrate can fail to answer. That is [`ChainView::Fault`], an
//! associated type the crate never inspects, returned as the *outer* `Err`
//! of [`validate`] and [`tx_against`]: `Result<Verdict<_>, V::Fault>`.
//! [`tx_form`] has no view and no outer fault. A refusal is the
//! inner `Err`, an [`InvalidBlock`] naming its [`CenRow`]. The two never
//! meet — a store error cannot become a refusal by `?`, by `From`, or by a
//! hand-written arm (`check_store_error_conversion_ban.py` holds the last of
//! those) — and a height above the tip is an [`AtHeight::AboveTip`] the rule
//! must match, not an `Option` it can propagate away.

#![deny(unsafe_code)]

mod block;
mod census;
mod coverage;
mod rule_set;
mod validate;
mod verdict;
mod view;

/// The negative-fixture harness (§8.2). Test-only: an in-memory `ChainView`
/// with the `assert_refused` / `boundary_pair` idiom every rule test uses.
#[cfg(test)]
mod harness;

pub use block::{Candidate, ValidatedBlock};
pub use census::{CenRow, Flag, PolicyRow, Row, RowStatus};
pub use coverage::{Coverage, PolicyCoverage, RuleCoverage};
pub use rule_set::{AdmissionPolicy, AdmissionPolicyId, RuleSchedule, RuleSet, RuleSetId};
pub use validate::{tx_against, tx_form, validate};
pub use verdict::{refused, ChainValid, InvalidBlock, Locus, TxSlot, Verdict};
pub use view::{AtHeight, ChainView, RecordedBlock};
