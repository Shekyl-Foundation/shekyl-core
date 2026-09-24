// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Consensus validation (`shekyl-chain-rules`, DRS-E6).
//!
//! One crate, one home for every consensus rule the C++ spread across
//! `blockchain.cpp`, `tx_pool.cpp`, `cryptonote_core.cpp` and the LMDB layer.
//! Two stages: [`form`] takes a candidate block, a `RuleSet` and a
//! [`Substrate`] (clock, longhash — the world, not the chain) and yields a
//! [`StructurallyValid`], stateless and outside any transaction;
//! [`validate`] takes that, a `ChainView<'id>` (narrow, read-only trait over
//! **recorded** chain facts), the rule set in force and the node's [`Trust`]
//! (the release anchors; from slice 6, the below-anchor posture), and yields
//! `ChainValid<'id, V>` or `InvalidBlock { rule: CenRow, .. }` — or a
//! [`Fault`], which is neither. Ruled in
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
//! # Where the port stands
//!
//! Increment 1 landed the scaffold: the census registry ([`CenRow`],
//! [`PolicyRow`]), the gate that holds it to the census, and zero rules
//! (DRS-D12). Its consumer, **S-CHAIN-W**, landed next (`DAEMON_REDB_STORE.md`
//! §3.6.2): the store projects a `ChainView<'id>` from its `WriteBatch<'_,
//! 'id>` and takes a `ChainValid<'id, V>` — `V` its own view type — into
//! `connect`. Increments 2+ port the 141 surface-free rules one census
//! subsystem at a time (`DAEMON_REDB_STORE.md` §7.5.2 table 3), flipping
//! entries to `implemented(<rule type>)` as they land: slice 1
//! (`CHAIN_RULES_SLICE_1.md`) landed 4.A/4.B's six predicate rows; slice 2
//! (`CHAIN_RULES_SLICE_2.md`) landed 4.C and 4.D — the two-stage split,
//! [`Substrate`], and ten rows (C1–C3, D1, D1b, D2, D3, D4, D6, D7; D5 is
//! subsumed by D4 over an alt view and closes with slice 9); slice 3
//! (`CHAIN_RULES_SLICE_3.md`) housed `PDM-Q5`'s anchor model — the
//! release-carried [`ReleaseAnchors`], the [`Trust`] input to `validate`,
//! CEN-E1 per block and CEN-E5 at writer open (the first `enforced_at` row;
//! E2 waits on the alt view and `D_max`); slice 4 (`CHAIN_RULES_SLICE_4.md`)
//! landed 4.F's sixteen operand-complete rows — the coinbase's shape and
//! height claims as predicates at [`TxSlot::Miner`], the emission
//! definitions derived and recorded in coverage (the priced value stays
//! off the verdict until F14b's paid reward), four rows `by_construction`
//! (the first of that status), every public network's genesis pinned in
//! [`ReleaseAnchors`] — verified by equality, in no trust band — and
//! `RuleSet::mined_money_unlock_window` (the split epoch is
//! `rules::miner::EMISSION_SPLIT_EPOCH` until a schedule step names
//! another); F14/F14b/F16/F18 wait on CEN-G6's
//! median (slice 7) and F17 on the curve tree's writer (DRS-E3); slice 5
//! (`CHAIN_RULES_SLICE_5.md`) landed 4.H — the transaction on its own —
//! as the third rule class, `TxRule` over a `TxContext` (crate-private,
//! `rules/mod.rs`) whose kind is derived from the **slot**
//! (a classification that selects the rules comes from outside the thing
//! classified), seventeen rows `implemented`, five `by_construction`,
//! H19's layout half running ahead of its verification, and the wallet's
//! wire twin (`shekyl_wire::Transaction::validate`) demoted to a
//! pre-check held to [`tx_form`] by a conformance test over every one of
//! its refusal arms. Only complete coverage is parity evidence, so no
//! verdict minted before the last slice can be read as one.
//!
//! # Consumers
//!
//! * **Block connect** (S-CHAIN-W): [`form`] outside the write transaction
//!   — the ingest driver supplies the [`Substrate`] and its seed and
//!   rule-set claims — then [`validate`] inside it, over the store's
//!   projected `ChainView<'id>`; the `ChainValid<'id, V>` it mints is the
//!   only thing `connect` accepts, branded with both the batch `'id` and
//!   the view type `V` so an unbranded impl cannot satisfy `connect`. A
//!   [`Fault::Stale`] from `validate` means redo `form` (bounded by
//!   [`FormAttempt`]); a [`Fault::Corrupt`] is an invariant violation
//!   `connect` treats as its own.
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
//! of [`tx_against`] and — wrapped in [`Fault::View`] — of [`validate`].
//! [`validate`] has two more outer arms of its own ([`Fault::Stale`],
//! [`Fault::Corrupt`]; `fault.rs`): a claim the stateless stage was given
//! that the committing view refutes, and view data no conforming store
//! holds. [`form`]'s outer position is the [`Substrate`]'s fault; [`tx_form`]
//! has no view and no outer fault. A refusal is the inner `Err`, an
//! [`InvalidBlock`] naming its [`CenRow`]. None of the faults ever meets a
//! refusal — a store error or a stale claim cannot become a refusal by `?`,
//! by `From`, or by a hand-written arm (`check_store_error_conversion_ban.py`
//! holds the last of those for every fault token) — and a height above the
//! tip is an [`AtHeight::AboveTip`] the rule must match, not an `Option` it
//! can propagate away.

#![deny(unsafe_code)]

mod anchors;
mod block;
mod census;
mod coverage;
mod fault;
mod rule_set;
mod rules;
mod substrate;
mod trust;
mod validate;
mod verdict;
mod view;

/// The negative-fixture harness (§8.2): an in-memory `ChainView`
/// (`MockChain`), an environment (`MockSubstrate`), fixtures, and the
/// `assert_refused` / `boundary_pair` idiom every rule test uses.
///
/// Test-only inside this crate. Behind the `harness` feature it is also a
/// library surface for exactly one consumer — the store's mock-vs-`BatchView`
/// conformance test (slice 2 F11): the mock's fidelity to the real view is
/// a **gated property** there, not an assumption here. G1 puts that test on
/// the store side (this crate cannot name the store), so the mock travels
/// to it rather than the store to the mock. Not a production API; a normal
/// dependency enabling the feature is a review finding.
#[cfg(any(test, feature = "harness"))]
pub mod harness;

pub use anchors::{Anchor, ReleaseAnchors};
pub use block::{Candidate, StructurallyValid, TxIdentity, ValidatedBlock};
pub use census::{CenRow, Flag, PolicyRow, Row, RowStatus};
pub use coverage::{Coverage, PolicyCoverage, RuleCoverage};
pub use fault::{Corrupt, Fault, FormAttempt, Retry, Stale, ViewRead, MAX_FORM_ATTEMPTS};
pub use rule_set::{
    AdmissionPolicy, AdmissionPolicyId, DifficultyRule, RuleSchedule, RuleSet, RuleSetId,
};
pub use rules::anchors::{AnchorConflict, Remedy};
pub use rules::difficulty::Target;
pub use rules::miner::{tx_volume_window, EMISSION_SPLIT_EPOCH};
pub use rules::seed_height;
pub use rules::timestamps::mtp_median_at;
pub use substrate::Substrate;
pub use trust::Trust;
pub use validate::{form, tx_against, tx_form, validate};
pub use verdict::{refused, ChainValid, InvalidBlock, Locus, TxSlot, Verdict};
pub use view::{AtHeight, ChainView, RecordedBlock, Tip};
