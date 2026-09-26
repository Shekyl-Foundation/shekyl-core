// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Daemon chain store (`shekyl-chain-store`, DRS-R-19).
//!
//! This crate is the named home for the daemon's consensus store. DRS-E1
//! will grow the redb engine here. Freeze layers land as sibling modules:
//!
//! - **DRS-P0d** — [`digest_v0`]: the layout-independent logical-state
//!   digest that DRS-0 / DRS-C use as a regression oracle against
//!   production LMDB
//!   ([`docs/design/DAEMON_REDB_STORE.md`](../../docs/design/DAEMON_REDB_STORE.md)
//!   §7.1, DRS-D11, Tier-A **A2**). Transform-shaped (rule 18): defined
//!   by the function over the three v0 families, not by a stored value.
//! - **DRS-0 slice A** — [`accumulator`]: the incremental replacements
//!   for that full-domain scan, the five-token class vocabulary, and
//!   the per-table write contracts the Rust port must honour.
//! - **DRS-0 slice B** — [`schema`] / [`lmdb_order`]: one redb
//!   `TableDefinition` per censused LMDB table, with the key types that
//!   reproduce LMDB order. Table types encode ordering; domain identity
//!   (`BlockHash` vs `TxHash` vs key image) converts at the engine API.
//!
//! - **DRS-E1 increment 1** — [`store`]: lifecycle and the write-transaction
//!   surface (S-TXN). The write handle is a possession type: table access
//!   goes through it (never a raw transaction), a second live batch is a
//!   typed error rather than a deadlock, and drop aborts. Durability,
//!   two-phase commit, and cache size are declared constants, not library
//!   defaults by omission.
//! - **DRS-E1 increment 2** — [`codec`], [`family_set`], [`provenance`],
//!   and the store header. [`codec::Canonical`] is the one encoding a
//!   value is stored under *and* the digest folds (§11.1(b)), with a
//!   committed fixture snapshot per codec gating it under rule 42. The
//!   store seals [`codec::SCHEMA_VERSION`] into a fresh file's first
//!   transaction and refuses any other version on reopen (§11.1(a)). The
//!   file's [`provenance::Provenance`] — which archival applies some
//!   committed batch skipped — is persisted beside it and widened
//!   atomically with each stubbed commit, so a reopen reads the file's
//!   history instead of guessing.
//!
//! - **DRS-E1 increment 3 (S-CHAIN-W)** — the connect/pop write set
//!   (`docs/completed/DRS_E1_SCHAIN_W.md`). [`store::WriteBatch::connect`]
//!   takes the validator's `ChainValid` (brand-bound to the batch and to
//!   [`store::BatchView`], the `ChainView` projected from it) plus
//!   [`store::ConnectFacts`] — the consensus-visible values the store
//!   records and never derives, each stamped `Derived` or `PassedThrough`
//!   — and writes the 17-table set in the C++ funnel's phase order, every
//!   write a declared verb bound to its `SI-` row and journaled.
//!   [`store::WriteBatch::pop`] is the reverse replay of one
//!   [`schema::UNDO_LOG`] row (the first table with no LMDB twin, named
//!   with its reason in [`schema::RUST_ONLY_TABLES`]; tables are named by
//!   declaration ordinal, so a reorder or removal is a layout bump).
//!   [`provenance::Provenance`] has three monotone components — stubbed
//!   applies, [`codec::CoverageGaps`], [`codec::PassedThroughFacts`] — all
//!   empty ⇔ parity evidence. A store invariant on connect or pop halts
//!   the writer ([`store::ChainStore::connect_state`]). The settlement
//!   -epoch schedule is pinned in the header at create and refused on
//!   mismatch at every open.
//!
//! Slice B's table names are bijection-pinned against
//! [`accumulator::TABLE_CLASSES`] **and** against the X-macro
//! `SHEKYL_LMDB_TABLES` by `scripts/ci/check_redb_schema_bijection.py` —
//! three surfaces, all 49 mirrored tables, checked in every direction, plus
//! the Rust-only map for the tables LMDB never had. Codecs for the
//! remaining tables' values land per surface (S-CHAIN-W onward) and
//! inherit both that pin and the snapshot gate.

//!
//! # What is public here, and to whom
//!
//! [`schema`], [`codec`] and [`store`] are `pub` so the daemon's other
//! crates can reach them; they are the daemon's **internal store
//! contract**, not a supported public API. Pre-genesis, this workspace is
//! the crate's only consumer — `shekyl-ffi` is its one dependent
//! (`cargo tree -i shekyl-chain-store`) and no sibling repository names
//! it — so a table definition, a codec type or a re-export changes shape
//! when the store's own design does, and the compiler finds every caller
//! in the same PR. No compatibility surface exists and none will be
//! written for callers that do not exist (rule 15): a shim is debt with
//! no creditor. What *is* held stable is the contract those modules
//! describe on disk — `TypeName`s, codec `NAME`s and the row bytes —
//! pinned by `schemas/*.snap` and the paired `SCHEMA_VERSION` bump
//! (`DAEMON_REDB_STORE.md` §11.1(b)). `HF_VERSIONS: Coded<RuleSetInForce>`
//! is the worked example: the Rust type changed with the codec's home,
//! `shekyl::Coded<rule_set_id>` and the row bytes did not.

#![deny(unsafe_code)]

pub mod accumulator;
pub mod apply_policy;
pub mod codec;
pub mod conformance;
pub mod digest_v0;
pub mod family_set;
pub mod ids;
pub mod lmdb_order;
pub mod pool;
pub mod provenance;
pub mod schema;
pub mod store;

pub use ids::{
    AmountIndex, ChunkIndex, LayerChunk, OutputSlot, OutputStorageId, TreeLayer, TxStorageId,
};
