// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Canonical Shekyl genesis **block/tx binary wire format** — serializer.
//!
//! This crate owns the genesis wire format end to end (block, header, the PoW
//! hashing-blob, and the transaction), per
//! `docs/design/GENESIS_TX_WIRE_FORMAT.md`. It is the clean, Shekyl-owned
//! replacement for the vendored `shekyl-oxide` block/tx/ct serializer (Decision
//! 1 / §4 of that doc); consumers migrate here and the vendored modules retire.
//!
//! ## Scope
//!
//! The full genesis tx/block surface: [`BlockHeader`], [`Block`], [`Transaction`]
//! (v3); inputs — `gen` ([`Input::Gen`]), the FCMP++ spend ([`Input::ToKey`]), and
//! the archival arms ([`Input::ServeCredit`] / [`Input::BondPost`]); the
//! `tagged_key` output ([`Output`]); both confidential sections (`Null` with its
//! committed base [`CtBase`], and `Fcmp` with tx-level [`PqcAuth`]s + [`Prunable`]);
//! the consensus hashing identities (tx/block hash + PoW blob); `tx_extra` parsing
//! ([`tx_extra`]); and structural validation ([`Transaction::validate`]).
//!
//! The coinbase `Null` section carries its committed base arrays
//! (`enc_amounts` / `enc_labels` / `outPk`) — exactly what the pre-fix
//! `shekyl-oxide` reader skipped (it returned `None` on the `Null` type byte and
//! never consumed the arrays, so `Block::read` mis-aligned and failed
//! `UnexpectedEof` on a live coinbase). The round-trip + hash KATs prove
//! byte-identity against captured daemon blobs; the FCMP++ spend is validated
//! end-to-end, in-process, by `tests/fcmp_spend_e2e.rs` — it builds a real
//! multi-layer-tree spend and self-validates every field against the consensus
//! verifier (`shekyl_fcmp::proof::verify`, RingCT balance, and the
//! Bulletproof+) before round-tripping it through this serializer. There is no
//! C++ spend oracle to capture: the daemon FCMP++ spend path never produced a
//! daemon-accepted transaction, so the authoritative oracle is the Rust
//! verifier itself, not a captured blob (see that test's module docs).
//!
//! ## Tag values
//!
//! Tags are the **genesis dense scheme** (GENESIS_TX_WIRE_FORMAT.md §2.0):
//! `gen = 0x00`, `fcmp = 0x01`, `serve_credit = 0x02`, `bond_post = 0x03`;
//! `tagged_key = 0x00`; ct `Null = 0x00`, `Fcmp = 0x01`. These match the renumbered
//! C++ oracle (the gate-(c) atomic cut — `VARIANT_TAG`s + the ct enum + the
//! regenerated genesis blocks), and the live-oracle corpus is captured on these
//! post-renumber bytes.

pub mod block;
pub mod transaction;
pub mod tx_extra;
pub mod varint;

mod bytes;
mod hash;

/// Parse-safety cap on any varint-declared length or element count read from an
/// untrusted blob — a DoS guard (bound the work before allocating/looping), **not**
/// a consensus bound: [`Transaction::validate`] enforces the tight consensus limits.
/// Shared by every count/length read across the crate so the bound has one source.
pub(crate) const READ_LEN_CAP: usize = 1_000_000;

pub use block::{Block, BlockHeader};
pub use transaction::{
    BondPost, BondPostKind, BpPlus, Ct, CtBase, Holdings, Input, Output, PqcAuth, Prunable,
    ServeCredit, Transaction, TxPrefix,
};
