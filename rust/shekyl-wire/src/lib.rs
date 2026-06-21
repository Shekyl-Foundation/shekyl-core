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
//! ## Scope of this first slice — the coinbase block
//!
//! [`BlockHeader`], [`Block`], [`Transaction`] (v3), the `gen` input
//! ([`Input::Gen`]), the `tagged_key` output ([`Output`]), and the coinbase
//! `Null` confidential section *with its committed base arrays*
//! (`enc_amounts` / `enc_labels` / `outPk`, [`CtBase`]). That base is exactly
//! what the pre-fix `shekyl-oxide` reader skipped — it returned `None` on the
//! `Null` type byte and never consumed the arrays, so `Block::read` mis-aligned
//! and failed `UnexpectedEof` on a live coinbase. The round-trip KAT
//! (`tests/coinbase_roundtrip.rs`) proves the fix against captured daemon blobs.
//!
//! Spend (`Fcmp`) transactions and the archival input arms land in later slices.
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

pub use block::{Block, BlockHeader};
pub use transaction::{
    BondPost, BpPlus, Ct, CtBase, Holdings, Input, Output, PqcAuth, Prunable, ServeCredit,
    Transaction, TxPrefix,
};
