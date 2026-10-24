// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The coinbase's `0x0C` draw commitment, drawn where the coinbase extra
//! is written (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §4.2;
//! `ARCHIVAL_SETTLEMENT_WRITER.md` §16.8 decision 4).
//!
//! The daemon's template builder calls `shekyl_coinbase_extra` for the
//! coinbase's extra and passes nothing about the commitment: this module
//! draws it inside that call. A witness key and a seed are drawn, committed
//! to, and dropped before the function returns, so nothing can open the
//! commitment and the block it rides in issues no draw.
//!
//! **The producer's secrets stay on this side of the boundary.** The
//! producer that keeps the pair for `W₂` blocks, reads the drawn shards and
//! files the reveal is Rust: it replaces the body of
//! [`commit_and_discard`] with a draw that also hands the pair to a Rust
//! store. The C interface does not change for it, and no secret, and no
//! commitment, becomes a C++ value (rule 36).
//!
//! The template is priced in passes, and each pass builds a coinbase, so
//! each pass draws. The last pass's coinbase is the block's. The field is
//! a fixed 32 bytes, so the passes agree on weight whatever they drew.
//! Which pass's secrets a producer keeps is that producer's question.

// The draw is `shekyl-archival-retention`'s: the Rust template producer and
// this FFI commit through one function (`DRS_X_STORE_FLIP.md` DX-Q3, Q4).
pub(crate) use shekyl_archival_retention::commit_and_discard;
