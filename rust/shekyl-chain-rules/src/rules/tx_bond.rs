// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.J, the bond-state rows on a serve-credit vin
//! (`CHAIN_RULES_SLICE_8.md` §5 row 3): the named persona has a bond record
//! (CEN-J4), the credited epoch is at or past the first the persona may
//! serve (CEN-J5, `E ≥ join + 1`), and the persona is `good_through` it
//! (CEN-J6). Three rows over **one view read per vin**,
//! [`ChainView::bond_record`], in the C++'s order — `check_tx_inputs`
//! reads the record (`get_archival_bond_hybrid_pubkey`), then its join
//! epoch against `shekyl_archival_serve_credit_epoch_ok`, then
//! `archival_bond_good_through`, which is the retention crate's
//! [`good_through`] over the record's intervals (`blockchain.cpp`, the
//! serve-credit arm; `db_lmdb.cpp`, `archival_bond_good_through_ffi`).
//!
//! **The record is read off the view the block is judged against**, as the
//! C++ reads it off the DB before the block (`check_tx_inputs` runs before
//! `add_block`). A join listed in the same block as the credit has not yet
//! written its record, so the credit is refused here on J4 — the C++'s
//! answer. The archival fold's in-block sequencing (`archival/inputs.rs`,
//! `apply_input` through `post`) saw such a join; until this module every
//! fixture pair in three crates relied on that admission, and the C++ never
//! gave it (slice 8 row 3's finding; the fixtures moved in the commit
//! before this one). The fold's L7 arm stays as the backstop beneath J4
//! (`STORE_INVARIANT_REGISTER.md` SI-15 is the store's belt beneath both).
//!
//! What these rows do **not** read: no credit count or pass bit (CEN-G7's
//! duplicate pass and the store's `pass_count`), no pruned record (CEN-J2,
//! CEN-J10), no window (CEN-J7: `H_close` and the seal, Slice C). A vin the
//! crate's one parse cannot read is CEN-J1's (Slice C) and, until then,
//! L7's at the fold; this module skips it rather than refusing it under a
//! row whose statement is about a record, not about bytes.
//!
//! The witness for J5 and J6, and for every accept, is a **driven chain** —
//! the ingest driver's `Persona::join` / `serve_credit` through `connect` —
//! never a constructed record: `MockChain` holds no bonds by policy
//! (`harness.rs`, `archival_reads!(empty)`; DRS-E4 §5.2, *No `Mock*`
//! archival state*). That policy is exactly J4's negative, so J4's refusal
//! and the three rows' vacuity off-class are the unit tests here
//! (`tx_bond_tests.rs`); the store witnesses J4 over a `Bond`-stubbed
//! session (`archival_write_tests`, ARW-9).

use shekyl_archival_retention::{good_through, serve_credit_epoch_ok};
use shekyl_types::PCanonicalId;
use shekyl_wire::Input;

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::rules::body::ArchivalKey;
use crate::rules::tx::TxClass;
use crate::rules::{Rule, TxContext};
use crate::verdict::{InvalidBlock, Locus, Verdict};
use crate::view::ChainView;

/// CEN-J4: the persona a serve-credit vin names has a bond record on the
/// view. The C++'s `get_archival_bond_hybrid_pubkey` miss; the fold's L7
/// is the backstop beneath it.
pub(crate) struct J4;

impl Rule for J4 {
    const ROW: CenRow = CenRow::J4;
}

/// CEN-J5: the credited settlement epoch is at or past `E_first = join + 1`
/// — [`serve_credit_epoch_ok`] over the record's `join_settlement_epoch`,
/// the function the C++ calls through `shekyl_archival_serve_credit_epoch_ok`.
/// Runs before J6 because [`good_through`] is also false below `E_first`,
/// and the row that names the reason is this one.
pub(crate) struct J5;

impl Rule for J5 {
    const ROW: CenRow = CenRow::J5;
}

/// CEN-J6: the persona is `good_through` the credited epoch —
/// [`good_through`] over the record's `bad_intervals`, the function the
/// C++ calls through `shekyl_archival_good_through`. A record with an open
/// bad interval (a slash not yet reinstated from) fails here; so does a
/// closed one that covers `E`.
pub(crate) struct J6;

impl Rule for J6 {
    const ROW: CenRow = CenRow::J6;
}

const ROWS: [CenRow; 3] = [J4::ROW, J5::ROW, J6::ROW];

/// CEN-J4, CEN-J5 and CEN-J6 as one sequence over every serve-credit vin of
/// a [`TxClass::ServeCreditOnly`] transaction, in vin order, one
/// [`ChainView::bond_record`] read each. A transaction of any other class
/// records the three rows vacuous (no credit vin to judge; H6 has already
/// refused a mixed shape). A refusal names the vin ([`Locus::Input`]).
///
/// # Errors
///
/// The view's fault, from the record read.
pub(crate) fn judge_serve_credit_bond<'id, V: ChainView<'id>>(
    cx: &TxContext<'_>,
    view: &V,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<()>, V::Fault> {
    if matches!(cx.class, TxClass::ServeCreditOnly { .. }) {
        for (input, item) in cx.tx.prefix.inputs.iter().enumerate() {
            if !matches!(item, Input::ServeCredit { .. }) {
                continue;
            }
            // A vin that does not parse is J1's (Slice C), module docs.
            let Some(ArchivalKey::ServeCredit { p, epoch, .. }) = ArchivalKey::of(item) else {
                continue;
            };
            let locus = Locus::Input {
                slot: cx.slot,
                input,
            };
            let Some(record) = view.bond_record(&PCanonicalId::from_bytes(p))? else {
                return Ok(Err(InvalidBlock::new(J4::ROW, locus)));
            };
            // The retention predicates take the raw epochs (an FFI-shaped
            // surface the C++ calls too); the typed record is read here and
            // unwrapped at this edge only.
            let join = record.join_settlement_epoch.to_raw();
            if !serve_credit_epoch_ok(epoch, join) {
                return Ok(Err(InvalidBlock::new(J5::ROW, locus)));
            }
            if !good_through(join, epoch, &record.bad_intervals) {
                return Ok(Err(InvalidBlock::new(J6::ROW, locus)));
            }
        }
    }
    for row in ROWS {
        coverage.insert(row);
    }
    Ok(Ok(()))
}

#[cfg(test)]
#[path = "tx_bond_tests.rs"]
mod tx_bond_tests;
