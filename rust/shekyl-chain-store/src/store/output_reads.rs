// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One read body for the output tables (S-OUT-KI O1 / O2,
//! `DRS_E1_SOUT_KI.md` §3.2–§3.3), the sibling of `chain_reads` for
//! `output_amounts` and `output_txs`.
//!
//! # Bound first, then the row
//!
//! Output ids are dense (SI-9): `output_id` is `output_txs`' entry count at
//! write time, and under one bucket `amount_index` equals it. So the count
//! is the **authority** on which indices exist, and every read classifies
//! the index against it *before* touching a row — the `AtHeight` discipline,
//! where a height is classified against the tip before `block_info` is
//! opened. Reading the row first and classifying its absence afterwards
//! would let a stray row at or beyond the count be served as
//! [`AtIndex::Recorded`], when the contract says that range is
//! [`AtIndex::BeyondCount`] (PR #783 review).
//!
//! What each outcome means, stated once:
//!
//! - `index >= count` → [`AtIndex::BeyondCount`]. No row is read.
//! - `index < count`, row absent → **SI-9** ([`StoreInvariant::IdNotFresh`]):
//!   the count and the keys disagree — a hole, never an absence a caller
//!   would read as "not yet".
//! - row present, bytes do not decode → **SI-7**
//!   (`CellCorrupt { Undecodable }`), as for every typed cell.
//! - `output_amounts[(0, i)]` present but its `output_id` is not `i` →
//!   **SI-9**: the join the record carries disagrees with the key it sits
//!   under. `connect` refuses to write that (SOK-2's belt); a raw or corrupt
//!   file can still contain it, and serving it would hand out the wrong
//!   output under a global index. The join is validated where the record is
//!   decoded, so the projection ([`RecordedOutput`]) can leave `output_id`
//!   out honestly.
//!
//! # The bucket is named, not spelled
//!
//! Every key is an [`OutputSlot`]; the read surface resolves a
//! [`GlobalOutputIndex`] to [`OutputSlot::confidential`], which is the one
//! place the "one bucket" premise (§3.4) is code.

use redb::{ReadableTable, ReadableTableMetadata};
use shekyl_types::{BlockHeight, CommitmentBytes, GlobalOutputIndex, OneTimePubkey};

use crate::codec::OutTx;
use crate::ids::OutputSlot;
use crate::schema::{OUTPUT_AMOUNTS, OUTPUT_TXS};

use super::at_index::AtIndex;
use super::chain_reads::{undecodable, ReadFault, ReadTables};
use super::error::StoreInvariant;

/// The stored record of one output, as [`ReadSnapshot::output`](super::ReadSnapshot::output)
/// returns it: one-time pubkey, commitment, recording height — LMDB's
/// `output_data_t` minus its `unlock_time`. `OutKey` minus its join key and
/// that field: the join was **validated** against the slot where the record
/// was decoded (module docs), so the projection carries what a consumer
/// needs and nothing it would have to re-check. A read projection, never stored, so not
/// `Canonical`. The live consumer is the path builder's `read_output_oc`,
/// which wants the pubkey **and** the commitment (SOK-7).
///
/// **No `unlock_time`** (S-TX STX-9, landed with the S-TX increment): the
/// stored `OutKey` row carries it and this read decodes that row, but no
/// public read type under `store/` hands the field out — its fate is census
/// U-2's, and this projection had no consumer of it. Gated by
/// `scripts/ci/check_store_unlock_time_projection.py`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordedOutput {
    /// The output's one-time public key (`O`).
    pub pubkey: OneTimePubkey,
    /// The amount commitment (`C`).
    pub commitment: CommitmentBytes,
    /// The height of the block that created the output.
    pub height: BlockHeight,
}

/// Where `index` sits relative to the dense count. The mirror of
/// `chain_reads::HeightClass`, for the second dense index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IndexClass {
    /// Below the count: a row must exist.
    Within,
    /// At or beyond the count: nothing has been recorded there.
    Beyond,
}

/// Classify `index` against `count`. One comparison, so the two reads
/// cannot disagree on where "beyond" begins.
pub(super) const fn class_of(count: u64, index: GlobalOutputIndex) -> IndexClass {
    if index.to_raw() < count {
        IndexClass::Within
    } else {
        IndexClass::Beyond
    }
}

/// The dense count: `output_txs`' length, the unique-key primary that
/// `output_id` is dense in (SI-9). Under one bucket `output_amounts` has
/// the same count, and SOK-2's belt at every connect is what keeps that
/// true — so one table is the authority and the other is checked against
/// it, never the reverse.
pub(super) fn output_count<T: ReadTables>(txn: &T) -> Result<u64, ReadFault> {
    Ok(txn.table(OUTPUT_TXS)?.len()?)
}

/// SI-9 for a read: the count and the keys disagree.
const fn not_dense() -> ReadFault {
    ReadFault::Invariant(StoreInvariant::IdNotFresh)
}

/// **O1.** The stored record at `index`, bound first (module docs).
pub(super) fn output_at<T: ReadTables>(
    txn: &T,
    index: GlobalOutputIndex,
) -> Result<AtIndex<RecordedOutput>, ReadFault> {
    if let IndexClass::Beyond = class_of(output_count(txn)?, index) {
        return Ok(AtIndex::BeyondCount);
    }
    // The primary must be present below the count before a side row is
    // served (PR #800 review, the same admission `tx_reads::admit` takes):
    // `output_txs` is the count's authority, and a hole in it at `index` is
    // the count lying — SI-9 — whatever `output_amounts` holds there.
    if txn.table(OUTPUT_TXS)?.get(index.to_raw())?.is_none() {
        return Err(not_dense());
    }
    let slot = OutputSlot::confidential(index);
    let table = txn.table(OUTPUT_AMOUNTS)?;
    let Some(guard) = table.get(slot.key())? else {
        return Err(not_dense());
    };
    let record = guard
        .value()
        .decode()
        .map_err(|cause| undecodable("output_amounts", cause))?;
    // The join the record carries must be the slot it sits under: with one
    // bucket, `output_id == amount_index` (SOK-2). Validated here, once, so
    // the projection below can omit it.
    if record.output_id.to_raw() != slot.index().to_raw() {
        return Err(not_dense());
    }
    Ok(AtIndex::Recorded(RecordedOutput {
        pubkey: record.pubkey,
        commitment: record.commitment,
        height: record.height,
    }))
}

/// **O2.** Which transaction created the output at `index`, and at which
/// `vout` position — the `_from_global` read, `output_txs[output_id]`, one
/// lookup, bound first (module docs). Returns [`OutTx`] as it exists
/// (SOK-Q4).
pub(super) fn origin_at<T: ReadTables>(
    txn: &T,
    index: GlobalOutputIndex,
) -> Result<AtIndex<OutTx>, ReadFault> {
    let table = txn.table(OUTPUT_TXS)?;
    if let IndexClass::Beyond = class_of(table.len()?, index) {
        return Ok(AtIndex::BeyondCount);
    }
    let Some(guard) = table.get(index.to_raw())? else {
        return Err(not_dense());
    };
    let origin = guard
        .value()
        .decode()
        .map_err(|cause| undecodable("output_txs", cause))?;
    Ok(AtIndex::Recorded(origin))
}
