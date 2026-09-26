// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The three reads the curve-tree writer's derivation consumes (DRS-E3,
//! `DRS_E3_CURVE_WRITER.md` §3.1–§3.4), the fifth sibling of `chain_reads`,
//! `output_reads`, `tx_reads` and `curve_reads`. Each is what
//! `shekyl_chain_rules::ChainView` asks the store for and nothing the store
//! computes for itself:
//!
//! - [`frontier`] — the tree as the next grow needs it: `curve_tree_meta`'s
//!   leaf count and, for every layer, the **last** chunk's hash from
//!   `curve_tree_layers`. Which chunk is last is
//!   [`TreeFrontier::last_chunk_indices`]'s arithmetic, so the reader and
//!   the grower cannot disagree about it. A layer whose last chunk is
//!   absent is **SI-12**'s family — the summary and the layer table
//!   disagree — raised as [`StoreInvariant::CellCorrupt`] on the layer
//!   table.
//! - [`leaf_count_at`] — `curve_tree_leaf_counts[h]`, keyed exactly as
//!   `curve_tree_roots[h]` is (SCW-19): the count *going into* block `h`.
//!   `0` at height `0` by definition, `AboveTip` past `tip + 1`, and an
//!   absent row in between is SI-7 (`CellCorrupt { Absent }`) — the row is
//!   written on every connect (SI-18), so its absence is a hole.
//! - [`outputs_at`] — the recorded block at `h`'s outputs as leaf sources,
//!   coinbase and listed halves apart, each in output order. Assembled
//!   from what the store already holds: the block body names the
//!   transactions, `tx_indices` locates each, `tx_outputs` gives its
//!   global indices (`SOK-2`: one bucket, so the amount index *is* the
//!   global index), `output_amounts` gives key and commitment, and the
//!   `0x07` leaf field of the transaction's own pruned bytes gives `CM`.
//!   No table stores this set (CTW-10): the C++ `locked_outputs` was a
//!   stored view of exactly this function, and a stored view of facts the
//!   store already holds is a query (§3.7).
//!
//! All three are generic over [`ReadTables`] so the batch view and a
//! committed snapshot read the same rows under the same absence rule.

use redb::ReadableTable;
use shekyl_chain_rules::{AtHeight, BlockOutputs, LeafSource, TreeFrontier};
use shekyl_types::{BlockHeight, GlobalOutputIndex};
use shekyl_wire::tx_extra::{admitted_leaf_blob, parse, pqc_leaf_entries_per_output};
use shekyl_wire::Transaction;

use crate::codec::{BlockInfo, CodecError};
use crate::ids::{ChunkIndex, LayerChunk, OutputSlot, TreeLayer};
use crate::schema::{CURVE_TREE_LAYERS, CURVE_TREE_LEAF_COUNTS, OUTPUT_AMOUNTS};

use super::at_index::AtIndex;
use super::chain_reads::{self, absent, undecodable, ReadFault, ReadTables};
use super::curve_reads;
use super::error::StoreInvariant;
use super::tx_reads;

const LAYERS: &str = "curve_tree_layers";
const LEAF_COUNTS: &str = "curve_tree_leaf_counts";

/// The frontier the next grow starts from (module docs).
pub(super) fn frontier<T: ReadTables>(txn: &T) -> Result<TreeFrontier, ReadFault> {
    let leaf_count = curve_reads::summary(txn)?.leaf_count.to_raw();
    let layers = txn.table(CURVE_TREE_LAYERS)?;
    let mut last_chunks = Vec::new();
    for (layer, chunk) in TreeFrontier::last_chunk_indices(leaf_count) {
        let key = LayerChunk::new(TreeLayer::from_raw(layer), ChunkIndex::from_raw(chunk)).key();
        let Some(guard) = layers.get(key)? else {
            return Err(absent(LAYERS));
        };
        let hash = guard
            .value()
            .decode()
            .map_err(|cause| undecodable(LAYERS, cause))?;
        last_chunks.push(*hash.as_bytes());
    }
    Ok(TreeFrontier {
        leaf_count,
        last_chunks,
    })
}

/// The leaf count going into block `height` (module docs).
pub(super) fn leaf_count_at<T: ReadTables>(
    txn: &T,
    height: BlockHeight,
) -> Result<AtHeight<u64>, ReadFault> {
    let h = height.to_raw();
    if h == 0 {
        return Ok(AtHeight::Recorded(0));
    }
    match chain_reads::tip_of(txn)? {
        Some((tip, _)) if h <= tip.saturating_add(1) => {}
        _ => return Ok(AtHeight::AboveTip),
    }
    let count = chain_reads::cell(txn, CURVE_TREE_LEAF_COUNTS, h, LEAF_COUNTS)?
        .ok_or_else(|| absent(LEAF_COUNTS))?;
    Ok(AtHeight::Recorded(count.to_raw()))
}

/// The recorded block at `height`'s outputs as leaf sources (module docs).
pub(super) fn outputs_at<T: ReadTables>(
    txn: &T,
    tip: Option<&(u64, BlockInfo)>,
    height: BlockHeight,
) -> Result<AtHeight<BlockOutputs>, ReadFault> {
    let (_, block) = match chain_reads::block_body(txn, tip, height.to_raw())? {
        AtHeight::Recorded(body) => body,
        AtHeight::AboveTip => return Ok(AtHeight::AboveTip),
    };
    let miner_hash = block.miner_transaction.txid_parts().hash;
    let coinbase = sources_of(txn, &block.miner_transaction, &miner_hash)?;
    let mut listed = Vec::new();
    for hash in &block.transaction_hashes {
        let Some(record) = tx_reads::record_at(txn, hash)? else {
            // A hash the block body names is a transaction the connect
            // recorded (SI-3's other direction); its absence is a hole.
            return Err(absent("tx_indices"));
        };
        let tx = Transaction::read(&mut record.pruned.as_bytes())
            .map_err(|_| pruned_invalid("pruned segment does not decode"))?;
        listed.extend(sources_of(txn, &tx, hash)?);
    }
    Ok(AtHeight::Recorded(BlockOutputs { coinbase, listed }))
}

/// One transaction's outputs as leaf sources: its recorded global indices
/// paired with the recorded key and commitment, and the `CM` point of each
/// output's `0x07` entry.
fn sources_of<T: ReadTables>(
    txn: &T,
    tx: &Transaction,
    hash: &shekyl_types::TxHash,
) -> Result<Vec<LeafSource>, ReadFault> {
    let Some(location) = tx_reads::location_at(txn, hash)? else {
        return Err(absent("tx_indices"));
    };
    let indices = match tx_reads::output_indices_at(txn, location.id)? {
        AtIndex::Recorded(indices) => indices.0,
        AtIndex::BeyondCount => return Err(absent("tx_outputs")),
    };
    let n_outputs = tx.prefix.outputs.len();
    if indices.len() != n_outputs {
        return Err(pruned_invalid(
            "tx_outputs row disagrees with the output count",
        ));
    }
    let fields = parse(&tx.prefix.extra).map_err(|_| pruned_invalid("extra does not parse"))?;
    let blob = admitted_leaf_blob(&fields, n_outputs)
        .map_err(|_| pruned_invalid("extra carries no admitted leaf field"))?;
    let entries = pqc_leaf_entries_per_output(&blob)
        .map_err(|_| pruned_invalid("leaf field is not whole entries"))?;
    if entries.len() != n_outputs {
        return Err(pruned_invalid("leaf field disagrees with the output count"));
    }
    let outputs_table = txn.table(OUTPUT_AMOUNTS)?;
    let mut sources = Vec::with_capacity(n_outputs);
    for (index, entry) in indices.into_iter().zip(entries) {
        // SOK-2: one bucket, so the amount index is the global index.
        let output = GlobalOutputIndex::from_raw(index.to_raw());
        let slot = OutputSlot::confidential(output);
        let Some(guard) = outputs_table.get(slot.key())? else {
            return Err(ReadFault::Invariant(StoreInvariant::IdNotFresh));
        };
        let record = guard
            .value()
            .decode()
            .map_err(|cause| undecodable("output_amounts", cause))?;
        if record.output_id.to_raw() != output.to_raw() {
            return Err(ReadFault::Invariant(StoreInvariant::IdNotFresh));
        }
        let mut pqc_leaf_commitment = [0u8; 32];
        pqc_leaf_commitment.copy_from_slice(&entry[..32]);
        sources.push(LeafSource {
            output,
            key: record.pubkey.to_bytes(),
            commitment: record.commitment.to_bytes(),
            pqc_leaf_commitment,
        });
    }
    Ok(sources)
}

fn pruned_invalid(reason: &'static str) -> ReadFault {
    undecodable(
        "txs_pruned",
        CodecError::Invalid {
            codec: "transaction",
            reason,
        },
    )
}
