// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A relayed tip as a compact announcement (2008).
//!
//! The block and its attestation witness, and no transactions. The owner
//! sends that announcement to every established session but the supplier.
//! The model has already decided that the block is relayed.

use shekyl_chain_rules::AtHeight;
use shekyl_chain_store::store::{ChainStore, StoreError};
use shekyl_levin::{
    notify, BlockCompleteEntry, NewCompactBlock, PayloadError, PortableMap,
    NOTIFY_NEW_COMPACT_BLOCK,
};
use shekyl_seam::{Hub, SocketId};
use shekyl_types::BlockHash;

/// `block_weight` of zero is omitted on the wire. A relay does not claim
/// a weight; the receiver forms the block.
const OMITTED_BLOCK_WEIGHT: u64 = 0;

/// Why a relay could not be built.
pub(crate) enum Fault {
    /// The store could not be read.
    Store(StoreError),
    /// The announcement did not encode.
    Encode(PayloadError),
}

/// The main chain's block `hash` as one 2008 frame, or `None` when `hash`
/// is not on main.
pub(crate) fn announcement(store: &ChainStore, hash: &BlockHash) -> Result<Option<Vec<u8>>, Fault> {
    let snap = store.begin_read().map_err(Fault::Store)?;
    let Some(height) = snap.height_of(hash).map_err(Fault::Store)? else {
        return Ok(None);
    };
    let AtHeight::Recorded(body) = snap.block(height).map_err(Fault::Store)? else {
        return Ok(None);
    };
    let attestation_witness = match snap.attestation_witness_at(height).map_err(Fault::Store)? {
        AtHeight::Recorded(Some(witness)) => witness,
        _ => Vec::new(),
    };
    let current_blockchain_height = snap
        .tip()
        .map_err(Fault::Store)?
        .recorded
        .map_or(0, |tip| tip.height.to_raw().saturating_add(1));
    let compact = NewCompactBlock {
        b: BlockCompleteEntry {
            pruned: false,
            block: body.block.serialize(),
            block_weight: OMITTED_BLOCK_WEIGHT,
            txs: Vec::new(),
            attestation_witness,
        },
        current_blockchain_height,
    };
    let payload = compact.store().map_err(Fault::Encode)?;
    Ok(Some(notify(NOTIFY_NEW_COMPACT_BLOCK, &payload)))
}

/// Send `bytes` to every established session but `from`.
pub(crate) fn fan_out(hub: &Hub, from: SocketId, bytes: &[u8]) {
    for row in hub.board().rows() {
        if row.established() && row.id() != from {
            // A refused send is the transport's close, not sync's.
            let _sent = hub.send(row.id(), bytes.to_vec());
        }
    }
}
