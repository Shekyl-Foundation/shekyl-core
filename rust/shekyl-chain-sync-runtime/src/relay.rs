// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A relayed tip as a compact announcement (2008), and the fan-out that
//! relays it and a bundle (2015, [`crate::bundles`]).
//!
//! The block and its bundle references, and no transactions. The owner
//! sends that announcement to every established session but the supplier,
//! and to every established session when no session supplied it. The model
//! has already decided that the block is relayed. A bundle goes by the same
//! fan-out once the queue has admitted it.

use shekyl_chain_rules::AtHeight;
use shekyl_chain_store::store::{ChainStore, StoreError};
use shekyl_levin::{BlockCompleteEntry, NewCompactBlock};
use shekyl_p2p_session::{Encoded, Established};
use shekyl_types::BlockHash;

use crate::session::Session;

/// `block_weight` of zero is omitted on the wire. A relay does not claim
/// a weight; the receiver forms the block.
const OMITTED_BLOCK_WEIGHT: u64 = 0;

/// The main chain's block `hash` as one 2008, or `None` when `hash` is
/// not on main.
pub(crate) fn announcement(
    store: &ChainStore,
    hash: &BlockHash,
) -> Result<Option<NewCompactBlock>, StoreError> {
    let snap = store.begin_read()?;
    let Some(height) = snap.height_of(hash)? else {
        return Ok(None);
    };
    let AtHeight::Recorded(body) = snap.block(height)? else {
        return Ok(None);
    };
    let bundle_references = match snap.bundle_references_at(height)? {
        AtHeight::Recorded(Some(references)) => references.into_inner(),
        _ => Vec::new(),
    };
    let current_blockchain_height = snap
        .tip()?
        .recorded
        .map_or(0, |tip| tip.height.to_raw().saturating_add(1));
    Ok(Some(NewCompactBlock {
        b: BlockCompleteEntry {
            pruned: false,
            block: body.block.serialize(),
            block_weight: OMITTED_BLOCK_WEIGHT,
            txs: Vec::new(),
            bundle_references,
        },
        current_blockchain_height,
    }))
}

/// Send `encoded` to every established session but `from`. With no `from`
/// it goes to every established session. A refused send is the session
/// layer's close, not sync's.
pub(crate) fn fan_out<'a>(
    sessions: impl IntoIterator<Item = (&'a Session, &'a Established)>,
    from: Option<Session>,
    encoded: &Encoded,
) {
    for (session, handle) in sessions {
        if Some(*session) != from {
            let _sent = handle.send_encoded(encoded);
        }
    }
}
