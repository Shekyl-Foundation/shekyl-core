// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bytes a peer is shown for one transaction.
//!
//! The chain's record comes first, when this node still holds the
//! prunable region. Otherwise the pool's shown body. An entry the pool
//! holds and does not show stays missing: resolving a stem body would
//! tell the asker this node holds it (PR2-Q4, [`Pool::shown_body`]).
//!
//! This is the public-bit read. It decides nothing about admission.

use shekyl_chain_store::store::{AtIndex, Prunable, ReadSnapshot, StoreError};
use shekyl_types::TxHash;
use shekyl_wire::Transaction;

use crate::Pool;

/// The wire bytes of `id` this node may show.
///
/// The chain's recomposed record when the prunable region is still
/// held, otherwise the pool's shown body. `None` when neither shows it.
///
/// # Errors
///
/// A store fault.
pub fn resolve_shown(
    snap: &ReadSnapshot<'_>,
    pool: &Pool,
    id: &TxHash,
) -> Result<Option<Vec<u8>>, StoreError> {
    if let Some(bytes) = chain_wire(snap, id)? {
        return Ok(Some(bytes));
    }
    Ok(pool.shown_body(id).map(Transaction::serialize))
}

fn chain_wire(snap: &ReadSnapshot<'_>, id: &TxHash) -> Result<Option<Vec<u8>>, StoreError> {
    let Some(record) = snap.tx_record(id)? else {
        return Ok(None);
    };
    let prunable = match snap.tx_prunable(record.location.id)? {
        AtIndex::Recorded(prunable) => prunable,
        AtIndex::BeyondCount => return Ok(None),
    };
    let Prunable::Retained(segment) = prunable else {
        return Ok(None);
    };
    Ok(record.wire_bytes(segment))
}
