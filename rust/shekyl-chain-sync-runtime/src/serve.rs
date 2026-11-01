// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The responder side of 2011–2014, from the store (CS-3 §4.5). Reads only.
//!
//! A header request is a sparse locator. The first hash the store holds on
//! its main chain is the fork point, and a hash held only as an alternative
//! block is passed over: the requester accepts a response only when its
//! first header's parent is a hash it named. The null hash, an empty
//! chain's whole locator, starts the response at genesis. From the fork
//! point's child upward the response carries
//! `pow_blob`s until [`HEADERS_RESPONSE_BYTES`] would be passed. `more` says
//! whether the main chain continues, and `tip_work` is the tip's cumulative
//! difficulty.
//!
//! A body request names hashes. Each one on the main chain is answered with
//! its block, its listed transactions and its attestation witness, and
//! [`BodyPlanner`] decides what is sent, deferred and missed; a body the
//! budget defers is never read. Until DRS-SB's
//! discard lands every transaction is held whole and is served
//! [`TxBody::Full`]. One whose prunable region, or `pqc_auths` region, this
//! node no longer holds is served as a [`SkeletonTx`].
//!
//! A request for an announced block's missing transactions (2009, CS-5 §6)
//! names the block and indices into its transaction list. It is answered
//! with one 2008 carrying the block, its witness and those transactions
//! whole. The peer's own faults close its session, each with its cause
//! ([`MissingTxsRefused`]). A block this node holds only as an alternative
//! left the main chain after it was announced; that is not the peer's
//! fault, and it is not answered.

use shekyl_chain_rules::AtHeight;
use shekyl_chain_store::store::{
    AtIndex, ChainStore, Prunable, ReadSnapshot, StoreError, TxRecord,
};
use shekyl_levin::{
    body_budget_bytes, BlockCompleteEntry, BodyPlanner, NewCompactBlock, RequestBodies,
    RequestCompactMissingTx, RequestHeaders, ResponseBodies, ResponseHeaders, TxBlobEntry,
    HASH_SIZE, HEADERS_RESPONSE_BYTES,
};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, TxHash};
use shekyl_wire::{BlockBody, SkeletonTx, TxBody};

/// Answer a header request from `store`.
///
/// # Errors
///
/// The store's own fault. A hash the store does not hold is not one: an
/// unknown locator is answered with no headers.
pub fn serve_headers(
    store: &ChainStore,
    request: &RequestHeaders,
) -> Result<ResponseHeaders, StoreError> {
    let snap = store.begin_read()?;
    let Some(tip) = snap.tip()?.recorded else {
        return Ok(ResponseHeaders {
            blobs: Vec::new(),
            tip_work: 0,
            more: false,
        });
    };
    let tip_work = match snap.block_info(tip.height)? {
        AtHeight::Recorded(info) => info.cumulative_difficulty.to_raw(),
        AtHeight::AboveTip => 0,
    };
    let Some(start) = first_held(&snap, &request.block_ids)? else {
        return Ok(ResponseHeaders {
            blobs: Vec::new(),
            tip_work,
            more: false,
        });
    };
    let max = usize::try_from(HEADERS_RESPONSE_BYTES).unwrap_or(usize::MAX);
    let mut blobs = Vec::new();
    let mut sent = 0usize;
    let mut height = start;
    while height <= tip.height {
        let AtHeight::Recorded(body) = snap.block(height)? else {
            break;
        };
        let pow = body.block.pow_blob();
        let Some(next) = sent.checked_add(pow.len()).filter(|next| *next <= max) else {
            break;
        };
        sent = next;
        blobs.push(pow);
        height = height + BlockCount::ONE;
    }
    Ok(ResponseHeaders {
        blobs,
        tip_work,
        more: height <= tip.height,
    })
}

/// The height the response starts at: the child of the first locator hash
/// this store holds on its main chain. A hash held only as an alternative
/// block is passed over, since the response's first parent must be a
/// locator hash and an alternative block's fork point seldom is. `None`
/// when no locator hash is on the main chain.
fn first_held(
    snap: &ReadSnapshot<'_>,
    locator: &[[u8; HASH_SIZE]],
) -> Result<Option<BlockHeight>, StoreError> {
    for hash in locator {
        let hash = BlockHash::from_bytes(*hash);
        // An empty chain's locator is the null hash alone: it holds
        // nothing, so the response starts at genesis.
        if hash == BlockHash::NULL {
            return Ok(Some(BlockHeight::ZERO));
        }
        if let Some(height) = snap.height_of(&hash)? {
            return Ok(Some(height + BlockCount::ONE));
        }
    }
    Ok(None)
}

/// Answer a body request from `store`: what is sent, deferred by the byte
/// budget, and marked unavailable is [`BodyPlanner`]'s, so a response this
/// serves passes the requester's `check_form`.
///
/// A body is read only while the budget can still send it, and kept only
/// when it is sent. Past the budget a held block is deferred whatever its
/// size, so for each later hash only whether the main chain holds it is
/// read. A main-chain block always has its transaction rows, so that read
/// classifies a hash as reading its body would.
///
/// # Errors
///
/// The store's own fault.
pub fn serve_bodies(
    store: &ChainStore,
    request: &RequestBodies,
) -> Result<ResponseBodies, StoreError> {
    let snap = store.begin_read()?;
    answer_bodies(
        &request.hashes,
        |id| body_of(&snap, id),
        |id| Ok(snap.height_of(&id)?.is_some()),
    )
}

/// The body response for `requested`, apart from the store: `body` reads
/// a block's body (`None` when it is not held), and `held` says only
/// whether it is held. `body` is called only while the budget can still
/// send the block; `held` after that.
fn answer_bodies<E>(
    requested: &[[u8; HASH_SIZE]],
    mut body: impl FnMut(BlockHash) -> Result<Option<BlockBody>, E>,
    mut held: impl FnMut(BlockHash) -> Result<bool, E>,
) -> Result<ResponseBodies, E> {
    let mut planner = BodyPlanner::new();
    let mut bodies = Vec::new();
    for hash in requested {
        let id = BlockHash::from_bytes(*hash);
        if planner.deferring() {
            if held(id)? {
                planner.defer(*hash);
            } else {
                planner.miss(*hash);
            }
            continue;
        }
        match body(id)? {
            None => planner.miss(*hash),
            Some(found) => {
                if planner.charge(*hash, body_budget_bytes(&found)) {
                    bodies.push(found);
                }
            }
        }
    }
    let plan = planner.finish();
    Ok(ResponseBodies {
        bodies,
        deferred: plan.deferred,
        missed_ids: plan.missed,
    })
}

/// The body of the main-chain block `hash`, or `None` when the main chain
/// does not hold it whole.
fn body_of(snap: &ReadSnapshot<'_>, hash: BlockHash) -> Result<Option<BlockBody>, StoreError> {
    let Some(height) = snap.height_of(&hash)? else {
        return Ok(None);
    };
    let AtHeight::Recorded(body) = snap.block(height)? else {
        return Ok(None);
    };
    let mut txs = Vec::with_capacity(body.block.transaction_hashes.len());
    for txid in &body.block.transaction_hashes {
        let Some(tx) = tx_body(snap, txid)? else {
            return Ok(None);
        };
        txs.push(tx);
    }
    Ok(Some(BlockBody {
        block: body.block.serialize(),
        txs,
        attestation_witness: witness_at(snap, height)?,
    }))
}

/// The transaction `txid` as this store holds it: whole, or as its
/// skeleton when a region it binds is no longer held. `None` when it is
/// not recorded.
fn tx_body(snap: &ReadSnapshot<'_>, txid: &TxHash) -> Result<Option<TxBody>, StoreError> {
    let Some(record) = snap.tx_record(txid)? else {
        return Ok(None);
    };
    Ok(match snap.tx_prunable(record.location.id)? {
        AtIndex::Recorded(Prunable::Retained(prunable)) => {
            let skeleton = skeleton_of(&record);
            Some(match record.wire_bytes(prunable) {
                Some(bytes) => TxBody::Full(bytes),
                None => TxBody::Skeleton(skeleton),
            })
        }
        AtIndex::Recorded(Prunable::Discarded) => Some(TxBody::Skeleton(skeleton_of(&record))),
        AtIndex::BeyondCount => None,
    })
}

/// The attestation witness of the main-chain block at `height`; empty when
/// it has none.
fn witness_at(snap: &ReadSnapshot<'_>, height: BlockHeight) -> Result<Vec<u8>, StoreError> {
    Ok(match snap.attestation_witness_at(height)? {
        AtHeight::Recorded(Some(witness)) => witness,
        AtHeight::Recorded(None) | AtHeight::AboveTip => Vec::new(),
    })
}

/// Why a request for an announced block's missing transactions closes its
/// session (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MissingTxsRefused {
    /// No block this store holds, on main or as an alternative, has the
    /// hash.
    UnknownBlock,
    /// An index past the block's transaction list.
    IndexOutOfRange {
        /// The index.
        index: u64,
        /// How many transactions the block lists.
        count: usize,
    },
    /// An index named twice.
    DuplicateIndex {
        /// The index.
        index: u64,
    },
    /// A listed transaction this store does not hold whole.
    TxNotHeld {
        /// Its index in the block.
        index: u64,
    },
}

/// What a request for an announced block's missing transactions gets.
#[derive(Debug, PartialEq, Eq)]
pub enum MissingTxsServed {
    /// The block, its witness and the transactions asked for, in the
    /// order asked, as one 2008.
    Answer(NewCompactBlock),
    /// The block is held only as an alternative: it left the main chain
    /// after it was announced. Not answered, and not the peer's fault.
    LeftMain,
    /// The session closes.
    Refused(MissingTxsRefused),
}

/// Answer a request for an announced block's missing transactions from
/// `store` (module docs). The indices are judged before any transaction
/// is read.
///
/// # Errors
///
/// The store's own fault.
pub fn serve_missing_txs(
    store: &ChainStore,
    request: &RequestCompactMissingTx,
) -> Result<MissingTxsServed, StoreError> {
    let snap = store.begin_read()?;
    let hash = BlockHash::from_bytes(request.block_hash);
    let Some(height) = snap.height_of(&hash)? else {
        return Ok(if snap.has_alt_block(&hash)? {
            MissingTxsServed::LeftMain
        } else {
            MissingTxsServed::Refused(MissingTxsRefused::UnknownBlock)
        });
    };
    let AtHeight::Recorded(body) = snap.block(height)? else {
        return Ok(MissingTxsServed::Refused(MissingTxsRefused::UnknownBlock));
    };
    let listed = &body.block.transaction_hashes;
    let mut seen = vec![false; listed.len()];
    let mut wanted = Vec::with_capacity(request.missing_tx_indices.len());
    for &index in &request.missing_tx_indices {
        let at = usize::try_from(index).ok();
        let (Some(slot), Some(txid)) = (
            at.and_then(|at| seen.get_mut(at)),
            at.and_then(|at| listed.get(at)),
        ) else {
            return Ok(MissingTxsServed::Refused(
                MissingTxsRefused::IndexOutOfRange {
                    index,
                    count: listed.len(),
                },
            ));
        };
        if *slot {
            return Ok(MissingTxsServed::Refused(
                MissingTxsRefused::DuplicateIndex { index },
            ));
        }
        *slot = true;
        wanted.push((index, txid));
    }
    let mut txs = Vec::with_capacity(wanted.len());
    for (index, txid) in wanted {
        let Some(TxBody::Full(blob)) = tx_body(&snap, txid)? else {
            return Ok(MissingTxsServed::Refused(MissingTxsRefused::TxNotHeld {
                index,
            }));
        };
        txs.push(TxBlobEntry {
            blob,
            prunable_hash: [0; HASH_SIZE],
        });
    }
    Ok(MissingTxsServed::Answer(NewCompactBlock {
        b: BlockCompleteEntry {
            pruned: false,
            block: body.block.serialize(),
            block_weight: 0,
            txs,
            attestation_witness: witness_at(&snap, height)?,
        },
        current_blockchain_height: request.current_blockchain_height,
    }))
}

/// The skeleton of a recorded transaction: its pruned segment and the three
/// operands its txid binds (`PDM-Q-F28`).
fn skeleton_of(record: &TxRecord) -> SkeletonTx {
    SkeletonTx {
        unprunable: record.pruned.clone().into_wire_bytes(),
        prunable_hash: record.prunable_hash,
        pqc_auth_hash: record.pqc_auth_hash,
        archival_len: record.archival_len,
    }
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod tests;
