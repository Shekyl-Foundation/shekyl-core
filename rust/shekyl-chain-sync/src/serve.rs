// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The responder side of 2011–2014, from the store (CS-3 §4.5). Reads only.
//!
//! A header request is a sparse locator. The first hash the store holds on
//! its main chain is the fork point. The null hash, an empty chain's whole
//! locator, starts the response at genesis. A hash held as an alternative block is
//! walked down its parents to the main chain, and that block is the fork
//! point. From the fork point's child upward the response carries
//! `pow_blob`s until [`HEADERS_RESPONSE_BYTES`] would be passed. `more` says
//! whether the main chain continues, and `tip_work` is the tip's cumulative
//! difficulty.
//!
//! A body request names hashes. Each one on the main chain is answered with
//! its block, its listed transactions and its attestation witness, and
//! [`plan_bodies`] decides what is sent, deferred and missed. Until DRS-SB's
//! discard lands every transaction is held whole and is served
//! [`TxBody::Full`]. One whose prunable region, or `pqc_auths` region, this
//! node no longer holds is served as a [`SkeletonTx`].

use std::collections::HashMap;

use shekyl_chain_rules::AtHeight;
use shekyl_chain_store::store::{
    AtIndex, ChainStore, Prunable, ReadSnapshot, StoreError, TxRecord,
};
use shekyl_levin::{
    plan_bodies, RequestBodies, RequestHeaders, ResponseBodies, ResponseHeaders, HASH_SIZE,
    HEADERS_RESPONSE_BYTES,
};
use shekyl_types::{BlockCount, BlockHash, BlockHeight};
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
/// this store holds on its main chain, directly or as the base of an
/// alternative chain. `None` when no locator hash is held.
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
        if let Some(fork) = fork_of_alt(snap, hash)? {
            return Ok(Some(fork + BlockCount::ONE));
        }
    }
    Ok(None)
}

/// Where the alternative chain through `hash` leaves the main chain: the
/// height of its first ancestor on main. `None` when `hash` is not an
/// alternative block, or its chain reaches nothing on main. The walk is
/// bounded by the alternative blocks the store holds.
fn fork_of_alt(
    snap: &ReadSnapshot<'_>,
    hash: BlockHash,
) -> Result<Option<BlockHeight>, StoreError> {
    let mut steps = snap.alt_block_count()?;
    let mut at = hash;
    while let Some(alt) = snap.alt_block(&at)? {
        let parent = alt.block().header.previous;
        if let Some(height) = snap.height_of(&parent)? {
            return Ok(Some(height));
        }
        if steps == 0 {
            return Ok(None);
        }
        steps -= 1;
        at = parent;
    }
    Ok(None)
}

/// Answer a body request from `store`: what is sent, deferred by the byte
/// budget, and marked unavailable is [`plan_bodies`]'s, so a response this
/// serves passes the requester's `check_form`.
///
/// # Errors
///
/// The store's own fault.
pub fn serve_bodies(
    store: &ChainStore,
    request: &RequestBodies,
) -> Result<ResponseBodies, StoreError> {
    let snap = store.begin_read()?;
    let mut held: HashMap<[u8; HASH_SIZE], BlockBody> = HashMap::new();
    for hash in &request.hashes {
        if held.contains_key(hash) {
            continue;
        }
        if let Some(body) = body_of(&snap, BlockHash::from_bytes(*hash))? {
            held.insert(*hash, body);
        }
    }
    let plan = plan_bodies(&request.hashes, |hash| held.get(hash));
    let bodies = plan
        .send
        .iter()
        .filter_map(|hash| held.get(hash).cloned())
        .collect();
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
        let Some(record) = snap.tx_record(txid)? else {
            return Ok(None);
        };
        let tx = match snap.tx_prunable(record.location.id)? {
            AtIndex::Recorded(Prunable::Retained(prunable)) => {
                let skeleton = skeleton_of(&record);
                match record.wire_bytes(prunable) {
                    Some(bytes) => TxBody::Full(bytes),
                    None => TxBody::Skeleton(skeleton),
                }
            }
            AtIndex::Recorded(Prunable::Discarded) => TxBody::Skeleton(skeleton_of(&record)),
            AtIndex::BeyondCount => return Ok(None),
        };
        txs.push(tx);
    }
    let attestation_witness = match snap.attestation_witness_at(height)? {
        AtHeight::Recorded(Some(witness)) => witness,
        AtHeight::Recorded(None) | AtHeight::AboveTip => Vec::new(),
    };
    Ok(Some(BlockBody {
        block: body.block.serialize(),
        txs,
        attestation_witness,
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
