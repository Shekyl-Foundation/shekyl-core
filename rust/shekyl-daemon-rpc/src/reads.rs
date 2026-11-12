// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The chain's reads on the 4.0 wire (`RPC_WIRE.md` RW-Q8;
//! `INPUT_GRAMMAR.md` Part C as Part F and IG-Q94 amend it).
//!
//! Each function is the whole method: it takes the facts, applies the
//! method's rules, and returns its reply type from
//! `shekyl_rpc_types::wire`. No Axum and no JSON: the dispatcher
//! (`handlers::rpc`) frames the result, so one unit test over in-memory
//! facts pins a method for every caller.
//!
//! A failure is an [`RpcFault`]; the dispatcher turns it into the error
//! object's class and dotted diagnostic ([`RpcFault::into_error`]).

use shekyl_rpc_types::errors::{Diagnostic, ErrorClass, RpcError};
use shekyl_rpc_types::hash::HashHex;
use shekyl_rpc_types::hex128::HexU128;
use shekyl_rpc_types::kinds::{Asked, Bytes, Count, Height, Integer, Micro, Milli, Size, Time};
use shekyl_rpc_types::method::caller_bounded;
use shekyl_rpc_types::nullable::Nullable;
use shekyl_rpc_types::wire::{archival, block, chain, shared, tx};
use shekyl_types::{BlockHash, BlockHeight, ChainCount, KeyImage, PCanonicalId, TxHash};
use shekyl_units::{wire::AtomicUnitsString, AtomicUnits};

use crate::chain_facts::{BlockHeaderFacts, BlockLookup, ChainFacts, FactsFault};
use crate::core::{FullForm, TxBody, TxSlot};
use crate::info_facts::PoolScope;
use crate::methods::{
    bound_exceeded, codes, RpcFault, RESTRICTED_BLOCK_COUNT, RESTRICTED_BLOCK_HEADER_RANGE,
    RESTRICTED_SPENT_KEY_IMAGES_COUNT, RESTRICTED_TRANSACTIONS_COUNT,
};
use crate::read_facts::{
    ChainReadFacts, CoinbaseRange, PowAdmission, PowDecline, PowSeed, SpentAt,
};
use shekyl_chain_rules::{EmissionEpochFacts, EmissionEpochStanding};

fn hash(bytes: [u8; 32]) -> HashHex {
    HashHex::from_bytes(bytes)
}

fn block_hash(id: BlockHash) -> HashHex {
    hash(id.to_bytes())
}

fn amount(raw: u64) -> AtomicUnitsString {
    AtomicUnitsString::from(AtomicUnits::from_raw(raw))
}

fn wide_amount(raw: u128) -> Result<AtomicUnitsString, RpcFault> {
    u64::try_from(raw).map(amount).map_err(|_| {
        RpcFault::Refused(RpcError::new(
            ErrorClass::Internal,
            Diagnostic::new(codes::DAEMON_INTERNAL, "an amount past u64 atomic units")
                .param("stage", "amount"),
        ))
    })
}

fn usize_count(n: usize) -> Count {
    Count(u64::try_from(n).unwrap_or(u64::MAX))
}

/// The tip's height, from a chain count. A chain with no block has no tip;
/// production always holds genesis, so that is the store contradicting its
/// own count.
fn tip_of(count: ChainCount) -> Result<Height, RpcFault> {
    count
        .tip()
        .map(|tip| Height(tip.to_raw()))
        .ok_or(RpcFault::Facts(FactsFault::Inconsistent))
}

/// A target count as an ordinal: `null` when the core reports none.
fn target_of(target: Option<ChainCount>) -> Nullable<Height> {
    target
        .and_then(ChainCount::tip)
        .map(|tip| Height(tip.to_raw()))
        .into()
}

fn missing_block(what: &str, chain: ChainCount) -> RpcFault {
    let tip = chain.tip().map_or(0, BlockHeight::to_raw);
    RpcFault::Refused(RpcError::new(
        ErrorClass::RefusedByMethod,
        Diagnostic::new(
            codes::BLOCK_MISSING,
            format!("this node holds no block {what}; its tip is {tip}"),
        )
        .param("block", what)
        .param("tip", tip.to_string()),
    ))
}

/// The chain store's writer (IG-Q92).
#[must_use]
pub fn writer_of(halt: Option<(BlockHeight, u32)>) -> chain::Writer {
    match halt {
        None => chain::Writer::Live(shared::Null),
        Some((at, row)) => chain::Writer::Halted(chain::Halt {
            height: Height(at.to_raw()),
            invariant: Integer(u64::from(row)),
        }),
    }
}

/// `version`: the RPC contract's version and the identity tuple (RW-Q6,
/// VC-2). Only `version` is frozen (RK-D25).
///
/// # Errors
///
/// The facts' fault.
pub fn version(facts: &dyn ChainFacts) -> Result<chain::Version, RpcFault> {
    let tip = facts.chain_tip()?;
    let identity = facts.identity()?;
    Ok(chain::Version {
        version: Integer(u64::from(shekyl_rpc_types::CORE_RPC_VERSION)),
        tagged: tip.release_build,
        height: tip_of(tip.chain_height)?,
        target_height: target_of(tip.target_height),
        // This build's own constant: compiled from `config/`, it has one
        // source.
        consensus_digest: shekyl_rpc_types::CONSENSUS_CONSTANTS_DIGEST_HASH,
        network: identity.nettype,
        genesis: block_hash(identity.genesis_hash),
    })
}

/// `chain_height`: the tip, its hash, and whether the store's writer is
/// live (IG-Q45, IG-Q92).
///
/// # Errors
///
/// The facts' fault.
pub fn chain_height(facts: &dyn ChainFacts) -> Result<chain::ChainHeight, RpcFault> {
    let tip = facts.chain_tip()?;
    Ok(chain::ChainHeight {
        height: tip_of(tip.chain_height)?,
        hash: block_hash(tip.top_hash),
        writer: writer_of(tip.halt),
    })
}

/// A header's facts on the wire. `pow` is the hash recorded at validation,
/// present exactly when the request asked for it (IG-Q56, RW-Q4).
///
/// # Errors
///
/// A header asked for `pow` whose facts carry none: the facts cannot
/// supply what the request selected, which is their fault, never a blank.
pub fn header(facts: &BlockHeaderFacts, pow: bool) -> Result<block::BlockHeader, RpcFault> {
    let pow = match (pow, facts.pow_hash) {
        (true, Some(bytes)) => Asked::Present(hash(bytes)),
        (true, None) => return Err(RpcFault::Facts(FactsFault::Inconsistent)),
        (false, _) => Asked::Unasked,
    };
    Ok(block::BlockHeader {
        version_major: Integer(u64::from(facts.major_version)),
        version_minor: Integer(u64::from(facts.minor_version)),
        time: Time(facts.timestamp),
        parent: block_hash(facts.prev_hash),
        nonce: Integer(u64::from(facts.nonce)),
        orphan: facts.orphan_status,
        height: Height(facts.height.to_raw()),
        depth: Count(facts.depth.to_raw()),
        hash: block_hash(facts.hash),
        difficulty: HexU128(facts.difficulty),
        difficulty_cumulative: HexU128(facts.cumulative_difficulty),
        reward: amount(facts.reward),
        weight: Size(facts.block_weight),
        weight_longterm: facts.long_term_weight.map(Size).into(),
        tx_count: Count(facts.num_txes),
        pow,
        coinbase: hash(facts.miner_tx_hash.to_bytes()),
        curve_root: hash(facts.curve_tree_root.to_bytes()),
        attestation_root: hash(facts.attestation_root.to_bytes()),
    })
}

/// How many times [`tip_header`] re-reads a tip that moved.
///
/// Each attempt is one lock; a second only happens when a block arrived
/// inside the first, which at any real block interval is rare and never
/// twice running.
const TIP_READ_ATTEMPTS: usize = 4;

/// The tip's header, or a refusal: never a header that is no longer the
/// tip.
///
/// Selecting the tip and reading its header are two snapshots, and the
/// chain can move between them, so the read repeats until the header's own
/// snapshot names it the tip (`at.chain_height.tip() == Some(height)`). An
/// unsynchronized node has no chain tip to report: the top of a partial
/// chain is not the top of the chain, so it refuses as not ready.
fn tip_header(facts: &dyn ChainFacts, pow: bool) -> Result<BlockHeaderFacts, RpcFault> {
    let tip = facts.chain_tip()?;
    if !tip.synchronized {
        return Err(RpcFault::Refused(RpcError::new(
            ErrorClass::NotReady,
            Diagnostic::new(
                codes::CHAIN_SYNCING,
                "this node is not synchronized, so it has no chain tip to report",
            ),
        )));
    }
    let mut top = tip.chain_height.tip().unwrap_or(BlockHeight::ZERO);
    for _ in 0..TIP_READ_ATTEMPTS {
        let at = facts.block_header_at(BlockLookup::Height(top), pow)?;
        let chain_tip = at.chain_height.tip().unwrap_or(BlockHeight::ZERO);
        match at.header {
            Some(header) if at.chain_height.tip() == Some(header.height) => return Ok(header),
            _ => top = chain_tip,
        }
    }
    Err(RpcFault::Refused(RpcError::new(
        ErrorClass::NotReady,
        Diagnostic::new(
            codes::CHAIN_MOVING,
            "the chain advanced on every attempt to read its tip",
        )
        .param("attempts", TIP_READ_ATTEMPTS.to_string()),
    )))
}

/// `block_header_show`: one header, by exactly one selector (IG-Q94).
///
/// # Errors
///
/// `block.missing` for a height above the tip or a hash this node does not
/// hold; for the tip, `chain.syncing` or `chain.moving`; the facts' fault.
pub fn block_header_show(
    facts: &dyn ChainFacts,
    request: &block::HeaderSelect,
) -> Result<block::BlockHeader, RpcFault> {
    let select = request.0;
    let (lookup, what) = match select.select {
        shared::Selector::Tip => return header(&tip_header(facts, select.pow)?, select.pow),
        shared::Selector::Height(height) => (
            BlockLookup::Height(BlockHeight::from_raw(height.0)),
            format!("at height {}", height.0),
        ),
        shared::Selector::Hash(id) => (BlockLookup::Hash(id.to_bytes()), format!("{id}")),
    };
    let at = facts.block_header_at(lookup, select.pow)?;
    at.header
        .as_ref()
        .map(|found| header(found, select.pow))
        .ok_or_else(|| missing_block(&what, at.chain_height))?
}

/// `block_header_list`: an inclusive range of headers, or headers by hash
/// in request order, each slot the header or `{"missing": null}` (IG-Q73).
///
/// # Errors
///
/// `block.range` for a range whose start is past its end; `block.missing`
/// for a range that leaves the chain; `bound.header` or `bound.block` for a
/// bounded caller over its cap; the facts' fault.
pub fn block_header_list(
    facts: &dyn ChainFacts,
    request: &block::HeaderRange,
    bounded: bool,
) -> Result<Vec<shared::Slot<block::BlockHeader>>, RpcFault> {
    match &request.select {
        block::HeaderRangeSelect::Hash(ids) => {
            if bounded && ids.len() > RESTRICTED_BLOCK_COUNT {
                return Err(bound_exceeded(
                    codes::BOUND_BLOCK,
                    "blocks",
                    RESTRICTED_BLOCK_COUNT as u64,
                    ids.len() as u64,
                ));
            }
            ids.iter()
                .map(|id| {
                    let at =
                        facts.block_header_at(BlockLookup::Hash(id.to_bytes()), request.pow)?;
                    Ok(match at.header.as_ref() {
                        Some(found) => shared::Slot::Item(header(found, request.pow)?),
                        None => shared::Slot::State(shared::SlotState::Missing(shared::Null)),
                    })
                })
                .collect()
        }
        block::HeaderRangeSelect::Range { from, to } => {
            if from.0 > to.0 {
                return Err(RpcFault::Refused(RpcError::new(
                    ErrorClass::BadParams,
                    Diagnostic::new(codes::BLOCK_RANGE, "a range's start is past its end")
                        .param("from", from.0.to_string())
                        .param("to", to.0.to_string()),
                )));
            }
            // Both ends against the tip before any per-height read, so an
            // absurd range costs nothing to refuse.
            let chain = facts.chain_tip()?.chain_height;
            if !chain.has_block(BlockHeight::from_raw(to.0)) {
                return Err(missing_block(&format!("at height {}", to.0), chain));
            }
            // The cap bounds the count, not the difference.
            let span = (to.0 - from.0).saturating_add(1);
            if bounded && span > RESTRICTED_BLOCK_HEADER_RANGE {
                return Err(bound_exceeded(
                    codes::BOUND_HEADER,
                    "headers",
                    RESTRICTED_BLOCK_HEADER_RANGE,
                    span,
                ));
            }
            (from.0..=to.0)
                .map(|raw| {
                    let at = facts.block_header_at(
                        BlockLookup::Height(BlockHeight::from_raw(raw)),
                        request.pow,
                    )?;
                    // A height that vanished mid-read means the chain shortened
                    // under the range: the range left the chain.
                    let found = at.header.as_ref().ok_or_else(|| {
                        missing_block(&format!("at height {raw}"), at.chain_height)
                    })?;
                    Ok(shared::Slot::Item(header(found, request.pow)?))
                })
                .collect()
        }
    }
}

/// One transaction's body in the form the caller asked for: the pruned
/// segment under `prune`, else the whole body, or the archived state where
/// this node discarded its archival good (`SB-Q2`, `PDM-Q10`).
fn body_form(id: TxHash, body: &TxBody, prune: bool) -> Result<Bytes, shared::Archived> {
    if prune {
        return Ok(Bytes(body.skeleton.unprunable.clone()));
    }
    match body.full_form() {
        FullForm::Whole(bytes) => Ok(Bytes(bytes)),
        FullForm::Archived { shard } => Err(shared::Archived {
            id: hash(id.to_bytes()),
            shard: Integer(shard.to_raw()),
        }),
    }
}

fn block_tx(id: TxHash, body: &TxBody, prune: bool) -> shared::OrArchived<block::BlockTx> {
    match body_form(id, body, prune) {
        Ok(bytes) => shared::OrArchived::Item(block::BlockTx {
            id: hash(id.to_bytes()),
            body: bytes,
            prunable_hash: Asked::when(prune, || hash(body.skeleton.prunable_hash.to_bytes())),
            pqc_auth_hash: Asked::when(prune, || {
                body.skeleton
                    .pqc_auth_hash
                    .map(|auth| hash(auth.to_bytes()))
                    .into()
            }),
            archival_size: Asked::when(prune, || Size(body.skeleton.archival_len.to_raw())),
        }),
        Err(archived) => shared::OrArchived::Archived(shared::ArchivedState::Archived(archived)),
    }
}

/// The global index of a block's first output: the coinbase's first, which
/// every block pays (RW-Q5).
fn first_output_index(read: &dyn ChainReadFacts, coinbase: TxHash) -> Result<Integer, RpcFault> {
    read.output_indices(&coinbase)?
        .and_then(|indices| indices.first().copied())
        .map(Integer)
        .ok_or(RpcFault::Facts(FactsFault::Inconsistent))
}

/// `block_show`: one block, by exactly one selector, with its transactions
/// in the form `prune` chooses and its first output's global index.
///
/// The header and the block's bytes are one snapshot; the transactions'
/// bodies are read by id, which a reorg between the two cannot make wrong.
///
/// # Errors
///
/// `block.missing`; for the tip, `chain.syncing` or `chain.moving`; the
/// facts' fault.
pub fn block_show(
    facts: &dyn ChainFacts,
    read: &dyn ChainReadFacts,
    request: &block::BlockShowSelect,
) -> Result<block::Block, RpcFault> {
    let select = request.0;
    let prune = select.prune.unwrap_or(false);
    let (lookup, what) = match select.select {
        shared::Selector::Tip => {
            let top = tip_header(facts, false)?;
            (
                BlockLookup::Hash(top.hash.to_bytes()),
                format!("{}", block_hash(top.hash)),
            )
        }
        shared::Selector::Height(height) => (
            BlockLookup::Height(BlockHeight::from_raw(height.0)),
            format!("at height {}", height.0),
        ),
        shared::Selector::Hash(id) => (BlockLookup::Hash(id.to_bytes()), format!("{id}")),
    };
    let at = facts.block_at(lookup, select.pow)?;
    let Some(found) = at.block else {
        return Err(missing_block(&what, at.chain_height));
    };
    let ids: Vec<TxHash> = found.tx_hashes.clone();
    let listed = read.transactions(&ids, PoolScope::Broadcast)?;
    let tx = ids
        .iter()
        .zip(listed.slots.iter())
        .map(|(id, slot)| match slot {
            TxSlot::Chain { body, .. } => Ok(block_tx(*id, body, prune)),
            // A transaction the block lists and the chain does not hold is
            // the store contradicting itself.
            _ => Err(RpcFault::Facts(FactsFault::Inconsistent)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(block::Block {
        output_index: first_output_index(read, found.header.miner_tx_hash)?,
        header: header(&found.header, select.pow)?,
        body: Bytes(found.blob),
        tx,
    })
}

/// `block_list`: blocks by height in request order, each slot the block or
/// `{"missing": null}` for a height above the tip (RW-Q5).
///
/// # Errors
///
/// `bound.block` for a bounded caller over its cap; the facts' fault.
pub fn block_list(
    facts: &dyn ChainFacts,
    read: &dyn ChainReadFacts,
    request: &block::BlockListQuery,
    bounded: bool,
) -> Result<block::BlockList, RpcFault> {
    if bounded && request.height.len() > RESTRICTED_BLOCK_COUNT {
        return Err(bound_exceeded(
            codes::BOUND_BLOCK,
            "blocks",
            RESTRICTED_BLOCK_COUNT as u64,
            request.height.len() as u64,
        ));
    }
    let heights: Vec<BlockHeight> = request
        .height
        .iter()
        .map(|height| BlockHeight::from_raw(height.0))
        .collect();
    let bodies = read.blocks_by_height(&heights)?;
    let mut bodies = bodies.blocks.into_iter();
    heights
        .iter()
        .map(|height| {
            let at = facts.block_header_at(BlockLookup::Height(*height), false)?;
            let Some(found) = at.header else {
                return Ok(shared::Slot::State(shared::SlotState::Missing(
                    shared::Null,
                )));
            };
            // The bodies read stops at the first height above the tip, so
            // every height with a header has its body, in order.
            let body = bodies
                .next()
                .ok_or(RpcFault::Facts(FactsFault::Inconsistent))?;
            Ok(shared::Slot::Item(block::Block {
                output_index: first_output_index(read, found.miner_tx_hash)?,
                // `block_list` takes no `pow` switch.
                header: header(&found, false)?,
                body: Bytes(body.block),
                tx: body
                    .txs
                    .iter()
                    .map(|listed| block_tx(listed.hash, &listed.body, request.prune))
                    .collect(),
            }))
        })
        .collect()
}

/// One transaction's entry, from the chain or the pool, or the archived
/// state in its place.
fn tx_entry(
    id: TxHash,
    slot: &TxSlot,
    prune: bool,
    chain_height: u64,
) -> Option<shared::OrArchived<tx::TxEntry>> {
    let (body, pooled, mined, public) = match slot {
        TxSlot::Missed | TxSlot::PoolUnavailable => return None,
        TxSlot::Chain {
            body,
            block_height,
            block_timestamp,
            output_indices,
        } => (
            body,
            false,
            Some((*block_height, *block_timestamp, output_indices.clone())),
            None,
        ),
        TxSlot::Pool { body, relayed, .. } => (body, true, None, Some(*relayed)),
    };
    let body_bytes = match body_form(id, body, prune) {
        Ok(bytes) => bytes,
        Err(archived) => {
            return Some(shared::OrArchived::Archived(
                shared::ArchivedState::Archived(archived),
            ))
        }
    };
    Some(shared::OrArchived::Item(tx::TxEntry {
        id: hash(id.to_bytes()),
        body: body_bytes,
        prunable_hash: Asked::when(prune, || hash(body.skeleton.prunable_hash.to_bytes())),
        pqc_auth_hash: Asked::when(prune, || {
            body.skeleton
                .pqc_auth_hash
                .map(|auth| hash(auth.to_bytes()))
                .into()
        }),
        archival_size: Asked::when(prune, || Size(body.skeleton.archival_len.to_raw())),
        pooled,
        mined_height: mined.as_ref().map(|(at, _, _)| Height(*at)).into(),
        // Against the count read once for the whole gather.
        confirmations: mined
            .as_ref()
            .map(|(at, _, _)| Count(chain_height.saturating_sub(*at)))
            .into(),
        mined_time: mined.as_ref().map(|(_, time, _)| Time(*time)).into(),
        output_index: mined
            .map(|(_, _, indices)| indices.into_iter().map(Integer).collect())
            .unwrap_or_default(),
        public: public.into(),
    }))
}

/// The pool scope a caller may see: an entry not yet public is host-only
/// (RT-O9.3), so to anyone else it is not in the pool.
#[must_use]
pub const fn scope_for(host: bool) -> PoolScope {
    if host {
        PoolScope::WithUnbroadcast
    } else {
        PoolScope::Broadcast
    }
}

/// `tx_show`: one transaction, or the archived state in its place.
///
/// # Errors
///
/// `tx.missing` when neither the chain nor the pool the caller may see
/// holds it; `txpool.retired` when the chain does not and the pool cannot
/// be asked; the facts' fault.
pub fn tx_show(
    read: &dyn ChainReadFacts,
    request: &tx::TxQuery,
    host: bool,
) -> Result<shared::OrArchived<tx::TxEntry>, RpcFault> {
    let id = TxHash::from_bytes(request.id.to_bytes());
    let gathered = read.transactions(&[id], scope_for(host))?;
    let slot = gathered
        .slots
        .first()
        .ok_or(RpcFault::Facts(FactsFault::Inconsistent))?;
    match slot {
        TxSlot::Missed => Err(RpcFault::Refused(RpcError::new(
            ErrorClass::RefusedByMethod,
            Diagnostic::new(
                codes::TX_MISSING,
                format!("this node holds no transaction {}", request.id),
            )
            .param("id", request.id.to_string()),
        ))),
        TxSlot::PoolUnavailable => Err(RpcFault::Refused(txpool_retired())),
        _ => tx_entry(id, slot, request.prune, gathered.chain_height)
            .ok_or(RpcFault::Facts(FactsFault::Inconsistent)),
    }
}

/// The refusal while the pool is retired (IG-Q74).
#[must_use]
pub fn txpool_retired() -> RpcError {
    RpcError::new(
        ErrorClass::NotReady,
        Diagnostic::new(
            codes::TXPOOL_RETIRED,
            "this node's pool file faulted; it holds no pool until it restarts",
        ),
    )
}

/// `tx_list`: transactions by id in request order. Each slot is the entry,
/// the archived state, `{"missing": null}` where the chain and the pool the
/// caller may see hold none, or `null` where the chain does not hold it and
/// the pool could not be asked (IG-Q73).
///
/// # Errors
///
/// `bound.tx` for a bounded caller over its cap; the facts' fault.
pub fn tx_list(
    read: &dyn ChainReadFacts,
    request: &tx::TxListQuery,
    host: bool,
) -> Result<tx::TxList, RpcFault> {
    if caller_bounded(host) && request.id.len() > RESTRICTED_TRANSACTIONS_COUNT {
        return Err(bound_exceeded(
            codes::BOUND_TX,
            "transactions",
            RESTRICTED_TRANSACTIONS_COUNT as u64,
            request.id.len() as u64,
        ));
    }
    let ids: Vec<TxHash> = request
        .id
        .iter()
        .map(|id| TxHash::from_bytes(id.to_bytes()))
        .collect();
    let gathered = read.transactions(&ids, scope_for(host))?;
    Ok(ids
        .iter()
        .zip(gathered.slots.iter())
        .map(|(id, slot)| match slot {
            TxSlot::Missed => shared::Slot::State(shared::SlotState::Missing(shared::Null)),
            TxSlot::PoolUnavailable => shared::Slot::Unasked,
            _ => match tx_entry(*id, slot, request.prune, gathered.chain_height) {
                Some(shared::OrArchived::Item(entry)) => shared::Slot::Item(entry),
                Some(shared::OrArchived::Archived(shared::ArchivedState::Archived(state))) => {
                    shared::Slot::State(shared::SlotState::Archived(state))
                }
                None => shared::Slot::Unasked,
            },
        })
        .collect())
}

/// `chain_spent`: where each key image is spent, in request order. A spend
/// the caller may not see in the pool answers `unspent` (RT-O9.3).
///
/// # Errors
///
/// `bound.key-image` for a bounded caller over its cap; the facts' fault.
pub fn chain_spent(
    read: &dyn ChainReadFacts,
    request: &chain::SpentQuery,
    host: bool,
) -> Result<Vec<chain::Spent>, RpcFault> {
    if caller_bounded(host) && request.key_image.len() > RESTRICTED_SPENT_KEY_IMAGES_COUNT {
        return Err(bound_exceeded(
            codes::BOUND_KEY_IMAGE,
            "key images",
            RESTRICTED_SPENT_KEY_IMAGES_COUNT as u64,
            request.key_image.len() as u64,
        ));
    }
    let images: Vec<KeyImage> = request
        .key_image
        .iter()
        .map(|image| KeyImage::from_bytes(image.to_bytes()))
        .collect();
    Ok(read
        .key_images_spent(&images)?
        .into_iter()
        .map(|spent| match spent {
            SpentAt::Unspent => chain::Spent::Unspent,
            SpentAt::Chain => chain::Spent::Chain,
            SpentAt::Pool => chain::Spent::Txpool,
        })
        .collect())
}

/// `fee`: the served tiers at the tip, each per unit of weight (IG-Q52).
///
/// # Errors
///
/// The facts' fault.
pub fn fee(facts: &dyn ChainFacts) -> Result<chain::Fee, RpcFault> {
    let [economy, standard, high] = facts.fee_estimate()?.fees;
    Ok(chain::Fee {
        economy: amount(economy),
        standard: amount(standard),
        high: amount(high),
    })
}

/// `chain_coinbase_sum`: what the blocks from `from` to `to`, inclusive,
/// emitted and paid in fees.
///
/// # Errors
///
/// `block.range` for a start past the end; `block.missing` for a range
/// that leaves the chain; the facts' fault.
pub fn chain_coinbase_sum(
    read: &dyn ChainReadFacts,
    request: &chain::CoinbaseSumRange,
) -> Result<chain::CoinbaseSum, RpcFault> {
    let (from, to) = (request.from.0, request.to.0);
    if from > to {
        return Err(RpcFault::Refused(RpcError::new(
            ErrorClass::BadParams,
            Diagnostic::new(codes::BLOCK_RANGE, "a range's start is past its end")
                .param("from", from.to_string())
                .param("to", to.to_string()),
        )));
    }
    let count = (to - from).saturating_add(1);
    match read.coinbase_sum(BlockHeight::from_raw(from), count)? {
        CoinbaseRange::TooLarge => Err(RpcFault::Refused(RpcError::new(
            ErrorClass::RefusedByMethod,
            Diagnostic::new(
                codes::BLOCK_MISSING,
                format!("the range {from} to {to} leaves the chain"),
            )
            .param("from", from.to_string())
            .param("to", to.to_string()),
        ))),
        CoinbaseRange::Summed(sum) => Ok(chain::CoinbaseSum {
            emission: wide_amount(sum.emission)?,
            fee: wide_amount(sum.fees)?,
        }),
    }
}

/// `chain_alt`: every alternative chain, by its tip, tip first.
///
/// # Errors
///
/// The facts' fault.
pub fn chain_alt(read: &dyn ChainReadFacts) -> Result<Vec<chain::AltChain>, RpcFault> {
    read.alternate_chains()?
        .into_iter()
        .map(|alt| {
            let tip = *alt
                .blocks
                .first()
                .ok_or(RpcFault::Facts(FactsFault::Inconsistent))?;
            Ok(chain::AltChain {
                hash: block_hash(tip),
                height: Height(alt.tip_height.to_raw()),
                difficulty_cumulative: HexU128(alt.cumulative_difficulty),
                block: alt.blocks.into_iter().map(block_hash).collect(),
                parent: block_hash(alt.parent),
            })
        })
        .collect()
}

/// `curve_show`: the curve tree after the block at a height, or after the
/// tip (IG-Q47).
///
/// # Errors
///
/// `curve.missing` above the tip; the facts' fault.
pub fn curve_show(
    read: &dyn ChainReadFacts,
    request: &chain::CurveSelect,
) -> Result<chain::Curve, RpcFault> {
    let tree = match request.0 {
        shared::Selector::Height(height) => read
            .curve_tree_after(BlockHeight::from_raw(height.0))?
            .ok_or_else(|| {
                RpcFault::Refused(RpcError::new(
                    ErrorClass::RefusedByMethod,
                    Diagnostic::new(
                        codes::CURVE_MISSING,
                        format!(
                            "no curve tree after height {}: it is above the tip",
                            height.0
                        ),
                    )
                    .param("height", height.0.to_string()),
                ))
            })?,
        // The selector's reader refuses a hash here; tip and height remain.
        shared::Selector::Tip | shared::Selector::Hash(_) => read.curve_tree()?,
    };
    Ok(chain::Curve {
        root: hash(tree.root.to_bytes()),
        layers: Count(u64::from(tree.depth)),
        leaf_count: Count(tree.leaf_count),
        height: Height(tree.after.to_raw()),
    })
}

/// One window epoch on the wire: its budget and snapshot where the claim
/// verify's citing gate admitted it, its work alone while unsettled (the
/// budget stays `null`: a wallet reads a budget as an admitted close row),
/// or nothing gathered where it is below the claim window (`SO-D11g`).
fn claim_epoch(epoch: EmissionEpochFacts) -> archival::Epoch {
    let mut row = archival::Epoch {
        id: Integer(epoch.settlement_epoch),
        closing_height: Height(epoch.close_height.map_or(0, BlockHeight::to_raw)),
        work: Milli(0),
        budget: Nullable(None),
        bond: Vec::new(),
        shard: Vec::new(),
        credit: Vec::new(),
        claimant: Nullable(None),
    };
    match epoch.standing {
        EmissionEpochStanding::Expired { .. } => {}
        EmissionEpochStanding::Unsettled {
            sigma_work_milli, ..
        } => {
            row.work = Milli(sigma_work_milli.unwrap_or(0));
        }
        EmissionEpochStanding::Settled {
            sigma_work_milli,
            budget,
            snapshot,
        } => {
            row.work = Milli(sigma_work_milli);
            row.budget = Some(amount(budget)).into();
            row.bond = snapshot
                .bonds
                .into_iter()
                .map(|bond| archival::ClaimBond {
                    joined_epoch: Integer(bond.join_settlement_epoch),
                    complete_tree: bond.is_support_complete_tree,
                    // Inclusive on the wire; the record's end is exclusive.
                    failure: bond
                        .bad_intervals
                        .iter()
                        .map(|interval| archival::Failure {
                            from: Integer(interval.start_epoch),
                            to: Integer(interval.end_exclusive.saturating_sub(1)),
                        })
                        .collect(),
                })
                .collect();
            row.shard = snapshot
                .shards
                .into_iter()
                .map(|shard| {
                    let close = shard.close.to_wire();
                    archival::ClaimShard {
                        id: Integer(shard.shard_id),
                        freeze_height: Height(close.freeze_height),
                        segment: close.has_segment,
                    }
                })
                .collect();
            row.credit = snapshot
                .pairs
                .into_iter()
                .map(|pair| archival::Credit {
                    bond: Integer(usize_count(pair.bond_idx).0),
                    shard: Integer(usize_count(pair.shard_idx).0),
                })
                .collect();
            row.claimant = snapshot
                .claimant_bond_idx
                .map(|index| Integer(usize_count(index).0))
                .into();
        }
    }
    row
}

/// `archival_claim_show`: what a persona's emission claim is built from,
/// at the tip of one snapshot, whose hash the reply carries (IG-Q84).
///
/// # Errors
///
/// The facts' fault.
pub fn archival_claim_show(
    read: &dyn ChainReadFacts,
    request: &archival::PersonaQuery,
) -> Result<archival::ClaimSource, RpcFault> {
    let source =
        read.emission_claim_source(&PCanonicalId::from_bytes(request.persona.to_bytes()))?;
    let bond = source.bond.as_ref();
    Ok(archival::ClaimSource {
        height: tip_of(source.chain_height)?,
        hash: block_hash(source.tip_hash),
        settled_epoch: Integer(source.current_settled_epoch.to_raw()),
        joined_epoch: bond
            .map(|b| Integer(b.join_settlement_epoch.to_raw()))
            .into(),
        holding: match bond.map(|b| b.holdings_kind.to_u8()) {
            Some(1) => archival::Holding::CompleteTree,
            _ => archival::Holding::Shards,
        },
        shard: bond.map_or_else(Vec::new, |b| {
            b.held_shards.iter().map(|s| Integer(s.to_raw())).collect()
        }),
        claimed: bond.map_or_else(Vec::new, |b| {
            b.claimed_settlement_epochs
                .iter()
                .map(|e| Integer(e.to_raw()))
                .collect()
        }),
        bond_total: amount(bond.map_or(0, |b| b.bonded_total.to_raw())),
        failure_count: usize_count(bond.map_or(0, |b| b.bad_interval_count)),
        served_epoch: bond.and_then(|b| b.last_served).map(Integer).into(),
        slash_epoch: bond
            .and_then(|b| b.last_settled_slash)
            .map(|e| Integer(e.to_raw()))
            .into(),
        epoch: source.epochs.into_iter().map(claim_epoch).collect(),
    })
}

/// `shard_coverage`: the shards a join can hold, ranked by join scarcity
/// (`order_shard_coverage`, SL-D4). Before the first settlement pass the
/// budget and the work are `null` and so is every expected profit.
///
/// # Errors
///
/// The facts' fault.
pub fn shard_coverage(read: &dyn ChainReadFacts) -> Result<archival::Coverage, RpcFault> {
    let coverage = read.shard_coverage()?;
    let budget = coverage.budget.unwrap_or(0);
    let sigma = coverage.sigma_work_milli.unwrap_or(0);
    let estimated = sigma != 0;
    let ranked = shekyl_archival_retention::order_shard_coverage(
        coverage.as_of.to_raw(),
        budget,
        sigma,
        &coverage.shards,
    );
    Ok(archival::Coverage {
        height: Height(coverage.as_of.to_raw()),
        leaf_count: Count(coverage.leaf_count),
        frozen_count: usize_count(coverage.shards.len()),
        settled_epoch: Integer(coverage.settled_epoch.to_raw()),
        budget: coverage.budget.map(amount).into(),
        work: coverage.sigma_work_milli.map(Milli).into(),
        shard: ranked
            .into_iter()
            .map(|row| archival::CoverageShard {
                id: Integer(row.shard_id),
                bonded_count: Count(row.bonded_count),
                served_count: Count(row.served_count),
                freeze_height: Height(row.freeze_height),
                scarcity: Micro(row.join_scarcity_micro),
                profit: estimated.then(|| amount(row.expected_profit_atomic)).into(),
            })
            .collect(),
    })
}

/// `pow`: RandomX over the hashing bytes, under the seed named or the
/// chain's seed for `height`, only under a cache this node already holds.
///
/// A bounded caller pays one hash from the shared budget, after the seed is
/// admitted and before RandomX, so a request that will not hash spends
/// nothing (`RPC_CHANNEL.md` §6.3).
///
/// # Errors
///
/// `bound.pow-size` for hashing bytes longer than the hashing blob;
/// `pow.seed` for a seed this node does not hold or one above the tip;
/// `bound.hash` for a bounded caller while the budget is empty; the facts'
/// fault.
pub fn pow(
    read: &dyn ChainReadFacts,
    request: &block::PowInput,
    bounded: bool,
    budget: &crate::hash_budget::HashBudget,
) -> Result<block::Pow, RpcFault> {
    let blob = &request.hashing.0;
    if blob.len() > shekyl_wire::block::MAX_POW_BLOB_SIZE {
        return Err(bound_exceeded(
            codes::BOUND_POW_SIZE,
            "bytes",
            u64::try_from(shekyl_wire::block::MAX_POW_BLOB_SIZE).unwrap_or(u64::MAX),
            u64::try_from(blob.len()).unwrap_or(u64::MAX),
        ));
    }
    let seed = match request.seed {
        Some(seed) => PowSeed::Given(BlockHash::from_bytes(seed.to_bytes())),
        None => PowSeed::AtHeight(BlockHeight::from_raw(request.height.0)),
    };
    let refused = |message: String| {
        RpcFault::Refused(RpcError::new(
            ErrorClass::RefusedByMethod,
            Diagnostic::new(codes::POW_SEED, message),
        ))
    };
    let admitted = match read.admit_pow(seed)? {
        PowAdmission::Admitted(admitted) => admitted,
        PowAdmission::Declined(PowDecline::SeedNotHeld { seed }) => {
            return Err(refused(format!(
                "seed {} is not held: pow hashes under held seeds only",
                block_hash(seed)
            )))
        }
        PowAdmission::Declined(PowDecline::SeedAboveTip { seed_height, tip }) => {
            return Err(refused(format!(
                "no seed for height {}: its seed height {} is above the tip {}",
                request.height.0,
                seed_height.to_raw(),
                tip.to_raw()
            )))
        }
    };
    if bounded {
        budget
            .spend(std::time::Instant::now())
            .map_err(RpcFault::Refused)?;
    }
    let pow = read.hash_admitted(blob, &admitted)?;
    Ok(block::Pow {
        pow: hash(pow.to_bytes()),
    })
}

#[cfg(test)]
#[path = "reads_tests.rs"]
mod tests;
