// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The store flip's native read handlers (`DRS_X_STORE_FLIP.md` DX-Q3,
//! PR 3), over [`ChainReadFacts`]. The JSON-RPC rows are dispatched from
//! `handlers::json_rpc`, and the REST and `.bin` rows dispatch here too.
//! Each
//! answers on the C++ wire (`shekyl_rpc_types::chain_reads`, `archival`);
//! where it answers differently, the difference is a row in
//! `DRS_X_STORE_FLIP.md`'s divergence register, and the flip's
//! `CORE_RPC_VERSION` bump is stated there.

use shekyl_rpc_types::{
    AltChainInfo, CalcPowRequest, GetAltBlocksHashesResponse, GetAlternateChainsResponse,
    GetCoinbaseTxSumRequest, GetCoinbaseTxSumResponse, GetCurveTreeCheckpointRequest,
    GetCurveTreeCheckpointResponse, GetCurveTreeInfoResponse, HashHex, RpcStatus,
    CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB,
};
use shekyl_rpc_types::{
    ClaimBondRow, ClaimCreditPair, ClaimEpochSnapshot, ClaimShardRow,
    GetArchivalEmissionClaimSourceRequest, GetArchivalEmissionClaimSourceResponse,
    GetArchivalShardCoverageResponse, ShardCoverageRow,
};
use shekyl_types::{BlockHash, BlockHeight, KeyImage, PCanonicalId, TxHash};

use crate::core::FullForm;
use crate::methods::{
    bound_exceeded, bound_fault, parse_request_hashes, split_128, RpcFault, RpcRefusal,
    KI_PARSE_FAILED, RESTRICTED_BLOCK_COUNT, RESTRICTED_SPENT_KEY_IMAGES_COUNT,
    RESTRICTED_TRANSACTIONS_COUNT, TX_PARSE_FAILED,
};
use crate::read_facts::{
    ChainReadFacts, CoinbaseRange, CurveTreeFacts, ListedTx, PowAdmission, PowDecline, PowSeed,
    SpentAt,
};
use shekyl_chain_rules::{EmissionEpochFacts, EmissionEpochStanding};
use shekyl_rpc_types::methods::caller_bounded;
use shekyl_rpc_types::{
    BlockEntry, BlockTx, BlockTxSkeleton, GetBlocksByHeightRequest, GetBlocksByHeightResponse,
    GetOIndexesRequest, GetOIndexesResponse, IsKeyImageSpentRequest, IsKeyImageSpentResponse,
    KeyImageStatus,
};

/// The status `get_coinbase_tx_sum` answers a range outside the chain with
/// — the C++ handler's string, which clients match on.
pub const COINBASE_SUM_RANGE_REFUSAL: &str = "height or count is too large";

fn hash_hex(hash: BlockHash) -> HashHex {
    HashHex::from_bytes(hash.to_bytes())
}

/// `get_alt_blocks_hashes` (`/get_alt_blocks_hashes`): every alt block's
/// identity, in the alt table's key order.
///
/// # Errors
///
/// The facts' fault.
pub fn get_alt_blocks_hashes(
    facts: &dyn ChainReadFacts,
) -> Result<GetAltBlocksHashesResponse, RpcFault> {
    Ok(GetAltBlocksHashesResponse {
        status: RpcStatus::ok(),
        blks_hashes: facts
            .alt_block_hashes()?
            .into_iter()
            .map(hash_hex)
            .collect(),
    })
}

/// `get_alternate_chains`: every alternative chain, by tip, tip first.
///
/// `main_chain_parent_block` is the parent the chain's lowest block names
/// — read off the block, never the main chain's block at the height below
/// (the divergence register's row for this method).
///
/// # Errors
///
/// The facts' fault.
pub fn get_alternate_chains(
    facts: &dyn ChainReadFacts,
) -> Result<GetAlternateChainsResponse, RpcFault> {
    let chains = facts
        .alternate_chains()?
        .into_iter()
        .map(|chain| {
            let (difficulty, wide_difficulty, difficulty_top64) =
                split_128(chain.cumulative_difficulty);
            AltChainInfo {
                block_hash: hash_hex(chain.blocks[0]),
                height: chain.tip_height.to_raw(),
                length: u64::try_from(chain.blocks.len()).unwrap_or(u64::MAX),
                difficulty,
                wide_difficulty,
                difficulty_top64,
                block_hashes: chain.blocks.into_iter().map(hash_hex).collect(),
                main_chain_parent_block: hash_hex(chain.parent),
            }
        })
        .collect();
    Ok(GetAlternateChainsResponse {
        status: RpcStatus::ok(),
        chains,
    })
}

/// `get_coinbase_tx_sum`: what `count` blocks from `height` emitted, and
/// what their transactions paid in fees.
///
/// The emission is the coins the range generated — each block's paid
/// reward, miner and staker legs — not the C++'s coinbase outputs less the
/// fees (the divergence register's row). A range outside the chain answers
/// [`COINBASE_SUM_RANGE_REFUSAL`] in its status, every amount zero and the
/// wide strings empty, as the C++ response did.
///
/// # Errors
///
/// The facts' fault.
pub fn get_coinbase_tx_sum(
    facts: &dyn ChainReadFacts,
    request: &GetCoinbaseTxSumRequest,
) -> Result<GetCoinbaseTxSumResponse, RpcFault> {
    match facts.coinbase_sum(BlockHeight::from_raw(request.height), request.count)? {
        CoinbaseRange::TooLarge => Ok(GetCoinbaseTxSumResponse {
            status: RpcStatus(COINBASE_SUM_RANGE_REFUSAL.to_owned()),
            emission_amount: 0,
            wide_emission_amount: String::new(),
            emission_amount_top64: 0,
            fee_amount: 0,
            wide_fee_amount: String::new(),
            fee_amount_top64: 0,
        }),
        CoinbaseRange::Summed(sum) => {
            let (emission_amount, wide_emission_amount, emission_amount_top64) =
                split_128(sum.emission);
            let (fee_amount, wide_fee_amount, fee_amount_top64) = split_128(sum.fees);
            Ok(GetCoinbaseTxSumResponse {
                status: RpcStatus::ok(),
                emission_amount,
                wide_emission_amount,
                emission_amount_top64,
                fee_amount,
                wide_fee_amount,
                fee_amount_top64,
            })
        }
    }
}

/// `calc_pow`: RandomX over the request's bytes, under the seed it names
/// or the chain's seed for `height`. The reply is the hash as bare hex.
///
/// The bytes are hashed as given — a block's hashing blob. Their length
/// is the longest hashing blob the format can write
/// ([`MAX_POW_BLOB_SIZE`](shekyl_wire::block::MAX_POW_BLOB_SIZE)), not the
/// block-body parse cap: the body is not hashed. A bounded caller pays
/// one hash from the shared budget for a blob of that length. The floor
/// measurement showed a blob two hundred thousand times longer still costs
/// one hash, so one format-maximum blob is one hash.
///
/// The hash is computed only under a cache the daemon already holds;
/// `calc_pow` never derives one (ruled 2026-10-17). The C++ derived a cache
/// for any seed, evicting the validator's spare, with no bound across
/// concurrent seeds.
///
/// # Errors
///
/// [`RpcFault::Refused`]: the blob is not hex (`WRONG_BLOCKBLOB`), longer
/// than the hashing blob (`OverResourceBound`), the seed is not 32 bytes of hex,
/// the seed height is above the tip, or the seed's cache is not held (all
/// `WRONG_PARAM`). A bounded caller whose request will hash and whose
/// bucket is empty is `OverResourceBound` and spends nothing. The facts'
/// fault otherwise. The hash budget is spent after the seed is admitted
/// and before RandomX, so a bad blob, a bad seed, a seed above the tip,
/// and a seed whose cache is not held return without spending.
pub fn calc_pow(
    facts: &dyn ChainReadFacts,
    request: &CalcPowRequest,
    bounded: bool,
    budget: &crate::hash_budget::HashBudget,
) -> Result<String, RpcFault> {
    let Ok(blob) = hex::decode(&request.block_blob) else {
        return Err(RpcFault::Refused(RpcRefusal {
            code: CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB,
            message: "Wrong block blob".to_owned(),
            data: None,
        }));
    };
    if blob.len() > shekyl_wire::block::MAX_POW_BLOB_SIZE {
        return Err(crate::methods::bound_fault(
            "calc_pow",
            "bytes",
            u64::try_from(shekyl_wire::block::MAX_POW_BLOB_SIZE).unwrap_or(u64::MAX),
            u64::try_from(blob.len()).unwrap_or(u64::MAX),
        ));
    }
    let seed = if request.seed_hash.is_empty() {
        PowSeed::AtHeight(BlockHeight::from_raw(request.height))
    } else {
        match HashHex::from_hex(&request.seed_hash) {
            Ok(seed) => PowSeed::Given(BlockHash::from_bytes(seed.to_bytes())),
            Err(_) => {
                return Err(RpcFault::Refused(RpcRefusal::wrong_param(
                    "Wrong seed hash",
                )))
            }
        }
    };
    let admitted = match facts.admit_pow(seed)? {
        PowAdmission::Admitted(admitted) => admitted,
        PowAdmission::Declined(PowDecline::SeedNotHeld { seed }) => {
            return Err(RpcFault::Refused(RpcRefusal::wrong_param(&format!(
                "Seed {} is not held: calc_pow hashes under held seeds only",
                hex::encode(seed.to_bytes())
            ))))
        }
        PowAdmission::Declined(PowDecline::SeedAboveTip { seed_height, tip }) => {
            return Err(RpcFault::Refused(RpcRefusal::wrong_param(&format!(
                "No seed for height {}: its seed height {} is above the chain's top block {}",
                request.height,
                seed_height.to_raw(),
                tip.to_raw()
            ))))
        }
    };
    if bounded {
        budget
            .spend("calc_pow", std::time::Instant::now())
            .map_err(|error| RpcFault::Refused(RpcRefusal::of_error(&error)))?;
    }
    let pow = facts.hash_admitted(&blob, &admitted)?;
    Ok(hex::encode(pow.to_bytes()))
}

/// `get_curve_tree_info`: the curve tree after the top block.
///
/// # Errors
///
/// The facts' fault.
pub fn get_curve_tree_info(
    facts: &dyn ChainReadFacts,
) -> Result<GetCurveTreeInfoResponse, RpcFault> {
    let CurveTreeFacts {
        after,
        root,
        depth,
        leaf_count,
    } = facts.curve_tree()?;
    Ok(GetCurveTreeInfoResponse {
        status: RpcStatus::ok(),
        root: hex::encode(root.to_bytes()),
        depth,
        leaf_count,
        height: after.to_raw(),
    })
}

/// `get_curve_tree_checkpoint`: the curve tree after the block at
/// `block_height`, for every height through the tip — the store records
/// the tree at every height, where the C++ kept one every
/// `FCMP_CURVE_TREE_CHECKPOINT_INTERVAL` (the divergence register's row).
///
/// # Errors
///
/// [`RpcFault::Refused`] (`WRONG_PARAM`, the C++ wording) above the tip;
/// the facts' fault otherwise.
pub fn get_curve_tree_checkpoint(
    facts: &dyn ChainReadFacts,
    request: &GetCurveTreeCheckpointRequest,
) -> Result<GetCurveTreeCheckpointResponse, RpcFault> {
    let Some(tree) = facts.curve_tree_after(BlockHeight::from_raw(request.block_height))? else {
        return Err(RpcFault::Refused(RpcRefusal::wrong_param(&format!(
            "No checkpoint at height {}",
            request.block_height
        ))));
    };
    Ok(GetCurveTreeCheckpointResponse {
        status: RpcStatus::ok(),
        root: hex::encode(tree.root.to_bytes()),
        depth: tree.depth,
        leaf_count: tree.leaf_count,
        block_height: tree.after.to_raw(),
    })
}

/// The refusal for a `p_id` that is not 32 bytes of hex — the C++ wording.
pub const P_ID_REFUSAL: &str = "p_id must be 64 hex characters (32-byte P_canonical_id)";

fn usize_wire(n: usize) -> u64 {
    u64::try_from(n).expect("a count fits u64")
}

/// One window epoch on the wire: its snapshot where the citing gate
/// admitted it, an empty gather with `has_budget_row = false` where it did
/// not, or where the epoch is already below the claim window (nothing is
/// read for it; the wire's `false` is "not claimable", which it is not).
/// `close_block_height` is `0` only for an epoch whose close is past a
/// `u64`, which no window epoch is.
fn claim_epoch_row(epoch: EmissionEpochFacts) -> ClaimEpochSnapshot {
    let mut row = ClaimEpochSnapshot {
        settlement_epoch: epoch.settlement_epoch,
        close_block_height: epoch.close_height.map_or(0, BlockHeight::to_raw),
        sigma_work_milli: 0,
        budget_atomic: 0,
        has_budget_row: false,
        bonds: Vec::new(),
        shards: Vec::new(),
        credit_pairs: Vec::new(),
        claimant_bond_idx: u64::MAX,
    };
    match epoch.standing {
        EmissionEpochStanding::Expired { .. } => {}
        EmissionEpochStanding::Unsettled {
            sigma_work_milli,
            budget,
        } => {
            row.sigma_work_milli = sigma_work_milli.unwrap_or(0);
            row.budget_atomic = budget.unwrap_or(0);
        }
        EmissionEpochStanding::Settled {
            sigma_work_milli,
            budget,
            snapshot,
        } => {
            row.sigma_work_milli = sigma_work_milli;
            row.budget_atomic = budget;
            row.has_budget_row = true;
            row.bonds = snapshot
                .bonds
                .into_iter()
                .map(|bond| ClaimBondRow {
                    join_settlement_epoch: bond.join_settlement_epoch,
                    is_support_complete_tree: bond.is_support_complete_tree,
                    bad_intervals_flat: bond
                        .bad_intervals
                        .iter()
                        .flat_map(|i| [i.start_epoch, i.end_exclusive])
                        .collect(),
                })
                .collect();
            row.shards = snapshot
                .shards
                .into_iter()
                .map(|shard| {
                    let wire = shard.close.to_wire();
                    ClaimShardRow {
                        shard_id: shard.shard_id,
                        freeze_height: wire.freeze_height,
                        has_segment: wire.has_segment,
                    }
                })
                .collect();
            row.credit_pairs = snapshot
                .pairs
                .into_iter()
                .map(|pair| ClaimCreditPair {
                    bond_idx: usize_wire(pair.bond_idx),
                    shard_idx: usize_wire(pair.shard_idx),
                })
                .collect();
            row.claimant_bond_idx = snapshot.claimant_bond_idx.map_or(u64::MAX, usize_wire);
        }
    }
    row
}

/// `get_archival_emission_claim_source`: what `p_id`'s emission claim is
/// built from — the chain count and settled epoch, the record's claim
/// context, and every epoch of the claim window
/// (`EMISSION_CLAIM_BUILDER.md` §7). The request names the persona and
/// nothing else, and the handler branches on nothing claimable-set-derived:
/// every window epoch is listed, and only the epochs the claim verify's
/// citing gate admits carry its gather (`SO-D11g`).
///
/// # Errors
///
/// [`RpcFault::Refused`] (`WRONG_PARAM`, the C++ wording) for a `p_id`
/// that is not 32 bytes of hex; the facts' fault otherwise.
pub fn get_archival_emission_claim_source(
    facts: &dyn ChainReadFacts,
    request: &GetArchivalEmissionClaimSourceRequest,
) -> Result<GetArchivalEmissionClaimSourceResponse, RpcFault> {
    let Ok(p_id) = HashHex::from_hex(&request.p_id) else {
        return Err(RpcFault::Refused(RpcRefusal::wrong_param(P_ID_REFUSAL)));
    };
    let source = facts.emission_claim_source(&PCanonicalId::from_bytes(p_id.to_bytes()))?;
    let mut response = GetArchivalEmissionClaimSourceResponse {
        status: RpcStatus::ok(),
        chain_height: source.chain_height.to_raw(),
        current_settled_epoch: source.current_settled_epoch.to_raw(),
        has_bond_record: source.bond.is_some(),
        join_settlement_epoch: 0,
        holdings_kind: 0,
        held_shard_ids: Vec::new(),
        claimed_settlement_epochs: Vec::new(),
        bonded_total_atomic: 0,
        bad_interval_count: 0,
        has_last_served_epoch: false,
        last_served_epoch: 0,
        has_last_settled_slash_epoch: false,
        last_settled_slash_epoch: 0,
        epochs: source.epochs.into_iter().map(claim_epoch_row).collect(),
    };
    if let Some(bond) = source.bond {
        response.join_settlement_epoch = bond.join_settlement_epoch.to_raw();
        response.holdings_kind = bond.holdings_kind.to_u8();
        response.held_shard_ids = bond.held_shards.iter().map(|s| s.to_raw()).collect();
        response.claimed_settlement_epochs = bond
            .claimed_settlement_epochs
            .iter()
            .map(|e| e.to_raw())
            .collect();
        response.bonded_total_atomic = bond.bonded_total.to_raw();
        response.bad_interval_count = usize_wire(bond.bad_interval_count);
        response.has_last_served_epoch = bond.last_served.is_some();
        response.last_served_epoch = bond.last_served.unwrap_or(0);
        response.has_last_settled_slash_epoch = bond.last_settled_slash.is_some();
        response.last_settled_slash_epoch = bond
            .last_settled_slash
            .map_or(0, shekyl_types::SettlementEpoch::to_raw);
    }
    Ok(response)
}

/// `get_archival_shard_coverage`: the shards a join can hold — closed and
/// final, the byte-cut universe CEN-J15 judges — ranked by join scarcity by
/// the retention crate's ordering (`order_shard_coverage`, SL-D4). The
/// expected-profit hint reads the slash pass's watermark, the epoch whose
/// gather wrote `r_market`, the budget and `Σwork`. Before any pass the
/// hint is absent. The wire epoch is 0 then, and also when epoch 0 settled
/// with a zero `Σwork`; the hint is available when `Σwork` is not zero.
///
/// # Errors
///
/// The facts' fault.
pub fn get_archival_shard_coverage(
    facts: &dyn ChainReadFacts,
) -> Result<GetArchivalShardCoverageResponse, RpcFault> {
    let coverage = facts.shard_coverage()?;
    let budget = coverage.budget.unwrap_or(0);
    let sigma = coverage.sigma_work_milli.unwrap_or(0);
    let ranked = shekyl_archival_retention::order_shard_coverage(
        coverage.as_of.to_raw(),
        budget,
        sigma,
        &coverage.shards,
    );
    Ok(GetArchivalShardCoverageResponse {
        status: RpcStatus::ok(),
        as_of_height: coverage.as_of.to_raw(),
        leaf_count: coverage.leaf_count,
        frozen_count: usize_wire(coverage.shards.len()),
        settled_epoch: coverage.settled_epoch.to_raw(),
        budget_atomic: budget,
        sigma_work_milli: sigma,
        profit_estimate_available: sigma != 0,
        shards: ranked
            .into_iter()
            .map(|row| ShardCoverageRow {
                shard_id: row.shard_id,
                bonded_count: row.bonded_count,
                served_count: row.served_count,
                freeze_height: row.freeze_height,
                join_scarcity_micro: row.join_scarcity_micro,
                expected_profit_atomic: row.expected_profit_atomic,
            })
            .collect(),
    })
}

/// `/get_blocks_by_height.bin` over the store (Q1; `SB-Q2`): each height's
/// block and its listed transactions in the request's form. Under `prune`
/// every body is its skeleton. Without it a body is whole, or — where this
/// node discarded its archival good — the slot state `archived` with its
/// shard (`PDM-Q10`), never a failure of the height. Only a height above
/// the tip ends the reply, with C++'s error status and the blocks read
/// before it.
///
/// # Errors
///
/// [`RpcFault::Refused`] when a bounded caller asks for more than
/// [`RESTRICTED_BLOCK_COUNT`] heights. The facts' fault otherwise.
pub fn get_blocks_by_height(
    facts: &dyn ChainReadFacts,
    request: &GetBlocksByHeightRequest,
    host: bool,
) -> Result<GetBlocksByHeightResponse, RpcFault> {
    if caller_bounded(host) && request.heights.len() > RESTRICTED_BLOCK_COUNT {
        return Err(bound_fault(
            "get_blocks_by_height.bin",
            "heights",
            RESTRICTED_BLOCK_COUNT as u64,
            request.heights.len() as u64,
        ));
    }
    let heights: Vec<BlockHeight> = request
        .heights
        .iter()
        .map(|height| BlockHeight::from_raw(*height))
        .collect();
    let read = facts.blocks_by_height(&heights)?;
    Ok(GetBlocksByHeightResponse {
        status: read.failed.map_or_else(RpcStatus::ok, |height| {
            RpcStatus(format!(
                "Error retrieving block at height {}",
                height.to_raw()
            ))
        }),
        blocks: read
            .blocks
            .into_iter()
            .map(|block| BlockEntry {
                txs: block
                    .txs
                    .iter()
                    .map(|tx| block_tx(tx, request.prune))
                    .collect(),
                block: block.block,
                bundle_references: block.bundle_references,
                bundle_bodies: block.bundle_bodies,
            })
            .collect(),
    })
}

/// One listed transaction in the request's form.
fn block_tx(tx: &ListedTx, prune: bool) -> BlockTx {
    if prune {
        let skeleton = &tx.body.skeleton;
        return BlockTx::Skeleton(BlockTxSkeleton {
            unprunable: skeleton.unprunable.clone(),
            prunable_hash: skeleton.prunable_hash.to_bytes(),
            pqc_auth_hash: skeleton
                .pqc_auth_hash
                .map(shekyl_types::PqcAuthHash::to_bytes),
            archival_len: skeleton.archival_len.to_raw(),
        });
    }
    match tx.body.full_form() {
        FullForm::Whole(bytes) => BlockTx::Full(bytes),
        FullForm::Archived { shard } => BlockTx::Archived {
            tx_hash: tx.hash.to_bytes(),
            shard: shard.to_raw(),
        },
    }
}

/// `/get_transactions` over the store and the pool (`DRS_X_STORE_FLIP.md`
/// DX-Q3, Q1; the review of #1165, ruling 7; `SB-Q2`): today's name and
/// request, the body in the form `prune` chooses — the skeleton, or the
/// whole body with a discarded one answered `archived` (`PDM-Q10`) — its
/// height, time and output indices from the chain, or its pool entry as
/// the host may see it (S6). The wallet's block fetch and its proofs read
/// it with `prune`. A pool entry carries no receive time (S7).
///
/// # Errors
///
/// The facts' fault.
pub fn get_transactions(
    facts: &dyn ChainReadFacts,
    request: &shekyl_rpc_types::GetTransactionsRequest,
    host: bool,
) -> Result<shekyl_rpc_types::GetTransactionsResponse, shekyl_rpc_types::errors::RpcError> {
    let status_only = |status: &str| shekyl_rpc_types::GetTransactionsResponse {
        status: RpcStatus(status.to_owned()),
        txs: Vec::new(),
        missed_tx: Vec::new(),
        archived: Vec::new(),
        unavailable_tx: Vec::new(),
    };
    // The inherited cap (§6.3). A bounded caller over it is
    // `OverResourceBound`. The bound lives in this handler.
    if caller_bounded(host) && request.txs_hashes.len() > RESTRICTED_TRANSACTIONS_COUNT {
        return Err(bound_exceeded(
            "get_transactions",
            "transactions",
            RESTRICTED_TRANSACTIONS_COUNT as u64,
            request.txs_hashes.len() as u64,
        ));
    }
    let ids = match parse_request_hashes(&request.txs_hashes, TX_PARSE_FAILED) {
        Ok(ids) => ids,
        Err(status) => return Ok(status_only(&status)),
    };
    let hashes: Vec<TxHash> = ids.iter().copied().map(TxHash::from_bytes).collect();
    let read = facts.transactions(&hashes, crate::pool_methods::scope_for(host))?;
    Ok(crate::methods::project_transactions(
        request,
        &ids,
        &read.slots,
        read.chain_height,
    ))
}

/// `/get_o_indexes.bin` over the store (Q1): the transaction's outputs'
/// global indices, in `vout` order; C++'s `Failed` for one the chain does
/// not hold.
///
/// # Errors
///
/// The facts' fault.
pub fn get_o_indexes(
    facts: &dyn ChainReadFacts,
    request: &GetOIndexesRequest,
) -> Result<GetOIndexesResponse, RpcFault> {
    Ok(
        match facts.output_indices(&TxHash::from_bytes(request.txid))? {
            Some(o_indexes) => GetOIndexesResponse {
                status: RpcStatus::ok(),
                o_indexes,
            },
            None => GetOIndexesResponse {
                status: RpcStatus("Failed".to_owned()),
                o_indexes: Vec::new(),
            },
        },
    )
}

/// `/is_key_image_spent` over the store and the pool (Q1): spent in the
/// chain, spent by a transaction the pool shows, or unspent. A spend still
/// in its stem phase answers unspent (S6).
///
/// # Errors
///
/// The facts' fault.
pub fn is_key_image_spent(
    facts: &dyn ChainReadFacts,
    request: &IsKeyImageSpentRequest,
    host: bool,
) -> Result<IsKeyImageSpentResponse, RpcFault> {
    let refused = |status: &str| IsKeyImageSpentResponse {
        status: RpcStatus(status.to_owned()),
        spent_status: Vec::new(),
    };
    if caller_bounded(host) && request.key_images.len() > RESTRICTED_SPENT_KEY_IMAGES_COUNT {
        return Err(bound_fault(
            "is_key_image_spent",
            "key images",
            RESTRICTED_SPENT_KEY_IMAGES_COUNT as u64,
            request.key_images.len() as u64,
        ));
    }
    let images = match parse_request_hashes(&request.key_images, KI_PARSE_FAILED) {
        Ok(images) => images,
        Err(status) => return Ok(refused(&status)),
    };
    let images: Vec<KeyImage> = images.into_iter().map(KeyImage::from_bytes).collect();
    Ok(IsKeyImageSpentResponse {
        status: RpcStatus::ok(),
        spent_status: facts
            .key_images_spent(&images)?
            .into_iter()
            .map(|spent| match spent {
                SpentAt::Unspent => KeyImageStatus::Unspent,
                SpentAt::Chain => KeyImageStatus::SpentInBlockchain,
                SpentAt::Pool => KeyImageStatus::SpentInPool,
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use shekyl_rpc_types::errors::ErrorClass;
    use shekyl_rpc_types::GetBlocksByHeightRequest;
    use shekyl_types::{BlockHash, BlockHeight, KeyImage, PCanonicalId, PowHash, TxHash};

    use crate::chain_facts::FactsFault;
    use crate::info_facts::PoolScope;
    use crate::methods::{RpcFault, RpcRefusal, RESTRICTED_BLOCK_COUNT};
    use crate::read_facts::{
        AdmittedPow, AltChainFacts, BlocksAt, ChainReadFacts, ClaimSource, CoinbaseRange,
        CurveTreeFacts, PowAdmission, PowSeed, ShardCoverage, SpentAt, TransactionsAt,
    };

    use super::get_blocks_by_height;

    /// Answers `blocks_by_height` with nothing and panics on every other
    /// read. The cap test watches [`Self::read`].
    struct HeightProbe {
        read: AtomicBool,
    }

    fn unread() -> ! {
        panic!("the height cap returns before any other chain read")
    }

    impl ChainReadFacts for HeightProbe {
        fn blocks_by_height(&self, _heights: &[BlockHeight]) -> Result<BlocksAt, FactsFault> {
            self.read.store(true, Ordering::SeqCst);
            Ok(BlocksAt {
                blocks: Vec::new(),
                failed: None,
            })
        }

        fn transactions(
            &self,
            _ids: &[TxHash],
            _scope: PoolScope,
        ) -> Result<TransactionsAt, FactsFault> {
            unread()
        }

        fn output_indices(&self, _txid: &TxHash) -> Result<Option<Vec<u64>>, FactsFault> {
            unread()
        }

        fn key_images_spent(&self, _key_images: &[KeyImage]) -> Result<Vec<SpentAt>, FactsFault> {
            unread()
        }

        fn alt_block_hashes(&self) -> Result<Vec<BlockHash>, FactsFault> {
            unread()
        }

        fn alternate_chains(&self) -> Result<Vec<AltChainFacts>, FactsFault> {
            unread()
        }

        fn curve_tree(&self) -> Result<CurveTreeFacts, FactsFault> {
            unread()
        }

        fn curve_tree_after(
            &self,
            _height: BlockHeight,
        ) -> Result<Option<CurveTreeFacts>, FactsFault> {
            unread()
        }

        fn coinbase_sum(
            &self,
            _start: BlockHeight,
            _count: u64,
        ) -> Result<CoinbaseRange, FactsFault> {
            unread()
        }

        fn admit_pow(&self, _seed: PowSeed) -> Result<PowAdmission, FactsFault> {
            unread()
        }

        fn hash_admitted(
            &self,
            _pow_blob: &[u8],
            _admitted: &AdmittedPow,
        ) -> Result<PowHash, FactsFault> {
            unread()
        }

        fn emission_claim_source(
            &self,
            _persona: &PCanonicalId,
        ) -> Result<ClaimSource, FactsFault> {
            unread()
        }

        fn shard_coverage(&self) -> Result<ShardCoverage, FactsFault> {
            unread()
        }
    }

    fn probe() -> HeightProbe {
        HeightProbe {
            read: AtomicBool::new(false),
        }
    }

    fn heights(count: usize) -> GetBlocksByHeightRequest {
        GetBlocksByHeightRequest {
            heights: vec![0; count],
            prune: false,
        }
    }

    /// The method owns the cap. One past it refuses before the chain is
    /// read, and the refusal is the one JSON-RPC error object. At the cap,
    /// and for the host at any count, the chain is read.
    #[test]
    fn the_block_cap_refuses_before_the_chain_is_read() {
        let over = heights(RESTRICTED_BLOCK_COUNT + 1);
        let facts = probe();
        let fault = get_blocks_by_height(&facts, &over, false).unwrap_err();
        assert!(!facts.read.load(Ordering::SeqCst));
        let RpcFault::Refused(refusal) = fault else {
            panic!("the cap is a refusal");
        };
        let value = serde_json::to_value(refusal.to_json_rpc(serde_json::Value::Null))
            .expect("a refusal serializes");
        assert_eq!(value["jsonrpc"], "2.0");
        assert!(value["id"].is_null());
        assert!(value.get("result").is_none());
        assert_eq!(
            value
                .pointer("/error/code")
                .and_then(serde_json::Value::as_i64),
            Some(ErrorClass::OverResourceBound.code())
        );
        let message = value
            .pointer("/error/message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        assert!(message.contains("1000"), "{message}");
        assert!(message.contains("1001"), "{message}");
        assert_eq!(
            value
                .pointer("/error/data/code")
                .and_then(serde_json::Value::as_str),
            Some("rpc.bound.exceeded")
        );

        let at_cap = probe();
        let served = get_blocks_by_height(&at_cap, &heights(RESTRICTED_BLOCK_COUNT), false)
            .expect("a thousand heights are inside the cap");
        assert!(at_cap.read.load(Ordering::SeqCst));
        assert!(served.status.is_ok());

        let host = probe();
        assert!(get_blocks_by_height(&host, &over, true).is_ok());
        assert!(host.read.load(Ordering::SeqCst), "the host is not capped");
    }

    /// The same object `Authority::refusal` builds, so a handler cannot
    /// drift onto a second encoding.
    #[test]
    fn a_refusal_and_the_authority_share_one_error_object() {
        use shekyl_rpc_types::errors::{Diagnostic, RpcError};
        let error = RpcError::new(
            ErrorClass::OverResourceBound,
            Diagnostic::new("rpc.bound.exceeded", "over"),
        );
        let from_refusal = RpcRefusal::of_error(&error).to_json_rpc(serde_json::Value::Null);
        let from_authority = crate::authority::refusal(serde_json::Value::Null, &error);
        assert_eq!(
            serde_json::to_value(from_refusal).unwrap(),
            serde_json::to_value(from_authority).unwrap()
        );
    }
}
