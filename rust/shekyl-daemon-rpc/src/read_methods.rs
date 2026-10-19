// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The store flip's native read handlers (`DRS_X_STORE_FLIP.md` DX-Q3,
//! PR 3), over [`ChainReadFacts`]. **Built and not routed:** no handler
//! here is in [`native_method_for`](crate::handlers) or a REST route, and
//! the server answers each method from the C++ table until the flip. Each
//! answers on the C++ wire (`shekyl_rpc_types::chain_reads`, `archival`);
//! where it answers differently, the difference is a row in
//! `DRS_X_STORE_FLIP.md`'s divergence register, and the flip's
//! `CORE_RPC_VERSION` bump is stated there.

use shekyl_rpc_types::{
    AltChainInfo, CalcPowRequest, GetAltBlocksHashesResponse, GetAlternateChainsResponse,
    GetCoinbaseTxSumRequest, GetCoinbaseTxSumResponse, GetCurveTreeCheckpointRequest,
    GetCurveTreeCheckpointResponse, GetCurveTreeInfoResponse, HashHex, RpcStatus,
    CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB, CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB_SIZE,
};
use shekyl_rpc_types::{
    ClaimBondRow, ClaimCreditPair, ClaimEpochSnapshot, ClaimShardRow,
    GetArchivalEmissionClaimSourceRequest, GetArchivalEmissionClaimSourceResponse,
    GetArchivalShardCoverageResponse, ShardCoverageRow,
};
use shekyl_types::{BlockHash, BlockHeight, PCanonicalId};

use crate::methods::{split_128, RpcFault, RpcRefusal};
use crate::read_facts::{ChainReadFacts, CoinbaseRange, CurveTreeFacts, PowAt, PowSeed};
use shekyl_chain_rules::{EmissionEpochFacts, EmissionEpochStanding};

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
/// The bytes are hashed as given — a block's hashing blob — as the C++
/// handler hashed them. Their length is bounded by the largest block blob
/// the wire parses (`MAX_BLOCK_BLOB_SIZE`): `calc_pow` admits nothing, so
/// the bound protects the hasher, not the chain.
///
/// The hash is computed only under a cache the daemon already holds;
/// `calc_pow` never derives one (ruled 2026-10-17). The C++ derived a cache
/// for any seed, evicting the validator's spare, with no bound across
/// concurrent seeds.
///
/// # Errors
///
/// [`RpcFault::Refused`]: the blob is not hex (`WRONG_BLOCKBLOB`), larger
/// than the bound (`WRONG_BLOCKBLOB_SIZE`), the seed is not 32 bytes of hex,
/// the seed height is above the tip, or the seed's cache is not held (all
/// `WRONG_PARAM`). The facts' fault otherwise.
pub fn calc_pow(facts: &dyn ChainReadFacts, request: &CalcPowRequest) -> Result<String, RpcFault> {
    let Ok(blob) = hex::decode(&request.block_blob) else {
        return Err(RpcFault::Refused(RpcRefusal {
            code: CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB,
            message: "Wrong block blob".to_owned(),
            data: None,
        }));
    };
    if blob.len() > shekyl_wire::block::MAX_BLOCK_BLOB_SIZE {
        return Err(RpcFault::Refused(RpcRefusal {
            code: CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB_SIZE,
            message: "Block blob size is too big, rejecting block".to_owned(),
            data: None,
        }));
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
    match facts.pow_hash(&blob, seed)? {
        PowAt::Hashed(pow) => Ok(hex::encode(pow.to_bytes())),
        PowAt::SeedNotHeld { seed } => Err(RpcFault::Refused(RpcRefusal::wrong_param(&format!(
            "Seed {} is not held: calc_pow hashes under held seeds only",
            hex::encode(seed.to_bytes())
        )))),
        PowAt::SeedAboveTip { seed_height, tip } => {
            Err(RpcFault::Refused(RpcRefusal::wrong_param(&format!(
                "No seed for height {}: its seed height {} is above the chain's top block {}",
                request.height,
                seed_height.to_raw(),
                tip.to_raw()
            ))))
        }
    }
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
                    is_foundation_complete_tree: bond.is_foundation_complete_tree,
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
