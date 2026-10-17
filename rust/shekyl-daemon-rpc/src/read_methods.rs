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
use shekyl_types::{BlockHash, BlockHeight};

use crate::methods::{RpcFault, RpcRefusal};
use crate::read_facts::{ChainReadFacts, CoinbaseRange, CurveTreeFacts, PowAt, PowSeed};

/// The status `get_coinbase_tx_sum` answers a range outside the chain with
/// — the C++ handler's string, which clients match on.
pub const COINBASE_SUM_RANGE_REFUSAL: &str = "height or count is too large";

/// The wire's three-field rendering of a 128-bit value — `store_128`'s
/// split: the low word, the whole value as `0x` minimal lowercase hex
/// (`cryptonote::hex`), the high word.
fn split_128(value: u128) -> (u64, String, u64) {
    let low = u64::try_from(value & u128::from(u64::MAX)).expect("masked to 64 bits");
    let top = u64::try_from(value >> 64).expect("a u128 shifted right 64 fits in u64");
    (low, format!("0x{value:x}"), top)
}

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
        }));
    };
    if blob.len() > shekyl_wire::block::MAX_BLOCK_BLOB_SIZE {
        return Err(RpcFault::Refused(RpcRefusal {
            code: CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB_SIZE,
            message: "Block blob size is too big, rejecting block".to_owned(),
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
