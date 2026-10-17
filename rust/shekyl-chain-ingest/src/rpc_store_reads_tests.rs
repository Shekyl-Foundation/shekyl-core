// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The store flip's native read handlers (`shekyl-daemon-rpc`'s
//! `read_methods`, over `StoreFacts`' `ChainReadFacts`; `DRS_X_STORE_FLIP.md`
//! DX-Q3, PR 3) over scenario chains mined through the production stack.
//! The captured-chain differential for the same reads is in
//! `rpc_store_facts_tests.rs`, beside the one for the header facts, so the
//! six chains replay once.
//!
//! Every expectation is computed from something other than the facts under
//! test: the mined template and its verdict, the producer's seed, a hash
//! recomputed through the substrate, the next block's header.

use std::collections::BTreeSet;
use std::sync::Arc;

use shekyl_chain_rules::AtHeight;
use shekyl_daemon_rpc::chain_facts::FactsFault;
use shekyl_daemon_rpc::info_facts::InfoFacts;
use shekyl_daemon_rpc::methods::{RpcFault, RpcRefusal};
use shekyl_daemon_rpc::read_facts::ChainReadFacts;
use shekyl_daemon_rpc::read_methods::{
    calc_pow, get_alt_blocks_hashes, get_alternate_chains, get_coinbase_tx_sum,
    get_curve_tree_checkpoint, get_curve_tree_info, COINBASE_SUM_RANGE_REFUSAL,
};
use shekyl_harness_spender::Spender;
use shekyl_rpc_types::{
    CalcPowRequest, GetCoinbaseTxSumRequest, GetCurveTreeCheckpointRequest, HashHex,
    CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB, CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB_SIZE,
    CORE_RPC_ERROR_CODE_WRONG_PARAM,
};
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::{Ct, Transaction};

use crate::connector::Offered;
use crate::rpc_store_facts_tests::{facts_over, hex, keccak_pow, KeccakPow};
use crate::scenario::{Mined, Scenario, RULES};
use crate::test_support::{cleanup, h, open_store, tmp, Family, FIRST_SPEND_HEIGHT};

/// The fee a listed body pays.
fn fee_of(tx: &Transaction) -> u64 {
    match tx.ct {
        Ct::Fcmp { fee, .. } => fee,
        Ct::Null(_) => 0,
    }
}

/// The coinbase's outputs, summed.
fn coinbase_total(mined: &Mined) -> u64 {
    mined
        .template
        .block
        .miner_transaction
        .prefix
        .outputs
        .iter()
        .map(|o| o.amount)
        .sum()
}

/// Two branches off one main chain: `y` leaves after block 3 and is two
/// blocks long, `z` leaves after block 4 and is one. The alt table holds
/// their three blocks; the alt chains are the two tips walked down to the
/// block each leaves from.
#[tokio::test]
async fn the_alt_reads_are_the_alt_table_walked_into_chains() {
    let mut x = Scenario::open_with("rpc-reads-alt-x", KeccakPow);
    let mut y = Scenario::open_with("rpc-reads-alt-y", KeccakPow);
    let mut z = Scenario::open_with("rpc-reads-alt-z", KeccakPow);
    x.mine(4).await;
    y.mine(4).await;
    z.mine(5).await;
    let main = x.mine(3).await;
    y.idle();
    let y_branch = y.mine(2).await;
    z.idle();
    let z_branch = z.mine(1).await;
    assert_eq!(z_branch[0].template.block.header.previous, main[0].hash);
    for alt in y_branch.iter().chain(&z_branch) {
        match x.offer(alt).await.expect("offer") {
            Offered::Held { height } => assert_eq!(height, alt.height),
            other => panic!("a lighter branch is held: {other:?}"),
        }
    }
    x.reopen(|path| {
        let store = Arc::new(open_store(path));
        let facts = facts_over(Arc::clone(&store), path, RULES);
        let snap = store.begin_read().expect("read");
        let table_order: Vec<HashHex> = snap
            .alt_blocks()
            .expect("alt rows")
            .into_iter()
            .map(|entry| hex(entry.id))
            .collect();

        // Every alt block, in the table's order.
        let hashes = get_alt_blocks_hashes(&facts).expect("alt hashes");
        assert!(hashes.status.is_ok());
        assert_eq!(hashes.blks_hashes, table_order);
        let offered: BTreeSet<HashHex> = y_branch
            .iter()
            .chain(&z_branch)
            .map(|m| hex(m.hash))
            .collect();
        assert_eq!(
            hashes.blks_hashes.iter().copied().collect::<BTreeSet<_>>(),
            offered,
            "the alt blocks are the three offered"
        );

        // The two chains, each from its tip down to where it leaves.
        let chains = get_alternate_chains(&facts).expect("alt chains");
        assert!(chains.status.is_ok());
        assert_eq!(chains.chains.len(), 2, "two tips");
        let main_at = |height: u64| match snap.block_info(h(height)).expect("info") {
            AtHeight::Recorded(info) => hex(info.hash),
            AtHeight::AboveTip => panic!("main block {height}"),
        };
        for (branch, leaves_after) in [(&y_branch, 3u64), (&z_branch, 4u64)] {
            let tip = branch.last().expect("non-empty");
            let chain = chains
                .chains
                .iter()
                .find(|c| c.block_hash == hex(tip.hash))
                .unwrap_or_else(|| panic!("a chain tipped at {:?}", tip.hash));
            let expected_blocks: Vec<HashHex> = branch.iter().rev().map(|m| hex(m.hash)).collect();
            assert_eq!(chain.block_hashes, expected_blocks, "tip first");
            assert_eq!(chain.length, u64::try_from(branch.len()).expect("fits"));
            assert_eq!(chain.height, tip.height.to_raw());
            let row = snap
                .alt_block(&tip.hash)
                .expect("read")
                .expect("the tip is held");
            let work = row.cumulative_difficulty().to_raw();
            assert_eq!(
                (u128::from(chain.difficulty_top64) << 64) | u128::from(chain.difficulty),
                work
            );
            assert_eq!(chain.wide_difficulty, format!("0x{work:x}"));
            // The parent the lowest block names, which here is also the
            // main chain's block below the chain — the C++'s reading.
            assert_eq!(chain.main_chain_parent_block, main_at(leaves_after));
            assert_eq!(
                chain.main_chain_parent_block,
                main_at(chain.height - chain.length)
            );
        }
        // The tips are walked in the table's key order.
        let tip_order: Vec<&HashHex> = chains.chains.iter().map(|c| &c.block_hash).collect();
        let mut by_table: Vec<&HashHex> = table_order
            .iter()
            .filter(|id| tip_order.contains(id))
            .collect();
        by_table.dedup();
        assert_eq!(tip_order, by_table);
        drop(snap);
        drop(facts);
        drop(store);
    })
    .await;
    x.close().await;
    y.close().await;
    z.close().await;
}

/// The tree after block `h` is the root the block at `h + 1` was built
/// against (its header carries it, CEN-B5), at every height of a chain
/// whose coinbases have matured into the tree; the tree after the tip is
/// `get_curve_tree_info`, and the store's own summary agrees; above the
/// tip there is no tree to report.
#[tokio::test]
async fn the_tree_after_each_block_is_the_root_the_next_block_was_built_on() {
    let mut s = Scenario::open("rpc-reads-tree");
    let mined = s.mine(FIRST_SPEND_HEIGHT + 3).await;
    let tip = mined.last().expect("mined").height;
    s.reopen(|path| {
        let store = Arc::new(open_store(path));
        let facts = facts_over(Arc::clone(&store), path, RULES);
        for pair in mined.windows(2) {
            let (below, above) = (&pair[0], &pair[1]);
            let checkpoint = get_curve_tree_checkpoint(
                &facts,
                &GetCurveTreeCheckpointRequest {
                    block_height: below.height.to_raw(),
                },
            )
            .expect("through the tip");
            assert!(checkpoint.status.is_ok());
            assert_eq!(checkpoint.block_height, below.height.to_raw());
            assert_eq!(
                checkpoint.root,
                hex::encode(above.template.block.header.curve_tree_root.to_bytes()),
                "the tree after {} is the root block {} was built on",
                below.height.to_raw(),
                above.height.to_raw()
            );
        }

        let info = get_curve_tree_info(&facts).expect("info");
        assert!(info.status.is_ok());
        assert_eq!(info.height, tip.to_raw());
        assert!(
            info.leaf_count > 0,
            "the coinbases matured into the tree (rule 47: the subject exists)"
        );
        let at_tip = get_curve_tree_checkpoint(
            &facts,
            &GetCurveTreeCheckpointRequest {
                block_height: tip.to_raw(),
            },
        )
        .expect("the tip");
        assert_eq!(
            (at_tip.root.as_str(), at_tip.depth, at_tip.leaf_count),
            (info.root.as_str(), info.depth, info.leaf_count),
            "info is the checkpoint at the tip"
        );
        let summary = store
            .begin_read()
            .expect("read")
            .curve_tree()
            .expect("summary");
        assert_eq!(info.root, hex::encode(summary.root.to_bytes()));
        assert_eq!(info.leaf_count, summary.leaf_count.to_raw());
        assert_eq!(info.depth, summary.depth.to_raw());

        let above = tip.to_raw() + 1;
        assert_eq!(
            get_curve_tree_checkpoint(
                &facts,
                &GetCurveTreeCheckpointRequest {
                    block_height: above
                }
            ),
            Err(RpcFault::Refused(RpcRefusal::wrong_param(&format!(
                "No checkpoint at height {above}"
            ))))
        );
        drop(facts);
        drop(store);
    })
    .await;
    s.close().await;
}

/// The coinbase sum over a chain with two listed spends: the emission is
/// what each block's verdict paid (CEN-G12's growth of the supply), the
/// fees are what the spends paid, and the whole chain's emission is the
/// supply accumulator `get_info` reports. The C++'s emission figure —
/// each coinbase less the block's fees — is printed beside it: on the
/// spending block it is not what was minted.
#[tokio::test]
async fn the_coinbase_sum_is_the_supply_growth_and_the_listed_fees() {
    const AT: u64 = FIRST_SPEND_HEIGHT + 1;
    let mut s = Scenario::open("rpc-reads-coinbase-sum");
    let mut mined = s.mine(AT).await;
    let (a, b) = {
        let spender = Spender::over(&mined);
        let wallet = s.wallet();
        (
            spender.spend_coinbase(wallet, h(0), h(AT), Family::Main.fee()),
            spender.spend_coinbase(wallet, h(1), h(AT), Family::Main.fee()),
        )
    };
    let fees = u128::from(fee_of(&a) + fee_of(&b));
    assert!(fees > 0, "the spends pay fees (rule 47)");
    let spending = s
        .mine_listing(vec![a, b])
        .await
        .unwrap_or_else(|outcome| panic!("the spends connect: {outcome}"));
    assert_eq!(spending.height, h(AT));
    mined.push(spending);
    mined.extend(s.mine(1).await);
    let tip = mined.last().expect("mined").height;
    let chain = tip.to_raw() + 1;
    s.reopen(|path| {
        let store = Arc::new(open_store(path));
        let facts = facts_over(Arc::clone(&store), path, RULES);
        let sum = |height: u64, count: u64| {
            get_coinbase_tx_sum(&facts, &GetCoinbaseTxSumRequest { height, count })
                .expect("coinbase sum")
        };
        let amount = |low: u64, top: u64| (u128::from(top) << 64) | u128::from(low);

        // Block by block: the verdict's paid reward, and the listed fees.
        for m in &mined {
            let one = sum(m.height.to_raw(), 1);
            assert!(one.status.is_ok());
            let listed: u128 = if m.height == h(AT) { fees } else { 0 };
            assert_eq!(
                amount(one.emission_amount, one.emission_amount_top64),
                u128::from(m.emission.paid.to_raw()),
                "emission at {} is the paid reward",
                m.height.to_raw()
            );
            assert_eq!(amount(one.fee_amount, one.fee_amount_top64), listed);
            let cxx = i128::from(coinbase_total(m)) - i128::try_from(listed).expect("fits");
            if m.height == h(AT) {
                eprintln!(
                    "coinbase sum at the spending block {}: minted {}, C++ figure (coinbase {} less fees {}) {}",
                    m.height.to_raw(),
                    m.emission.paid.to_raw(),
                    coinbase_total(m),
                    listed,
                    cxx
                );
            }
        }

        // The whole chain: the supply accumulator, and every fee.
        let whole = sum(0, chain);
        let coins = facts.chain().expect("info chain").already_generated_coins;
        assert_eq!(
            amount(whole.emission_amount, whole.emission_amount_top64),
            u128::from(coins.to_raw())
        );
        assert_eq!(
            whole.wide_emission_amount,
            format!("0x{:x}", coins.to_raw())
        );
        assert_eq!(amount(whole.fee_amount, whole.fee_amount_top64), fees);

        // A range that starts inside and runs past the tip stops at it.
        assert_eq!(sum(AT, chain), sum(AT, 2));
        // An empty range is zero and OK.
        let empty = sum(0, 0);
        assert!(empty.status.is_ok());
        assert_eq!((empty.emission_amount, empty.fee_amount), (0, 0));
        assert_eq!(empty.wide_emission_amount, "0x0");
        // The C++ bound: a start at the count, or a count past it.
        for (height, count) in [(chain, 1), (0, chain + 1)] {
            let refused = sum(height, count);
            assert_eq!(refused.status.0, COINBASE_SUM_RANGE_REFUSAL);
            assert_eq!(
                (refused.emission_amount, refused.wide_emission_amount.as_str()),
                (0, "")
            );
        }
        drop(facts);
        drop(store);
    })
    .await;
    s.close().await;
}

/// `calc_pow` is the substrate's hash of the bytes as given, under the seed
/// the height names — for every mined block, the hash the node recorded
/// when it judged the block — or under a seed the caller names. A seed
/// height above the tip, a blob that is not hex or is larger than any
/// block, and a seed that is not 32 bytes are refused with the C++ codes.
#[tokio::test]
async fn calc_pow_hashes_the_bytes_under_the_seed_the_height_names() {
    let mut s = Scenario::open_with("rpc-reads-calc-pow", KeccakPow);
    let mined = s.mine(6).await;
    s.reopen(|path| {
        let store = Arc::new(open_store(path));
        let facts = facts_over(Arc::clone(&store), path, RULES);
        let ask = |height: u64, blob: &str, seed: &str| {
            calc_pow(
                &facts,
                &CalcPowRequest {
                    height,
                    block_blob: blob.to_owned(),
                    seed_hash: seed.to_owned(),
                },
            )
        };
        for m in &mined {
            let blob = m.template.block.pow_blob();
            assert_eq!(
                ask(m.height.to_raw(), &hex::encode(&blob), ""),
                Ok(hex::encode(keccak_pow(&blob, &m.seed))),
                "the recorded PoW at {}",
                m.height.to_raw()
            );
        }
        let blob = mined[2].template.block.pow_blob();
        let named = BlockHash::from_bytes([7; 32]);
        assert_eq!(
            ask(0, &hex::encode(&blob), &hex::encode(named.to_bytes())),
            Ok(hex::encode(keccak_pow(&blob, &named)))
        );
        let far = 1_000_000u64;
        let seed_height = shekyl_chain_rules::seed_height(BlockHeight::from_raw(far))
            .expect("not genesis")
            .to_raw();
        let tip = mined.last().expect("mined").height.to_raw();
        assert_eq!(
            ask(far, &hex::encode(&blob), ""),
            Err(RpcFault::Refused(RpcRefusal::wrong_param(&format!(
                "No seed for height {far}: its seed height {seed_height} is above the chain's top block {tip}"
            ))))
        );
        assert_eq!(
            ask(1, "zz", ""),
            Err(RpcFault::Refused(RpcRefusal {
                code: CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB,
                message: "Wrong block blob".to_owned()
            }))
        );
        let oversize = vec![0u8; shekyl_wire::block::MAX_BLOCK_BLOB_SIZE + 1];
        assert_eq!(
            ask(1, &hex::encode(oversize), ""),
            Err(RpcFault::Refused(RpcRefusal {
                code: CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB_SIZE,
                message: "Block blob size is too big, rejecting block".to_owned()
            }))
        );
        assert!(matches!(
            ask(1, &hex::encode(&blob), "abcd"),
            Err(RpcFault::Refused(RpcRefusal { code: CORE_RPC_ERROR_CODE_WRONG_PARAM, .. }))
        ));
        drop(facts);
        drop(store);
    })
    .await;
    s.close().await;
}

/// An empty store has no tip: every chain read is not ready. A hash under a
/// seed the caller names needs no chain, and is answered.
#[test]
fn an_empty_store_has_no_chain_reads_and_hashes_under_a_named_seed() {
    let path = tmp("rpc-reads-empty");
    let store = Arc::new(open_store(&path));
    let facts = facts_over(Arc::clone(&store), &path, RULES);
    assert_eq!(facts.alt_block_hashes(), Err(FactsFault::NotReady));
    assert_eq!(facts.alternate_chains(), Err(FactsFault::NotReady));
    assert_eq!(facts.curve_tree(), Err(FactsFault::NotReady));
    assert_eq!(
        facts.curve_tree_after(BlockHeight::ZERO),
        Err(FactsFault::NotReady)
    );
    assert_eq!(
        facts.coinbase_sum(BlockHeight::ZERO, 1),
        Err(FactsFault::NotReady)
    );
    let seed = BlockHash::from_bytes([3; 32]);
    assert_eq!(
        calc_pow(
            &facts,
            &CalcPowRequest {
                height: 5,
                block_blob: "00".to_owned(),
                seed_hash: hex::encode(seed.to_bytes()),
            }
        ),
        Ok(hex::encode(keccak_pow(&[0], &seed)))
    );
    drop(facts);
    drop(store);
    cleanup(&path);
}
