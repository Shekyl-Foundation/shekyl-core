// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The driver's own contract: a scripted chain is a chain the validator
//! admitted, whose record is what the owners priced.

use shekyl_chain_rules::{CenRow, Locus, TxSlot};
use shekyl_types::{BlockHeight, CurveTreeRoot};

use super::{Scenario, RULES};
use crate::connector::HashAt;

/// The rows every landed block should have been judged under — the 4.F
/// coinbase rows and the header rows the template satisfies from the
/// tip's facts. A row that stops judging fails here.
const JUDGES_EVERY_BLOCK: [CenRow; 13] = [
    CenRow::F1,
    CenRow::F3,
    CenRow::F4,
    CenRow::F5,
    CenRow::F6,
    CenRow::F7,
    CenRow::F9,
    CenRow::F10,
    CenRow::A2,
    CenRow::B1,
    CenRow::B5,
    CenRow::C1,
    CenRow::C2,
];

#[tokio::test]
async fn a_mined_chain_is_admitted_block_by_block_and_the_record_is_the_owners() {
    let mut scenario = Scenario::open("scenario-mine");
    let mined = scenario.mine(6).await;
    assert_eq!(mined.len(), 6);
    for (i, block) in mined.iter().enumerate() {
        assert_eq!(block.height, BlockHeight::from_raw(i as u64));
        for row in JUDGES_EVERY_BLOCK {
            // C1/C2 are exempt at genesis but record as applied there
            // (timestamps.rs module docs), so the list holds at 0 too.
            assert!(
                block.judged_by.contains(&row),
                "{row} did not judge block {}",
                block.height
            );
        }
    }

    // The chain the producer reads back is the chain it built.
    let facts = scenario.facts().await.expect("facts");
    assert_eq!(facts.connecting, BlockHeight::from_raw(6));
    assert_eq!(facts.previous, mined[5].hash);
    // CEN-G12's accumulator is the validator's (slice 7 commit 5): at every
    // height it advances by the paid reward F14b prices, which is what the
    // template priced (`paid_block_reward`, one owner) — so the fold is the
    // sum of the templates' rewards. At genesis the validator takes the
    // coinbase's configured total (F11, the C++'s `base_reward =
    // money_in_use`), and since wave B the template pays its priced reward
    // **whole** there (CEN-G13: no staker leg at height 0), so the two
    // agree at genesis too. *Records-was:* from slice 7 commit 5 to wave B
    // this test pinned the finding — a template-built genesis paid only the
    // miner leg of a share the validator never accrued, so height 0
    // contributed less than `block_reward`.
    let genesis_paid: u64 = mined[0]
        .template
        .block
        .miner_transaction
        .prefix
        .outputs
        .iter()
        .map(|o| o.amount)
        .sum();
    assert_eq!(
        genesis_paid,
        mined[0].template.block_reward.to_raw(),
        "G13: the genesis template pays the priced reward whole"
    );
    let priced: u64 = mined.iter().map(|m| m.template.block_reward.to_raw()).sum();
    assert_eq!(facts.parent_coins_generated.to_raw(), priced);
    // CEN-F18 held every one of them: each coinbase paid exactly the miner
    // legs the template priced, and the validator's F17 split (over the
    // closed-shard count the facts carry, `closed_shards_before`) agreed
    // with the producer's — zero fees, the split at zero.
    for m in &mined {
        assert!(
            m.judged_by.contains(&CenRow::F18),
            "F18 judged {}",
            m.height
        );
    }
    // Empty blocks: the volume window counts none, over min(h, W) blocks.
    assert_eq!(facts.tx_volume, shekyl_economics::TxVolume::window(0, 6));
    // The next header will carry the root the store recorded after block
    // 5 — the verdict's derivation, the empty tree this early — CEN-B5 by
    // the same read the template performs.
    assert_eq!(facts.curve_tree_root, CurveTreeRoot::EMPTY);
    // Timestamps ascend by the interval; the median exists.
    assert!(facts.median_timestamp.is_some());
    let stamps: Vec<u64> = mined
        .iter()
        .map(|m| m.template.block.header.timestamp)
        .collect();
    assert!(stamps.windows(2).all(|w| w[1] > w[0]), "{stamps:?}");

    scenario.close().await;
}

#[tokio::test]
async fn a_rewind_pops_to_the_target_and_mining_resumes_on_the_new_tip() {
    let mut scenario = Scenario::open("scenario-reorg");
    let first = scenario.mine(5).await;
    let rewound = scenario
        .rewind_to(BlockHeight::from_raw(2))
        .await
        .expect("rewinds");
    assert_eq!(rewound.popped, 2);
    assert_eq!(
        scenario
            .hash_at(BlockHeight::from_raw(3))
            .await
            .expect("read"),
        None,
        "height 3 is gone"
    );

    // The fork: new blocks at 3 and 4 on the same parent, distinct from
    // the popped ones (a later clock, a later tx key), and the record
    // resumes from block 2's fold — not from the popped tip's.
    let fork = scenario.mine(2).await;
    assert_eq!(fork[0].height, BlockHeight::from_raw(3));
    assert_eq!(fork[0].template.block.header.previous, first[2].hash);
    assert_ne!(fork[0].hash, first[3].hash);
    let facts = scenario.facts().await.expect("facts");
    // Genesis contributes what its coinbase paid (F11); every later block
    // the paid reward its template priced (F14b) — the same two owners as
    // the admission test above.
    let genesis_paid: u64 = first[0]
        .template
        .block
        .miner_transaction
        .prefix
        .outputs
        .iter()
        .map(|o| o.amount)
        .sum();
    let expected: u64 = first[1..3]
        .iter()
        .chain(fork.iter())
        .map(|m| m.template.block_reward.to_raw())
        .sum();
    assert_eq!(
        facts.parent_coins_generated.to_raw(),
        genesis_paid + expected
    );
    assert_eq!(
        scenario
            .connector()
            .ask(HashAt {
                height: BlockHeight::from_raw(4)
            })
            .await
            .expect("read"),
        Some(fork[1].hash)
    );
    scenario.close().await;
}

/// The same first scenario under real RandomX: the free longhash above is
/// the driver's default, not its only substrate, and a block the free
/// hash admits is one the real hash admits at difficulty one. `#[ignore]`d
/// for the live lane — the cache derivation is seconds, not milliseconds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real RandomX; seconds. Run in the live lane: cargo test -p shekyl-chain-ingest scenario -- --ignored"]
async fn a_chain_mines_under_the_production_substrate() {
    use std::sync::Arc;

    use crate::metrics::Metrics;
    use crate::substrate::ProductionSubstrate;
    use shekyl_pow_randomx::CacheStore;

    let pow = ProductionSubstrate::new(Arc::new(CacheStore::new()), Arc::new(Metrics::new()));
    let mut scenario = Scenario::open_with("scenario-randomx", pow);
    let mined = scenario.mine(3).await;
    assert_eq!(mined.len(), 3);
    for block in &mined {
        for row in [CenRow::D1, CenRow::D2, CenRow::D3] {
            assert!(block.judged_by.contains(&row), "{row} at {}", block.height);
        }
    }
    scenario.close().await;
}

#[test]
fn the_scenario_rules_are_regtest_at_difficulty_one() {
    // Pinned so the free longhash and a real one agree: any hash satisfies
    // a target of one, and the subject of every scenario stays the chain.
    assert!(matches!(
        RULES,
        crate::schedule::ChainRules::Regtest {
            fixed_difficulty: Some(d),
            schedule,
        } if d.get() == 1 && schedule.is_production()
    ));
}

/// DRS-E3 commit 7 (`DRS_E3_CURVE_WRITER.md` §2.3, §6 row 7): the driver
/// produces a **real** FCMP++ spend against the tree the store grew, and the
/// store admits it — the object CEN-I15 and H19-verify wait for.
///
/// Two oracles in one test. The wallet-side tree (`shekyl_curve_tree`'s
/// client, fed the same blocks) and the store's writer (`grow.rs`) are held
/// equal at every root a header commits to — DRS-D3c's two Rust producers
/// compared, §2.5 — and the spend's membership proof, assembled from the
/// wallet side and self-verified against its root at the reference height,
/// is listed in a block whose validity the store judges against its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_real_spend_against_the_grown_tree_is_admitted_and_the_two_trees_agree() {
    use super::StepOutcome;
    use crate::scenario_spend::Spender;
    use shekyl_chain_rules::RuleSet;

    // Block 0's coinbase matures at connect 60 (`mined_money_unlock_window`)
    // and is in the tree going into 61; the newest admissible reference for a
    // block connecting at `c` is `c − 10`, so the first block that can spend
    // it against a root containing it connects at 71.
    let window = RuleSet::GENESIS.mined_money_unlock_window().to_raw();
    let age = RuleSet::GENESIS.tx_spendable_age().to_raw();
    let connecting = window + age + 1;
    let mut scenario = Scenario::open("scenario-spend");
    let mined = scenario.mine(connecting).await;
    assert_eq!(mined.len() as u64, connecting);

    // Oracle 1: the wallet-side tree over the same blocks equals the store's
    // at every height a header commits to — empty through the first drain,
    // then moving with it. (The client answers reference heights at or
    // below its tip, as a wallet asks them.)
    let mut spender = Spender::over(&mined);
    for h in 0..connecting {
        let ours = scenario
            .root_at(BlockHeight::from_raw(h))
            .await
            .expect("read")
            .expect("recorded");
        assert_eq!(
            spender.root_at(h),
            ours,
            "wallet-side vs store root going into {h}"
        );
        if h <= window {
            assert_eq!(
                ours,
                CurveTreeRoot::EMPTY,
                "nothing matured before {window}"
            );
        } else {
            assert_ne!(ours, CurveTreeRoot::EMPTY, "grown at {h}");
        }
    }

    // The spend: block 0's coinbase, referenced at the newest admissible
    // height, self-verified against the wallet-side root there.
    let fee = 1_000_000;
    let spend = spender.spend_coinbase(scenario.wallet(), 0, connecting, fee);
    let block = scenario
        .mine_listing(vec![spend.clone()])
        .await
        .unwrap_or_else(|outcome| panic!("the real spend is admitted: {outcome}"));
    assert_eq!(block.height, BlockHeight::from_raw(connecting));
    assert_eq!(block.template.transactions.len(), 1);
    assert_eq!(block.template.transactions[0].hash(), spend.hash());
    assert_eq!(block.template.total_fees.to_raw(), fee);

    // Listing the *same* spend again is CEN-G1's refusal since slice 7
    // commit 7 — the transaction is on the chain, and G1 runs before the
    // slot loop, so I7 (its key image is spent) never sees it (Q8's
    // ordering pin, on a real spend against a real store). Until then this
    // line read I7, which was the row that *could* fire: G1 was pending.
    match scenario.mine_listing(vec![spend]).await {
        Err(StepOutcome::Refused(refused)) => {
            assert_eq!(refused.rule, CenRow::G1);
            assert_eq!(
                refused.locus,
                Locus::Tx {
                    slot: TxSlot::Listed(0)
                }
            );
        }
        other => panic!("a re-listed spend is refused by G1, got {other:?}"),
    }

    // Oracle 1 again, with a listed transaction in the tree's history: the
    // roots still agree after the spend block and the block after it.
    spender.push(&block);
    let next = scenario.mine(1).await.pop().expect("one more block");
    spender.push(&next);
    let after = scenario
        .root_at(BlockHeight::from_raw(connecting + 1))
        .await
        .expect("read")
        .expect("recorded");
    assert_eq!(spender.root_at(connecting + 1), after);

    scenario.close().await;
}
