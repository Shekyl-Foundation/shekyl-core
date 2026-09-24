// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The driver's own contract: a scripted chain is a chain the validator
//! admitted, whose record is what the owners priced.

use shekyl_chain_rules::CenRow;
use shekyl_types::BlockHeight;

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
    // CEN-F13's accumulator is the fold of what each template priced.
    let priced: u64 = mined.iter().map(|m| m.template.block_reward.to_raw()).sum();
    assert_eq!(facts.parent_coins_generated.to_raw(), priced);
    // Empty blocks: the volume window counts none, over min(h, W) blocks.
    assert_eq!(facts.tx_volume, shekyl_economics::TxVolume::window(0, 6));
    // The next header will carry the placeholder root the driver recorded
    // after block 5 — CEN-B5 by the same read the template performs.
    assert_eq!(
        facts.curve_tree_root,
        super::placeholder_root_after(BlockHeight::from_raw(5))
    );
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
    let expected: u64 = first[..3]
        .iter()
        .chain(fork.iter())
        .map(|m| m.template.block_reward.to_raw())
        .sum();
    assert_eq!(facts.parent_coins_generated.to_raw(), expected);
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
            fixed_difficulty: Some(d)
        } if d.get() == 1
    ));
}
