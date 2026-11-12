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

#![cfg(test)]

use std::collections::BTreeSet;
use std::sync::Arc;

use shekyl_chain_rules::{AtHeight, Claimable, EpochFloor};
use shekyl_daemon_rpc::chain_facts::FactsFault;
use shekyl_daemon_rpc::info_facts::InfoFacts;
use shekyl_daemon_rpc::methods::RpcFault;
use shekyl_daemon_rpc::read_facts::ChainReadFacts;
use shekyl_daemon_rpc::reads::{
    archival_claim_show, block_header_show, chain_alt, chain_coinbase_sum, curve_show, pow,
    shard_coverage,
};
use shekyl_harness_spender::Spender;
use shekyl_pow_randomx::{compute_hash, CacheStore, Seedhash};
use shekyl_rpc_types::errors::ErrorClass;
use shekyl_rpc_types::kinds::{Bytes, Height};
use shekyl_rpc_types::wire::archival::PersonaQuery;
use shekyl_rpc_types::wire::block::{BlockSelect, HeaderSelect, PowInput};
use shekyl_rpc_types::wire::chain::{CoinbaseSumRange, CurveSelect};
use shekyl_rpc_types::wire::shared::Selector;
use shekyl_rpc_types::HashHex;
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::{Ct, Transaction};

use crate::connector::Offered;
use crate::metrics::Metrics;
use crate::rpc_store_facts_tests::{
    facts_over, facts_with_budget, facts_with_caches, hex, KeccakPow,
};
use crate::scenario::{Mined, Scenario, RULES};
use crate::substrate::ProductionSubstrate;
use crate::test_support::{h, open_store, open_store_under, tmp, Family, FIRST_SPEND_HEIGHT};

fn hash_budget() -> shekyl_daemon_rpc::hash_budget::HashBudget {
    shekyl_daemon_rpc::hash_budget::HashBudget::new(std::time::Instant::now())
}

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

        // Every alt block is in a chain (IG-Q46: the hashes list folds
        // into `chain_alt`).
        let chains = chain_alt(&facts).unwrap_or_else(|_| panic!("alt chains"));
        let offered: BTreeSet<HashHex> = y_branch
            .iter()
            .chain(&z_branch)
            .map(|m| hex(m.hash))
            .collect();
        assert_eq!(
            chains
                .iter()
                .flat_map(|c| c.block.iter().copied())
                .collect::<BTreeSet<_>>(),
            offered,
            "the alt blocks are the three offered"
        );

        // The two chains, each from its tip down to where it leaves.
        assert_eq!(chains.len(), 2, "two tips");
        let main_at = |height: BlockHeight| match snap.block_info(height).expect("info") {
            AtHeight::Recorded(info) => hex(info.hash),
            AtHeight::AboveTip => panic!("main block {height}"),
        };
        for (branch, leaves_after) in [(&y_branch, 3u64), (&z_branch, 4u64)] {
            let tip = branch.last().expect("non-empty");
            let chain = chains
                .iter()
                .find(|c| c.hash == hex(tip.hash))
                .unwrap_or_else(|| panic!("a chain tipped at {:?}", tip.hash));
            let expected_blocks: Vec<HashHex> = branch.iter().rev().map(|m| hex(m.hash)).collect();
            assert_eq!(chain.block, expected_blocks, "tip first");
            let length = u64::try_from(chain.block.len()).expect("fits");
            assert_eq!(chain.height.0, tip.height.to_raw());
            let row = snap
                .alt_block(&tip.hash)
                .expect("read")
                .expect("the tip is held");
            let work = row.cumulative_difficulty().to_raw();
            assert_eq!(chain.difficulty_cumulative.0, work);
            // The parent the lowest block names, which here is also the
            // main chain's block below the chain.
            assert_eq!(chain.parent, main_at(h(leaves_after)));
            assert_eq!(chain.parent, main_at(h(chain.height.0 - length)));
        }
        // The tips are walked in the table's key order.
        let tip_order: Vec<&HashHex> = chains.iter().map(|c| &c.hash).collect();
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

/// The claim source over a levered chain mined through several settled
/// epochs, for a persona with no bond. Every epoch of the claim window is
/// listed, ascending; its budget and `Σwork` are the store's rows; it
/// carries a gather (`has_budget_row`) exactly when both rows exist, with
/// no bonds or credits on a chain that has none; the chain count and the
/// settled epoch are the tip's. A `p_id` that is not 32 bytes of hex is
/// refused with the C++ wording.
#[tokio::test]
async fn the_claim_source_lists_the_window_and_gathers_what_the_gate_admits() {
    use crate::scenario::FreeHash;
    use crate::scenario_shard::{levered_rules, levered_schedule};
    let rules = levered_rules();
    let mut s = Scenario::open_under("rpc-reads-claim-source", FreeHash, rules);
    let mined = s.mine(100).await;
    let tip = mined.last().expect("mined").height;
    s.reopen(|path| {
        let store = Arc::new(open_store_under(
            path,
            &rules.in_force(BlockHeight::ZERO),
            shekyl_chain_store::apply_policy::ApplyPolicy::Full,
        ));
        let facts = facts_over(Arc::clone(&store), path, rules);
        let snap = store.begin_read().expect("read");
        let ask = |persona: [u8; 32]| {
            archival_claim_show(
                &facts,
                &PersonaQuery {
                    persona: HashHex::from_bytes(persona),
                },
            )
        };
        let source = ask([0x11; 32]).unwrap_or_else(|_| panic!("a claim source"));
        let connecting = tip.to_raw() + 1;
        assert_eq!(source.height.0, tip.to_raw(), "the gather tip");
        let settled = levered_schedule().epoch_at(h(connecting)).to_raw();
        assert_eq!(source.settled_epoch.0, settled);
        assert_eq!(source.joined_epoch.0, None, "no bond record");
        let window: Vec<u64> = (shekyl_archival_retention::claim_window_floor(
            settled,
            shekyl_archival_retention::archival_params(),
        )..settled)
            .collect();
        assert_eq!(
            source.epoch.iter().map(|e| e.id.0).collect::<Vec<_>>(),
            window
        );
        let mut admitted = 0;
        // The same claimable floor the citing gate reads through: a window
        // epoch the boundary has retired is SI-32, not a missing row.
        let claimable =
            EpochFloor::<Claimable>::under(BlockHeight::from_raw(connecting), levered_schedule());
        for epoch in &source.epoch {
            let e = shekyl_types::SettlementEpoch::from_raw(epoch.id.0);
            let budget = snap
                .budget(e, claimable)
                .expect("read")
                .map(shekyl_units::AtomicUnits::to_raw);
            let sigma = snap
                .sigma_work(e, claimable)
                .expect("read")
                .map(shekyl_types::archival::SigmaWorkMilli::to_raw);
            let gathered = budget.is_some() && sigma.is_some();
            assert_eq!(
                epoch.budget.0.map(|b| b.to_atomic_units().to_raw()),
                budget.filter(|_| gathered),
                "epoch {} carries its budget exactly when both rows exist",
                epoch.id.0
            );
            assert_eq!(epoch.work.0, sigma.unwrap_or(0));
            assert_eq!(
                epoch.closing_height.0,
                levered_schedule()
                    .close_height(epoch.id.0)
                    .expect("a window epoch closes")
            );
            assert!(epoch.bond.is_empty() && epoch.credit.is_empty());
            assert_eq!(epoch.claimant.0, None);
            admitted += u64::from(epoch.budget.0.is_some());
        }
        assert!(
            admitted > 0 && admitted < u64::try_from(window.len()).expect("fits"),
            "the window holds both an admitted epoch and one awaiting its pass"
        );
        // A persona that is not 32 bytes of hex is not a request: the
        // envelope refuses it as `rpc.params` before the handler runs.
        assert!(
            serde_json::from_value::<PersonaQuery>(serde_json::json!({ "persona": "zz" })).is_err()
        );
        drop(snap);
        drop(facts);
        drop(store);
    })
    .await;
    s.close().await;
}

/// The claim window is cause-blind: a persona that holds a bond is listed
/// the same window as one that holds none. On a levered chain with one
/// bonded persona, the claim source for that persona and for a stranger
/// list the same epochs with the same budget, `Σwork`, gather flag and
/// bonds; only the bond record and the claimant's index differ. The twin
/// of the no-bond test above; supersedes the C++ `archival_claim_source_rpc`
/// case `window_is_unconditional_and_cause_blind`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_claim_window_is_the_same_for_a_persona_with_a_bond() {
    use crate::archival_driver::{first_spending_height, ENDPOINT, FEE};
    use crate::scenario::FreeHash;
    use crate::scenario_archival::{complete_tree, Persona};
    use crate::scenario_shard::levered_rules;
    use shekyl_types::ChainCount;
    let rules = levered_rules();
    let mut s = Scenario::open_under("rpc-reads-claim-source-bond", FreeHash, rules);
    let connecting = first_spending_height();
    let mut mined = s
        .mine(ChainCount::from_next_height(connecting).to_raw())
        .await;
    let spender = Spender::over(&mined);
    let persona = Persona::at(1);
    let join = persona.join(complete_tree(), ENDPOINT);
    let joined = s
        .mine_listing(vec![spender.spend_coinbase_posting(
            s.wallet(),
            BlockHeight::ZERO,
            connecting,
            FEE,
            Some(&join),
        )])
        .await
        .unwrap_or_else(|outcome| panic!("the join connects: {outcome}"));
    mined.push(joined);
    mined.extend(s.mine(40).await);
    let bonded = persona.id().to_bytes();
    s.reopen(|path| {
        let store = Arc::new(open_store_under(
            path,
            &rules.in_force(BlockHeight::ZERO),
            shekyl_chain_store::apply_policy::ApplyPolicy::Full,
        ));
        let facts = facts_over(Arc::clone(&store), path, rules);
        let ask = |persona: [u8; 32]| {
            archival_claim_show(
                &facts,
                &PersonaQuery {
                    persona: HashHex::from_bytes(persona),
                },
            )
            .unwrap_or_else(|_| panic!("a claim source"))
        };
        let with_bond = ask(bonded);
        let without = ask([0x11; 32]);
        assert!(
            with_bond.joined_epoch.0.is_some(),
            "the joined persona holds a bond"
        );
        assert!(without.joined_epoch.0.is_none(), "the stranger holds none");
        assert!(!with_bond.epoch.is_empty(), "the window lists epochs");
        let window = |source: &shekyl_rpc_types::wire::archival::ClaimSource| {
            source
                .epoch
                .iter()
                .map(|e| (e.id, e.budget, e.work, e.closing_height, e.bond.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            window(&with_bond),
            window(&without),
            "the window does not branch on the bond"
        );
        assert_eq!(with_bond.height, without.height);
        assert_eq!(with_bond.settled_epoch, without.settled_epoch);
        assert!(without.epoch.iter().all(|e| e.claimant.0.is_none()));
        drop(facts);
        drop(store);
    })
    .await;
    s.close().await;
}

/// The coverage list over a chain that has closed no shard, on the block
/// after the first slash pass. Nothing a join can hold. The profit hint
/// reads the watermark the pass wrote, which the schedule's arithmetic
/// has already stepped past.
#[tokio::test]
async fn the_coverage_list_of_a_chain_with_no_closed_shard_is_empty() {
    use crate::scenario::FreeHash;
    use crate::scenario_shard::{levered_rules, levered_schedule};
    let rules = levered_rules();
    let schedule = levered_schedule();
    // The pass for epoch 0 runs on its deadline. The next block's
    // schedule epoch is the one that pass has not gathered.
    let after_pass = schedule.slash_deadline_height(0) + 1;
    let mut s = Scenario::open_under("rpc-reads-coverage", FreeHash, rules);
    let mined = s.mine(after_pass + 1).await;
    let tip = mined.last().expect("mined").height;
    assert_eq!(tip.to_raw(), after_pass);
    s.reopen(|path| {
        let store = Arc::new(open_store_under(
            path,
            &rules.in_force(BlockHeight::ZERO),
            shekyl_chain_store::apply_policy::ApplyPolicy::Full,
        ));
        let facts = facts_over(Arc::clone(&store), path, rules);
        let snap = store.begin_read().expect("read");
        let coverage = shard_coverage(&facts).unwrap_or_else(|_| panic!("coverage"));
        assert_eq!(coverage.height.0, tip.to_raw());
        assert_eq!(coverage.frozen_count.0, 0);
        assert!(coverage.shard.is_empty());
        let watermark = snap
            .last_settled_slash_epoch()
            .expect("read")
            .expect("the first pass has written the watermark");
        let arithmetic = schedule.last_settled_epoch_as_of_parent(tip.to_raw());
        assert_ne!(watermark.to_raw(), arithmetic);
        assert_eq!(coverage.settled_epoch.0, watermark.to_raw());
        let ahead = shekyl_types::SettlementEpoch::from_raw(arithmetic);
        // The claimable floor at the next block: the watermark's rows sit
        // inside it, and an epoch with no gather stays `None` rather than
        // a swallowed below-floor fault.
        let claimable =
            EpochFloor::<Claimable>::under(BlockHeight::from_raw(tip.to_raw() + 1), schedule);
        assert_eq!(
            snap.sigma_work(ahead, claimable).expect("read"),
            None,
            "the schedule's epoch has no gather yet"
        );
        let sigma = snap
            .sigma_work(watermark, claimable)
            .expect("read")
            .expect("the watermark's gather is a row");
        assert_eq!(coverage.work.0.map(|w| w.0), Some(sigma.to_raw()));
        assert_eq!(
            coverage.budget.0.map(|b| b.to_atomic_units().to_raw()),
            snap.budget(watermark, claimable)
                .expect("read")
                .map(shekyl_units::AtomicUnits::to_raw)
        );
        assert_eq!(
            coverage.leaf_count.0,
            snap.curve_tree().expect("summary").leaf_count.to_raw()
        );
        drop(snap);
        drop(facts);
        drop(store);
    })
    .await;
    s.close().await;
}

/// After a connect retires a branch, every alternative chain the handler
/// lists names a main-chain block as its parent: the death rule takes a
/// branch whole (`store/alt.rs`), so no chain is left hanging from a
/// removed row. Under the levered cap of 10: a 5-block branch from main
/// block 1 is crossed when the tip reaches its lowest row (2) plus the
/// cap; a one-row branch at 3 on main block 2 outlives it.
#[tokio::test]
async fn after_a_retirement_every_listed_chain_hangs_from_the_main_chain() {
    use crate::scenario::FreeHash;
    use crate::scenario_shard::{levered_rules, REORG_CAP_BLOCKS};
    let rules = levered_rules();
    let mut x = Scenario::open_under("rpc-reads-retire-x", FreeHash, rules);
    let mut y = Scenario::open_under("rpc-reads-retire-y", FreeHash, rules);
    let mut z = Scenario::open_under("rpc-reads-retire-z", FreeHash, rules);
    x.mine(2).await;
    y.mine(2).await;
    z.mine(3).await;
    y.idle();
    for _ in 0..5 {
        x.mine(1).await;
        for mined in y.mine(1).await {
            assert!(matches!(
                x.offer(&mined).await.expect("offer"),
                Offered::Held { .. }
            ));
        }
    }
    z.idle();
    let beside = z.mine(1).await;
    assert!(matches!(
        x.offer(&beside[0]).await.expect("offer"),
        Offered::Held { .. }
    ));
    // Mine to the crossing connect: the tip is the branch's lowest row (2)
    // plus the cap.
    let mut tip = 6;
    while tip < 2 + REORG_CAP_BLOCKS {
        x.mine(1).await;
        tip += 1;
    }
    x.reopen(|path| {
        let store = Arc::new(open_store_under(
            path,
            &rules.in_force(BlockHeight::ZERO),
            shekyl_chain_store::apply_policy::ApplyPolicy::Full,
        ));
        let facts = facts_over(Arc::clone(&store), path, rules);
        let snap = store.begin_read().expect("read");
        let chains = chain_alt(&facts).unwrap_or_else(|_| panic!("alt chains"));
        assert_eq!(
            chains.len(),
            1,
            "the crossed branch left whole; the one beside it stays"
        );
        assert_eq!(chains[0].hash, hex(beside[0].hash));
        for chain in &chains {
            let parent = BlockHash::from_bytes(chain.parent.to_bytes());
            let length = u64::try_from(chain.block.len()).expect("fits");
            assert_eq!(
                snap.height_of(&parent).expect("read"),
                Some(h(chain.height.0 - length)),
                "the parent of the chain tipped at {} is the main block below it",
                chain.hash
            );
        }
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
/// `curve_show` of the tip, and the store's own summary agrees; above the
/// tip there is no tree to report.
#[tokio::test]
async fn the_tree_after_each_block_is_the_root_the_next_block_was_built_on() {
    let mut s = Scenario::open("rpc-reads-tree");
    let mined = s.mine(FIRST_SPEND_HEIGHT + 3).await;
    let tip = mined.last().expect("mined").height;
    s.reopen(|path| {
        let store = Arc::new(open_store(path));
        let facts = facts_over(Arc::clone(&store), path, RULES);
        let at = |height: BlockHeight| {
            curve_show(
                &facts,
                &CurveSelect(Selector::Height(Height(height.to_raw()))),
            )
        };
        for pair in mined.windows(2) {
            let (below, above) = (&pair[0], &pair[1]);
            let checkpoint = at(below.height).unwrap_or_else(|_| panic!("through the tip"));
            assert_eq!(checkpoint.height.0, below.height.to_raw());
            assert_eq!(
                checkpoint.root.to_string(),
                hex::encode(above.template.block.header.curve_tree_root.to_bytes()),
                "the tree after {} is the root block {} was built on",
                below.height.to_raw(),
                above.height.to_raw()
            );
        }

        let info = curve_show(&facts, &CurveSelect(Selector::Tip))
            .unwrap_or_else(|_| panic!("the tip's tree"));
        assert_eq!(info.height.0, tip.to_raw());
        assert!(
            info.leaf_count.0 > 0,
            "the coinbases matured into the tree (rule 47: the subject exists)"
        );
        let at_tip = at(tip).unwrap_or_else(|_| panic!("the tip"));
        assert_eq!(at_tip, info, "the tip's tree is the tree after the tip");
        let summary = store
            .begin_read()
            .expect("read")
            .curve_tree()
            .expect("summary");
        assert_eq!(info.root.to_string(), hex::encode(summary.root.to_bytes()));
        assert_eq!(info.leaf_count.0, summary.leaf_count.to_raw());
        assert_eq!(info.layers.0, u64::from(summary.depth.to_raw()));

        let above = tip.saturating_add(shekyl_types::BlockCount::ONE);
        match at(above) {
            Err(RpcFault::Refused(refusal)) => {
                assert_eq!(refusal.diagnostic.code, "curve.missing");
            }
            other => panic!("above the tip there is no tree: {other:?}"),
        }
        drop(facts);
        drop(store);
    })
    .await;
    s.close().await;
}

/// The coinbase sum over a chain with two listed spends: the emission is
/// what each block's verdict paid (CEN-G12's growth of the supply), the
/// fees are what the spends paid, and the whole chain's emission is the
/// supply accumulator `daemon_status` reports. The C++'s emission figure —
/// each coinbase less the block's fees — is printed beside it: on the
/// spending block it is not what was minted.
/// `pow` hashes under a permit from the daemon's one hasher budget,
/// in its own class (PR2-Q3): while the one permit is held, it waits, and
/// it hashes once the permit is free.
#[tokio::test]
async fn pow_waits_for_a_hasher_permit_in_its_class() {
    use shekyl_hash_budget::{Budget, Class};
    let caches = Arc::new(CacheStore::new());
    let substrate = ProductionSubstrate::new(Arc::clone(&caches), Arc::new(Metrics::new()));
    let mut s = Scenario::open_with("rpc-reads-calc-pow-permit", substrate);
    let mined = s.mine(2).await;
    s.reopen(|path| {
        let store = Arc::new(open_store(path));
        let budget = Budget::new(std::num::NonZeroUsize::MIN);
        let facts = facts_with_budget(
            Arc::clone(&store),
            path,
            RULES,
            Arc::clone(&caches),
            budget.clone(),
        );
        let request = PowInput {
            height: Height(mined[1].height.to_raw()),
            hashing: Bytes(mined[1].template.block.pow_blob()),
            seed: None,
        };
        let held = budget.acquire(Class::Chain);
        std::thread::scope(|scope| {
            let asked = scope.spawn(|| pow(&facts, &request, false, &hash_budget()));
            let started = std::time::Instant::now();
            while budget.waiting(Class::CalcPow) == 0 {
                assert!(
                    started.elapsed() < std::time::Duration::from_secs(60),
                    "pow never waited for a permit"
                );
                std::thread::yield_now();
            }
            assert!(!asked.is_finished(), "no hash while the permit is held");
            drop(held);
            assert!(asked.join().expect("joins").is_ok(), "it hashes once free");
        });
    })
    .await;
    s.close().await;
}

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
        let sum = |height: BlockHeight, count: u64| {
            chain_coinbase_sum(
                &facts,
                &CoinbaseSumRange {
                    from: Height(height.to_raw()),
                    to: Height(height.to_raw() + count - 1),
                },
            )
        };
        let amount = |a: &shekyl_units::wire::AtomicUnitsString| {
            u128::from(a.to_atomic_units().to_raw())
        };

        // Block by block: the verdict's paid reward, and the listed fees.
        for m in &mined {
            let one = sum(m.height, 1).unwrap_or_else(|_| panic!("coinbase sum"));
            let listed: u128 = if m.height == h(AT) { fees } else { 0 };
            assert_eq!(
                amount(&one.emission),
                u128::from(m.emission.paid.to_raw()),
                "emission at {} is the paid reward",
                m.height.to_raw()
            );
            assert_eq!(amount(&one.fee), listed);
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
        let whole = sum(BlockHeight::ZERO, chain).unwrap_or_else(|_| panic!("coinbase sum"));
        let coins = facts.chain().expect("info chain").already_generated_coins;
        assert_eq!(amount(&whole.emission), u128::from(coins.to_raw()));
        assert_eq!(amount(&whole.fee), fees);

        // A range that starts inside and runs past the tip stops at it.
        assert_eq!(
            sum(h(AT), chain).map(|s| (amount(&s.emission), amount(&s.fee))).ok(),
            sum(h(AT), 2).map(|s| (amount(&s.emission), amount(&s.fee))).ok()
        );
        // A range whose start is past its end is the caller's error.
        match chain_coinbase_sum(
            &facts,
            &CoinbaseSumRange {
                from: Height(1),
                to: Height(0),
            },
        ) {
            Err(RpcFault::Refused(refusal)) => {
                assert_eq!(refusal.class, ErrorClass::BadParams);
                assert_eq!(refusal.diagnostic.code, "block.range");
            }
            other => panic!("a backwards range: {other:?}"),
        }
        // The bound: a start at the count, or a count past it, leaves the
        // chain.
        for (height, count) in [(chain, 1), (0, chain + 1)] {
            match sum(h(height), count) {
                Err(RpcFault::Refused(refusal)) => {
                    assert_eq!(refusal.class, ErrorClass::RefusedByMethod);
                    assert_eq!(refusal.diagnostic.code, "block.missing");
                }
                other => panic!("a range that leaves the chain: {other:?}"),
            }
        }
        drop(facts);
        drop(store);
    })
    .await;
    s.close().await;
}

/// `pow` is RandomX over the bytes as given, under a cache the
/// daemon's cache store already holds. The store here is the one the
/// connector's production substrate derived into while the chain was mined:
/// where it still holds the seed a height names, the answer is the PoW the
/// node recorded when it judged the block, and where it no longer does
/// (genesis's, replaced by the next seed) the request is refused. A held seed the
/// caller names is answered the same way. A seed height above the tip, a
/// blob that is not hex or is longer than a hashing blob, and a seed that is not
/// 32 bytes are refused with the C++ codes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pow_hashes_under_the_caches_the_validator_holds() {
    let caches = Arc::new(CacheStore::new());
    let substrate = ProductionSubstrate::new(Arc::clone(&caches), Arc::new(Metrics::new()));
    let mut s = Scenario::open_with("rpc-reads-calc-pow", substrate);
    let mined = s.mine(3).await;
    s.reopen(|path| {
        let store = Arc::new(open_store(path));
        let facts = facts_with_caches(Arc::clone(&store), path, RULES, Arc::clone(&caches));
        let ask = |height: BlockHeight, blob: &[u8], seed: Option<BlockHash>| {
            outcome(pow(
                &facts,
                &PowInput {
                    height: Height(height.to_raw()),
                    hashing: Bytes(blob.to_vec()),
                    seed: seed.map(|seed| HashHex::from_bytes(seed.to_bytes())),
                },
                false,
                &hash_budget(),
            ))
        };
        // The driver pins each connecting seed before the hash. Genesis
        // pins the null seed; the next block pins genesis's hash and
        // demotes the null seed to the transient slot. Two seeds, two
        // slots, both held. `pow` answers under either.
        assert_eq!(mined[0].seed, BlockHash::NULL);
        for m in &mined {
            let held = caches
                .lookup(&Seedhash::from_bytes(*m.seed.as_bytes()))
                .expect("the validator holds the seed it proved this block under");
            let blob = m.template.block.pow_blob();
            let recorded = block_header_show(
                &facts,
                &HeaderSelect(BlockSelect {
                    select: Selector::Height(Height(m.height.to_raw())),
                    pow: true,
                    prune: None,
                }),
            )
            .unwrap_or_else(|_| panic!("in range"))
            .pow
            .present()
            .expect("asked with pow");
            assert_eq!(
                ask(m.height, &blob, None),
                Ok(hex::encode(compute_hash(&held, &blob))),
                "RandomX under the held seed at {}",
                m.height.to_raw()
            );
            assert_eq!(
                ask(m.height, &blob, None),
                Ok(hex::encode(recorded.to_bytes())),
                "the PoW the node recorded at {}",
                m.height.to_raw()
            );
        }
        // A held seed the caller names: block 1's, under block 2's bytes.
        let blob = mined[2].template.block.pow_blob();
        let named = mined[1].seed;
        let held = caches
            .lookup(&Seedhash::from_bytes(*named.as_bytes()))
            .expect("held");
        assert_eq!(
            ask(BlockHeight::ZERO, &blob, Some(named)),
            Ok(hex::encode(compute_hash(&held, &blob)))
        );
        // One shared bucket. The first bounded hash spends the one hash
        // the bucket holds. The second is empty and spends nothing. The
        // host hashes from an empty bucket.
        let budget = hash_budget();
        let priced = PowInput {
            height: Height(mined[2].height.to_raw()),
            hashing: Bytes(blob.clone()),
            seed: None,
        };
        assert!(pow(&facts, &priced, true, &budget).is_ok());
        match pow(&facts, &priced, true, &budget) {
            Err(RpcFault::Refused(refusal)) => {
                assert_eq!(refusal.class, ErrorClass::OverResourceBound);
                assert_eq!(refusal.diagnostic.code, "bound.hash");
            }
            other => panic!("the second hash finds an empty bucket: {other:?}"),
        }
        let empty = shekyl_daemon_rpc::hash_budget::HashBudget::empty(std::time::Instant::now());
        assert!(
            pow(&facts, &priced, false, &empty).is_ok(),
            "the host does not pay"
        );
        let far = 1_000_000u64;
        let seed_height = shekyl_chain_rules::seed_height(BlockHeight::from_raw(far))
            .expect("not genesis")
            .to_raw();
        let tip = mined.last().expect("mined").height.to_raw();
        assert_eq!(
            ask(h(far), &blob, None),
            Err((
                "pow.seed".to_owned(),
                format!(
                    "no seed for height {far}: its seed height {seed_height} is above the tip {tip}"
                )
            ))
        );
        // Bytes that are not base64, and a seed that is not 32 bytes, are
        // not requests: the envelope refuses them as `rpc.params`.
        let oversize = vec![0u8; shekyl_wire::block::MAX_POW_BLOB_SIZE + 1];
        assert_eq!(
            ask(h(1), &oversize, None).map_err(|(code, _)| code),
            Err("bound.pow-size".to_owned())
        );
        drop(facts);
        drop(store);
    })
    .await;
    s.close().await;
}

/// A `pow` answer as the hash's hex, or the refusal's dotted code and
/// message.
fn outcome(
    answer: Result<shekyl_rpc_types::wire::block::Pow, RpcFault>,
) -> Result<String, (String, String)> {
    match answer {
        Ok(pow) => Ok(pow.pow.to_string()),
        Err(RpcFault::Refused(refusal)) => {
            Err((refusal.diagnostic.code, refusal.diagnostic.message))
        }
        Err(other) => panic!("a fault, not an answer: {other:?}"),
    }
}

/// The refusal for a seed the cache store does not hold, given or named by
/// a height.
fn not_held(seed: BlockHash) -> Result<String, (String, String)> {
    Err((
        "pow.seed".to_owned(),
        format!(
            "seed {} is not held: pow hashes under held seeds only",
            hex::encode(seed.to_bytes())
        ),
    ))
}

/// `pow` never derives a cache (ruled 2026-10-17). Over a chain whose
/// facts hold an empty cache store, a seed the caller names and the seed a
/// height names are each refused, naming the seed, and afterwards the store
/// still holds neither: a derivation publishes the cache it made, so a seed
/// still absent is one never derived.
#[tokio::test]
async fn pow_never_derives_a_cache() {
    let mut s = Scenario::open_with("rpc-reads-calc-pow-held", KeccakPow);
    let mined = s.mine(3).await;
    s.reopen(|path| {
        let store = Arc::new(open_store(path));
        let caches = Arc::new(CacheStore::new());
        let facts = facts_with_caches(Arc::clone(&store), path, RULES, Arc::clone(&caches));
        let blob = mined[2].template.block.pow_blob();
        let fresh = BlockHash::from_bytes([7; 32]);
        let not_held_request = PowInput {
            height: Height(2),
            hashing: Bytes(blob.clone()),
            seed: Some(HashHex::from_bytes(fresh.to_bytes())),
        };
        assert_eq!(
            outcome(pow(&facts, &not_held_request, false, &hash_budget())),
            not_held(fresh)
        );
        // An empty bucket and a seed that will not hash is the parameter
        // refusal, not the empty bucket. The spend sits after admission.
        let empty = shekyl_daemon_rpc::hash_budget::HashBudget::empty(std::time::Instant::now());
        assert_eq!(
            outcome(pow(&facts, &not_held_request, true, &empty)),
            not_held(fresh)
        );
        let named_by_height = mined[2].seed;
        assert_eq!(
            outcome(pow(
                &facts,
                &PowInput {
                    height: Height(2),
                    hashing: Bytes(blob),
                    seed: None,
                },
                false,
                &hash_budget(),
            )),
            not_held(named_by_height)
        );
        for seed in [fresh, named_by_height] {
            assert!(
                caches
                    .lookup(&Seedhash::from_bytes(*seed.as_bytes()))
                    .is_none(),
                "pow derived no cache for {seed:?}"
            );
        }
        drop(facts);
        drop(store);
    })
    .await;
    s.close().await;
}

/// An empty store has no tip: every chain read is not ready, and with no
/// cache held there is nothing `pow` hashes under, even for a seed the
/// caller names.
#[test]
fn an_empty_store_has_no_chain_reads_and_hashes_nothing() {
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
        outcome(pow(
            &facts,
            &PowInput {
                height: Height(5),
                hashing: Bytes(vec![0]),
                seed: Some(HashHex::from_bytes(seed.to_bytes())),
            },
            false,
            &hash_budget(),
        )),
        not_held(seed)
    );
    drop(facts);
    drop(store);
}
