// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the hasher holds on the ingest's production path
//! (`RANDOMX_CACHE_ACTOR.md` §8): the connect path over
//! [`ProductionPow`] and real RandomX, read off the hasher's own
//! [`Resident`](shekyl_hasher::Resident).
//!
//! The chains are mined at difficulty one, so a block a free-longhash
//! driver mined is a valid block under RandomX too, and the subject stays
//! the caches. Every driver over a production pow checks the cap after
//! each write and HA-R5 at its close ([`Scenario::close`]); a service
//! here is checked the same way by [`settled`].

use std::collections::BTreeSet;
use std::sync::Arc;

use shekyl_chain_rules::{CappedEpoch, SettlementEpochBlocks};
use shekyl_hasher::CAP;
use shekyl_types::{BlockCount, BlockHash, BlockHeight};

use crate::connector::{Offered, Switched};
use crate::pow::{Pow, ProductionPow};
use crate::scenario::{Clocked, FreeHash, Mined, Scenario, RULES};
use crate::schedule::ChainRules;
use crate::service::service_tests::arrival;
use crate::service::{Follow, Reply, Service, ServiceConfig};
use shekyl_hasher::quiet::{assert_matches_fresh, seeds as quiet_seeds};

use crate::test_support::{open_store, open_store_under, own_hasher, tmp, OwnHasher};

/// The seeds resident once `own`'s hasher is quiet.
fn quiet(own: &OwnHasher) -> BTreeSet<[u8; 32]> {
    quiet_seeds(&own.hasher.resident())
}

fn seeds(of: &[BlockHash]) -> BTreeSet<[u8; 32]> {
    of.iter().map(|seed| *seed.as_bytes()).collect()
}

/// The service's boundary: the production one, judging each block at a
/// clock ahead of every timestamp the scenario drivers stamp. Their
/// clock starts past the wall clock's now, and CEN-C1 refuses a block
/// from the future.
type Judged = Clocked<ProductionPow>;

fn ahead_of_the_drivers(own: &OwnHasher) -> Arc<Judged> {
    let clock = Clocked::new(own.pow.clone());
    clock.set_interval(std::num::NonZeroU64::new(1_000_000).expect("non-zero"));
    clock.tick();
    Arc::new(clock)
}

/// Offer `blocks` to `service` one span at a time and require each to
/// connect. After every reply: no more caches than the cap (HA-R5's
/// "always").
async fn connect_all(service: &Service<Judged>, own: &OwnHasher, blocks: &[Mined]) {
    let door = service.door();
    let mut tag = 0u64;
    for chunk in blocks.chunks(door.room().max(1)) {
        let span = chunk
            .iter()
            .map(|mined| {
                tag += 1;
                arrival(tag, 1, mined)
            })
            .collect();
        for (ticket, mined) in door.offer_span(span).expect("room").into_iter().zip(chunk) {
            let reply = ticket.reply().await.reply;
            assert_eq!(
                reply,
                Reply::Connected {
                    height: mined.height,
                    hash: mined.hash
                }
            );
            let resident = own.hasher.resident();
            let resident = resident.borrow();
            assert!(
                resident.caches.len() <= CAP,
                "more caches than the cap after block {:?}: {resident:?}",
                mined.height
            );
        }
    }
}

/// HA-R5 for a service: once its hasher is quiet it holds what a fresh
/// one fed the store's list holds. Returns what it holds.
async fn settled(
    service: &Service<Judged>,
    own: &OwnHasher,
    rules: ChainRules,
) -> BTreeSet<[u8; 32]> {
    assert!(service.ranked().await, "the service is running");
    let list = {
        let snap = service.store().begin_read().expect("read");
        crate::service::ranked_on(&snap, rules, None).expect("the store ranks")
    };
    assert_matches_fresh(&own.hasher.resident(), list.as_ref());
    quiet(own)
}

/// The null seed is built as genesis's job and never ranked
/// (`RANDOMX_CACHE_ACTOR.md` §5.1). A fresh store is offered genesis: the
/// form is a job on the null seed, which builds that cache in an outside
/// place. Once genesis connects the list is block 0's id alone, so the
/// null seed's cache is freed and block 0's is built. Two derives, one
/// cache resident.
///
/// Red edit: have `cache_window::gather` rank an empty store: the null
/// seed is listed, kept, and three caches' worth of builds do not match.
#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_store_derives_the_null_seed_and_block_zeros_and_keeps_one() {
    let mut y = Scenario::open("resident-genesis-y");
    let blocks = y.mine(1).await;
    let own = own_hasher();
    let path = tmp("resident-genesis");
    let service = Service::start(
        Arc::new(open_store(&path)),
        RULES,
        ahead_of_the_drivers(&own),
        ServiceConfig::default(),
        Follow::default(),
    );
    assert!(
        quiet(&own).is_empty(),
        "nothing is ranked on an empty store"
    );
    connect_all(&service, &own, &blocks).await;
    let held = settled(&service, &own, RULES).await;
    assert_eq!(
        held,
        seeds(&[blocks[0].hash]),
        "block 0's id alone is resident; the null seed's cache was freed"
    );
    assert_eq!(
        own.pow.derives().builds,
        2,
        "the null seed for genesis's form, then block 0's id for the list"
    );
    service.stop().await.expect("stops");
    y.close().await;
}

/// `RANDOMX_CACHE_ACTOR.md` §8, HA-F8: a switch whose blocks all carry
/// the hash this node recorded for them builds nothing and hashes
/// nothing. Every demoted block was hashed when it connected and every
/// promoted one when it arrived, and the plan carries those records, so
/// the forming asks for no job (`plan_form` module docs).
///
/// Red edit: in `plan_form::form_plan`, take the `lend` arm for every
/// run: the switch borrows a cache, and under an unranked seed builds
/// one.
#[tokio::test(flavor = "multi_thread")]
async fn a_switch_whose_blocks_carry_recorded_hashes_builds_nothing() {
    const PREFIX: u64 = 4;
    let own = own_hasher();
    let mut x = Scenario::open_with("resident-switch-x", own.pow.clone());
    let mut y = Scenario::open_with("resident-switch-y", FreeHash);
    x.mine(PREFIX).await;
    y.mine(PREFIX).await;
    x.mine(2).await;
    y.idle();
    let branch = y.mine(3).await;
    let (last, held) = branch.split_last().expect("a branch");
    for mined in held {
        assert!(matches!(
            x.offer(mined).await.expect("offer"),
            Offered::Held { .. }
        ));
    }
    let Offered::SwitchDue(plan) = x.offer(last).await.expect("offer") else {
        panic!("the heavier tip did not name a switch");
    };
    // Settle first, so a refill in flight is not counted as the switch's.
    let _resident = quiet(&own);
    let (builds, hashes) = (own.pow.derives().builds, own.pow.artifact().hashes);
    let switched = x.reorganize(&plan).await.expect("switch");
    assert!(matches!(switched, Switched::Done(_)), "{switched:?}");
    assert_eq!(
        (own.pow.derives().builds, own.pow.artifact().hashes),
        (builds, hashes),
        "{} blocks re-formed through their recorded hashes: no build, no hash",
        plan.demoted.len() + plan.promoted.len()
    );
    x.close().await;
    y.close().await;
}

/// Regtest at difficulty one under a reorg cap of `cap` blocks, inside a
/// settlement epoch that holds it.
fn rules_with_cap(cap: u64) -> ChainRules {
    ChainRules::harness_regtest(
        Some(std::num::NonZeroU128::MIN),
        CappedEpoch::new(
            SettlementEpochBlocks::new(512).expect("non-zero"),
            BlockCount::from_raw(cap),
        )
        .expect("the cap sits inside the epoch"),
    )
}

/// `RANDOMX_CACHE_ACTOR.md` §8, the fork seed (the leak §1 item 3 names):
/// a held fork past its own seed point, a second span of it, and the fork
/// leaving the cap.
///
/// The main chain reaches height 2190. A fork roots at 2040 and grows to
/// 2114, so its block 2048 is the seed its blocks from 2113 on hash
/// under: the fork's own block, which no window names.
///
/// 1. With the fork held inside the cap its seed is the list's third, and
///    its cache is resident beside the window's two.
/// 2. A second span of the fork (block 2115) finds that cache warm:
///    nothing is built.
/// 3. The main chain grows until the fork's root is past the cap. The
///    list drops the fork, and its cache is gone at the next quiescence.
///
/// Red edits: (1, 2) in `cache_window::ranked_seeds`, never take a held
/// fork as the third: the fork's cache is freed after its form and the
/// second span builds again. (3) in `cache_window::gather`, keep a fork
/// whose pops exceed the reach: the fork's cache stays resident.
///
/// Ignored: it mines 2,250 blocks under real RandomX and 2,116 under the
/// free longhash; the nightly ignored lane runs it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "mines past the first seed epoch under real RandomX; the chain-ingest ignored lane runs it"]
async fn a_held_fork_past_its_seed_point_is_warm_until_it_leaves_the_cap() {
    const CAP_BLOCKS: u64 = 200;
    const ROOT: u64 = 2040;
    const MAIN_TIP: u64 = 2190;
    const FORK_TIP: u64 = 2114;
    let rules = rules_with_cap(CAP_BLOCKS);
    let own = own_hasher();
    let mut x = Scenario::open_under("resident-fork-x", own.pow.clone(), rules);
    let mut z = Scenario::open_under("resident-fork-z", FreeHash, rules);
    // Heights 0..=ROOT on both; then each its own branch.
    let main = x.mine(ROOT + 1).await;
    z.mine(ROOT + 1).await;
    z.idle();
    let fork = z.mine(FORK_TIP - ROOT + 1).await;
    let main_above = x.mine(MAIN_TIP - ROOT).await;
    let genesis = main[0].hash;
    let main_seed = main_above[usize::try_from(2048 - ROOT - 1).expect("fits")].hash;
    let fork_seed = fork[usize::try_from(2048 - ROOT - 1).expect("fits")].hash;
    assert_eq!(
        main_above[usize::try_from(2048 - ROOT - 1).expect("fits")].height,
        BlockHeight::from_raw(2048)
    );
    assert_ne!(main_seed, fork_seed, "each branch has its own block 2048");
    // The fork, up to 2114: lighter than the main chain, inside the cap.
    let (second_span, first_span) = fork.split_last().expect("a fork");
    for mined in first_span {
        assert!(
            matches!(x.offer(mined).await.expect("offer"), Offered::Held { .. }),
            "fork block {:?} is held",
            mined.height
        );
    }
    assert_eq!(
        quiet(&own),
        seeds(&[main_seed, genesis, fork_seed]),
        "the window's two seeds and the held fork's own"
    );
    // A second span of the live fork: its seed is warm.
    let builds = own.pow.derives().builds;
    assert!(matches!(
        x.offer(second_span).await.expect("offer"),
        Offered::Held { .. }
    ));
    assert_eq!(
        own.pow.derives().builds,
        builds,
        "a second span of a live fork builds nothing"
    );
    assert_eq!(quiet(&own), seeds(&[main_seed, genesis, fork_seed]));
    // The fork's root passes the cap.
    x.mine(ROOT + CAP_BLOCKS + 10 - MAIN_TIP).await;
    assert_eq!(
        quiet(&own),
        seeds(&[main_seed, genesis]),
        "the fork left the cap and its cache is gone"
    );
    assert_eq!(
        own.pow.derives().builds,
        builds,
        "and nothing was built since"
    );
    x.close().await;
    z.close().await;
}

/// A2 on the hasher (carried over from #1338): once the window stops
/// naming the previous epoch's seed, its cache is freed. Under a reorg
/// cap of ten the window's lower end passes the epoch switch (connecting
/// height 2113) at connecting height 2123; from there both ends name
/// block 2048's seed, and genesis's cache goes.
///
/// The chain is offered through the service's door, so every block is
/// formed as a job on the node's path, the ranker sends each list, and
/// the cap is checked after every reply.
///
/// Red edit: in `cache_window::pair_of`, keep the older end as the
/// window's other seed whether or not it differs: the list repeats a seed
/// and is refused; or drop the ranker's wake on a tip move
/// (`Connector::publish_tip`): the last list sent still names genesis's
/// seed and its cache stays.
///
/// Ignored: it connects 2,124 blocks under real RandomX; the nightly
/// ignored lane runs it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "connects past the first seed epoch under real RandomX; the chain-ingest ignored lane runs it"]
async fn a_connect_past_the_windows_end_frees_the_previous_epochs_cache() {
    use crate::scenario_shard::{levered_rules, REORG_CAP_BLOCKS};
    use shekyl_difficulty::{SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG};
    let rules = levered_rules();
    let switch = SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG + 1; // 2113
    let release = switch + REORG_CAP_BLOCKS; // connecting height 2123
    let mut y = Scenario::open_under("resident-window-end-y", FreeHash, rules);
    // Heights 0..=release: the last connecting height is release + 1.
    let blocks = y.mine(release + 1).await;
    let genesis = blocks[0].hash;
    let epoch_seed = blocks[usize::try_from(SEEDHASH_EPOCH_BLOCKS).expect("fits")].hash;
    let own = own_hasher();
    let path = tmp("resident-window-end");
    let service = Service::start(
        Arc::new(open_store_under(
            &path,
            &rules.in_force(BlockHeight::ZERO),
            shekyl_chain_store::apply_policy::ApplyPolicy::Full,
        )),
        rules,
        ahead_of_the_drivers(&own),
        ServiceConfig::default(),
        Follow::default(),
    );
    // Up to three blocks short of the release: both seeds are in the window.
    let short = usize::try_from(release - 3).expect("fits");
    connect_all(&service, &own, &blocks[..short]).await;
    assert_eq!(
        settled(&service, &own, rules).await,
        seeds(&[epoch_seed, genesis]),
        "past the switch the window names block 2048's seed and genesis's"
    );
    // Across the release: the window names one seed.
    connect_all(&service, &own, &blocks[short..]).await;
    assert_eq!(
        settled(&service, &own, rules).await,
        seeds(&[epoch_seed]),
        "genesis's cache is freed once the window stops naming it"
    );
    service.stop().await.expect("stops");
    y.close().await;
}
