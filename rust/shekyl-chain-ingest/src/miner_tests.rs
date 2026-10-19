// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Rust miner loop (`shekyl-miner`; `DRS_X_STORE_FLIP.md` DX-Q4, PR 3)
//! over a scenario chain: the production template builder makes the job,
//! the workers hash with real RandomX under the cache the substrate
//! pinned, and what they find goes through the connector's own door — the
//! production `Substrate` sharing the miner's cache store, as the daemon's
//! one RandomX budget will. The workers look that seed up; they do not
//! derive it. No mock stands in for any of the three.
//!
//! The chain runs at a fixed difficulty above one, so the loop searches: at
//! one, the first nonce wins and the search is never exercised.
//!
//! Every test that starts workers holds [`MINER_LANE`]: the thread ledger
//! is the process's, and two miners at once would count each other's rows.

#![cfg(test)]

use std::num::{NonZeroU128, NonZeroUsize};
use std::sync::Arc;
use std::time::{Duration, Instant};

use curve25519_dalek::{EdwardsPoint, Scalar};
use shekyl_address::{Network, ShekylAddress, MSG_SIGN_PK_LEN};
use shekyl_block_template::MinerKeys;
use shekyl_chain_rules::{CenRow, FakechainSchedule, Substrate};
use shekyl_difficulty::{check_hash, Difficulty};
use shekyl_harness_wallet::MinerWallet;
use shekyl_miner::{found_blocks, Job, JobBoard, Miner, MinerConfig, MiningAddress, RATE_WINDOW};
use shekyl_pow_randomx::{compute_hash, CacheStore, Seedhash};
use shekyl_thread_ledger::RowKind;

use crate::metrics::Metrics;
use crate::scenario::{NextBlock, Scenario};
use crate::schedule::ChainRules;
use crate::substrate::ProductionSubstrate;

/// One miner at a time in this process (module docs).
static MINER_LANE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Regtest at a fixed difficulty of eight: a block takes a search.
const RULES: ChainRules = ChainRules::Regtest {
    fixed_difficulty: NonZeroU128::new(8),
    schedule: FakechainSchedule::PRODUCTION,
};

/// How long a test waits for a block at difficulty eight before calling the
/// search broken: generous for a debug build's light-mode hash.
const FIND_WITHIN: Duration = Duration::from_secs(300);

/// The harness miner's full address, encoded: the wallet every scenario
/// template pays, so the address the miner is given decodes to exactly the
/// keys the template producer is built with.
fn harness_address() -> String {
    let wallet = MinerWallet::harness();
    let view = Scalar::from_bytes_mod_order(wallet.kem_secret().x25519);
    ShekylAddress::new(
        Network::Mainnet,
        wallet.recipient().spend_public,
        EdwardsPoint::mul_base(&view).compress().to_bytes(),
        [0; MSG_SIGN_PK_LEN],
        wallet.recipient().ml_kem_ek.clone(),
    )
    .encode()
    .expect("the harness keys encode")
}

/// Pin `next`'s seed into the cache the workers share, then require the
/// lookup they will make to hit. A post of an unpinned seed is left, and
/// the same generation is not searched again.
fn pin_job_seed(substrate: &ProductionSubstrate, caches: &CacheStore, next: &NextBlock) {
    substrate.pin_seed(&next.seed);
    caches
        .lookup(&Seedhash::from_bytes(*next.seed.as_bytes()))
        .expect("the substrate holds the seed the miner will look up");
}

/// The job a miner is handed for `next`.
fn job_for(next: &NextBlock) -> Job {
    Job {
        block: next.template.block.clone(),
        height: next.height,
        seed: next.seed,
        difficulty: next.target.difficulty(),
    }
}

/// The OS nice value of every live thread named `sk-miner` in this process,
/// read back from `/proc` — Linux's readback, as `shekyl-thread-priority`'s
/// own tests read it. Elsewhere the status's not-lowered count is the
/// signal.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn miner_thread_nices() -> Vec<i32> {
    let mut nices = Vec::new();
    for task in std::fs::read_dir("/proc/self/task").expect("list threads") {
        let task = task.expect("thread entry").path();
        let Ok(comm) = std::fs::read_to_string(task.join("comm")) else {
            continue;
        };
        if comm.trim() != "sk-miner" {
            continue;
        }
        let stat = std::fs::read_to_string(task.join("stat")).expect("thread stat");
        // Field 19 is the nice value; the fields after the parenthesised
        // name are space-separated, the state being field 3.
        let after_name = &stat[stat.rfind(')').expect("comm is parenthesised") + 2..];
        let nice: i32 = after_name
            .split(' ')
            .nth(19 - 3)
            .expect("the nice field")
            .parse()
            .expect("a number");
        nices.push(nice);
    }
    nices
}

/// The miner's ledger rows.
fn miner_rows() -> usize {
    shekyl_thread_ledger::ledger()
        .into_iter()
        .filter(|row| row.name.as_str() == "sk-miner" && row.kind == RowKind::DedicatedThread)
        .count()
}

/// The loop end to end, over one cache derivation. The substrate pins each
/// job's seed before the post: the workers look that seed up and leave a
/// job whose seed is not held. The address decodes to the template's keys;
/// two workers find a block at the chain's target, one of them delivers it,
/// and the connector admits it under the real longhash; no second solution
/// follows for the same job; a job superseded while it is being searched is
/// left for the newer one, whose block connects too; every worker is a
/// ledger row, lowered below
/// the daemon (read back as nice 19 on Linux; on every platform the
/// status's not-lowered count is zero); the status reports both workers'
/// hashes over its window; and stopping joins every worker and removes its
/// row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_miner_mines_through_the_connector_and_leaves_a_superseded_job() {
    let _lane = MINER_LANE.lock().await;
    let caches = Arc::new(CacheStore::new());
    let pow = ProductionSubstrate::new(Arc::clone(&caches), Arc::new(Metrics::new()));
    let substrate = pow.clone();
    let mut s = Scenario::open_under("miner-loop", pow, RULES);

    let address =
        MiningAddress::decode(&harness_address(), Network::Mainnet).expect("the harness address");
    let recipient = MinerWallet::harness().recipient();
    assert_eq!(
        address.keys(),
        &MinerKeys {
            spend_public: recipient.spend_public,
            x25519_pk: recipient.x25519_pk,
            ml_kem_ek: recipient.ml_kem_ek.clone(),
        },
        "the address the miner is given pays the keys the template pays"
    );

    let board = Arc::new(JobBoard::new());
    let (sink, found) = found_blocks();
    let budget = shekyl_hash_budget::Budget::of_host();
    let miner = Miner::start(
        &MinerConfig {
            address: address.clone(),
            threads: NonZeroUsize::new(2).expect("two"),
        },
        Arc::clone(&board),
        Arc::clone(&caches),
        budget.clone(),
        sink,
    )
    .expect("the workers start");
    assert_eq!(miner_rows(), 2, "one ledger row per worker");

    // Genesis is priced at one whatever the fixed difficulty; the driver
    // mines it, and the search starts at height one.
    s.mine(1).await;
    // A block at the chain's target, through the connector.
    let mut next = s.next_template(Vec::new()).await.expect("a template");
    assert_eq!(next.target.difficulty(), Difficulty::from_raw(8));
    pin_job_seed(&substrate, &caches, &next);
    let first = board.publish(job_for(&next));
    let block = found.recv_timeout(FIND_WITHIN).expect("a block is found");
    assert_eq!(block.generation, first);
    assert_eq!(block.height, next.height);
    let cache = caches
        .lookup(&Seedhash::from_bytes(*next.seed.as_bytes()))
        .expect("the reported block was hashed under the pinned seed");
    assert_eq!(
        compute_hash(&cache, &block.block.pow_blob()),
        block.pow.to_bytes(),
        "the reported hash is the block's own"
    );
    assert!(check_hash(&block.pow.to_bytes(), next.target.difficulty()));
    next.template.block = block.block.clone();
    let mined = s
        .connect_template(next)
        .await
        .unwrap_or_else(|outcome| panic!("the found block connects: {outcome}"));
    assert_eq!(mined.hash, block.block.hash());
    for row in [CenRow::D1, CenRow::D2, CenRow::D3] {
        assert!(
            mined.judged_by.contains(&row),
            "{row} judged the mined block"
        );
    }

    // One solution per job: the workers parked.
    assert!(
        found.recv_timeout(Duration::from_secs(2)).is_err(),
        "no second block for one job"
    );

    // A job no hash can meet, searched and then superseded by the next
    // template: the block that arrives is the newer job's.
    let mut next = s.next_template(Vec::new()).await.expect("a template");
    let unreachable = Job {
        difficulty: Difficulty::from_raw(u128::MAX),
        ..job_for(&next)
    };
    pin_job_seed(&substrate, &caches, &next);
    let hopeless = board.publish(unreachable);
    std::thread::sleep(Duration::from_secs(2));
    let searching = miner.status();
    assert!(
        searching.rate.hashes > 0,
        "the hopeless job is being searched"
    );
    let second = board.publish(job_for(&next));
    assert!(second > hopeless);
    let block = found
        .recv_timeout(FIND_WITHIN)
        .expect("the newer job's block is found");
    assert_eq!(block.generation, second, "the superseded job was left");
    next.template.block = block.block.clone();
    s.connect_template(next)
        .await
        .unwrap_or_else(|outcome| panic!("the second found block connects: {outcome}"));

    // Below the daemon, and reported: on Linux read back from the kernel;
    // on every platform the status counts the workers the OS refused.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    assert_eq!(
        miner_thread_nices(),
        vec![shekyl_thread_priority::SERVING_NICE; 2],
        "every worker runs at nice 19"
    );
    let status = miner.status();
    assert!(status.active);
    assert_eq!(status.threads, 2);
    assert_eq!(status.address, address.encoded());
    assert_eq!(status.per_thread.len(), 2);
    assert_eq!(status.not_lowered, 0);
    assert!(status.rate.window <= RATE_WINDOW);
    assert_eq!(
        status.rate.hashes,
        status.per_thread.iter().map(|r| r.hashes).sum::<u64>()
    );

    miner.stop();
    // The join is the ledger's: a row leaves after its thread is joined.
    // (`/proc` can still list a joined thread until the kernel reaps it.)
    assert_eq!(miner_rows(), 0, "stopping joins every worker");
    s.close().await;
}

/// Five blocks in a row, each mined by the loop from the template over the
/// last and connected — the live lane's end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real RandomX, five searches; minutes in a debug build. Live lane: cargo test -p shekyl-chain-ingest --features pipeline -- --ignored miner"]
async fn the_miner_extends_the_chain_block_after_block() {
    let _lane = MINER_LANE.lock().await;
    let caches = Arc::new(CacheStore::new());
    let pow = ProductionSubstrate::new(Arc::clone(&caches), Arc::new(Metrics::new()));
    let mut s = Scenario::open_under("miner-five", pow, RULES);
    let board = Arc::new(JobBoard::new());
    let (sink, found) = found_blocks();
    let miner = Miner::start(
        &MinerConfig {
            address: MiningAddress::decode(&harness_address(), Network::Mainnet)
                .expect("the harness address"),
            threads: NonZeroUsize::new(2).expect("two"),
        },
        Arc::clone(&board),
        caches,
        shekyl_hash_budget::Budget::of_host(),
        sink,
    )
    .expect("the workers start");
    s.mine(1).await;
    for expected in 1..6u64 {
        let mut next = s.next_template(Vec::new()).await.expect("a template");
        assert_eq!(next.height.to_raw(), expected);
        board.publish(job_for(&next));
        let block = found.recv_timeout(FIND_WITHIN).expect("a block is found");
        next.template.block = block.block;
        s.connect_template(next)
            .await
            .unwrap_or_else(|outcome| panic!("block {expected} connects: {outcome}"));
    }
    miner.stop();
    s.close().await;
}

/// The miner leaves the last permit free (PR2-Q3). Two permits, one
/// worker, a job no hash meets: the worker holds one permit and a chain
/// `form` takes the other at once, while that hash is still running.
#[test]
fn a_form_takes_the_permit_the_miner_left_free() {
    use shekyl_hash_budget::{Budget, Class};
    let _lane = MINER_LANE.blocking_lock();
    let caches = Arc::new(CacheStore::new());
    let seed = shekyl_types::BlockHash::from_bytes([0x5f; 32]);
    caches.pin_canonical(&Seedhash::from_bytes(*seed.as_bytes()));
    let template = tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(async {
            let mut s = Scenario::open_with("miner-budget", crate::scenario::FreeHash);
            let mined = s.mine(1).await;
            s.close().await;
            mined[0].template.block.clone()
        });
    let budget = Budget::new(NonZeroUsize::new(2).expect("the miner and one higher class"));
    let board = Arc::new(JobBoard::new());
    let (sink, _found) = found_blocks();
    let miner = Miner::start(
        &MinerConfig {
            address: MiningAddress::decode(&harness_address(), Network::Mainnet)
                .expect("the harness address"),
            threads: NonZeroUsize::MIN,
        },
        Arc::clone(&board),
        Arc::clone(&caches),
        budget.clone(),
        sink,
    )
    .expect("the worker starts");
    board.publish(Job {
        block: template,
        height: shekyl_types::BlockHeight::from_raw(1),
        seed,
        difficulty: Difficulty::from_raw(u128::MAX),
    });
    let started = Instant::now();
    while budget.held(Class::Miner) == 0 {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the miner never took a permit"
        );
        std::thread::yield_now();
    }
    let asked = Instant::now();
    let permit = budget.acquire(Class::Chain);
    assert!(
        asked.elapsed() < Duration::from_millis(500),
        "the permit the miner left free is taken at once: {:?}",
        asked.elapsed()
    );
    assert_eq!(
        budget.held(Class::Miner),
        1,
        "the miner keeps the permit it already holds"
    );
    drop(permit);
    miner.stop();
}

/// The loop's hash rate per worker, for the report: one worker, then every
/// core, each searching a job no hash meets for a full window. Run in
/// release — a debug build's rate says nothing about the daemon's:
/// `cargo test --release -p shekyl-chain-ingest --features pipeline -- --ignored --nocapture the_miners_rate`.
#[test]
#[ignore = "a measurement, in release: see the doc comment"]
fn the_miners_rate_per_worker() {
    let _lane = MINER_LANE.blocking_lock();
    let caches = Arc::new(CacheStore::new());
    let seed = shekyl_types::BlockHash::from_bytes([0x5e; 32]);
    let derive = Instant::now();
    caches.lookup_or_derive(&Seedhash::from_bytes(*seed.as_bytes()));
    eprintln!("cache derivation: {:.2} s", derive.elapsed().as_secs_f64());
    let cores = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    let template = tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(async {
            let mut s = Scenario::open_with("miner-rate", crate::scenario::FreeHash);
            let mined = s.mine(1).await;
            s.close().await;
            mined[0].template.block.clone()
        });
    for threads in [1, cores] {
        let board = Arc::new(JobBoard::new());
        let (sink, _found) = found_blocks();
        let miner = Miner::start(
            &MinerConfig {
                address: MiningAddress::decode(&harness_address(), Network::Mainnet)
                    .expect("the harness address"),
                threads: NonZeroUsize::new(threads).expect("non-zero"),
            },
            Arc::clone(&board),
            Arc::clone(&caches),
            shekyl_hash_budget::Budget::of_host(),
            sink,
        )
        .expect("the workers start");
        board.publish(Job {
            block: template.clone(),
            height: shekyl_types::BlockHeight::from_raw(1),
            seed,
            difficulty: Difficulty::from_raw(u128::MAX),
        });
        std::thread::sleep(RATE_WINDOW + Duration::from_secs(2));
        let status = miner.status();
        let rates: Vec<String> = status
            .per_thread
            .iter()
            .map(|r| format!("{:.2}", r.per_second()))
            .collect();
        eprintln!(
            "{threads} worker(s) of {cores} cores: {:.2} H/s total over {} s; per worker [{}] H/s; not lowered {}",
            status.rate.per_second(),
            status.rate.window.as_secs(),
            rates.join(", "),
            status.not_lowered
        );
        miner.stop();
    }
}

/// The tip follower's template source in tests (`follower` module docs):
/// the scenario's template over the harness miner, stamped from the
/// service's own clock, one tick past the chain's median so CEN-C2 holds.
struct ScenarioSource {
    clock: Arc<crate::scenario::Clocked<ProductionSubstrate>>,
    miner: MinerKeys,
    counter: std::sync::atomic::AtomicU64,
}

impl crate::follower::TemplateSource for ScenarioSource {
    fn template(
        &self,
        facts: &crate::connector::ChainFacts,
    ) -> Option<(shekyl_wire::Block, Vec<shekyl_wire::Transaction>)> {
        let mut now = self.clock.tick();
        if let Some(median) = facts.median_timestamp {
            while now <= median {
                now = self.clock.tick();
            }
        }
        let counter = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let template = crate::scenario::build_template(
            RULES,
            &shekyl_economics::EconomicParams::default(),
            &self.miner,
            counter,
            facts,
            now,
            &[],
        )
        .ok()?;
        Some((template.block, template.transactions))
    }
}

/// The miner across a seed epoch (DX-Q2 item 5): the tip follower pins
/// `seed(tip + 1)` before it posts the job, so the miner, which hashes only
/// under a held cache, mines the first block of the new epoch. The first
/// epoch boundary is height 1: genesis is hashed under the null seed, and
/// every block from 1 under genesis's hash, which nothing else pins. The
/// block the miner finds enters through the service's door as a local
/// arrival and connects.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_follower_pins_the_new_epochs_seed_and_the_miner_mines_its_first_block() {
    use crate::follower::MinerFeed;
    use crate::service::{Arrival, ArrivalTag, Follow, Origin, Service, ServiceConfig};
    let _lane = MINER_LANE.lock().await;
    let caches = Arc::new(CacheStore::new());
    let clock = Arc::new(crate::scenario::Clocked::new(ProductionSubstrate::new(
        Arc::clone(&caches),
        Arc::new(Metrics::new()),
    )));
    // Genesis, built by a driver over the free longhash: block 0 is priced
    // at one whatever the fixed difficulty, so any hash meets it.
    let mut y = Scenario::open_under("miner-epoch-y", crate::scenario::FreeHash, RULES);
    let genesis = y.mine(1).await;
    let path = crate::test_support::tmp("miner-epoch");
    let store = crate::test_support::open_store_under(
        &path,
        &RULES.in_force(shekyl_types::BlockHeight::from_raw(0)),
        shekyl_chain_store::apply_policy::ApplyPolicy::Full,
    );
    let budget = shekyl_hash_budget::Budget::of_host();
    let board = Arc::new(JobBoard::new());
    let (sink, found) = found_blocks();
    let (_synced_tx, synced) = tokio::sync::watch::channel(true);
    let recipient = MinerWallet::harness().recipient();
    let source = ScenarioSource {
        clock: Arc::clone(&clock),
        miner: MinerKeys {
            spend_public: recipient.spend_public,
            x25519_pk: recipient.x25519_pk,
            ml_kem_ek: recipient.ml_kem_ek.clone(),
        },
        counter: std::sync::atomic::AtomicU64::new(1),
    };
    let service = Service::start(
        Arc::new(store),
        RULES,
        Arc::clone(&clock),
        ServiceConfig::default(),
        budget.clone(),
        Follow {
            miner: Some(MinerFeed {
                board: Arc::clone(&board),
                source: Arc::new(source),
                synced,
                found,
            }),
            pool: None,
        },
    );
    let miner = Miner::start(
        &MinerConfig {
            address: MiningAddress::decode(&harness_address(), Network::Mainnet)
                .expect("the harness address"),
            threads: NonZeroUsize::new(2).expect("two"),
        },
        Arc::clone(&board),
        Arc::clone(&caches),
        budget,
        sink,
    )
    .expect("the workers start");
    let mut tips = service.watch_tip().await.expect("watch");
    let connected = service
        .door()
        .offer(Arrival {
            tag: ArrivalTag(0),
            origin: Origin::Local,
            block: genesis[0].template.block.serialize(),
            bodies: Vec::new(),
        })
        .expect("room")
        .reply()
        .await;
    assert!(
        matches!(connected.reply, crate::service::Reply::Connected { .. }),
        "{connected:?}"
    );
    let started = Instant::now();
    loop {
        let tip = *tips.borrow_and_update();
        if tip
            .tip
            .is_some_and(|t| t.count.tip() >= Some(shekyl_types::BlockHeight::from_raw(1)))
        {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "block 1 was never mined"
        );
        let _waited: Result<_, tokio::time::error::Elapsed> =
            tokio::time::timeout(Duration::from_secs(5), tips.changed()).await;
    }
    assert!(
        caches
            .lookup(&Seedhash::from_bytes(*genesis[0].hash.as_bytes()))
            .is_some(),
        "the new epoch's seed is held"
    );
    miner.stop();
    service.stop().await.expect("stops");
    y.close().await;
    crate::test_support::cleanup(&path);
}
