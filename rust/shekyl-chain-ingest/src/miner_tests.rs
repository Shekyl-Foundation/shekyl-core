// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Rust miner loop (`shekyl-miner`; `DRS_X_STORE_FLIP.md` DX-Q4, PR 3)
//! over a scenario chain: the production template builder makes the job,
//! the workers hash with real RandomX on a warm loan from the test's own
//! hasher, and what they find goes through the connector's own door,
//! formed by the production boundary over that same hasher, as the
//! daemon's one hasher serves both. The workers build no cache: the driver
//! ranks the job's seed and waits for it to be warm before it posts. No
//! mock stands in for any of the three.
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
use shekyl_chain_rules::{CappedEpoch, CenRow};
use shekyl_difficulty::{check_hash, Difficulty};
use shekyl_harness_wallet::MinerWallet;
use shekyl_hasher::{Class, Ranked};
use shekyl_miner::{
    found_blocks, Found, FoundInbox, FoundWait, Job, JobBoard, Miner, MinerConfig, MiningAddress,
    SearchBound, RATE_WINDOW,
};
use shekyl_pow_randomx::Seedhash;
use shekyl_thread_ledger::RowKind;

use crate::pow::{Pow, ProductionPow};
use crate::scenario::{NextBlock, Scenario};
use crate::schedule::ChainRules;
use crate::test_support::{own_hasher, own_hasher_on, OwnHasher};

/// One miner at a time in this process (module docs).
static MINER_LANE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The fixed difficulty these chains run at: above one, so a block takes a
/// search.
const DIFFICULTY: u128 = 8;

/// Regtest at [`DIFFICULTY`].
const RULES: ChainRules =
    ChainRules::harness_regtest(NonZeroU128::new(DIFFICULTY), CappedEpoch::PRODUCTION);

/// The most blocks any test here waits for in turn: five, in
/// [`the_miner_extends_the_chain_block_after_block`], whose loop runs to it,
/// so the count the bound is derived from is the count the test mines.
const MOST_BLOCKS: u32 = 5;

/// How many times the expected hash count a block's search may try before
/// the test calls the miner broken.
///
/// Each hash meets the target with probability `1/D` at [`DIFFICULTY`]
/// (`D = 8`), independently of every other, so a working search misses
/// all of its first `k·D` hashes with probability `(1 − 1/D)^(k·D)`, about
/// `e^(−k)`. A test that waits for `b` blocks fails falsely with
/// probability at most `b` times that. The bound is one in a million for a
/// whole test (Rick, 2026-11-22): at [`MOST_BLOCKS`], `k = 15` is the least
/// that meets it, `5 × (7/8)^120 ≈ 5.5e-7`, where `k = 14` gives `1.6e-6`
/// ([`the_hash_bound_is_derived_from_the_difficulty`]). A test waiting for
/// fewer blocks has more margin.
///
/// The bound counts hashes, not seconds. The workers run at the lowest
/// priority by design, so on a host whose cores other work holds they are
/// starved, and a bound in seconds measured the host: the 2026-11-11
/// nightly set at load 12 to 32, and a build VM at load 21 on 2026-11-21,
/// each timed out a working miner at the old 195 s. The hashes the
/// workers actually tried judge the search alone.
const EXPECTED_MULTIPLE: u64 = 15;

/// [`DIFFICULTY`] as a hash count: the hashes a block takes on average.
/// [`the_hash_bound_is_derived_from_the_difficulty`] computes in `f64`
/// and needs it within `u32`, and its multiple within `i32`; a difficulty
/// past those is a search no test can wait for, and the conversions there
/// say so.
#[allow(
    clippy::cast_possible_truncation,
    reason = "the assert above the cast holds the difficulty inside u64"
)]
const EXPECTED_HASHES: u64 = {
    assert!(DIFFICULTY <= u64::MAX as u128);
    DIFFICULTY as u64
};

/// The hashes a block's search may try: [`EXPECTED_MULTIPLE`] ×
/// [`EXPECTED_HASHES`], 120. The wait adds one hash per worker: the count
/// is read just after the next job is posted, and each worker can finish
/// the hash it started on the previous job after that read, which is
/// counted against the next block. A worker checks the board before every
/// hash, so it starts no further hash on the previous job once the next is
/// posted. The read comes after the post, never before: a worker could
/// finish a hash and start another on the previous job in between.
const SEARCH_HASHES: u64 = EXPECTED_MULTIPLE * EXPECTED_HASHES;

/// How long a block's search may run before the test calls it a hang: the
/// workers stopped hashing, or the host starved them for this long. Not a
/// verdict on the search, which only the hash count gives. Twenty minutes
/// is far past the 120 hashes at the floor device's 1.25 s each, about
/// 2.5 minutes on one worker (rule 176, `DRS_X_STORE_FLIP.md` PR2-Q2).
const HANG_AFTER: Duration = Duration::from_secs(20 * 60);

/// How often the wait reads the miner's count while no block has come.
const POLL: Duration = Duration::from_millis(500);

/// The block found for the job just posted, `before` being `miner`'s count
/// read after the post ([`SEARCH_HASHES`] says why after), judged by hashes tried ([`SEARCH_HASHES`]), with [`HANG_AFTER`]
/// as a backstop that reports a hang, not a miner failure.
fn the_block(found: &FoundInbox, miner: &Miner, before: u64) -> Found {
    let workers = u64::try_from(miner.status().threads).expect("a worker count");
    let started = Instant::now();
    loop {
        // Read before the wait: a block among the hashes counted here is
        // almost always delivered within the wait. The winning hash is
        // counted before it is checked, claimed and sent, and a starved
        // worker can be descheduled between the two for longer than the
        // wait; a late block then needs the bound's worth of further
        // hashes from the other workers to look like a miss, minutes on
        // the floor device.
        let tried = miner.hashes_tried() - before;
        let asked = Instant::now();
        match found.recv_timeout(POLL) {
            Ok(block) => return block,
            // `FoundWait` is both a wait that ran out and an inbox that
            // ended; only an ended inbox returns before the wait is over.
            Err(FoundWait) => assert!(
                asked.elapsed() >= POLL,
                "the found-block inbox returned before the {POLL:?} wait ran out, so it \
                 ended: no block, after {tried} hashes"
            ),
        }
        assert!(
            tried <= SEARCH_HASHES + workers,
            "miner failure: {tried} hashes tried and no block; a working search misses \
             {SEARCH_HASHES} at difficulty {DIFFICULTY} with probability about e^-{EXPECTED_MULTIPLE}"
        );
        assert!(
            started.elapsed() < HANG_AFTER,
            "hang, not a miner verdict: no block and {tried} of the {SEARCH_HASHES} hashes \
             the bound allows tried in {HANG_AFTER:?} (the workers stopped, or the host starved them)"
        );
    }
}

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

/// How long a ranked seed's cache may take to build before a test calls
/// the hasher broken: one derive is about half a second on a desktop and
/// about two on the floor device.
const WARM_WITHIN: Duration = Duration::from_secs(120);

/// Wait until `seed`'s cache is built, which a warm loan needs.
fn wait_warm(own: &OwnHasher, seed: &shekyl_types::BlockHash) {
    let started = Instant::now();
    while !own.pow.warm(seed) {
        assert!(
            started.elapsed() < WARM_WITHIN,
            "the ranked seed {seed:?} was never built"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Rank from the driver's store, as the node's ranker does after a write,
/// and wait for `next`'s seed to be warm. A job posted on a seed that is
/// not listed and built is left, and the same generation is not searched
/// again.
fn warm_job_seed(s: &Scenario<ProductionPow>, own: &OwnHasher, next: &NextBlock) {
    s.rank();
    wait_warm(own, &next.seed);
}

/// Rank `seed` alone and wait for its cache: a job on a seed no store
/// names.
fn rank_alone(own: &OwnHasher, seed: &shekyl_types::BlockHash) {
    own.pow
        .rank(Ranked::new(Seedhash::from_bytes(*seed.as_bytes()), None, None).expect("one seed"));
    wait_warm(own, seed);
}

/// RandomX over `blob` under `seed`, as one job on the test's hasher.
fn hash_under(own: &OwnHasher, seed: &shekyl_types::BlockHash, blob: &[u8]) -> [u8; 32] {
    static NEVER_STOPS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    own.hasher
        .run(
            Class::Chain,
            Seedhash::from_bytes(*seed.as_bytes()),
            &NEVER_STOPS,
            |lent| lent.hash(blob),
        )
        .expect("the test's hasher runs for the test's life")
}

/// The job a miner is handed for `next`.
fn job_for(next: &NextBlock) -> Job {
    Job {
        block: next.template.block.clone(),
        height: next.height,
        seed: next.seed,
        difficulty: next.target.difficulty(),
        offsets: next
            .template
            .block
            .blob_offsets()
            .expect("a built coinbase reserves the extra nonce"),
        next_seed: None,
        reward: shekyl_units::AtomicUnits::ZERO,
        median_weight: 0,
        already_generated: shekyl_units::AtomicUnits::ZERO,
        listed: Vec::new(),
    }
}

/// The OS nice value of every live thread named `sk-miner` in this process,
/// read back from `/proc` — Linux's readback, as `shekyl-thread-priority`'s
/// own tests read it. Elsewhere the status's not-lowered count is the
/// signal.
#[cfg(target_os = "linux")]
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

/// The loop end to end, over one cache derivation. The driver ranks each
/// job's seed and waits for it to be warm before the post: the workers
/// borrow that seed's cache and leave a job whose seed is not warm. The address decodes to the template's keys;
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
    let own = own_hasher();
    let mut s = Scenario::open_under("miner-loop", own.pow.clone(), RULES);

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
    let miner = Miner::start(
        &MinerConfig {
            address: address.clone(),
            threads: NonZeroUsize::new(2).expect("two"),
            bound: SearchBound::Unbounded,
        },
        Arc::clone(&board),
        own.hasher.clone(),
        sink,
    )
    .expect("the workers start");
    assert_eq!(miner_rows(), 2, "one ledger row per worker");

    // Genesis is priced at one whatever the fixed difficulty; the driver
    // mines it, and the search starts at height one.
    s.mine(1).await;
    // A block at the chain's target, through the connector.
    let mut next = s.next_template(Vec::new()).await.expect("a template");
    assert_eq!(
        next.target.difficulty(),
        Difficulty::new(DIFFICULTY).expect("a test difficulty is non-zero")
    );
    warm_job_seed(&s, &own, &next);
    let first = board.publish(job_for(&next));
    let before = miner.hashes_tried();
    let block = the_block(&found, &miner, before);
    assert_eq!(block.generation, first);
    assert_eq!(block.height, next.height);
    assert_eq!(
        hash_under(&own, &next.seed, &block.block.pow_blob()),
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
        difficulty: Difficulty::new(u128::MAX).expect("a test difficulty is non-zero"),
        ..job_for(&next)
    };
    warm_job_seed(&s, &own, &next);
    let hopeless = board.publish(unreachable);
    std::thread::sleep(Duration::from_secs(2));
    let searching = miner.status();
    assert!(
        searching.rate.hashes > 0,
        "the hopeless job is being searched"
    );
    let second = board.publish(job_for(&next));
    let before = miner.hashes_tried();
    assert!(second > hopeless);
    let block = the_block(&found, &miner, before);
    assert_eq!(block.generation, second, "the superseded job was left");
    next.template.block = block.block.clone();
    s.connect_template(next)
        .await
        .unwrap_or_else(|outcome| panic!("the second found block connects: {outcome}"));

    // Below the daemon, and reported: on Linux read back from the kernel;
    // on every platform the status counts the workers the OS refused.
    #[cfg(target_os = "linux")]
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
    // Where the platform has no per-thread lowering (the BSDs), every
    // worker is counted as not lowered and still mines.
    let refused = if shekyl_thread_priority::LOWERS_THREADS {
        0
    } else {
        status.threads
    };
    assert_eq!(status.not_lowered, refused);
    assert!(status.rate.window <= RATE_WINDOW);
    assert_eq!(
        status.rate.hashes,
        status.per_thread.iter().map(|r| r.hashes).sum::<u64>()
    );

    miner.stop().join();
    // The join is the ledger's: a row leaves after its thread is joined.
    // (`/proc` can still list a joined thread until the kernel reaps it.)
    assert_eq!(
        miner_rows(),
        0,
        "joining the stopped workers removes every row"
    );
    s.close().await;
}

/// A miner started [`SearchBound::Until`] a height mines no block above
/// it (`dev_block_generate`'s exact count). The bound is height one: posted
/// that height's job, the one worker finds the block, which connects.
/// Posted the next template's, at height two, that worker parks: after a
/// full rate window the miner has hashed nothing and found nothing. One
/// worker, because a second can still be hashing the bound-height job
/// when the block is delivered, and that hash is recorded when it
/// finishes — inside the later window — before the superseded generation
/// is dropped. Red edit: drop the bound check in the worker loop; the job
/// at height two is searched and its block found. Red edit: start a
/// second worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_miner_searching_until_a_height_mines_no_block_above_it() {
    let _lane = MINER_LANE.lock().await;
    let own = own_hasher();
    let mut s = Scenario::open_under("miner-until", own.pow.clone(), RULES);
    let until = shekyl_types::BlockHeight::from_raw(1);

    let board = Arc::new(JobBoard::new());
    let (sink, found) = found_blocks();
    let miner = Miner::start(
        &MinerConfig {
            address: MiningAddress::decode(&harness_address(), Network::Mainnet)
                .expect("the harness address"),
            threads: NonZeroUsize::MIN,
            bound: SearchBound::Until(until),
        },
        Arc::clone(&board),
        own.hasher.clone(),
        sink,
    )
    .expect("the workers start");

    // Genesis is the driver's; height one, the bound, is the miner's.
    s.mine(1).await;
    let mut next = s.next_template(Vec::new()).await.expect("a template");
    assert_eq!(next.height, until);
    warm_job_seed(&s, &own, &next);
    let posted = board.publish(job_for(&next));
    let before = miner.hashes_tried();
    let block = the_block(&found, &miner, before);
    assert_eq!(block.generation, posted);
    assert_eq!(block.height, until);
    next.template.block = block.block.clone();
    s.connect_template(next)
        .await
        .unwrap_or_else(|outcome| panic!("the block at the bound connects: {outcome}"));

    // Height two is above it: posted, not searched.
    let above = s.next_template(Vec::new()).await.expect("a template");
    assert_eq!(above.height.to_raw(), 2);
    warm_job_seed(&s, &own, &above);
    board.publish(job_for(&above));
    assert!(
        found
            .recv_timeout(RATE_WINDOW + Duration::from_secs(1))
            .is_err(),
        "no block above the bound"
    );
    assert_eq!(
        miner.status().rate.hashes,
        0,
        "the worker parked on the job above the bound: not one hash in a full window"
    );

    miner.stop().join();
    s.close().await;
}

/// Five blocks in a row, each mined by the loop from the template over the
/// last and connected — the live lane's end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real RandomX, five searches; minutes in a debug build; run by nightly.yml's chain-ingest-ignored job"]
async fn the_miner_extends_the_chain_block_after_block() {
    let _lane = MINER_LANE.lock().await;
    let own = own_hasher();
    let mut s = Scenario::open_under("miner-five", own.pow.clone(), RULES);
    let board = Arc::new(JobBoard::new());
    let (sink, found) = found_blocks();
    let miner = Miner::start(
        &MinerConfig {
            address: MiningAddress::decode(&harness_address(), Network::Mainnet)
                .expect("the harness address"),
            threads: NonZeroUsize::new(2).expect("two"),
            bound: SearchBound::Unbounded,
        },
        Arc::clone(&board),
        own.hasher.clone(),
        sink,
    )
    .expect("the workers start");
    s.mine(1).await;
    for expected in 1..=u64::from(MOST_BLOCKS) {
        let mut next = s.next_template(Vec::new()).await.expect("a template");
        assert_eq!(next.height.to_raw(), expected);
        // The workers leave a job whose seed is not warm
        // (`warm_job_seed`), so each post ranks first, as the node does.
        warm_job_seed(&s, &own, &next);
        board.publish(job_for(&next));
        let before = miner.hashes_tried();
        let block = the_block(&found, &miner, before);
        next.template.block = block.block;
        s.connect_template(next)
            .await
            .unwrap_or_else(|outcome| panic!("block {expected} connects: {outcome}"));
    }
    miner.stop().join();
    s.close().await;
}

/// LWMA-1's floor, mined (`DAA_LWMA1.md` §5.3 step 10; Rick, 2026-11-07).
/// `N + 1` blocks at a fixed difficulty of one, a DAA target apart, are a
/// window of ones on time: LWMA-1's tail over it is `0.99`, which floors
/// to zero, and the block after it used to be refused (CEN-D6) with every
/// successor. Continued under LWMA-1, that block's target is one. At one
/// every hash is a block, so the chain's blocks come a second apart, and
/// the target climbs as the on-time window slides out: within the next
/// window it reaches ten, the tenfold climb of §8.1 vector 9 (the integer
/// model first reaches it about 62 blocks in). The test stops there: the
/// climb from ten to a hundred and on is the same arithmetic, pinned by
/// vector 9, and mining it costs about ten times as many hashes.
///
/// Real RandomX throughout: each nonce is hashed under the cache the
/// test's hasher lends and judged by `check_hash`, and every block goes
/// through the connector's door, which verifies it again as its own job.
/// The search is this test's own loop, not the miner's workers: they run
/// at the lowest priority by design, and the subject here is the
/// difficulty, not the miner. The scenario's clock is the only thing
/// scripted. Red edit: drop step 10, and the first template is never
/// built.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real RandomX, about 140 hashes over most of a window, five minutes in release; run by nightly.yml's chain-ingest-ignored job"]
async fn a_chain_at_the_difficulty_floor_mines_its_way_back() {
    let own = own_hasher();
    let mut s = Scenario::open_under(
        "miner-floor",
        own.pow.clone(),
        ChainRules::harness_regtest(NonZeroU128::new(1), CappedEpoch::PRODUCTION),
    );
    // Heights 0..=N at one, on time: the window of ones.
    s.mine(shekyl_difficulty::N + 1).await;
    s.continue_under(ChainRules::harness_regtest(None, CappedEpoch::PRODUCTION))
        .await;
    s.space_blocks(core::num::NonZeroU64::MIN);

    let began = Instant::now();
    let mut targets = Vec::new();
    let mut hashes = 0u64;
    let ten = Difficulty::new(10).expect("non-zero");
    for _ in 0..=shekyl_difficulty::N {
        let mut next = s.next_template(Vec::new()).await.expect("a template");
        let target = next.target.difficulty();
        targets.push(target);
        if target >= ten {
            break;
        }
        warm_job_seed(&s, &own, &next);
        let seed = next.seed;
        let block = &mut next.template.block;
        loop {
            hashes += 1;
            if check_hash(&hash_under(&own, &seed, &block.pow_blob()), target) {
                break;
            }
            block.header.nonce = block.header.nonce.wrapping_add(1);
        }
        let height = next.height;
        s.connect_template(next)
            .await
            .unwrap_or_else(|outcome| panic!("block {height:?} connects: {outcome}"));
    }
    s.close().await;
    eprintln!(
        "floor: {} blocks, {hashes} hashes, {:?}; targets {targets:?}",
        targets.len(),
        began.elapsed()
    );

    assert_eq!(
        targets.first(),
        Some(&Difficulty::ONE),
        "the block after the window of ones is claimed at the floor"
    );
    assert!(
        targets.windows(2).all(|pair| pair[0] <= pair[1]),
        "fast blocks never lower the target: {targets:?}"
    );
    let last = *targets.last().expect("a window of targets");
    assert!(
        last >= ten,
        "within one window of fast blocks the floor climbs tenfold: {targets:?}"
    );
}

/// The miner leaves the last permit free (PR2-Q3). Two permits, one
/// worker, a job no hash meets: the worker holds one permit and a chain
/// `form` takes the other at once, while that hash is still running.
#[test]
fn a_form_takes_the_permit_the_miner_left_free() {
    use shekyl_hash_budget::Budget;
    let _lane = MINER_LANE.blocking_lock();
    let seed = shekyl_types::BlockHash::from_bytes([0x5f; 32]);
    let template = tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(async {
            let mut s = Scenario::open_with("miner-budget", crate::scenario::FreeHash);
            let mined = s.mine(1).await;
            s.close().await;
            mined[0].template.block.clone()
        });
    let budget = Budget::new(NonZeroUsize::new(2).expect("the miner and one higher class"));
    // The hasher takes its permits from this budget, so the test reads
    // what the miner's loan holds and takes the other permit itself.
    let own = own_hasher_on(budget.clone());
    rank_alone(&own, &seed);
    let board = Arc::new(JobBoard::new());
    let (sink, _found) = found_blocks();
    let miner = Miner::start(
        &MinerConfig {
            address: MiningAddress::decode(&harness_address(), Network::Mainnet)
                .expect("the harness address"),
            threads: NonZeroUsize::MIN,
            bound: SearchBound::Unbounded,
        },
        Arc::clone(&board),
        own.hasher.clone(),
        sink,
    )
    .expect("the worker starts");
    board.publish(Job {
        offsets: template
            .blob_offsets()
            .expect("a built coinbase reserves the extra nonce"),
        next_seed: None,
        reward: shekyl_units::AtomicUnits::ZERO,
        median_weight: 0,
        already_generated: shekyl_units::AtomicUnits::ZERO,
        listed: Vec::new(),
        block: template,
        height: shekyl_types::BlockHeight::from_raw(1),
        seed,
        difficulty: Difficulty::new(u128::MAX).expect("a test difficulty is non-zero"),
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
    miner.stop().join();
}

/// `RANDOMX_CACHE_ACTOR.md` §8: a mining job whose seed leaves the ranked
/// list. The worker's warm loan is cancelled, the worker leaves the job
/// (it stops hashing and holds no permit), and the seed's cache is gone at
/// the next quiescence. A cancelled loan never holds off the node.
///
/// Red edit: in `shekyl-miner`'s worker, treat `Unhashed::Cancelled` as a
/// reason to ask for the loan again on the same seed: the worker logs
/// "not warm" in a loop; or in the hasher, do not cancel a warm lease
/// whose seed left the list: the worker keeps hashing and the cache stays.
#[test]
fn a_mining_job_whose_seed_leaves_the_list_is_cancelled_and_its_cache_freed() {
    use shekyl_hash_budget::{Budget, Class as BudgetClass};
    let _lane = MINER_LANE.blocking_lock();
    let mined_under = shekyl_types::BlockHash::from_bytes([0x6a; 32]);
    let next_tip = shekyl_types::BlockHash::from_bytes([0x6b; 32]);
    let template = tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(async {
            let mut s = Scenario::open_with("miner-cancel", crate::scenario::FreeHash);
            let mined = s.mine(1).await;
            s.close().await;
            mined[0].template.block.clone()
        });
    let budget = Budget::new(NonZeroUsize::new(2).expect("the miner and one higher class"));
    let own = own_hasher_on(budget.clone());
    rank_alone(&own, &mined_under);
    let board = Arc::new(JobBoard::new());
    let (sink, _found) = found_blocks();
    let miner = Miner::start(
        &MinerConfig {
            address: MiningAddress::decode(&harness_address(), Network::Mainnet)
                .expect("the harness address"),
            threads: NonZeroUsize::MIN,
            bound: SearchBound::Unbounded,
        },
        Arc::clone(&board),
        own.hasher.clone(),
        sink,
    )
    .expect("the worker starts");
    // A job no hash meets, so the worker searches until its loan ends.
    board.publish(Job {
        offsets: template
            .blob_offsets()
            .expect("a built coinbase reserves the extra nonce"),
        next_seed: None,
        reward: shekyl_units::AtomicUnits::ZERO,
        median_weight: 0,
        already_generated: shekyl_units::AtomicUnits::ZERO,
        listed: Vec::new(),
        block: template,
        height: shekyl_types::BlockHeight::from_raw(1),
        seed: mined_under,
        difficulty: Difficulty::new(u128::MAX).expect("a test difficulty is non-zero"),
    });
    let started = Instant::now();
    while budget.held(BudgetClass::Miner) == 0 {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the miner never hashed"
        );
        std::thread::yield_now();
    }
    // The tip moves on: the list names another seed and not the job's.
    rank_alone(&own, &next_tip);
    // The wait uses a timer. A current-thread runtime has none until asked.
    let quiet = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime")
        .block_on(crate::test_support::quiet_seeds(
            &own.hasher,
            format!("the list names {next_tip} and not the job's seed"),
        ));
    assert_eq!(
        quiet,
        std::iter::once(*next_tip.as_bytes()).collect(),
        "the job's seed left the list and its cache is gone"
    );
    // The worker left the job: it holds no permit, and it stays that way.
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        budget.held(BudgetClass::Miner),
        0,
        "a cancelled loan is not hashed under again"
    );
    assert_eq!(
        own.hasher.resident().borrow().builds,
        2,
        "one build per ranked seed; the cancelled job built nothing"
    );
    miner.stop().join();
}

/// The loop's hash rate per worker, for the report: one worker, then every
/// core, each searching a job no hash meets for a full window. Run in
/// release — a debug build's rate says nothing about the daemon's:
/// `cargo test --release -p shekyl-chain-ingest --features pipeline -- --ignored --nocapture the_miners_rate`.
#[test]
#[ignore = "a measurement in release (see the doc comment); run by nightly.yml's chain-ingest-ignored job"]
fn the_miners_rate_per_worker() {
    let _lane = MINER_LANE.blocking_lock();
    let own = own_hasher();
    let seed = shekyl_types::BlockHash::from_bytes([0x5e; 32]);
    let derive = Instant::now();
    rank_alone(&own, &seed);
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
                bound: SearchBound::Unbounded,
            },
            Arc::clone(&board),
            own.hasher.clone(),
            sink,
        )
        .expect("the workers start");
        board.publish(Job {
            block: template.clone(),
            height: shekyl_types::BlockHeight::from_raw(1),
            seed,
            difficulty: Difficulty::new(u128::MAX).expect("a test difficulty is non-zero"),
            offsets: template
                .blob_offsets()
                .expect("a built coinbase reserves the extra nonce"),
            next_seed: None,
            reward: shekyl_units::AtomicUnits::ZERO,
            median_weight: 0,
            already_generated: shekyl_units::AtomicUnits::ZERO,
            listed: Vec::new(),
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
        miner.stop().join();
    }
}

/// The miner across a seed epoch (DX-Q2 item 5): the tip follower has the
/// list name `seed(tip + 1)` and waits for that cache before it posts the
/// job, so the miner, which hashes only on a warm loan, mines the first
/// block of the new epoch. The first epoch boundary is height 1: genesis
/// is hashed under the null seed, and every block from 1 under genesis's
/// hash, which nothing ranks until genesis connects. The block the miner
/// finds enters through the service's door as a local arrival and
/// connects.
///
/// Red edit: in the follower's loop, drop the `seed_built` arm of the
/// select: the first build finds genesis's seed still building, leaves no
/// job, and nothing wakes it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_follower_waits_for_the_new_epochs_seed_and_the_miner_mines_its_first_block() {
    use crate::service::{Arrival, ArrivalTag, Follow, Origin, Service, ServiceConfig};
    let _lane = MINER_LANE.lock().await;
    let own = own_hasher();
    let clock = Arc::new(crate::scenario::Clocked::new(own.pow.clone()));
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
    let board = Arc::new(JobBoard::new());
    let (_sync_tx, sync) = tokio::sync::watch::channel(shekyl_chain_sync::SyncState::Synced);
    // The node's own producer builds every job, paying the harness wallet,
    // stamped from the service's clock.
    let (seat, sink, _posting) =
        crate::test_support::job_seat(&board, Some(crate::test_support::harness_keys()), sync);
    let service = Service::start(
        Arc::new(store),
        RULES,
        Arc::clone(&clock),
        ServiceConfig::default(),
        Follow {
            job: Some(seat),
            pool: None,
            ..Default::default()
        },
    );
    let miner = Miner::start(
        &MinerConfig {
            address: MiningAddress::decode(&harness_address(), Network::Mainnet)
                .expect("the harness address"),
            threads: NonZeroUsize::new(2).expect("two"),
            bound: SearchBound::Unbounded,
        },
        Arc::clone(&board),
        own.hasher.clone(),
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
            bundle_references: Vec::new(),
            bundle_bodies: Vec::new(),
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
        own.pow.warm(&genesis[0].hash),
        "the new epoch's seed is warm"
    );
    miner.stop().join();
    service.stop().await.expect("stops");
    y.close().await;
}

/// A one-permit budget never grants the miner a permit: it leaves the
/// last one for a higher class. Starting a miner there is refused before
/// a thread starts, rather than reported active and hashing nothing.
#[test]
fn a_miner_on_a_one_permit_budget_is_refused() {
    let (sink, _found) = found_blocks();
    let refused = Miner::start(
        &MinerConfig {
            address: MiningAddress::decode(&harness_address(), Network::Mainnet)
                .expect("the harness address"),
            threads: NonZeroUsize::new(1).expect("one"),
            bound: SearchBound::Unbounded,
        },
        Arc::new(JobBoard::new()),
        own_hasher_on(shekyl_hash_budget::Budget::new(NonZeroUsize::MIN))
            .hasher
            .clone(),
        sink,
    );
    assert!(matches!(
        refused,
        Err(shekyl_miner::MinerStartRefused::OnePermit)
    ));
}

/// [`EXPECTED_MULTIPLE`] is the least multiple of the expected hash count
/// at which a test waiting for [`MOST_BLOCKS`] blocks at [`DIFFICULTY`]
/// fails falsely with probability below one in a million. Red edit: raise
/// the difficulty, or the most blocks a test waits for, and leave `k`.
#[test]
fn the_hash_bound_is_derived_from_the_difficulty() {
    let win =
        1.0 / f64::from(u32::try_from(EXPECTED_HASHES).expect("a difficulty a test can wait for"));
    let false_failure = |multiple: u64| {
        let hashes = i32::try_from(multiple * EXPECTED_HASHES).expect("small");
        f64::from(MOST_BLOCKS) * (1.0 - win).powi(hashes)
    };
    assert!(
        false_failure(EXPECTED_MULTIPLE) < 1e-6,
        "{}",
        false_failure(EXPECTED_MULTIPLE)
    );
    assert!(
        false_failure(EXPECTED_MULTIPLE - 1) >= 1e-6,
        "one multiple fewer already meets it: {}",
        false_failure(EXPECTED_MULTIPLE - 1)
    );
    assert_eq!(SEARCH_HASHES, 120);
}
