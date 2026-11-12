// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A chain whose archival bytes are real spends, dense enough that a shard
//! closes in a few blocks (Rick's shard-fill ruling, option A, 2026-11-11).
//!
//! A spend's archival length is mostly a hybrid key and signature per
//! input, about 7 KB. A chain that spends only coinbases matures one a
//! block, so a 3 MB shard takes some 430 blocks. This chain fans out
//! instead: each spend takes one output and pays the miner two, which the
//! chain watches ([`Grown::watch`]) and spends once they are old enough
//! ([`Grown::spend_watched`]). The outputs double every spendable age, so
//! after a short ramp every block is as full as [`BLOCK_TARGET`] allows.
//!
//! The builder is deterministic: the coinbases, the headers and the order
//! in which outputs are spent depend on the height alone, so a capture of
//! its bodies replays as the same blocks.

use shekyl_chain_rules::RuleSet;
use shekyl_types::BlockHeight;
use shekyl_wire::Transaction;

use shekyl_harness_spender::captured::{CapturedBlock, CapturedChain};

use super::connect_fixtures::{Grown, FIRST_SPEND_HEIGHT};
use super::store_tests::TestErr;
use super::*;

/// The weight the builder lists in one block, at most. Under the full
/// reward zone (`block_weight_full_reward_zone_bytes`, 300 000), so no
/// block's coinbase is priced with a penalty.
pub(super) const BLOCK_TARGET: usize = 280_000;

/// Coinbases the builder never spends: the ingest's scenarios post their
/// bonds from these (`shekyl-chain-ingest`, `FILL_FROM_COINBASE`), so a
/// chain that loads this one can still spend them.
pub(super) const RESERVED_COINBASES: u64 =
    shekyl_harness_spender::captured::SHARD_FILL_RESERVED_COINBASES;

/// The fee each spend pays. Not a consensus figure: the chain only needs
/// one every spent output can pay.
const FEE: u64 = 1_000;

/// One block's bodies as the builder listed them.
pub(super) type Listing = Vec<Transaction>;

/// Build the dense chain on `store` under `rules` through the first block
/// at which `until(cumulative archival length)` holds, and return the
/// chain and each block's listing.
pub(super) fn build(
    store: &ChainStore,
    rules: &RuleSet,
    until: impl Fn(u64) -> bool,
) -> (Grown, Vec<Listing>) {
    // An output drains into the tree `tx_spendable_age` blocks after the
    // block that listed it, and a spend's reference is at least
    // `REFERENCE_BLOCK_MIN_AGE` below the block it connects in: the
    // coinbase maturity's sum (`coinbase_maturity`) with the spendable age
    // in place of the unlock window.
    let ready_after = rules.tx_spendable_age().to_raw()
        + 1
        + shekyl_chain_rules::REFERENCE_BLOCK_MIN_AGE.to_raw();
    let mut grown = Grown::new();
    let mut listings: Vec<Listing> = Vec::new();
    // Watched outputs, oldest first: the key and the height that listed it.
    let mut waiting: std::collections::VecDeque<([u8; 32], u64)> =
        std::collections::VecDeque::new();
    let mut next_coinbase = RESERVED_COINBASES;
    let mut total = 0u64;
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        loop {
            let h = grown.height().to_raw();
            let mut listed: Listing = Vec::new();
            let mut weight = 0usize;
            if h >= FIRST_SPEND_HEIGHT {
                loop {
                    // Every spend here is one input, so the last one's
                    // weight is the next one's: stop before proving it.
                    if listed
                        .last()
                        .is_some_and(|last| weight + last.weight() > BLOCK_TARGET)
                    {
                        break;
                    }
                    let ready = waiting
                        .front()
                        .is_some_and(|(_, listed_at)| h >= listed_at + ready_after);
                    // A spend that would pass the target is not listed, and
                    // what it spent goes back for the next block.
                    let (tx, undo) = if ready {
                        let (key, at) = waiting.pop_front().expect("front");
                        (grown.spend_watched(&[key], FEE), Some((key, at)))
                    } else if next_coinbase + FIRST_SPEND_HEIGHT <= h {
                        next_coinbase += 1;
                        (grown.spend_of(next_coinbase - 1, FEE), None)
                    } else {
                        break;
                    };
                    if weight + tx.weight() > BLOCK_TARGET {
                        match undo {
                            Some(watched) => waiting.push_front(watched),
                            None => next_coinbase -= 1,
                        }
                        break;
                    }
                    weight += tx.weight();
                    listed.push(tx);
                }
            }
            for tx in &listed {
                for output in &tx.prefix.outputs {
                    grown.watch(output.key);
                    waiting.push_back((output.key, h));
                }
            }
            total += listed
                .iter()
                .map(|tx| tx.archival_len().to_raw())
                .sum::<u64>();
            let judged = grown.judge_listing(&view, rules, &listed)?;
            batch.connect(judged, *rules)?;
            listings.push(listed);
            if until(total) {
                break;
            }
        }
        Ok(())
    });
    out.expect("the dense chain connects");
    (grown, listings)
}

/// Shards the captured chain closes: the deepest consumer's need (the
/// store's three-shard boundary tests).
pub(super) const SHARDS: u64 = 3;

/// The rule set the chain is built under: genesis rules under a 100-block
/// epoch with a 50-block retention. The blocks it builds connect the same
/// under every schedule the store and ingest tests run, which the replays
/// in those tests hold.
pub(super) const CAPTURE_RULES: RuleSet = RuleSet::GENESIS.with_levers(None, capture_pair());

const fn capture_pair() -> shekyl_chain_rules::CappedEpoch {
    let Some(epoch) = shekyl_types::archival::SettlementEpochBlocks::new(100) else {
        panic!("a zero epoch");
    };
    match shekyl_chain_rules::CappedEpoch::new(epoch, shekyl_types::BlockCount::from_raw(50)) {
        Ok(pair) => pair,
        Err(_) => panic!("the cap is not inside the epoch"),
    }
}

/// A store under [`CAPTURE_RULES`]'s horizons.
pub(super) fn capture_store(path: impl AsRef<std::path::Path>) -> ChainStore {
    let path: &std::path::Path = path.as_ref();
    ChainStore::with_horizons(
        path,
        crate::apply_policy::ApplyPolicy::default(),
        Horizons::new(
            CAPTURE_RULES.settlement_schedule().blocks(),
            shekyl_types::BlockCount::from_raw(50),
            CAPTURE_RULES.reorg_cap(),
        )
        .expect("cap ≤ retention < epoch"),
    )
    .expect("create")
}

/// Build the chain the vector holds: through the block that closes shard
/// `SHARDS − 1`.
pub(super) fn build_capture(store: &ChainStore) -> (Grown, Vec<Listing>) {
    let w = shekyl_types::SHARD_LENGTH.to_raw();
    build(store, &CAPTURE_RULES, |total| total >= SHARDS * w)
}

/// `grown`'s blocks with their listings, as the vector records them.
pub(super) fn captured(grown: &Grown, listings: &[Listing], capture_rev: String) -> CapturedChain {
    CapturedChain {
        capture_rev,
        blocks: listings
            .iter()
            .enumerate()
            .map(|(h, listed)| CapturedBlock {
                block: grown
                    .block(BlockHeight::from_raw(u64::try_from(h).expect("small")))
                    .clone(),
                listed: listed.clone(),
            })
            .collect(),
    }
}

/// The checked-in chain, decoded once per process.
pub(super) fn shard_fill() -> &'static CapturedChain {
    static CHAIN: std::sync::OnceLock<CapturedChain> = std::sync::OnceLock::new();
    CHAIN.get_or_init(CapturedChain::shard_fill)
}

/// How many of the chain's blocks, from genesis, close shard `k`: the
/// prefix through the first block whose cumulative listed archival length
/// reaches `(k + 1)·W`.
pub(super) fn blocks_closing(chain: &CapturedChain, k: u64) -> usize {
    chain.blocks_closing(k).unwrap_or_else(|| {
        panic!("the captured chain closes {SHARDS} shards; shard {k} is not among them")
    })
}

/// Write `chain` as the checked-in vector, once the invocation cites the
/// decision that moves it and the checkout is clean but for the vector.
/// The revision recorded is the checkout's.
pub(super) fn write_capture(grown: &Grown, listings: &[Listing]) {
    let decision = shekyl_crypto_pq::test_support::regen_decision_or_refuse("the shard-fill chain");
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("git runs");
        assert!(out.status.success(), "git {args:?}");
        String::from_utf8(out.stdout).expect("utf-8")
    };
    let path = shekyl_harness_spender::captured::shard_fill_path();
    let dirty: Vec<String> = git(&["status", "--porcelain"])
        .lines()
        .filter(|line| !line.ends_with("vectors/shard-fill.bin"))
        .map(str::to_owned)
        .collect();
    assert!(
        dirty.is_empty(),
        "the capture records the revision it was built from; this checkout has changes: {dirty:?}"
    );
    let rev = git(&["rev-parse", "HEAD"]).trim().to_owned();
    let chain = captured(grown, listings, rev);
    std::fs::write(&path, chain.encode()).expect("write the shard-fill chain");
    eprintln!(
        "wrote {} ({} blocks, revision {}) under decision: {decision}",
        path.display(),
        chain.blocks.len(),
        chain.capture_rev
    );
}

/// The armed regenerator: build the chain and write it as the checked-in
/// vector ([`write_capture`]). Refuses unless the invocation cites the
/// decision that moves the vector, and unless the checkout is clean.
/// Release: about ten minutes of proving.
///
/// ```text
/// SHEKYL_PINNED_REGEN_DECISION="YYYY-MM-DD <rationale>" \
///   cargo test --release -p shekyl-chain-store --lib \
///   capture_the_shard_fill_chain -- --ignored --nocapture
/// ```
#[test]
#[ignore = "armed regeneration helper; writes the checked-in shard-fill chain; requires SHEKYL_PINNED_REGEN_DECISION"]
fn capture_the_shard_fill_chain() {
    // Refuse before proving anything: a refused regeneration costs nothing.
    shekyl_crypto_pq::test_support::regen_decision_or_refuse("the shard-fill chain");
    let path = super::store_tests::tmp("shard-fill-capture");
    let store = capture_store(&path);
    let (grown, listings) = build_capture(&store);
    write_capture(&grown, &listings);
}

/// The stores the tests start from, connected once per process: for each
/// schedule, the store file after each prefix of the captured chain a test
/// asked for. Verifying the capture is the cost of these tests (about 65 s
/// in the debug test profile for the whole chain), so a schedule pays it
/// once and every test copies the file it needs. A prefix with no file yet
/// is built from the longest shorter one, so the chain is verified once per
/// schedule whatever order the tests ask in.
struct Snapshots {
    /// The directory the files live in, for the life of the process.
    dir: crate::test_paths::TestPath,
    /// Each prefix's store file, by its block count.
    files: std::collections::BTreeMap<usize, std::path::PathBuf>,
}

/// One schedule's snapshots, keyed by the caller's name for the schedule.
fn snapshots() -> &'static std::sync::Mutex<std::collections::BTreeMap<&'static str, Snapshots>> {
    static ALL: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<&'static str, Snapshots>>,
    > = std::sync::OnceLock::new();
    ALL.get_or_init(Default::default)
}

/// A store at `path` holding the captured chain's first `blocks` blocks
/// under `rules` and `horizons`, and the chain over it. `schedule` names
/// the pair for the process-wide snapshots: one name, one pair.
pub(super) fn store_with_prefix(
    path: impl AsRef<std::path::Path>,
    schedule: &'static str,
    rules: RuleSet,
    horizons: Horizons,
    blocks: usize,
) -> (ChainStore, Grown) {
    let chain = shard_fill();
    let file = {
        let mut all = snapshots()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let snaps = all.entry(schedule).or_insert_with(|| Snapshots {
            dir: crate::test_paths::tmp(&format!("shard-fill-{schedule}")),
            files: std::collections::BTreeMap::new(),
        });
        if let Some(file) = snaps.files.get(&blocks) {
            file.clone()
        } else {
            let from = snaps
                .files
                .range(..blocks)
                .next_back()
                .map(|(&n, file)| (n, file.clone()));
            let file = snaps
                .dir
                .path()
                .with_file_name(format!("prefix-{blocks}.redb"));
            let have = match from {
                Some((n, earlier)) => {
                    std::fs::copy(earlier, &file).expect("copy the shorter prefix");
                    n
                }
                None => 0,
            };
            let store = ChainStore::with_horizons(
                &file,
                crate::apply_policy::ApplyPolicy::default(),
                horizons,
            )
            .expect("open the prefix store");
            let mut grown = regrown(chain, have);
            let out: Result<(), TestErr> = store.write(|batch| {
                let view = batch.chain_view();
                for captured in &chain.blocks[have..blocks] {
                    let judged = grown.judge_listing(&view, &rules, &captured.listed)?;
                    batch.connect(judged, rules)?;
                    assert_eq!(
                        grown.hashes.last(),
                        Some(&captured.block.hash()),
                        "the captured block (capture {})",
                        chain.capture_rev
                    );
                }
                Ok(())
            });
            out.expect("the captured prefix connects");
            drop(store);
            snaps.files.insert(blocks, file.clone());
            file
        }
    };
    let path: &std::path::Path = path.as_ref();
    std::fs::copy(&file, path).expect("copy the prefix store");
    let store =
        ChainStore::with_horizons(path, crate::apply_policy::ApplyPolicy::default(), horizons)
            .expect("open the copied store");
    (store, regrown(chain, blocks))
}

/// The chain record over the captured chain's first `blocks` blocks, as
/// connected: each block recorded on the wallet-side tree, nothing judged.
pub(super) fn regrown(chain: &CapturedChain, blocks: usize) -> Grown {
    let mut grown = Grown::new();
    for captured in &chain.blocks[..blocks] {
        grown.record(&captured.block, &captured.listed);
    }
    grown
}
