// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-M10's arithmetic over planted entries (the admission of real ones is
//! `shekyl-chain-ingest`'s): a kept entry's age in blocks, the weight cap
//! cheapest-per-weight first, the template's refusals, and the limits.

use shekyl_chain_rules::harness::fixture::{listed, paying_fee};
use shekyl_chain_rules::RuleSet;
use shekyl_chain_store::pool::{PoolRecord, PoolStore, ReceivedHour, Standing};
use shekyl_types::{BlockCount, BlockHeight};

use super::{Evicted, Limits};
use crate::pool::Pool;

fn pool(name: &str) -> (Pool, std::path::PathBuf) {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "shekyl-mempool-evict-{name}-{}-{:?}.redb",
        std::process::id(),
        std::thread::current().id()
    ));
    drop(std::fs::remove_file(&p));
    let (pool, _) = Pool::create(&p).expect("create");
    (pool, p)
}

fn record(standing: Standing) -> PoolRecord {
    PoolRecord {
        received: ReceivedHour::from_raw(1),
        public: true,
        standing,
    }
}

/// A distinct transaction per `n`, paying `n`: every one the same shape,
/// so the same weight.
fn tx(n: u8) -> shekyl_wire::Transaction {
    paying_fee(listed([n; 32]), u64::from(n))
}

/// The weight every [`tx`] has.
fn weight() -> u64 {
    u64::try_from(tx(1).weight()).expect("fits")
}

fn h(n: u64) -> BlockHeight {
    BlockHeight::from_raw(n)
}

/// A kept entry leaves once the tip is `kept_for` blocks past its return,
/// and not a block before.
#[test]
fn a_kept_entry_ages_in_blocks_from_its_return() {
    let (mut pool, path) = pool("aged");
    let limits = Limits {
        kept_for: BlockCount::from_raw(10),
        ..Limits::GENESIS
    };
    let kept = pool.plant(
        tx(2),
        record(Standing::Kept {
            returned_at: h(100),
        }),
    );
    let admitted = pool.plant(tx(1), record(Standing::Admitted));
    assert!(pool.evict(h(109), &limits, &[]).unwrap().is_empty());
    assert_eq!(
        pool.evict(h(110), &limits, &[]).unwrap(),
        vec![(kept, Evicted::KeptAged)]
    );
    assert!(
        pool.record(&admitted).is_some(),
        "an admitted entry has no age"
    );
    drop(pool);
    let (store, _) = PoolStore::create(&path).unwrap();
    assert_eq!(
        store.begin_read().unwrap().len().unwrap(),
        1,
        "the file agrees"
    );
    drop(store);
    drop(std::fs::remove_file(&path));
}

/// Over the cap, the least per unit of weight leaves first, and only until
/// the pool fits: fees 3 < 5 < 9 over one weight, a cap of two of them —
/// one leaves.
#[test]
fn over_the_cap_the_cheapest_per_weight_leaves_first() {
    let (mut pool, path) = pool("weight");
    let limits = Limits {
        max_weight: 2 * weight(),
        ..Limits::GENESIS
    };
    let dear = pool.plant(tx(9), record(Standing::Admitted));
    let cheap = pool.plant(tx(3), record(Standing::Admitted));
    let middle = pool.plant(tx(5), record(Standing::Admitted));
    assert_eq!(
        pool.evict(h(5), &limits, &[]).unwrap(),
        vec![(cheap, Evicted::OverWeight)]
    );
    assert!(pool.record(&dear).is_some() && pool.record(&middle).is_some());
    drop(std::fs::remove_file(&path));
}

/// The template's refusals evict admitted entries only: a kept entry is
/// never selected, so a refusal naming it is not the template's.
#[test]
fn the_templates_refusals_evict_admitted_entries_and_their_images() {
    let (mut pool, path) = pool("refused");
    let admitted_tx = tx(1);
    let image = crate::pool::key_images_of(&admitted_tx)[0];
    let admitted = pool.plant(admitted_tx, record(Standing::Admitted));
    let kept = pool.plant(tx(2), record(Standing::Kept { returned_at: h(5) }));
    assert!(pool.key_images().contains(&image));
    assert_eq!(
        pool.evict(h(5), &Limits::GENESIS, &[admitted, kept])
            .unwrap(),
        vec![(admitted, Evicted::Refused)]
    );
    assert!(
        !pool.key_images().contains(&image),
        "the image is free again"
    );
    assert!(pool.record(&kept).is_some());
    drop(std::fs::remove_file(&path));
}

/// A kept entry is held for the genesis reorg cap: no switch back reaches
/// further. The weight cap is the C++ pool's (`cryptonote_config.h`).
#[test]
fn the_genesis_limits() {
    assert_eq!(Limits::GENESIS.kept_for, RuleSet::GENESIS.reorg_cap());
    const HEADER: &str = include_str!("../../../src/cryptonote_config.h");
    let value = |name: &str| -> String {
        HEADER
            .lines()
            .find_map(|line| {
                let mut words = line.split_whitespace();
                (words.next() == Some("#define") && words.next() == Some(name))
                    .then(|| words.next().expect("a value").to_owned())
            })
            .unwrap_or_else(|| panic!("cryptonote_config.h defines {name}"))
    };
    assert_eq!(value("DEFAULT_TXPOOL_MAX_WEIGHT"), "648000000ull");
    assert_eq!(Limits::GENESIS.max_weight, 648_000_000);
}
