// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-M10's arithmetic over planted entries (the admission of real ones is
//! `shekyl-chain-ingest`'s): the lifetimes by standing, the weight cap
//! cheapest-per-weight first, the template's refusals, and the limits held
//! to the C++ pool's while both exist.

use shekyl_chain_rules::harness::fixture::{listed, paying_fee};
use shekyl_chain_store::pool::{PoolRecord, PoolStore, Standing};
use shekyl_types::UnixSeconds;
use shekyl_units::AtomicUnits;

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

fn record(weight: u64, fee: u64, at: u64, standing: Standing) -> PoolRecord {
    PoolRecord {
        weight,
        fee: AtomicUnits::from_raw(fee),
        receive_time: UnixSeconds::from_raw(at),
        public: true,
        standing,
    }
}

const ADMITTED: Standing = Standing::Admitted { proven: None };

/// A distinct transaction per `n` (its key image and fee differ).
fn tx(n: u8) -> shekyl_wire::Transaction {
    paying_fee(listed([n; 32]), u64::from(n))
}

#[test]
fn each_standing_ages_on_its_own_lifetime() {
    let (mut pool, path) = pool("aged");
    let limits = Limits::GENESIS;
    let admitted = pool.plant(tx(1), record(10, 10, 0, ADMITTED));
    let kept = pool.plant(tx(2), record(10, 10, 0, Standing::Kept));
    // One second past three days: the admitted entry goes, the kept stays.
    let now = UnixSeconds::from_raw(limits.admitted_lifetime + 1);
    assert_eq!(
        pool.evict(now, &limits, &[]).unwrap(),
        vec![(admitted, Evicted::Aged)]
    );
    assert!(pool.record(&kept).is_some());
    // Past the week, the kept one goes too.
    let now = UnixSeconds::from_raw(limits.kept_lifetime + 1);
    assert_eq!(
        pool.evict(now, &limits, &[]).unwrap(),
        vec![(kept, Evicted::KeptAged)]
    );
    assert!(pool.is_empty());
    // The file agrees.
    drop(pool);
    let (store, _) = PoolStore::create(&path).unwrap();
    assert!(store.begin_read().unwrap().is_empty().unwrap());
    drop(store);
    drop(std::fs::remove_file(&path));
}

/// Over the cap, the least per unit of weight leaves first, and only until
/// the pool fits: 3/10 < 5/10 < 9/10, cap 20 of 30 — one leaves.
#[test]
fn over_the_cap_the_cheapest_per_weight_leaves_first() {
    let (mut pool, path) = pool("weight");
    let limits = Limits {
        max_weight: 20,
        ..Limits::GENESIS
    };
    let dear = pool.plant(tx(1), record(10, 9, 5, ADMITTED));
    let cheap = pool.plant(tx(2), record(10, 3, 5, ADMITTED));
    let middle = pool.plant(tx(3), record(10, 5, 5, ADMITTED));
    assert_eq!(
        pool.evict(UnixSeconds::from_raw(5), &limits, &[]).unwrap(),
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
    let admitted = pool.plant(admitted_tx, record(10, 10, 5, ADMITTED));
    let kept = pool.plant(tx(2), record(10, 10, 5, Standing::Kept));
    assert!(pool.key_images().contains(&image));
    assert_eq!(
        pool.evict(
            UnixSeconds::from_raw(5),
            &Limits::GENESIS,
            &[admitted, kept]
        )
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

/// The limits are the C++ pool's (`cryptonote_config.h`) while both pools
/// exist; the pin goes with the C++ at `DEL-010`.
#[test]
fn the_limits_are_the_cxx_pools() {
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
    assert_eq!(value("CRYPTONOTE_MEMPOOL_TX_LIVETIME"), "(86400*3)");
    assert_eq!(Limits::GENESIS.admitted_lifetime, 86_400 * 3);
    assert_eq!(
        value("CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME"),
        "604800"
    );
    assert_eq!(Limits::GENESIS.kept_lifetime, 604_800);
    assert_eq!(value("DEFAULT_TXPOOL_MAX_WEIGHT"), "648000000ull");
    assert_eq!(Limits::GENESIS.max_weight, 648_000_000);
}
