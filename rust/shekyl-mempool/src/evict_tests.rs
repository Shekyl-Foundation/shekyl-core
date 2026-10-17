// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-M10 over planted entries (the admission of real ones is
//! `shekyl-chain-ingest`'s): the limits derived from the chain, a kept
//! entry's age in blocks, the rising minimum at admission, kept entries
//! before admitted ones under weight pressure, and the template's refusals.

use shekyl_chain_rules::harness::fixture::{listed, paying_fee, spendable_chain};
use shekyl_chain_rules::{AdmissionPolicy, RuleSet};
use shekyl_chain_store::pool::{PoolRecord, PoolStore, ReceivedHour, Standing};
use shekyl_types::{BlockCount, BlockHeight, UnixSeconds};

use super::{Evicted, Limits};
use crate::door::Judged;
use crate::pool::{Admission, Arrival, Pool};

/// Generous limits; each test narrows the one it is about.
const ROOMY: Limits = Limits {
    kept_for: BlockCount::from_raw(10),
    max_weight: u64::MAX,
    kept_max_weight: u64::MAX,
};

fn pool(name: &str, limits: Limits) -> (Pool, std::path::PathBuf) {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "shekyl-mempool-evict-{name}-{}-{:?}.redb",
        std::process::id(),
        std::thread::current().id()
    ));
    drop(std::fs::remove_file(&p));
    let (pool, _) = Pool::create(&p, limits).expect("create");
    (pool, p)
}

fn record(standing: Standing) -> PoolRecord {
    PoolRecord {
        received: ReceivedHour::from_raw(1),
        public: true,
        standing,
    }
}

fn kept(at: u64) -> PoolRecord {
    record(Standing::Kept {
        returned_at: BlockHeight::from_raw(at),
    })
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

/// The limits at genesis, from the chain: `REFERENCE_BLOCK_MAX_AGE` (100)
/// blocks at the genesis block weight limit (twice the 300 000-byte full
/// reward zone) for the pool, the reorg cap for a kept entry's blocks, and
/// that many blocks' weight for the kept entries.
#[test]
fn the_limits_at_genesis_derive_from_the_chain() {
    let chain = spendable_chain();
    let limits = chain.with_view(|view| Limits::at(&view, &RuleSet::GENESIS).expect("limits"));
    let cap = RuleSet::GENESIS.reorg_cap();
    assert_eq!(limits.kept_for, cap);
    assert_eq!(limits.max_weight, 100 * 600_000);
    assert_eq!(limits.kept_max_weight, cap.to_raw() * 600_000);
}

/// A kept entry leaves once the tip is `kept_for` blocks past its return,
/// and not a block before.
#[test]
fn a_kept_entry_ages_in_blocks_from_its_return() {
    let (mut pool, path) = pool("aged", ROOMY);
    let kept = pool.plant(tx(2), kept(100));
    let admitted = pool.plant(tx(1), record(Standing::Admitted));
    assert!(pool.evict(h(109), &[]).unwrap().is_empty());
    assert_eq!(
        pool.evict(h(110), &[]).unwrap(),
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

/// The rising minimum: a full pool refuses, before the door, a candidate
/// paying no more per weight than its cheapest admitted entry — equal is
/// refused, less is refused — and lets one paying more through to the door
/// (which refuses this fixture body on its bytes: the bound decided
/// nothing about it).
#[test]
fn a_full_pool_refuses_at_or_below_its_cheapest_before_the_door() {
    let limits = Limits {
        max_weight: weight(),
        ..ROOMY
    };
    let (mut pool, path) = pool("full", limits);
    let held = pool.plant(tx(5), record(Standing::Admitted));
    let chain = spendable_chain();
    let offer = |pool: &mut Pool, fee: u64| {
        let body = paying_fee(listed([0x77; 32]), fee);
        chain.with_view(|view| {
            pool.admit(
                body,
                Arrival::Relayed,
                UnixSeconds::from_raw(1),
                &view,
                &RuleSet::GENESIS,
                &AdmissionPolicy::GENESIS,
            )
            .expect("no fault")
        })
    };
    assert_eq!(offer(&mut pool, 5), Admission::PoolFull, "equal is refused");
    assert_eq!(offer(&mut pool, 4), Admission::PoolFull, "less is refused");
    assert!(
        matches!(
            offer(&mut pool, 6),
            Admission::Refused(Judged::Stateless(_))
        ),
        "more reaches the door"
    );
    assert!(
        pool.record(&held).is_some(),
        "nothing was evicted for a refusal"
    );
    drop(std::fs::remove_file(&path));
}

/// Under weight pressure kept entries leave before any admitted one, the
/// oldest return first; then the cheapest admitted.
#[test]
fn kept_entries_leave_before_admitted_ones() {
    let (mut pool, path) = pool("kept-first", ROOMY);
    let dear = pool.plant(tx(9), record(Standing::Admitted));
    let cheap = pool.plant(tx(3), record(Standing::Admitted));
    let old = pool.plant(tx(7), kept(10));
    let young = pool.plant(tx(8), kept(20));
    // Room for two of the four: both kept entries go, oldest first.
    pool.set_limits(Limits {
        max_weight: 2 * weight(),
        ..ROOMY
    });
    assert_eq!(
        pool.evict(h(11), &[]).unwrap(),
        vec![(old, Evicted::OverWeight), (young, Evicted::OverWeight)]
    );
    // Room for one: the cheaper admitted entry goes.
    pool.set_limits(Limits {
        max_weight: weight(),
        ..ROOMY
    });
    assert_eq!(
        pool.evict(h(11), &[]).unwrap(),
        vec![(cheap, Evicted::OverWeight)]
    );
    assert!(pool.record(&dear).is_some());
    drop(std::fs::remove_file(&path));
}

/// The kept entries have a cap of their own, which binds them even when
/// the pool as a whole has room.
#[test]
fn the_kept_cap_binds_the_kept_entries_alone() {
    let (mut pool, path) = pool("kept-cap", ROOMY);
    let old = pool.plant(tx(7), kept(10));
    let young = pool.plant(tx(8), kept(20));
    let admitted = pool.plant(tx(1), record(Standing::Admitted));
    pool.set_limits(Limits {
        kept_max_weight: weight(),
        ..ROOMY
    });
    assert_eq!(
        pool.evict(h(11), &[]).unwrap(),
        vec![(old, Evicted::OverWeight)]
    );
    assert!(pool.record(&young).is_some() && pool.record(&admitted).is_some());
    drop(std::fs::remove_file(&path));
}

/// The template's refusals evict admitted entries only: a kept entry is
/// never selected, so a refusal naming it is not the template's.
#[test]
fn the_templates_refusals_evict_admitted_entries_and_their_images() {
    let (mut pool, path) = pool("refused", ROOMY);
    let admitted_tx = tx(1);
    let image = crate::pool::key_images_of(&admitted_tx)[0];
    let admitted = pool.plant(admitted_tx, record(Standing::Admitted));
    let kept = pool.plant(tx(2), kept(5));
    assert!(pool.key_images().contains(&image));
    assert_eq!(
        pool.evict(h(5), &[admitted, kept]).unwrap(),
        vec![(admitted, Evicted::Refused)]
    );
    assert!(
        !pool.key_images().contains(&image),
        "the image is free again"
    );
    assert!(pool.record(&kept).is_some());
    drop(std::fs::remove_file(&path));
}
