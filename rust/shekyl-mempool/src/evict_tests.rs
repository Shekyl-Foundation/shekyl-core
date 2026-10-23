// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-M10 over planted entries (the admission of real ones is
//! `shekyl-chain-ingest`'s): the limit derived from the chain, the rising
//! minimum at admission, the cheapest leaving first under weight pressure,
//! and the template's refusals.

use shekyl_chain_rules::harness::fixture::{listed, paying_fee, spendable_chain};
use shekyl_chain_rules::{AdmissionPolicy, RuleSet};
use shekyl_chain_store::pool::{PoolRecord, ReceivedHour};
use shekyl_types::UnixSeconds;

use super::{Evicted, Limits};
use crate::door::Judged;
use crate::pool::{Admission, Pool};

/// A generous limit; each test narrows it.
const ROOMY: Limits = Limits {
    max_weight: u64::MAX,
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

const RECORD: PoolRecord = PoolRecord {
    received: ReceivedHour::from_raw(1),
    public: true,
};

/// A distinct transaction per `n`, paying `n`: every one the same shape,
/// so the same weight.
fn tx(n: u8) -> shekyl_wire::Transaction {
    paying_fee(listed([n; 32]), u64::from(n))
}

/// The weight every [`tx`] has.
fn weight() -> u64 {
    u64::try_from(tx(1).weight()).expect("fits")
}

/// The limit at genesis, from the chain: `REFERENCE_BLOCK_MAX_AGE` (100)
/// blocks at the genesis block weight limit — the hard limit, twice the
/// 300 000-byte penalty-free zone — 60 MB.
#[test]
fn the_limit_at_genesis_derives_from_the_chain() {
    let chain = spendable_chain();
    let limits = chain.with_view(|view| Limits::at(&view).expect("limits"));
    assert_eq!(limits.max_weight, 100 * 600_000);
}

/// The rising minimum: a full pool refuses, before the door, a candidate
/// paying no more per weight than its cheapest entry — equal is refused,
/// less is refused — and lets one paying more through to the door (which
/// refuses this fixture body on its bytes: the bound decided nothing about
/// it).
#[test]
fn a_full_pool_refuses_at_or_below_its_cheapest_before_the_door() {
    let limits = Limits {
        max_weight: weight(),
    };
    let (mut pool, path) = pool("full", limits);
    let held = pool.plant(tx(5), RECORD);
    let chain = spendable_chain();
    let offer = |pool: &mut Pool, fee: u64| {
        let body = paying_fee(listed([0x77; 32]), fee);
        chain.with_view(|view| {
            pool.admit(
                body,
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

/// Under weight pressure the entries paying least per weight leave first.
#[test]
fn the_cheapest_leave_first_under_weight_pressure() {
    let (mut pool, path) = pool("cheapest", ROOMY);
    let dear = pool.plant(tx(9), RECORD);
    let cheap = pool.plant(tx(3), RECORD);
    let middle = pool.plant(tx(7), RECORD);
    pool.set_limits(Limits {
        max_weight: 2 * weight(),
    });
    assert_eq!(
        pool.evict(&[], &[]).unwrap(),
        vec![(cheap, Evicted::OverWeight)]
    );
    pool.set_limits(Limits {
        max_weight: weight(),
    });
    assert_eq!(
        pool.evict(&[], &[]).unwrap(),
        vec![(middle, Evicted::OverWeight)]
    );
    assert!(pool.record(&dear).is_some());
    drop(std::fs::remove_file(&path));
}

/// A body the template lists is never chosen by the over-weight pass: a
/// posted job must not name a body the pool no longer holds. The next
/// cheapest leaves in its place (the review of #1165, M4). Red edit: the
/// pass ignores `listed`.
#[test]
fn a_listed_body_survives_the_over_weight_pass() {
    let (mut pool, path) = pool("listed-kept", ROOMY);
    let dear = pool.plant(tx(9), RECORD);
    let cheap = pool.plant(tx(3), RECORD);
    let middle = pool.plant(tx(7), RECORD);
    pool.set_limits(Limits {
        max_weight: 2 * weight(),
    });
    assert_eq!(
        pool.evict(&[], &[cheap]).unwrap(),
        vec![(middle, Evicted::OverWeight)]
    );
    assert!(pool.record(&cheap).is_some(), "the listed body stays");
    assert!(pool.record(&dear).is_some());
    drop(std::fs::remove_file(&path));
}

/// The template's refusals evict the entries they name, and free their key
/// images; a refusal naming nothing the pool holds evicts nothing.
#[test]
fn the_templates_refusals_evict_their_entries_and_images() {
    let (mut pool, path) = pool("refused", ROOMY);
    let refused_tx = tx(1);
    let image = crate::pool::key_images_of(&refused_tx)[0];
    let refused = pool.plant(refused_tx, RECORD);
    let other = pool.plant(tx(2), RECORD);
    let stranger = tx(3).txid_parts().hash;
    assert!(pool.key_images().contains(&image));
    assert_eq!(
        pool.evict(&[refused, stranger], &[]).unwrap(),
        vec![(refused, Evicted::Refused)]
    );
    assert!(
        !pool.key_images().contains(&image),
        "the image is free again"
    );
    assert!(pool.record(&other).is_some());
    drop(std::fs::remove_file(&path));
}

/// `flush_txpool`'s verb: the named entries leave, tagged `Flushed` (not
/// a CEN-M10 refusal), their key images free again and their rows gone
/// from the file; an id the pool does not hold, or one named twice, is
/// flushed once or not at all; the rest stay.
#[test]
fn a_flush_removes_the_named_entries_tagged_flushed() {
    let (mut pool, path) = pool("flush", ROOMY);
    let flushed_tx = tx(1);
    let image = crate::pool::key_images_of(&flushed_tx)[0];
    let flushed = pool.plant(flushed_tx, RECORD);
    let kept = pool.plant(tx(2), RECORD);
    let stranger = tx(3).txid_parts().hash;
    assert_eq!(
        pool.flush(&[flushed, stranger, flushed]).unwrap(),
        vec![(flushed, Evicted::Flushed)]
    );
    assert!(pool.record(&flushed).is_none());
    assert!(
        !pool.key_images().contains(&image),
        "the image is free again"
    );
    assert!(pool.record(&kept).is_some());
    let file = pool.store().begin_read().expect("the file");
    assert!(
        file.record(&flushed).expect("read").is_none(),
        "the file dropped it"
    );
    assert!(file.record(&kept).expect("read").is_some());
    drop(file);
    drop(pool);
    drop(std::fs::remove_file(&path));
}

/// Who is shown a stem entry: the host's listing (`RelayView::entries`)
/// lists it, marked not shown; any caller's (`Pool::shown_entries`) does
/// not list it at all (RT-O9.3).
#[test]
fn a_stem_entry_is_listed_to_the_host_only() {
    let (mut pool, path) = pool("listing", ROOMY);
    let public = pool.plant(tx(1), RECORD);
    let stem = pool.plant(
        tx(2),
        PoolRecord {
            received: ReceivedHour::from_raw(1),
            public: false,
        },
    );
    let anyone: Vec<_> = pool.shown_entries().map(|entry| entry.id).collect();
    assert_eq!(anyone, vec![public], "a stem entry is no caller's to see");
    let mut host: Vec<_> = pool
        .relay_view()
        .entries()
        .map(|entry| (entry.id, entry.shown))
        .collect();
    host.sort_by_key(|(id, _)| id.to_bytes());
    let mut expected = vec![(public, true), (stem, false)];
    expected.sort_by_key(|(id, _)| id.to_bytes());
    assert_eq!(host, expected);
    let entry = pool
        .relay_view()
        .entries()
        .find(|entry| entry.id == stem)
        .expect("held");
    assert_eq!(entry.key_images, crate::pool::key_images_of(&tx(2)));
    drop(std::fs::remove_file(&path));
}
