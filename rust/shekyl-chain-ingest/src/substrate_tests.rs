// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use shekyl_chain_rules::Substrate;
use shekyl_pow_randomx::{compute_hash, PreparedCache, Seedhash};
use shekyl_types::{BlockHash, PowHash};

use super::*;

fn fresh() -> ProductionSubstrate {
    ProductionSubstrate::new(Arc::new(CacheStore::new()), Arc::new(Metrics::new()))
}

#[test]
fn the_longhash_is_the_verifiers_compute_hash_under_the_same_seed() {
    // The adapter is thin or it is wrong: the same seed and blob through
    // `PreparedCache::derive` + `compute_hash` directly must equal what the
    // substrate returns. One derivation (~256 MiB) is the price of proving
    // the production path is the verifier's path and not a re-implementation.
    let seed = BlockHash::from_bytes([0x5e; 32]);
    let blob = b"shekyl ingest substrate probe";
    let direct = {
        let cache = PreparedCache::derive(Seedhash::from_bytes(*seed.as_bytes()));
        PowHash::from_bytes(compute_hash(&cache, blob))
    };
    let substrate = fresh();
    // The pin is the derive. The longhash looks the cache up.
    substrate.pin_seed(&seed);
    let via = substrate.longhash(blob, &seed).expect("pinned");
    assert_eq!(via, direct);
    // A second call under the same seed hits the cache store, not a second
    // derivation; the answer is the same by construction.
    assert_eq!(substrate.longhash(blob, &seed).expect("pinned"), via);
    // A different seed is a different hash — the seed is load-bearing
    // (CEN-D3), which is why Stale::Seed exists. It is pinned first: a
    // longhash does not derive.
    let other_seed = BlockHash::from_bytes([0x5f; 32]);
    substrate.pin_seed(&other_seed);
    let other = substrate.longhash(blob, &other_seed).expect("pinned");
    assert_ne!(other, via);
    // The sink the substrate was given saw every hash and the one derive
    // per seed — the counters the pipeline's artifact reads. Both derives
    // are the pins.
    let seen = substrate.metrics().snapshot();
    assert_eq!((seen.hashes, seen.cache_derives), (3, 2));
}

#[test]
fn a_longhash_of_an_unpinned_seed_does_not_derive() {
    let substrate = fresh();
    let seed = BlockHash::from_bytes([0x5e; 32]);
    let fault = substrate
        .longhash(b"unpinned", &seed)
        .expect_err("a miss is a fault");
    assert!(matches!(fault, SubstrateFault::CacheAbsent), "{fault:?}");
    assert!(substrate.cache_absent(&fault));
    assert_eq!(
        substrate.metrics().snapshot().cache_derives,
        0,
        "a miss builds nothing"
    );
}

#[test]
fn pinning_a_seed_derives_once_and_counts_it_at_the_source() {
    // RD-F20: the pin is the derive; the hash under that seed is a hit.
    let substrate = fresh();
    let seed = BlockHash::from_bytes([0x5d; 32]);
    substrate.pin_seed(&seed);
    let pinned = substrate.metrics().snapshot();
    assert_eq!((pinned.cache_derives, pinned.hashes), (1, 0));
    substrate
        .longhash(b"after the pin", &seed)
        .expect("infallible");
    let after = substrate.metrics().snapshot();
    assert_eq!(
        (after.cache_derives, after.hashes),
        (1, 1),
        "a hit, not a second fill"
    );
    substrate.pin_seed(&seed);
    assert_eq!(
        substrate.metrics().snapshot().cache_derives,
        1,
        "re-pinning is a no-op"
    );
}

#[test]
fn the_clock_is_now_in_unix_seconds() {
    let substrate = fresh();
    let now = substrate.local_clock().expect("after the epoch");
    // Not before this test was written, not absurdly far ahead.
    assert!(now.to_raw() > 1_780_000_000, "{now:?}");
    assert!(now.to_raw() < 4_000_000_000, "{now:?}");
}

#[test]
fn clones_share_one_cache_store() {
    let a = fresh();
    let b = a.clone();
    assert!(Arc::ptr_eq(&a.caches, &b.caches));
}

/// B2: a branch seed is derived once, into the transient slot, and the
/// chain's seed stays canonical. Pinning a third seed shows which slot
/// each was in: the canonical seed is demoted and kept, the prepared one
/// evicted. A second preparation is a hit.
#[test]
fn preparing_a_branch_seed_derives_once_into_the_transient_slot() {
    let substrate = fresh();
    let chain = BlockHash::from_bytes([0x61; 32]);
    let branch = BlockHash::from_bytes([0x62; 32]);
    let next = BlockHash::from_bytes([0x63; 32]);
    let slot = |seed: &BlockHash| Seedhash::from_bytes(*seed.as_bytes());
    substrate.pin_seed(&chain);
    let held = substrate.prepare_seed(&branch);
    assert!(held.is_some(), "the preparation hands the cache over");
    assert_eq!(
        substrate.metrics().snapshot().cache_derives,
        2,
        "one derive for the branch"
    );
    let _again = substrate.prepare_seed(&branch);
    assert_eq!(
        substrate.metrics().snapshot().cache_derives,
        2,
        "held already: a hit"
    );
    // The chain's seed was canonical: a new pin demotes it to transient and
    // evicts the branch seed, which only ever held the transient slot.
    substrate.pin_seed(&next);
    assert!(
        substrate.caches.lookup(&slot(&chain)).is_some(),
        "the chain's seed stayed canonical"
    );
    assert!(
        substrate.caches.lookup(&slot(&branch)).is_none(),
        "the branch seed was transient"
    );
}

/// B2: the form hashes with the cache the preparation returned. Evicting
/// it from both slots between the preparation and the hash does not fail
/// the hash, while a plain longhash of that seed is a miss.
#[test]
fn an_eviction_between_the_preparation_and_the_form_does_not_fail_it() {
    let substrate = fresh();
    let branch = BlockHash::from_bytes([0x71; 32]);
    let blob = b"a block on the branch";
    let held = substrate.prepare_seed(&branch);
    for evicting in [[0x72; 32], [0x73; 32]] {
        substrate.pin_seed(&BlockHash::from_bytes(evicting));
    }
    assert!(matches!(
        substrate.longhash(blob, &branch),
        Err(SubstrateFault::CacheAbsent)
    ));
    let direct = {
        let cache = PreparedCache::derive(Seedhash::from_bytes(*branch.as_bytes()));
        PowHash::from_bytes(compute_hash(&cache, blob))
    };
    assert_eq!(
        substrate.longhash_held(blob, &branch, &held).expect("held"),
        direct
    );
}
