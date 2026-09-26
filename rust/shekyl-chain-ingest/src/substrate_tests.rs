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
    let via = substrate.longhash(blob, &seed).expect("infallible");
    assert_eq!(via, direct);
    // A second call under the same seed hits the cache store, not a second
    // derivation; the answer is the same by construction.
    assert_eq!(substrate.longhash(blob, &seed).expect("infallible"), via);
    // A different seed is a different hash — the seed is load-bearing
    // (CEN-D3), which is why Stale::Seed exists.
    let other = substrate
        .longhash(blob, &BlockHash::from_bytes([0x5f; 32]))
        .expect("infallible");
    assert_ne!(other, via);
    // The sink the substrate was given saw every hash and the one derive
    // per seed — the counters the pipeline's artifact reads.
    let seen = substrate.metrics().snapshot();
    assert_eq!((seen.hashes, seen.cache_derives), (3, 2));
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
