// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use shekyl_chain_rules::Substrate;
use shekyl_pow_randomx::{compute_hash, PreparedCache, Seedhash};
use shekyl_types::{BlockHash, PowHash};

use super::*;

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
    let substrate = ProductionSubstrate::new();
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
}

#[test]
fn the_clock_is_now_in_unix_seconds() {
    let substrate = ProductionSubstrate::new();
    let now = substrate.local_clock().expect("after the epoch");
    // Not before this test was written, not absurdly far ahead.
    assert!(now.to_raw() > 1_780_000_000, "{now:?}");
    assert!(now.to_raw() < 4_000_000_000, "{now:?}");
}

#[test]
fn clones_share_one_cache_store() {
    let a = ProductionSubstrate::new();
    let b = a.clone();
    assert!(Arc::ptr_eq(&a.caches, &b.caches));
}
