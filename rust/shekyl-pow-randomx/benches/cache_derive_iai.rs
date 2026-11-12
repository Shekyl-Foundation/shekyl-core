// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One `PreparedCache::derive`, counted in instructions (gungraun).
//!
//! The criterion `cache_derive` beside this file is wall clock, and wall
//! clock is the floor device's question: one forced rebuild there is about
//! 2.1 s (`docs/benchmarks/cache_derive_pi4_20261110.txt`). This row is the
//! drift gate on the same work. The hashing actor's bounds are counted in
//! derives (`docs/design/RANDOMX_CACHE_ACTOR.md` §5.8, §5.9: a forced
//! rebuild, an evidence check's two builds), so a change that makes a
//! derive dearer moves those bounds, and this count says so on the pull
//! request.
//!
//! `hot_path_bench_`: slowdown-only (`scripts/bench/compare.py`). A cheaper
//! derive is not a regression.

use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;

use shekyl_pow_randomx::{PreparedCache, Seedhash};

/// The seed the criterion bench derives under (`cache_derive.rs`), so the
/// two rows measure the same derive.
const SEED: [u8; 32] = *b"shekyl-randomx-v2-bench-Cache-00";

#[library_benchmark]
fn hot_path_bench_cache_derive() -> PreparedCache {
    black_box(PreparedCache::derive(black_box(Seedhash::from_bytes(SEED))))
}

library_benchmark_group!(name = cache_derive_group; benchmarks = hot_path_bench_cache_derive);

main!(library_benchmark_groups = cache_derive_group);
