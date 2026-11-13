// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One block header's proof-of-work verification, as an instruction count
//! (`BENCHMARK_ALIGNMENT.md` BA-T42; the proof-of-work term of
//! `DAEMON_REDB_STORE.md` §1.3a's `PB-D1` and `PB-D2`).
//!
//! The measured call is [`shekyl_pow_randomx::compute_hash`] over a prepared
//! cache: what the production substrate's `longhash` runs for every block a
//! node connects (`shekyl-chain-ingest` `substrate.rs`), in light mode,
//! with a scratchpad allocated per call. The input is a header-sized
//! proof-of-work blob, [`HEADER_POW_BYTES`] long, the length
//! `examples/rt_w10_request_cost.rs` times on the floor device.
//!
//! The cache is derived in `setup`, outside the measured region. A cache
//! lasts an epoch of 2,048 blocks; its Argon2d fill is not a per-block
//! cost, and `benches/cache_derive.rs` is its instrument.
//!
//! # What a count here is
//!
//! An instruction count on the CI runner's x86, where the verifier
//! dispatches to the instruction set it finds. It says whether a pull
//! request changed the work. It is not a time and not a floor figure
//! (rule 76): the floor's figure is BA-T40's, and the Rust-to-C latency
//! ratio is BA-T27's.

use std::hint::black_box;

use gungraun::{library_benchmark, library_benchmark_group, main};
use shekyl_pow_randomx::{compute_hash, PreparedCache, Seedhash};

/// `shekyl_wire::block::MIN_POW_BLOB_SIZE`: the shortest proof-of-work
/// preimage, a header's. The literal is the one
/// `examples/rt_w10_request_cost.rs` carries, which the wire crate's test
/// `the_shortest_pow_blob_is_the_named_minimum` holds to the constant.
const HEADER_POW_BYTES: usize = 136;

const SEEDHASH: [u8; 32] = *b"shekyl-randomx-v2-bench-header00";

/// The cache for [`SEEDHASH`] and a blob whose bytes are fixed, so the
/// program the hash generates is the same on every run.
fn prepared() -> (PreparedCache, [u8; HEADER_POW_BYTES]) {
    let mut blob = [0u8; HEADER_POW_BYTES];
    for (index, byte) in blob.iter_mut().enumerate() {
        *byte = u8::try_from(index % 251).expect("below 251");
    }
    (PreparedCache::derive(Seedhash::from_bytes(SEEDHASH)), blob)
}

// The cache is returned, not dropped in the body: freeing 256 MiB inside
// the measured region would be counted as verification.
#[library_benchmark]
#[bench::header(setup = prepared)]
fn crypto_bench_randomx_verify_header(
    (cache, blob): (PreparedCache, [u8; HEADER_POW_BYTES]),
) -> (PreparedCache, [u8; 32]) {
    let hash = black_box(compute_hash(black_box(&cache), black_box(&blob)));
    (cache, hash)
}

library_benchmark_group!(
    name = verify_header_group;
    benchmarks = crypto_bench_randomx_verify_header
);

main!(library_benchmark_groups = verify_header_group);
