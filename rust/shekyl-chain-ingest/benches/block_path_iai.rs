// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block path's instruction counts (`BENCHMARK_ALIGNMENT.md` BA-T2 and
//! BA-T41; the `PB-D1` and `PB-D1s` terms of `DAEMON_REDB_STORE.md` §1.3a).
//!
//! Three calls, each its own row, on one committed block per shape:
//!
//! - **`crypto_bench_block_form_*`**: `shekyl_chain_rules::form`. The
//!   stateless stage every connected block pays: each listed transaction's
//!   form, its signatures and its membership proof, then the block's range
//!   proofs as one batch. This is the verifier's share of `PB-D1`.
//! - **`crypto_bench_block_connect_*`**: `validate_with_memo` over the
//!   batch's view, `WriteBatch::connect` and the commit, at production
//!   durability. The store's share, `PB-D1s`.
//! - **`crypto_bench_block_pop_*`**: one pop and its commit.
//!
//! The block's proof-of-work is not in any of them (the fixture chain runs
//! under the harness longhash); one header's RandomX verification is
//! `shekyl-pow-randomx`'s `verify_header_iai`.
//!
//! # What a count here is
//!
//! An instruction count on the CI runner's x86. It says whether a pull
//! request changed the work, and by how much. It is not a time and never a
//! floor figure (rule 76): `PB-D1`'s seconds are read at a release cut on
//! the two devices, and `block_connect_verify` in `shekyl-verify-cost`
//! stays the wall-clock instrument a device runs.
//!
//! # Fixtures
//!
//! `benches/fixtures/block_path_<shape>.corpus`, written by
//! `regenerate_block_path_fixtures` and held to the tree by
//! `every_block_path_fixture_replays` (`src/bench_fixture_tests.rs`). The
//! history is replayed into a fresh store in `setup`, outside the measured
//! region. The driver refuses a block the validator refuses, so a stale
//! fixture fails the bench by panicking in setup; it cannot count a refusal
//! path and present it as a faster connect.

use std::hint::black_box;

use gungraun::{library_benchmark, library_benchmark_group, main};
use shekyl_chain_ingest::bench_support::{BlockPath, Claimed};
use shekyl_chain_rules::{Candidate, StructurallyValid};

const SPEND_1IN_2OUT: &[u8] = include_bytes!("fixtures/block_path_spend_1in_2out.corpus");

/// A chain replayed to the block below the subject, and the subject with
/// its claims read.
fn before_form(corpus: &[u8]) -> (BlockPath, Candidate, Claimed) {
    let (mut chain, subject) = BlockPath::replayed(corpus);
    let claimed = chain.claims(&subject);
    (chain, subject, claimed)
}

/// The same chain with the subject formed: what `connect` is handed.
fn before_connect(corpus: &[u8]) -> (BlockPath, StructurallyValid, Claimed) {
    let (chain, subject, claimed) = before_form(corpus);
    let formed = chain.form(subject, &claimed);
    (chain, formed, claimed)
}

/// The same chain with the subject connected: what `pop` removes.
fn before_pop(corpus: &[u8]) -> BlockPath {
    let (mut chain, formed, claimed) = before_connect(corpus);
    chain.connect(formed, &claimed);
    chain
}

// Each function returns what it was handed. A store, a candidate or a
// verdict dropped inside the body would charge its teardown to the measured
// region (`relay_admission_verify_iai.rs` records the same artifact).

#[library_benchmark]
#[bench::spend_1in_2out(args = (SPEND_1IN_2OUT), setup = before_form)]
fn crypto_bench_block_form(
    (chain, subject, claimed): (BlockPath, Candidate, Claimed),
) -> (BlockPath, StructurallyValid, Claimed) {
    let formed = black_box(chain.form(black_box(subject), &claimed));
    (chain, formed, claimed)
}

#[library_benchmark]
#[bench::spend_1in_2out(args = (SPEND_1IN_2OUT), setup = before_connect)]
fn crypto_bench_block_connect(
    (mut chain, formed, claimed): (BlockPath, StructurallyValid, Claimed),
) -> (BlockPath, Claimed) {
    chain.connect(black_box(formed), &claimed);
    (chain, claimed)
}

#[library_benchmark]
#[bench::spend_1in_2out(args = (SPEND_1IN_2OUT), setup = before_pop)]
fn crypto_bench_block_pop(mut chain: BlockPath) -> BlockPath {
    chain.pop();
    chain
}

library_benchmark_group!(
    name = block_path_group;
    benchmarks = crypto_bench_block_form, crypto_bench_block_connect, crypto_bench_block_pop
);

main!(library_benchmark_groups = block_path_group);
