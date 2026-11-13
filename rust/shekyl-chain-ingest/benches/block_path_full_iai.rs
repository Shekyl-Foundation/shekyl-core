// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block path's instruction counts on a block at the weight limit:
//! the shapes of `DAEMON_REDB_STORE.md` §1.3a.7 as that section defines
//! them, one block of each filled to the limit in force
//! (`BENCHMARK_ALIGNMENT.md` BA-T2 and BA-T41).
//!
//! The rows are `block_path_iai.rs`'s three, under a `_full` name, over
//! `benches/fixtures/block_path_<shape>_full.corpus`. They are not a
//! per-PR capture: forming the 45 spends of the smallest shape is 17.1
//! billion instructions, about twenty minutes of callgrind on a loaded
//! workstation (first capture, 2026-11-12), and the connect and pop rows
//! each pay a form in setup. `nightly.yml`'s `bench-full` job captures them
//! every night (the capture script's nightly set) and `bench-full-drift`
//! compares the counts with the night before; a pull request's capture
//! runs the unit blocks.
//!
//! What a full block adds over the unit block is the count: the range
//! proofs of every listed transaction folded in one batch, the store's
//! write at a block's worth of outputs and key images, and the per-block
//! terms beside 45, 10, 17 or 24 transactions instead of four.

use std::hint::black_box;

use gungraun::{library_benchmark, library_benchmark_group, main};
use shekyl_chain_ingest::bench_support::{BlockPath, Claimed};
use shekyl_chain_rules::{Candidate, StructurallyValid};

#[path = "support/block_path.rs"]
mod support;
use support::{before_connect, before_form, connected};

const SPEND_1IN_2OUT: &[u8] = include_bytes!("fixtures/block_path_spend_1in_2out_full.corpus");
const SPEND_8IN_2OUT: &[u8] = include_bytes!("fixtures/block_path_spend_8in_2out_full.corpus");
const SPEND_1IN_16OUT: &[u8] = include_bytes!("fixtures/block_path_spend_1in_16out_full.corpus");
const BOND_POST: &[u8] = include_bytes!("fixtures/block_path_bond_post_full.corpus");

#[library_benchmark]
#[bench::spend_1in_2out(args = (SPEND_1IN_2OUT), setup = before_form)]
#[bench::spend_8in_2out(args = (SPEND_8IN_2OUT), setup = before_form)]
#[bench::spend_1in_16out(args = (SPEND_1IN_16OUT), setup = before_form)]
#[bench::bond_post(args = (BOND_POST), setup = before_form)]
fn crypto_bench_block_form_full(
    (chain, subject, claimed): (BlockPath, Candidate, Claimed),
) -> (BlockPath, StructurallyValid, Claimed) {
    let formed = black_box(chain.form(black_box(subject), &claimed));
    (chain, formed, claimed)
}

#[library_benchmark]
#[bench::spend_1in_2out(args = (SPEND_1IN_2OUT), setup = before_connect)]
#[bench::spend_8in_2out(args = (SPEND_8IN_2OUT), setup = before_connect)]
#[bench::spend_1in_16out(args = (SPEND_1IN_16OUT), setup = before_connect)]
#[bench::bond_post(args = (BOND_POST), setup = before_connect)]
fn crypto_bench_block_connect_full(
    (mut chain, formed, claimed): (BlockPath, StructurallyValid, Claimed),
) -> (BlockPath, Claimed) {
    chain.connect(black_box(formed), &claimed);
    (chain, claimed)
}

#[library_benchmark]
#[bench::spend_1in_2out(args = (SPEND_1IN_2OUT), setup = connected)]
#[bench::spend_8in_2out(args = (SPEND_8IN_2OUT), setup = connected)]
#[bench::spend_1in_16out(args = (SPEND_1IN_16OUT), setup = connected)]
#[bench::bond_post(args = (BOND_POST), setup = connected)]
fn crypto_bench_block_pop_full(mut chain: BlockPath) -> BlockPath {
    chain.pop();
    chain
}

library_benchmark_group!(
    name = block_path_full_group;
    benchmarks =
        crypto_bench_block_form_full,
        crypto_bench_block_connect_full,
        crypto_bench_block_pop_full
);

main!(library_benchmark_groups = block_path_full_group);
