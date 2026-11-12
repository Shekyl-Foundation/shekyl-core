// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block path's instruction counts on every pull request
//! (`BENCHMARK_ALIGNMENT.md` BA-T2 and BA-T41; the `PB-D1` and `PB-D1s`
//! terms of `DAEMON_REDB_STORE.md` §1.3a).
//!
//! Three calls, each its own row, on one committed block per shape:
//!
//! - **`crypto_bench_block_form`**: `shekyl_chain_rules::form`. The
//!   stateless stage every connected block pays: each listed transaction's
//!   form, its signatures and its membership proof, then the block's range
//!   proofs as one batch. This is the verifier's share of `PB-D1`.
//! - **`crypto_bench_block_connect`**: `validate_with_memo` over the
//!   batch's view, `WriteBatch::connect` and the commit, at production
//!   durability. The store's share, `PB-D1s`.
//! - **`crypto_bench_block_pop`**: one pop and its commit.
//!
//! and three reads a wallet or a syncing peer issues, on the output-cap
//! fixture's store: the subject block by height once it is connected, and
//! over its history a run of
//! 64 header records, and a run of 8 curve-tree leaves.
//!
//! The block's proof-of-work is not in any of them (the fixture chain runs
//! under the harness longhash); one header's RandomX verification is
//! `shekyl-pow-randomx`'s `verify_header_iai`.
//!
//! # The block is the unit block
//!
//! Four transactions of the shape, not a block at the weight limit
//! (`src/bench_fixture_tests.rs` records why: a full block is twenty
//! minutes of callgrind a row). `form` judges each listed transaction on
//! its own and folds the range proofs once, so the four carry every term.
//! The full blocks' rows are `block_path_full_iai.rs`, captured on `dev`.
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
//! `benches/fixtures/block_path_<shape>_unit.corpus`, written by
//! `regenerate_block_path_fixtures` and held to the tree by
//! `every_block_path_fixture_replays` (`src/bench_fixture_tests.rs`). The
//! history is replayed into a fresh store in `setup`, outside the measured
//! region. The driver panics on a block the validator refuses, so a stale
//! fixture fails the bench in setup; it cannot count a refusal path and
//! present it as a faster connect.

use std::hint::black_box;

use gungraun::{library_benchmark, library_benchmark_group, main};
use shekyl_chain_ingest::bench_support::{BlockPath, Claimed};
use shekyl_chain_rules::{AtHeight, Candidate, StructurallyValid};
use shekyl_chain_store::store::AtIndex;
use shekyl_types::{BlockHeight, TreeLeaf, TreePosition};

#[path = "support/block_path.rs"]
mod support;
use support::{before_connect, before_form, connected};

const SPEND_1IN_2OUT: &[u8] = include_bytes!("fixtures/block_path_spend_1in_2out_unit.corpus");
const SPEND_8IN_2OUT: &[u8] = include_bytes!("fixtures/block_path_spend_8in_2out_unit.corpus");
const SPEND_1IN_16OUT: &[u8] = include_bytes!("fixtures/block_path_spend_1in_16out_unit.corpus");

/// The header records one range read asks for.
const RANGE: u64 = 64;

/// The curve-tree leaves one range read asks for. An output enters the
/// tree when it matures, so a chain this short holds few.
const LEAVES: u64 = 8;

// Each function returns what it was handed. A store, a candidate or a
// verdict dropped inside the body would charge its teardown to the measured
// region (`relay_admission_verify_iai.rs` records the same artifact).

#[library_benchmark]
#[bench::spend_1in_2out(args = (SPEND_1IN_2OUT), setup = before_form)]
#[bench::spend_8in_2out(args = (SPEND_8IN_2OUT), setup = before_form)]
#[bench::spend_1in_16out(args = (SPEND_1IN_16OUT), setup = before_form)]
fn crypto_bench_block_form(
    (chain, subject, claimed): (BlockPath, Candidate, Claimed),
) -> (BlockPath, StructurallyValid, Claimed) {
    let formed = black_box(chain.form(black_box(subject), &claimed));
    (chain, formed, claimed)
}

#[library_benchmark]
#[bench::spend_1in_2out(args = (SPEND_1IN_2OUT), setup = before_connect)]
#[bench::spend_8in_2out(args = (SPEND_8IN_2OUT), setup = before_connect)]
#[bench::spend_1in_16out(args = (SPEND_1IN_16OUT), setup = before_connect)]
fn crypto_bench_block_connect(
    (mut chain, formed, claimed): (BlockPath, StructurallyValid, Claimed),
) -> (BlockPath, Claimed) {
    chain.connect(black_box(formed), &claimed);
    (chain, claimed)
}

#[library_benchmark]
#[bench::spend_1in_2out(args = (SPEND_1IN_2OUT), setup = connected)]
#[bench::spend_8in_2out(args = (SPEND_8IN_2OUT), setup = connected)]
#[bench::spend_1in_16out(args = (SPEND_1IN_16OUT), setup = connected)]
fn crypto_bench_block_pop(mut chain: BlockPath) -> BlockPath {
    chain.pop();
    chain
}

/// The chain with its subject connected, and the tip's height.
fn readable(corpus: &[u8]) -> (BlockPath, BlockHeight) {
    with_tip(connected(corpus))
}

/// The fixture's history alone, and its tip's height: what a range read
/// needs, without a `form` of the subject block in setup.
fn readable_history(corpus: &[u8]) -> (BlockPath, BlockHeight) {
    with_tip(BlockPath::replayed(corpus).0)
}

/// `chain` and its tip's height, with the reads' subjects asserted
/// present: a read of a row that is not there would count the absence
/// path.
fn with_tip(chain: BlockPath) -> (BlockPath, BlockHeight) {
    let tip = {
        let read = chain.store().begin_read().expect("a read");
        let tip = read
            .tip()
            .expect("the tip")
            .recorded
            .expect("a connected chain")
            .height;
        assert!(tip.to_raw() >= RANGE, "the chain holds a full header run");
        let leaves = read
            .leaves(TreePosition::from_raw(0)..TreePosition::from_raw(LEAVES))
            .expect("the leaf read");
        assert!(
            matches!(leaves, AtIndex::Recorded(ref run) if run.len() as u64 == LEAVES),
            "the tree holds a full leaf run"
        );
        tip
    };
    (chain, tip)
}

// The subject block by height: the blob read, parsed and hashed against
// its recorded identity. The block lists the unit's four 16-output spends.
#[library_benchmark]
#[bench::tip(args = (SPEND_1IN_16OUT), setup = readable)]
fn crypto_bench_store_read_block((chain, tip): (BlockPath, BlockHeight)) -> (BlockPath, usize) {
    let listed = {
        let read = chain.store().begin_read().expect("a read");
        match black_box(read.block(black_box(tip)).expect("the block read")) {
            AtHeight::Recorded(body) => body.block.transaction_hashes.len(),
            AtHeight::AboveTip => panic!("the tip is recorded"),
        }
    };
    (chain, listed)
}

// The last `RANGE` header records below the tip, as a syncing peer's
// header request walks them.
#[library_benchmark]
#[bench::below_tip(args = (SPEND_1IN_16OUT), setup = readable_history)]
fn crypto_bench_store_read_header_range(
    (chain, tip): (BlockPath, BlockHeight),
) -> (BlockPath, u64) {
    let count = {
        let read = chain.store().begin_read().expect("a read");
        let from = BlockHeight::from_raw(tip.to_raw() - RANGE);
        let AtHeight::Recorded(rows) = read
            .block_infos(black_box(from)..tip)
            .expect("the range read")
        else {
            panic!("the range starts below the tip");
        };
        let mut count = 0;
        for row in rows {
            black_box(row.expect("a header row"));
            count += 1;
        }
        count
    };
    assert_eq!(count, RANGE);
    (chain, count)
}

// `LEAVES` curve-tree leaves from the first position: the leaf run the
// proving side reads to assemble a membership path.
#[library_benchmark]
#[bench::first_run(args = (SPEND_1IN_16OUT), setup = readable_history)]
fn crypto_bench_store_read_tree_leaves(
    (chain, _tip): (BlockPath, BlockHeight),
) -> (BlockPath, Vec<TreeLeaf>) {
    let leaves = {
        let read = chain.store().begin_read().expect("a read");
        let run = read
            .leaves(TreePosition::from_raw(0)..TreePosition::from_raw(black_box(LEAVES)))
            .expect("the leaf read");
        match black_box(run) {
            AtIndex::Recorded(leaves) => leaves,
            other => panic!("the leaf run is recorded: {other:?}"),
        }
    };
    (chain, leaves)
}

library_benchmark_group!(
    name = block_path_group;
    benchmarks =
        crypto_bench_block_form,
        crypto_bench_block_connect,
        crypto_bench_block_pop,
        crypto_bench_store_read_block,
        crypto_bench_store_read_header_range,
        crypto_bench_store_read_tree_leaves
);

main!(library_benchmark_groups = block_path_group);
