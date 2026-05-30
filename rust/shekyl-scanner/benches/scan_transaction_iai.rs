// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! iai-callgrind companion to `benches/scan_transaction.rs`
//! (PR 4 §3.1 / F11-S substrate).
//!
//! Callgrind simulation produces deterministic per-iteration
//! instruction / cycle counts, so this harness omits the warm/cold
//! split that the wall-clock harness uses (`benches/scan_transaction.rs`
//! captures that via criterion's quantile estimator). Each
//! `[library_benchmark]` here measures one `Scanner::scan` call
//! against a freshly-constructed `ScannableBlock`; the setup
//! (constructing the block + scanner) runs outside the measured
//! region per iai-callgrind's `with_setup` semantics, so the
//! reported counts isolate scan-time cost.
//!
//! ## Group classification
//!
//! - `worst_case_all_view_tags_match_*` — F11-S binding (per the
//!   wall-clock harness's module doc-comment; the load-bearing
//!   identifier is `F11S_BINDING_GROUP` in
//!   `benches/scan_transaction.rs`).
//! - `typical_case_view_tag_filtered_*` — contextual; sanity-check
//!   denominator for the worst-case-to-typical-case cost ratio.

use std::hint::black_box;

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use zeroize::Zeroizing;

use shekyl_scanner::{
    bench_fixtures::{
        build_typical_case_scannable_block, build_worst_case_scannable_block, make_bench_wallet,
        BenchWalletKeys,
    },
    Scanner,
};

fn fresh_scanner(wallet: &BenchWalletKeys) -> Scanner {
    Scanner::new(
        wallet.view_pair.clone(),
        Zeroizing::new(*wallet.spend_secret),
    )
}

fn setup_worst_case(n: usize) -> (Scanner, shekyl_rpc::ScannableBlock) {
    let wallet = make_bench_wallet();
    let scanner = fresh_scanner(&wallet);
    let block = build_worst_case_scannable_block(n, &wallet);
    (scanner, block)
}

fn setup_typical_case(n: usize) -> (Scanner, shekyl_rpc::ScannableBlock) {
    let wallet = make_bench_wallet();
    let scanner = fresh_scanner(&wallet);
    let block = build_typical_case_scannable_block(n);
    (scanner, block)
}

#[library_benchmark]
#[benches::with_setup(args = [1, 4, 8, 16], setup = setup_worst_case)]
fn worst_case_all_view_tags_match(input: (Scanner, shekyl_rpc::ScannableBlock)) -> Scanner {
    let (mut scanner, block) = input;
    let res = scanner
        .scan(black_box(block))
        .expect("scan_transaction must not error on well-formed worst-case fixture");
    black_box(res);
    scanner
}

#[library_benchmark]
#[benches::with_setup(args = [1, 4, 8, 16], setup = setup_typical_case)]
fn typical_case_view_tag_filtered(input: (Scanner, shekyl_rpc::ScannableBlock)) -> Scanner {
    let (mut scanner, block) = input;
    let res = scanner
        .scan(black_box(block))
        .expect("scan_transaction must not error on well-formed typical-case fixture");
    black_box(res);
    scanner
}

library_benchmark_group!(
    name = scan_transaction;
    benchmarks = worst_case_all_view_tags_match, typical_case_view_tag_filtered,
);

main!(library_benchmark_groups = scan_transaction);
