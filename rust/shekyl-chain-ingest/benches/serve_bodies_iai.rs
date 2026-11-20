// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One body response built from the store (`BENCHMARK_ALIGNMENT.md`
//! BA-T44): `shekyl_chain_sync_runtime::serve::serve_bodies`, the call the
//! sync owner makes for a peer's body request (command 2013) to produce the
//! response it sends (2014).
//!
//! The request names the tail of a block-path fixture's chain with its
//! subject connected: seven coinbase-only blocks and the subject, which
//! lists [`SUBJECT_SPENDS`] spends. For each hash the serve reads
//! the height, the block, each listed transaction's record and body, and
//! the attestation witness, and charges the body to the response's byte
//! budget (`BodyPlanner`). Every requested block is held and inside the
//! budget, so the row counts the sent path and neither the deferred nor
//! the missed one; setup asserts that.
//!
//! The bench is this crate's because the store it reads is the block-path
//! driver's (`bench_support.rs`), which is behind this crate's `harness`.
//! The subject is `shekyl-chain-sync-runtime`'s, reached through a
//! dev-dependency edge, so the ledger row's path set names that crate
//! (a dev edge is not in the capture's linked closure). The frame row
//! shares the path set: the two cannot be told apart at package grain.
//!
//! An instruction count on the CI runner's x86, never a floor figure
//! (rule 76).

use std::hint::black_box;

use gungraun::{library_benchmark, library_benchmark_group, main};
use shekyl_chain_ingest::bench_support::BlockPath;
use shekyl_chain_sync_runtime::serve::serve_bodies;
use shekyl_levin::{RequestBodies, ResponseBodies};

#[path = "support/tail.rs"]
mod tail;
use tail::{RequestedTail, SUBJECT_SPENDS, TAIL_BLOCKS};

const SPEND_1IN_2OUT: &[u8] = include_bytes!("fixtures/block_path_spend_1in_2out_unit.corpus");

/// The chain with its subject connected, and a request for its tail, the
/// subject last.
fn before_serve(corpus: &[u8]) -> (BlockPath, RequestBodies) {
    let tail = RequestedTail::connected(corpus);
    let request = RequestBodies {
        hashes: tail.hashes.clone(),
    };
    let served = serve_bodies(tail.chain.store(), &request).expect("the serve");
    assert_eq!(served.bodies.len(), TAIL_BLOCKS, "every body is sent");
    assert!(served.deferred.is_empty() && served.missed_ids.is_empty());
    assert_eq!(
        served.bodies[TAIL_BLOCKS - 1].txs.len(),
        SUBJECT_SPENDS,
        "the subject carries its spends"
    );
    (tail.chain, request)
}

#[library_benchmark]
#[bench::tip_run(args = (SPEND_1IN_2OUT), setup = before_serve)]
fn crypto_bench_sync_serve_bodies(
    (chain, request): (BlockPath, RequestBodies),
) -> (BlockPath, RequestBodies, ResponseBodies) {
    let response = black_box(serve_bodies(chain.store(), black_box(&request)).expect("the serve"));
    (chain, request, response)
}

library_benchmark_group!(
    name = serve_bodies_group;
    benchmarks = crypto_bench_sync_serve_bodies
);

main!(library_benchmark_groups = serve_bodies_group);
