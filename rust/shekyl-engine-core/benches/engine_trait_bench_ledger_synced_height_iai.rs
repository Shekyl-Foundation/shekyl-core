// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! iai-callgrind companion to
//! `engine_trait_bench_ledger_synced_height.rs`.
//!
//! Same workload (a single call to
//! `Engine::<SoloSigner>::synced_height(&self) -> u64`) measured via
//! Valgrind's Callgrind for deterministic instruction-count metrics.
//! This is the bench whose `instructions` value the CI gate
//! (`ci/benchmarks` workflow, extended in Stage 0 PR-2 commit 3) uses
//! for the pass/fail signal under the `engine_trait_bench_*` threshold
//! class (bidirectional ±10% slowdown / ±25% speedup).
//!
//! Requires `cargo install iai-callgrind-runner` and a working Valgrind
//! install. See `docs/design/STAGE_0_HARNESS.md` §3 for the existing
//! harness substrate this bench plugs into.
//!
//! # Expected post-fixture instructions
//!
//! Per `docs/design/STAGE_0_HARNESS.md` §4.2 measurement-region
//! discipline: the post-fixture `instructions` count for this bench
//! is expected to be in the single-digit-to-low-tens range —
//! `Engine::synced_height` resolves to a chain of field accesses
//! returning `u64` (`self.ledger.ledger.height()`), wrapped in
//! `black_box`. Orders-of-magnitude-larger values (thousands,
//! millions) indicate the fixture has leaked into the measured region
//! and the bench is invalid; investigate the
//! `#[bench::fresh_engine(setup = …)]` attribute and the function
//! body's `black_box` placement before transcribing into
//! `PERFORMANCE_BASELINE.md`.
//!
//! # Naming alignment
//!
//! The function name (`engine_trait_bench_ledger_synced_height`) is
//! what `compare.py`'s `classify()` routes on for threshold-class
//! resolution (per Stage 0 PR-2 commit 3's CI integration). The file
//! name's `_iai` suffix and the group name's `_group` suffix are
//! convention; the function name is the load-bearing identifier. All
//! three names share the `engine_trait_bench_ledger_synced_height`
//! stem so PR reviewers grepping for the workload find consistent
//! surface across the criterion / iai pair and the manifest row.

use std::hint::black_box;

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use tempfile::TempDir;

use shekyl_engine_core::{Engine, SoloSigner};

mod common;

use common::engine_fixture::build_engine_fixture;

#[library_benchmark]
#[bench::fresh_engine(setup = build_engine_fixture)]
fn engine_trait_bench_ledger_synced_height(fixture: (Engine<SoloSigner>, TempDir)) {
    let (engine, _tmp) = fixture;
    black_box(engine.synced_height());
    // Keep the TempDir alive past the measured call so the wallet's
    // file footprint is not torn down mid-measurement. Belt-and-
    // suspenders: `_tmp` lives to scope end already, but `black_box`
    // makes the liveness explicit against any future compiler-level
    // dead-store elimination on bindings the function does not visibly
    // consume.
    black_box(_tmp);
}

library_benchmark_group!(
    name = engine_trait_bench_ledger_synced_height_group;
    benchmarks = engine_trait_bench_ledger_synced_height,
);

main!(library_benchmark_groups = engine_trait_bench_ledger_synced_height_group);
