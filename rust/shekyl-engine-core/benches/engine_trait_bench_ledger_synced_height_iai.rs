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
//! discipline and the symmetry rule subsection: the post-fixture
//! `instructions` count for this bench is expected to be in the
//! **single-digit-to-low-tens range** — `Engine::synced_height`
//! resolves to a chain of field accesses returning `u64`
//! (`self.ledger.ledger.height()`), wrapped in `black_box`, with
//! both fixture construction and fixture teardown excluded from the
//! measured region.
//!
//! Orders-of-magnitude-larger values (thousands, millions) indicate
//! a symmetry-rule violation — fixture setup or teardown has leaked
//! into the measured region. Investigation order per §4.4's static
//! sanity-check:
//!
//! 1. **Teardown leakage** — the bench function returns the fixture
//!    and `teardown = drop_fixture` lifts `Drop` outside the measured
//!    region. If the function consumes the fixture without returning
//!    it (or the `teardown =` parameter is missing), `Drop` runs
//!    inside the measurement and dominates the count. The criterion
//!    sibling reports nanoseconds-per-iter consistent with a few
//!    cycles when the workload itself is measured cleanly; an
//!    iai-callgrind / criterion divergence of orders of magnitude on
//!    the same workload is the textbook diagnostic.
//! 2. **Setup leakage** — the `#[bench::fresh_engine(setup =
//!    build_engine_fixture, ...)]` attribute must keep the fixture
//!    build outside the measured function body. If the build moves
//!    inside, the Argon2id KDF + ML-KEM keygen + envelope encryption
//!    cost (~1–2 seconds wall-clock) appears as billions of
//!    instructions.
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

use common::engine_fixture::{build_engine_fixture, drop_fixture};

#[library_benchmark]
#[bench::fresh_engine(setup = build_engine_fixture, teardown = drop_fixture)]
fn engine_trait_bench_ledger_synced_height(
    fixture: (Engine<SoloSigner>, TempDir),
) -> (Engine<SoloSigner>, TempDir) {
    let (engine, tmp) = fixture;
    let _ = black_box(engine.synced_height());
    (engine, tmp)
}

library_benchmark_group!(
    name = engine_trait_bench_ledger_synced_height_group;
    benchmarks = engine_trait_bench_ledger_synced_height,
);

main!(library_benchmark_groups = engine_trait_bench_ledger_synced_height_group);
