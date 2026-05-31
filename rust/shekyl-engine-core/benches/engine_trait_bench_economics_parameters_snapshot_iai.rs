// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! iai-callgrind companion to
//! `engine_trait_bench_economics_parameters_snapshot.rs`.
//!
//! `EconomicsEngine` is `pub(crate)` in `shekyl-engine-core`, so the
//! trait is not in scope from a bench-target compilation unit and
//! cannot be referenced via rustdoc intra-doc links here. References
//! to `EconomicsEngine` and `EconomicsEngine::parameters_snapshot`
//! render as plain backticked code throughout this file by design.
//!
//! Same workload (a single `EconomicsEngine::parameters_snapshot` call
//! against a freshly constructed engine fixture) measured via
//! Valgrind's Callgrind for deterministic instruction-count metrics.
//! This is the bench whose `instructions` value the CI gate
//! (`ci/benchmarks` workflow) uses for the pass/fail signal under the
//! `engine_trait_bench_*` threshold class (bidirectional ±10%
//! slowdown / ±25% speedup).
//!
//! Requires `cargo install iai-callgrind-runner` and a working
//! Valgrind install. See `docs/design/STAGE_0_HARNESS.md` §3 for the
//! existing harness substrate this bench plugs into.
//!
//! # Workload class
//!
//! **Pure compute with a digest.** The method rebuilds the snapshot
//! fresh on every call (§6.3 G5, no process-wide cache) and computes a
//! Blake2b-256 `params_digest` over the fixed-width parameter layout;
//! the digest dominates, so the count is well above the
//! trivial-pure-read range but is a fixed, height-independent value
//! (the parameter set is build-time-resolved). The method reads
//! nothing from `ChainEconomicsSource`. iai-callgrind's deterministic
//! instruction count is the load-bearing signal; the criterion sibling
//! is the Tier-2 informational column.
//!
//! # Diagnostic signals
//!
//! Per `docs/design/STAGE_0_HARNESS.md` §4.4's static check, a count
//! far above the digest-dominated expectation suggests setup or
//! teardown leaked into the measured region (the `setup =
//! build_engine_fixture` / `teardown = drop_fixture` attributes keep
//! the `Engine::create` ceremony and the engine / `TempDir` teardown
//! outside the measured function body). A count near the
//! trivial-pure-read range suggests the digest was elided — the
//! shim's internal `black_box` around the snapshot guards against this.
//!
//! # Boundary rule (unified fixture shape)
//!
//! The fixture shape `(Box<Engine<SoloSigner>>, TempDir)` is the
//! canonical `engine_trait_bench_*` shape per
//! `docs/design/STAGE_0_HARNESS.md` §4.2: the `Engine<SoloSigner>` is
//! several KiB, so it goes behind `Box<T>` to keep the bench-function
//! boundary memcpy at pointer size. The shim returns a `u64` summary,
//! so the boundary moves only the engine pointer in and a primitive
//! out.
//!
//! # Naming alignment
//!
//! The function name
//! (`engine_trait_bench_economics_parameters_snapshot`) is what
//! `compare.py`'s `classify()` routes on for threshold-class
//! resolution. The file name's `_iai` suffix and the group name's
//! `_group` suffix are convention; the function name is the
//! load-bearing identifier. All three names share the
//! `engine_trait_bench_economics_parameters_snapshot` stem so PR
//! reviewers grepping for the workload find consistent surface across
//! the criterion / iai pair and the manifest row.

use std::hint::black_box;

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use shekyl_engine_core::__bench_internals::engine_economics_parameters_snapshot_for_bench;
use shekyl_engine_core::{Engine, SoloSigner};
use tempfile::TempDir;

mod common;

use common::engine_fixture::{build_engine_fixture, drop_fixture};

#[library_benchmark]
#[bench::parameters_snapshot(setup = build_engine_fixture, teardown = drop_fixture)]
fn engine_trait_bench_economics_parameters_snapshot(
    fixture: (Box<Engine<SoloSigner>>, TempDir),
) -> (Box<Engine<SoloSigner>>, TempDir) {
    let (engine, tmp) = fixture;
    let _ = black_box(engine_economics_parameters_snapshot_for_bench(&engine));
    (engine, tmp)
}

library_benchmark_group!(
    name = engine_trait_bench_economics_parameters_snapshot_group;
    benchmarks = engine_trait_bench_economics_parameters_snapshot,
);

main!(library_benchmark_groups = engine_trait_bench_economics_parameters_snapshot_group);
