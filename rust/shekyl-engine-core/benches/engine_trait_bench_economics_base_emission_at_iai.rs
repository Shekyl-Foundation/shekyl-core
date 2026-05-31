// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! iai-callgrind companion to
//! `engine_trait_bench_economics_base_emission_at.rs`.
//!
//! `EconomicsEngine` is `pub(crate)` in `shekyl-engine-core`, so the
//! trait is not in scope from a bench-target compilation unit and
//! cannot be referenced via rustdoc intra-doc links here. References
//! to `EconomicsEngine` and `EconomicsEngine::base_emission_at` render
//! as plain backticked code throughout this file by design.
//!
//! Same workload (a single `EconomicsEngine::base_emission_at` call at
//! [`ECONOMICS_BENCH_HEIGHT`] against a freshly constructed engine
//! fixture) measured via Valgrind's Callgrind for deterministic
//! instruction-count metrics. This is the bench whose `instructions`
//! value the CI gate (`ci/benchmarks` workflow) uses for the pass/fail
//! signal under the `engine_trait_bench_*` threshold class
//! (bidirectional ±10% slowdown / ±25% speedup).
//!
//! Requires `cargo install iai-callgrind-runner` and a working
//! Valgrind install. See `docs/design/STAGE_0_HARNESS.md` §3 for the
//! existing harness substrate this bench plugs into.
//!
//! # Workload class
//!
//! **State-independent compute, O(height).** The method walks
//! `projected_already_generated(height)` block-by-block from genesis,
//! so the dominant cost is `ECONOMICS_BENCH_HEIGHT` iterations of
//! checked arithmetic — `instructions` is expected to be proportional
//! to the bench height, not in the trivial-pure-read range. The method
//! reads nothing from `ChainEconomicsSource`. iai-callgrind's
//! deterministic instruction count is the load-bearing signal; the
//! criterion sibling is the Tier-2 informational column.
//!
//! # Diagnostic signals
//!
//! Per `docs/design/STAGE_0_HARNESS.md` §4.4's static check, an
//! instruction count *below* the per-height-proportional expectation
//! suggests the optimizer elided the loop (the height was constant-
//! folded) — the `black_box` around the height argument in the
//! [`engine_economics_base_emission_at_for_bench`] call path guards
//! against this. An instruction count *far above* the expectation
//! suggests setup or teardown leaked into the measured region (the
//! `setup = build_engine_fixture` / `teardown = drop_fixture`
//! attributes keep the `Engine::create` ceremony and the engine /
//! `TempDir` teardown outside the measured function body).
//!
//! # Boundary rule (unified fixture shape)
//!
//! The fixture shape `(Box<Engine<SoloSigner>>, TempDir)` is the
//! canonical `engine_trait_bench_*` shape per
//! `docs/design/STAGE_0_HARNESS.md` §4.2: the `Engine<SoloSigner>` is
//! several KiB, so it goes behind `Box<T>` to keep the bench-function
//! boundary memcpy at pointer size. The shim reads `engine.economics`
//! through the boxed engine; the boundary moves only the engine
//! pointer.
//!
//! # Naming alignment
//!
//! The function name
//! (`engine_trait_bench_economics_base_emission_at`) is what
//! `compare.py`'s `classify()` routes on for threshold-class
//! resolution. The file name's `_iai` suffix and the group name's
//! `_group` suffix are convention; the function name is the
//! load-bearing identifier. All three names share the
//! `engine_trait_bench_economics_base_emission_at` stem so PR
//! reviewers grepping for the workload find consistent surface across
//! the criterion / iai pair and the manifest row.

use std::hint::black_box;

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use shekyl_engine_core::__bench_internals::engine_economics_base_emission_at_for_bench;
use shekyl_engine_core::{Engine, SoloSigner};
use tempfile::TempDir;

mod common;

use common::engine_fixture::{build_engine_fixture, drop_fixture, ECONOMICS_BENCH_HEIGHT};

#[library_benchmark]
#[bench::base_emission_at(setup = build_engine_fixture, teardown = drop_fixture)]
fn engine_trait_bench_economics_base_emission_at(
    fixture: (Box<Engine<SoloSigner>>, TempDir),
) -> (Box<Engine<SoloSigner>>, TempDir) {
    let (engine, tmp) = fixture;
    let _ = black_box(engine_economics_base_emission_at_for_bench(
        &engine,
        black_box(ECONOMICS_BENCH_HEIGHT),
    ));
    (engine, tmp)
}

library_benchmark_group!(
    name = engine_trait_bench_economics_base_emission_at_group;
    benchmarks = engine_trait_bench_economics_base_emission_at,
);

main!(library_benchmark_groups = engine_trait_bench_economics_base_emission_at_group);
