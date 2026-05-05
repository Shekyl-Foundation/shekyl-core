// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved.
// BSD-3-Clause

//! iai-callgrind companion to
//! `engine_trait_bench_ledger_balance.rs`.
//!
//! `LedgerEngine` is `pub(crate)` in `shekyl-engine-core`, so the
//! type is not in scope from a bench-target compilation unit and
//! cannot be referenced via rustdoc intra-doc links here. References
//! to `LedgerEngine` and `LedgerEngine::balance` render as plain
//! backticked code throughout this file by design.
//!
//! Same workload (a single `LedgerEngine::balance` call against a
//! 1024-transfer state-populated fixture) measured via
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
//! **State-dependent compute.** Unlike
//! `engine_trait_bench_ledger_synced_height` (a `u64` field-access
//! chain whose criterion `median_ns` reflects optimizer amortization
//! across the iteration loop), `balance` walks the transfer slice on
//! every call:
//! [`shekyl_scanner::BalanceSummary::compute`] iterates `transfers`
//! summing per-output amounts subject to spend / maturity filters.
//! Optimizer amortization does not apply meaningfully because each
//! iteration measures meaningful work; both criterion and iai-callgrind
//! report numbers consistent with the per-call cost.
//!
//! # Expected post-fixture instructions
//!
//! Per `docs/design/STAGE_0_HARNESS.md` §4.4's static check
//! (component model): the post-fixture `instructions` count for this
//! bench is expected to be in the **2,000–10,000 range** —
//! `BalanceSummary::compute` over 1024 transfers performs ~1024
//! iterations of a small inner loop (per-transfer spend / maturity /
//! amount checks) plus the per-call trait-dispatch ceremony shared
//! with the synced_height bench (~10 instructions; see
//! `engine_trait_bench_ledger_synced_height_iai.rs`'s expected range).
//!
//! Numbers below the lower bound (<1,000 instructions) suggest the
//! transfer slice was not actually populated (state-injection
//! failure) — the fixture must have at least `n` transfers to make
//! the loop measurable. Numbers above the upper bound (>20,000
//! instructions) suggest:
//!
//! 1. **Setup leakage** — the `#[bench::balance(setup =
//!    build_engine_fixture_with_balance, ...)]` attribute did not
//!    keep the fixture build (Argon2id KDF + ML-KEM keygen + envelope
//!    encryption + 1024-transfer construction) outside the measured
//!    function body. Setup leakage manifests as billions of
//!    instructions for this workload class.
//! 2. **Teardown leakage (symmetry-rule violation)** — the bench
//!    function returns the fixture and `teardown =
//!    drop_balance_fixture` lifts `Drop` outside the measured region.
//!    Without that explicit teardown, the engine teardown + temp-dir
//!    `unlink` would dominate the count.
//! 3. **Workload genuinely larger than the model assumed** — e.g.,
//!    `BalanceSummary::compute` grew per-transfer work (additional
//!    filter passes, derivation, etc.). Tighten the model with the
//!    additional component, refresh the expected range, and document
//!    the refinement in the PR description.
//!
//! # Boundary rule (unified fixture shape)
//!
//! The fixture shape `(Box<Engine<SoloSigner, DaemonClient,
//! LocalLedger>>, TempDir)` is the canonical
//! `engine_trait_bench_*` shape per
//! `docs/design/STAGE_0_HARNESS.md` §4.2: any fixture field exceeding
//! 64 bytes goes behind `Box<T>` so the bench-function boundary moves
//! only pointer-sized data, keeping iai-callgrind's residual boundary
//! cost at ~5–10 instructions instead of ~600 (the
//! `Engine<SoloSigner, ...>` is 6,296 bytes; passing it by value
//! would dominate the measurement). The `LedgerBlock` populated with
//! 1024 transfers stays inside the engine; the boundary moves only
//! the engine pointer.
//!
//! # Naming alignment
//!
//! The function name (`engine_trait_bench_ledger_balance`) is what
//! `compare.py`'s `classify()` routes on for threshold-class
//! resolution. The file name's `_iai` suffix and the group name's
//! `_group` suffix are convention; the function name is the
//! load-bearing identifier. All three names share the
//! `engine_trait_bench_ledger_balance` stem so PR reviewers grepping
//! for the workload find consistent surface across the criterion /
//! iai pair and the manifest row.

use std::hint::black_box;

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use shekyl_engine_core::__bench_internals::{engine_balance_for_bench, LocalLedger};
use shekyl_engine_core::{DaemonClient, Engine, SoloSigner};
use tempfile::TempDir;

mod common;

use common::engine_fixture::{build_engine_fixture_with_default_balance, drop_balance_fixture};

#[library_benchmark]
#[bench::balance(
    setup = build_engine_fixture_with_default_balance,
    teardown = drop_balance_fixture
)]
fn engine_trait_bench_ledger_balance(
    fixture: (Box<Engine<SoloSigner, DaemonClient, LocalLedger>>, TempDir),
) -> (Box<Engine<SoloSigner, DaemonClient, LocalLedger>>, TempDir) {
    let (engine, tmp) = fixture;
    let _ = black_box(engine_balance_for_bench(&engine));
    (engine, tmp)
}

library_benchmark_group!(
    name = engine_trait_bench_ledger_balance_group;
    benchmarks = engine_trait_bench_ledger_balance,
);

main!(library_benchmark_groups = engine_trait_bench_ledger_balance_group);
