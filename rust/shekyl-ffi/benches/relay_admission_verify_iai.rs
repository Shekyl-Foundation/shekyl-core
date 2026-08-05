// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! gungraun companion to `relay_admission_verify.rs` — the **drift gate**.
//!
//! Same workload, measured as Callgrind instruction counts instead of wall
//! clock. The two are different instruments serving different purposes (§72.6)
//! and must not be conflated:
//!
//! - **Wall clock** (`relay_admission_verify.rs`) is the `hop` input. It is
//!   hardware-dependent *on purpose* — the quantile is over the node
//!   population, so it is run on the reference machine **and** on the slow one,
//!   and the constant derives from the slow end.
//! - **Instruction counts** (here) are hardware-independent, so they fire from
//!   any runner. This is what makes *"`hop` moves when the proof system moves"*
//!   an enforced invariant rather than a comment someone can miss: a change to
//!   FCMP++ verification shifts this count and trips the CI threshold, and the
//!   embargo re-derivation is then owed before the change lands.
//!
//! Conflating them would give either a gate that flaps with runner hardware or
//! a number that cannot be gated.
//!
//! **Pinned to the admission path, not to a primitive.** The quantity is what
//! pool admission costs; a primitive-level gate drifts from it the moment the
//! calling code changes — `peers`' mirrored `#define` is the same failure
//! (§70.3).
//!
//! **One shape, deliberately.** The gate answers *"did the cost of verifying a
//! transaction move?"*, which needs a fixed workload, not a surface. The
//! surface is the wall-clock bench's job. `1-in / 2-out` is the modal shape and
//! the cheapest cell, so the gate is sensitive to the per-transaction floor
//! rather than to a tail cell nobody's traffic occupies.
//!
//! Requires `cargo install gungraun-runner` and a working Valgrind. Not run on
//! aarch64 — the slow arm is wall clock only.

// gungraun's `setup` hands the fixture in **by value** — that is the harness's
// contract, not a style choice: taking it by reference would put the fixture's
// construction inside the measured region and gate on the prover.
#![allow(clippy::needless_pass_by_value)]

use std::hint::black_box;

use gungraun::{library_benchmark, library_benchmark_group, main};

#[path = "relay_admission_fixture.rs"]
mod relay_admission_fixture;

use relay_admission_fixture::{admission_verify, build_fixture, AdmissionFixture, ChunkLayout};

// The gate's fixed shape: one input, two outputs.
fn modal_shape() -> AdmissionFixture {
    // Depth 2: the gate must sit at a shape production actually presents.
    build_fixture(1, 2, 2, ChunkLayout::Shared)
}

// Setup is excluded from the measured region: `prove` is orders of magnitude
// more expensive than `verify`, and it is not on the relay path at all. A
// bench that folded it in would gate on the prover and call it verification.
#[library_benchmark]
#[bench::modal(setup = modal_shape)]
fn relay_admission_verify_iai(fixture: AdmissionFixture) -> u8 {
    black_box(admission_verify(black_box(&fixture), 1, 2))
}

library_benchmark_group!(
    name = relay_admission_verify_group;
    benchmarks = relay_admission_verify_iai
);

main!(library_benchmark_groups = relay_admission_verify_group);
