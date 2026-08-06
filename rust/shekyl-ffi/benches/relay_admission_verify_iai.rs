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
//! **Where that enforcement lives, because a gate nobody runs is a comment
//! with a harness.** This target is registered as an iai-only row in
//! `scripts/bench/capture_rust_baseline.sh`, which `ci/benchmarks` runs on
//! every PR; `scripts/bench/compare.py` gates on the `instructions` metric.
//! Its wall-clock twin is deliberately NOT registered — that one is a 64-cell
//! sweep measured on the reference machine and on the Pi, not a per-PR job.
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

use relay_admission_fixture::{
    admission_verify, build_fixture, AdmissionFixture, AdmissionStatus, ChunkLayout, ADMISSION_OK,
};

// The gate's fixed shape: one input, two outputs.
fn modal_shape() -> AdmissionFixture {
    // Depth 2: the gate must sit at a shape production actually presents.
    let fixture = build_fixture(1, 2, 2, ChunkLayout::Shared);
    // Self-witness, asserted HERE because setup is outside the measured region.
    // Without it, a fixture that stopped verifying would still produce a
    // plausible instruction count -- the early-return reject path, an order of
    // magnitude cheaper -- and the gate would present that as "verification got
    // dramatically faster", which is the shape a maintainer re-baselines rather
    // than investigates. Once re-baselined the gate measures the reject path
    // forever and can never again see a real change in verification cost.
    assert_eq!(
        admission_verify(&fixture),
        ADMISSION_OK,
        "gate fixture must VERIFY, or the drift gate counts the reject path"
    );
    fixture
}

// Setup is excluded from the measured region: `prove` is orders of magnitude
// more expensive than `verify`, and it is not on the relay path at all. A
// bench that folded it in would gate on the prover and call it verification.
//
// The fixture is RETURNED rather than dropped here, for the same reason: a
// by-value fixture dropped inside the body charges its five heap
// deallocations to the measured region, so the gate would move whenever the
// fixture's shape changed rather than when verification's cost did. Same
// artifact `shekyl-engine-state/benches/balance_iai.rs` documents at its own
// `-> (BalanceSummary, Vec<TransferDetails>)`, where the by-value drop was
// ~95 % of the count; there it was `zeroize`, here it would be `free`.
#[library_benchmark]
#[bench::modal(setup = modal_shape)]
fn relay_admission_verify_iai(fixture: AdmissionFixture) -> (AdmissionFixture, AdmissionStatus) {
    let status = black_box(admission_verify(black_box(&fixture)));
    (fixture, status)
}

library_benchmark_group!(
    name = relay_admission_verify_group;
    benchmarks = relay_admission_verify_iai
);

main!(library_benchmark_groups = relay_admission_verify_group);
