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
//! **And how the gate finds this bench, because registration alone is not
//! routing.** `compare.py` routes each entry by function-name prefix; a name
//! outside its three classes is `unrouted` — reported, never failed — and the
//! paragraph above becomes a comment with a harness after all. The function
//! below is therefore named into the `crypto_bench_*` class
//! (`docs/benchmarks/shekyl_rust_v0.manifest.md` §11), and that class rather
//! than slowdown-only `hot_path_bench_*` **because its threshold is
//! bidirectional**: the failure mode `modal_shape` documents — a fixture that
//! stops verifying — presents as a dramatic instruction-count *drop*, which a
//! slowdown-only class would wave through as a pleasant result.
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
use rand::rngs::StdRng;
use rand::SeedableRng;

#[path = "relay_admission_fixture.rs"]
mod relay_admission_fixture;

use relay_admission_fixture::{
    admission_verify, build_fixture, AdmissionFixture, AdmissionStatus, ChunkLayout, ADMISSION_OK,
};

/// Fixed seed for the gate fixture's derivation. Its value has no cryptographic
/// meaning; it is pinned so the fixture — the FCMP++ proof included, which
/// `prove` would otherwise draw from `OsRng` — is **byte-identical** every run.
/// Callgrind instruction counts are deterministic only for identical inputs, so
/// without this the gate carried the proof's run-to-run variance (~0.19%,
/// measured on `dev` — #405 Finding C) as noise against its ±5%/±15% thresholds.
/// Mirrors the pinned-seed convention of
/// `shekyl-tx-builder/benches/transfer_e2e_iai.rs`.
///
/// This pins the **proof**, not the whole count. `verify` itself draws from
/// `OsRng` to weight its `BatchVerifier` (`shekyl-fcmp` `proof.rs`), and that
/// variable-time multiexp is inside the measured region, so a **~0.02% residual
/// remains** (measured: 352,470,032 vs 352,397,600 — 10× below the un-seeded
/// noise, 250× under the ±5% gate). Pinning it too would need a seedable verify
/// FFI; not worth an ABI change for 0.02%, and the batch randomness is a
/// soundness feature of verification, not a defect.
const BENCH_SEED: [u8; 32] = [
    0xBE, 0xEF, 0xF0, 0x0D, 0xCA, 0xFE, 0xBA, 0xBE, //
    0xBE, 0xEF, 0xF0, 0x0D, 0xCA, 0xFE, 0xBA, 0xBE, //
    0xBE, 0xEF, 0xF0, 0x0D, 0xCA, 0xFE, 0xBA, 0xBE, //
    0xBE, 0xEF, 0xF0, 0x0D, 0xCA, 0xFE, 0xBA, 0xBE, //
];

// The gate's fixed shape: one input, two outputs.
fn modal_shape() -> AdmissionFixture {
    // Depth 2: the gate must sit at a shape production actually presents.
    // Seeded (`BENCH_SEED`) so the fixture — proof included — is identical
    // run-to-run; the instruction count must be reproducible for the drift gate
    // to mean anything (the wall-clock sibling stays on `OsRng`).
    let fixture = build_fixture(
        &mut StdRng::from_seed(BENCH_SEED),
        1,
        2,
        2,
        ChunkLayout::Shared,
    );
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
fn crypto_bench_relay_admission_verify(
    fixture: AdmissionFixture,
) -> (AdmissionFixture, AdmissionStatus) {
    let status = black_box(admission_verify(black_box(&fixture)));
    (fixture, status)
}

library_benchmark_group!(
    name = relay_admission_verify_group;
    benchmarks = crypto_bench_relay_admission_verify
);

main!(library_benchmark_groups = relay_admission_verify_group);
