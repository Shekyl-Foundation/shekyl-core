// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The verification floor of `hop` — §72's enumerated admission surface.
//!
//! `hop` (`DAEMON_RELAY_PRIVACY.md` §71) is receive-to-forward: transit plus
//! **`B`'s verification** plus scheduling. This measures that middle term, and
//! it is the only part of `hop` measurable with no network — which is why it
//! comes before either field arm (§72.7).
//!
//! # Why the FFI entry points and not the primitives
//!
//! The quantity is what **pool admission** costs, so the bench calls the same
//! `shekyl_*` functions `blockchain.cpp` calls, in the order it calls them. A
//! primitive-level bench drifts from that the moment the calling code changes
//! — the same reason `peers` needed a Rust owner rather than a mirrored
//! `#define` (§70.3).
//!
//! Two boundaries this respects, both from §72:
//!
//! - **Pool admission only.** `blockchain.cpp` skips `shekyl_fcmp_verify` on
//!   the *block* path because admission already did it, so the block path is a
//!   deliberately cheaper traversal and is not `hop`.
//! - **No ML-DSA-65.** The PQ material enters as `PqcLeafScalar` — a hash bound
//!   *into* the proof, not a signature checked beside it (§72.2). Benching a
//!   lattice cost here would report a term the relay never pays.
//!
//! # What it does *not* measure, by design
//!
//! **Batch depth.** `handle_incoming_tx` runs in a per-transaction loop that
//! completes before `relay_transactions`, so a batch of `N` pays `N`
//! verifications before *any* forward. Depth is a free parameter, so it is a
//! multiplier in the derivation — `(N+1)/2` at the mean position, `N` for the
//! worst-placed transaction — never a bench dimension (§72.4).
//!
//! **Storage.** Pool insertion is inside `hop` but not inside this term; it is
//! measured with the end-to-end arm, where the substrate matters (§72.5).
//!
//! # A named landmine: FCMP++ *does* support batch verification
//!
//! `fcmps/src/lib.rs` exposes `verify` taking `&mut BatchVerifier<C::C1>` /
//! `<C::C2>` — *"This only queues the FCMP for batch verification"* — so the
//! proof system permits verifying many transactions together, and the marginal
//! cost of doing so is far below the serial sum.
//!
//! **`handle_incoming_tx` does not use it.** It is a per-transaction loop, so
//! the implementation verifies serially and `hop` measures the implementation,
//! not the system's potential. This bench is therefore correct as written.
//!
//! **Evaluate it as the fix, not only as a hazard.** At the measured serial
//! cost — 127 ms per transaction on the arm the constant derives from (§73) —
//! a batch of 10 puts the last transaction at ~1.27 s of verification, an
//! order above the whole current `hop` budget. Batching amortises the
//! multi-exponentiation, collapsing `N × 127 ms` toward `127 ms + small·N`, so
//! it is plausibly what keeps `hop` bounded under load rather than a throughput
//! nicety.
//!
//! Either way it **changes `hop`'s batch term and obliges a re-derivation**.
//! Recorded here because the natural reviewer of that change is looking at
//! mempool throughput and has no reason to open §71 — but the note must not
//! read as "don't", because on present numbers the answer may well be "must".
//!
//! # Reading the output
//!
//! The result is a **surface over `(n_in, n_out)`**, not a scalar. Collapsing
//! it to the constant is a separate step and must use the *effective* scalar
//! over the shape distribution, never the p90 of any single cell — otherwise
//! §66's compounding error reappears one level down, inside `hop`.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

#[path = "relay_admission_fixture.rs"]
mod relay_admission_fixture;

use relay_admission_fixture::{admission_verify, build_fixture, ADMISSION_OK};

fn bench_admission(c: &mut Criterion) {
    let mut group = c.benchmark_group("relay_admission_verify");
    // A verification is not amortisable across a batch, so sample counts stay
    // low and the wall-clock figure is per-transaction by construction.
    group.sample_size(10);

    // Depth 2 is production's SHALLOWEST tree (`tree.rs`: a non-empty tree
    // yields depth >= 2). Depth 1 is retained as the sub-production floor the
    // first sweep measured, so the pair gives the per-layer slope — the term
    // that grows monotonically with the chain and has no code change to gate on.
    for tree_depth in [1u8, 2] {
        for n_in in [1usize, 2, 4] {
            for n_out in [2usize, 16] {
                let fixture = build_fixture(n_in, n_out, tree_depth);

                // Self-witnessing: a fixture that does not verify would make every
                // timing below a measurement of the rejection path.
                let rc = admission_verify(&fixture, n_in, n_out);
                assert_eq!(
                    rc, ADMISSION_OK,
                    "fixture must VERIFY, or the bench times the reject path \
                 (depth={tree_depth}, n_in={n_in}, n_out={n_out})"
                );

                group.throughput(Throughput::Elements(n_in as u64));
                group.bench_with_input(
                    BenchmarkId::from_parameter(format!("d{tree_depth}_in{n_in}_out{n_out}")),
                    &fixture,
                    |b, f| b.iter(|| admission_verify(f, n_in, n_out)),
                );
            }
        }
    }

    group.finish();
}

criterion_group!(benches, bench_admission);
criterion_main!(benches);
