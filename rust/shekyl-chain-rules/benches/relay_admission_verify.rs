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
//! # Why the door's bodies and not the primitives
//!
//! The quantity is what **pool admission** costs, so the bench calls the
//! bodies the pool door runs (`shekyl-mempool`'s `door::stateless` →
//! `shekyl_chain_rules::judge_lone_stateless` → `judge_slot_stateless` at
//! `TxSlot::Lone`), in the order it runs them: CEN-H17's mask rule
//! (`shekyl_ct_balance::check_commitment_masks`), then CEN-I15's proof
//! (`shekyl_fcmp::proof::verify`). A primitive-level bench drifts from that
//! the moment the calling code changes — the same reason `peers` needed a
//! Rust owner rather than a mirrored `#define` (§70.3). Why the bodies and
//! not `judge_lone_stateless` itself: the fixture is a real proof, not a
//! consensus-valid transaction (`common/relay_admission_fixture.rs`).
//!
//! Two boundaries this states, both from §72, and what the Rust door does
//! with each:
//!
//! - **Pool admission, and the block path is not cheaper.** `form` judges
//!   every listed transaction with the same `judge_slot_stateless` and never
//!   takes the pool's prior pass (E5-Q8), so a connected block verifies every
//!   proof it carries whether or not the pool held the transaction. CEN-M8's
//!   cache spares only the pool's *re*-judgement of a transaction whose
//!   claim has not moved. The block path is GAP-7's subject
//!   (`block_connect_verify.rs`), not `hop`.
//! - **The door does verify ML-DSA-65.** §72.2 excluded a lattice term on
//!   the ground that the PQ material enters only as the leaf key scalar bound
//!   into the proof. On the Rust door that ground is gone: `judge_slot_stateless`
//!   runs CEN-I17/I18 — one hybrid Ed25519+ML-DSA-65 verification per input
//!   — before the proof, and at `Lone` the range proof as a batch of one
//!   (CEN-H19) after it. This sequence keeps the masks-and-proof pair the
//!   surface below was measured on, and the drift gate's subject; the two
//!   further terms are timed per input and per proof by
//!   `block_connect_verify.rs`'s `block_connect_terms` group (dev box
//!   2026-09-04: 178 µs per hybrid verification, 2.82 ms for a 2-output
//!   range proof, against 22.8 ms for this pair at 1-in/2-out). `hop`'s
//!   verification term is the sum, not this pair alone.
//!
//! # What it does *not* measure, by design
//!
//! **Batch depth.** A received 2002 batch is admitted one transaction at a
//! time — the relay owner's `Port::new_transactions` (`shekyl-relay`) calls
//! its `PoolDoor` per blob, and the node's door (`shekyl-node`
//! `pool_door.rs`) runs `shekyl-mempool`'s `stateless` on each — and only
//! then forwards the admitted ones, so a batch of `N` pays `N` verifications
//! before *any* forward. Depth is a free parameter, so it is a multiplier in
//! the derivation — `(N+1)/2` at the mean position, `N` for the worst-placed
//! transaction — never a bench dimension (§72.4).
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
//! **The door does not use it.** `proof::verify` finalizes its own batch
//! verifiers per call, and the door calls it once per transaction, so the
//! implementation verifies serially and `hop` measures the implementation,
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
//! The result is a **surface, not a scalar**: 64 cells over `n_in ∈ 1..=8`
//! crossed with the eight depth/layout rows swept below.
//!
//! **`n_out` is not one of the axes** — it is pinned at the modal 2. §72.3
//! measured that term at ~0.07 ms per output, an order below the cell-to-cell
//! spread on either real axis, so sweeping it would buy a third dimension that
//! cannot move the constant and would dilute the one §79 is about. Naming it
//! as an axis here would misdescribe what the numbers cover.
//!
//! Collapsing the surface to the constant is a separate step and must use the
//! *effective* scalar over the shape distribution, never the p90 of any single
//! cell — otherwise §66's compounding error reappears one level down, inside
//! `hop`.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand_core::OsRng;

#[path = "common/relay_admission_fixture.rs"]
mod relay_admission_fixture;

use relay_admission_fixture::{admission_verify, build_fixture, ChunkLayout};

fn bench_admission(c: &mut Criterion) {
    let mut group = c.benchmark_group("relay_admission_verify");
    // A verification is not amortisable across a batch, so sample counts stay
    // low and the wall-clock figure is per-transaction by construction.
    group.sample_size(10);

    // Depth 2 is production's SHALLOWEST tree (`tree.rs`: a non-empty tree
    // yields depth >= 2). Depth 1 is retained as the sub-production floor the
    // first sweep measured, so the pair gives the per-layer slope — the term
    // that grows monotonically with the chain and has no code change to gate on.
    for (tree_depth, layout, tag) in [
        (1u8, ChunkLayout::Shared, "d1"),
        (2u8, ChunkLayout::Shared, "d2"),
        // §76.1's owed measurement: production spends are scattered, so each
        // input walks its OWN path. `f`'s per-input term is built from this
        // marginal, so the layout must be measured rather than assumed. At
        // n_in = 1 the two layouts are identical by construction, which makes
        // that cell a built-in control on the comparison.
        (2u8, ChunkLayout::Spread, "d2spread"),
        // Capacity tiers (§72): depth 3..=7 cover 1,444 / 25,992 / 987,696 /
        // 17.8M / 675M outputs. PROJECTIONS, not measurements (§81.2) --
        // synthesized trees under genesis-era conditions.
        (3u8, ChunkLayout::Spread, "d3proj"),
        (4u8, ChunkLayout::Spread, "d4proj"),
        (5u8, ChunkLayout::Spread, "d5proj"),
        (6u8, ChunkLayout::Spread, "d6proj"),
        (7u8, ChunkLayout::Spread, "d7proj"),
    ] {
        // Outputs are pinned at the modal 2: §72.3 measured that axis at
        // ~0.07 ms each, which cannot move the constant, and holding it fixed
        // keeps this sweep on the axis §79 is about.
        let n_out = 2usize;
        // EXHAUSTIVE over the consensus domain. `shekyl_wire::transaction::
        // MAX_FCMP_INPUTS = 8` and `shekyl_fcmp::MAX_INPUTS = 8` agree, and the
        // cap is enforced at three layers: consensus (CEN-I4,
        // `shekyl-chain-rules` `rules/tx_inputs.rs`), the wire's `validate`,
        // and `proof::verify` itself.
        //
        // So there is no functional form to choose and nothing to extrapolate:
        // the domain has EIGHT points, and measuring all of them makes the
        // surface itself the specification (§80).
        for n_in in 1usize..=8 {
            // Wall-clock timing averages over many samples, so a fresh random
            // fixture each build is fine (and closer to production variety). The
            // instruction-count sibling (`relay_admission_verify_iai`) pins a
            // seed instead, because Callgrind counts must be byte-reproducible.
            let fixture = build_fixture(&mut OsRng, n_in, n_out, tree_depth, layout);

            // Self-witnessing: a fixture that does not verify would make every
            // timing below a measurement of the rejection path. The status
            // carries both results, so a failure names which check refused.
            let status = admission_verify(&fixture);
            assert!(
                status.verified(),
                "fixture must VERIFY, or the bench times the reject path \
                 ({tag}, n_in={n_in}, n_out={n_out}): {status:?}"
            );

            group.throughput(Throughput::Elements(n_in as u64));
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{tag}_in{n_in}_out{n_out}")),
                &fixture,
                |b, f| b.iter(|| admission_verify(f)),
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_admission);
criterion_main!(benches);
