// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! GAP-7 instrument: worst-case **COLD-block** connect-verification cost.
//!
//! # The subject is the cold block, and that is the whole instrument
//!
//! A block whose transactions came through our pool measures the CHEAP
//! traversal: the block path deliberately skips `shekyl_fcmp_verify` because
//! admission already verified (CEN-M8's hash-gated skip), so a warm-block
//! bench returns a comforting number that **cannot fail on GAP-7's axis**.
//! The states that produce cold blocks — every tx unseen — are exactly the
//! two GAP-7 cares about:
//!
//! 1. **Initial sync on the provisioning floor** (rule 76: Raspberry Pi 4),
//!    where every historical block arrives cold; and
//! 2. **the withhold-then-announce adversary**, who keeps transactions out of
//!    relay and announces a full block, forcing the whole verification bill
//!    at connect time.
//!
//! # SHAPE, NOT FLOOR — rule 76 §3/§4, do not misread these numbers
//!
//! This bench runs on a development machine and establishes **which component
//! dominates and how cost scales with the constants census-C2 R2 ratifies**.
//! It is NOT a floor measurement and must never be presented as one:
//!
//! - *"Any constant derived from measured work time is provisioned at the
//!   floor device, not at the machine that happened to be available"*
//!   (rule 76 §1) — record the machine beside every number.
//! - *"Cross-machine ratios are measured, never assumed"* (§3).
//! - *"Values AND INCREMENTS for the floor device are measured ON it, never
//!   scaled to it"* (§4) — the rule's own counter-example saw aggregate
//!   ratios of 5.36–5.75× while the per-layer MARGINAL ratio was 5.98×, so
//!   scaling an increment by an aggregate ratio under-provisions invisibly.
//!
//! GAP-7's hardware half therefore stays OPEN whatever this reports; the
//! point of this file is that a Pi arriving tomorrow has something to run.
//!
//! # What is measured, mapped to the sites that pay it
//!
//! Per transaction, at shape `(n_in, n_out)`:
//!
//! - **`adm`** — `shekyl_check_commitment_masks` + `shekyl_fcmp_verify`, the
//!   admission pair `blockchain.cpp` calls (via the relay bench's fixture;
//!   its 64-cell depth/layout surface owns the tree-depth axis — this bench
//!   pins depth 2 / `Spread`, today's production topology, and does not
//!   re-sweep that axis).
//! - **`pqc`** — one hybrid Ed25519+ML-DSA-65 verification
//!   (`shekyl_pqc_verify`), which the daemon runs **per input**
//!   (`verify_transaction_pqc_auth`, `blockchain.cpp:4342`; CEN-I18) for
//!   every non-serve-credit v3 tx. The relay bench excluded this term
//!   because *its* calls never pay it; the connect path does.
//! - **`bp_proxy`** — Bp+ aggregate verification over `n_out` commitments.
//!   **PROXY**: the Rust verifier (`shekyl-bulletproofs`), sibling of the
//!   production prover — the SHIPPED verifier is the inherited C++
//!   `bulletproofs_plus.cc` (CEN-H19) and is invisible to a Rust bench. The
//!   proxy answers the SHAPE question (does output-density compete with
//!   input-density); its absolute cost does not discharge CEN-H19.
//!   **Escalation rule: if the proxy lands within ~10× of the top term, a
//!   C++ microbench of the shipped verifier is owed before any dominance
//!   conclusion** — an inherited C++ verifier can plausibly be several
//!   times slower than a modern Rust one, so a proxy well below the top
//!   term could still BE the top term in the shipped path.
//! - **`parse`** — `Transaction::from_bytes` on the fixture's wire bytes.
//!
//! Per block: **`randomx_once`** — one PoW hash (`compute_hash` against a
//! prepared cache; cache derivation is epoch-scoped and amortized out).
//!
//! # Budget fill and the marginal rule
//!
//! `budget_fill` runs the FULL per-tx term set N times at measured budget
//! points (N = budget / weight(shape), duplicated fixtures — legitimate
//! because none of the measured calls hold cross-tx caches; key-image
//! uniqueness is DB-side, CEN-L1, outside them). Points span 600 000 (2× the
//! penalty-free zone — the permanent floor operating point) up to 4 800 000;
//! the 30 MB surge ceiling (`2 × 50 × LTEM`, census CEN-G6/G6b) is reported
//! by extrapolation from the measured MARGINAL cost per weight-byte across
//! these points — never from two endpoints — with the measured span stated
//! beside it (data to 4.8 MB; 30 MB is 6.25× beyond the last measured
//! point). A linearity failure across the points is a finding, not an
//! obstacle, and the multi-point design exists so the instrument can see one.
//!
//! # Fences
//!
//! Archival families (serve-credit / bond-post / emission) are OUT of this
//! first cut, **as reasoning, not verified impossibility**: their admission
//! requires consensus-valid archival state — a bonded `P` identity, a sealed
//! challenge, the epoch window (CEN-J7, CEN-J10; bond floor
//! `archival_bond_floor_atomic`) — so an adversary cannot pack them to the
//! weight cap the way spends pack, and their honest density is settlement-
//! cadence-bounded. **Reopener:** if archival load at scale approaches
//! weight-cap density, they carry hybrid signature verification per vin and
//! must enter the argmax. The pins test asserts the spend fixtures saturate
//! the caps they claim; nothing asserts archival absence — it is a scope
//! fence, stated.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand_core::OsRng;

#[path = "block_connect_fixture.rs"]
mod block_connect_fixture;

use block_connect_fixture::{
    bp_verify, build_connect_tx, parse_wire, pqc_verify_code, relay::admission_verify,
    relay::ChunkLayout, relay::ADMISSION_OK, ConnectTxFixture,
};

/// The candidate worst-case shapes. The argmax must EMERGE from the sweep —
/// these are the two density extremes plus the interior, not a presumed
/// winner.
const SWEEP_SHAPES: [(usize, usize); 6] = [
    (1, 2),  // modal control (relay bench's pinned shape)
    (8, 2),  // max input density — fcmp + pqc heavy
    (1, 16), // max output density — bp + extra heavy
    (8, 16), // both caps
    (4, 4),  // interior
    (2, 8),  // interior
];

/// Today's production topology: depth 2, scattered inputs. The depth axis is
/// the relay bench's surface (its d1..d7 sweep); re-sweeping it here would
/// duplicate an instrument.
const TREE_DEPTH: u8 = 2;

fn full_tx_verify(fx: &ConnectTxFixture) {
    // Shape agreement between the crypto fixtures and the wire form — the
    // same pin the tests carry, kept live where the timing happens.
    assert_eq!(fx.bp.commitments.len(), fx.n_out);
    let parsed = parse_wire(fx);
    std::hint::black_box(parsed);
    assert_eq!(admission_verify(&fx.adm), ADMISSION_OK);
    for _ in 0..fx.n_in {
        assert_eq!(pqc_verify_code(&fx.pqc), 0);
    }
    assert!(bp_verify(&fx.bp));
}

fn bench_terms(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_connect_terms");
    group.sample_size(10);

    for (n_in, n_out) in SWEEP_SHAPES {
        let fx = build_connect_tx(&mut OsRng, n_in, n_out, TREE_DEPTH, ChunkLayout::Spread);

        // Self-witness every component or the bench times a reject path.
        assert_eq!(admission_verify(&fx.adm), ADMISSION_OK);
        assert_eq!(pqc_verify_code(&fx.pqc), 0);
        assert!(bp_verify(&fx.bp));

        let tag = format!("in{n_in}_out{n_out}_w{}", fx.weight);
        group.throughput(Throughput::Bytes(fx.weight as u64));

        group.bench_with_input(BenchmarkId::new("adm", &tag), &fx, |b, f| {
            b.iter(|| admission_verify(&f.adm))
        });
        group.bench_with_input(BenchmarkId::new("pqc_per_input", &tag), &fx, |b, f| {
            b.iter(|| pqc_verify_code(&f.pqc))
        });
        group.bench_with_input(BenchmarkId::new("bp_proxy", &tag), &fx, |b, f| {
            b.iter(|| bp_verify(&f.bp))
        });
        group.bench_with_input(BenchmarkId::new("parse", &tag), &fx, |b, f| {
            b.iter(|| parse_wire(f))
        });
    }

    group.finish();
}

fn bench_budget_fill(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_connect_budget_fill");
    group.sample_size(10);

    // The two density extremes; the sweep decides which is the argmax.
    for (n_in, n_out, shape_tag) in [(8usize, 2usize, "in8_out2"), (1usize, 16usize, "in1_out16")] {
        let fx = build_connect_tx(&mut OsRng, n_in, n_out, TREE_DEPTH, ChunkLayout::Spread);
        assert_eq!(admission_verify(&fx.adm), ADMISSION_OK);
        assert_eq!(pqc_verify_code(&fx.pqc), 0);
        assert!(bp_verify(&fx.bp));

        // Multi-point span so the marginal per-byte cost is MEASURED, not
        // inferred from endpoints (rule 76 §4's failure mode within one
        // machine). 600 000 = 2 × zone, the permanent floor operating point.
        for budget in [600_000usize, 1_200_000, 2_400_000, 4_800_000] {
            let n_txs = budget / fx.weight;
            assert!(n_txs >= 1, "budget below one tx weight");
            group.throughput(Throughput::Bytes((n_txs * fx.weight) as u64));
            group.bench_with_input(
                BenchmarkId::new(shape_tag, format!("budget{budget}_n{n_txs}")),
                &fx,
                |b, f| {
                    b.iter(|| {
                        for _ in 0..n_txs {
                            full_tx_verify(f);
                        }
                    })
                },
            );
        }
    }

    group.finish();
}

fn bench_randomx_once(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_connect_pow");
    group.sample_size(10);

    // Cache derivation is epoch-scoped (once per seed epoch, amortized over
    // thousands of blocks) — derived in setup, deliberately outside the
    // per-block figure. The per-block PoW term is one compute_hash.
    let prepared = shekyl_pow_randomx::PreparedCache::derive(
        shekyl_pow_randomx::Seedhash::from_bytes([7u8; 32]),
    );
    let header = [0x5Au8; 80];

    group.bench_function("randomx_once_per_block", |b| {
        b.iter(|| shekyl_pow_randomx::compute_hash(&prepared, &header))
    });

    group.finish();
}

criterion_group!(benches, bench_terms, bench_budget_fill, bench_randomx_once);
criterion_main!(benches);
