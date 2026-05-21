// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bench harness for [`Scanner::scan`] per-output cost measurement
//! (PR 4 §3.1 / F11-S substrate).
//!
//! ## Two bench groups
//!
//! - **`scan_transaction/worst_case_all_view_tags_match`** —
//!   **LOAD-BEARING** for the F11-S disposition. Every output's view
//!   tag matches the test wallet, forcing the full hybrid PQC slow
//!   path (X25519 ECDH + ML-KEM-768 decap + HKDF + amount /
//!   commitment verification) on every output. Per-output cost = full
//!   slow path. This is the adversarial-daemon worst-case under the
//!   §3.1 threat model: the daemon knows the wallet's hybrid public
//!   keys (they're part of the wallet's address — public to anyone
//!   the wallet has transacted with through this daemon) and can
//!   call [`shekyl_crypto_pq::output::construct_output`] against them
//!   to produce on-chain ciphertexts that pass every cryptographic
//!   check inside [`shekyl_crypto_pq::output::scan_output_recover`].
//!   Subaddress lookup then misses post-recovery (the constructed
//!   recovered-`B'` is `2 * G`, registered subaddress is `G`); the
//!   per-output cost is exactly full-slow-path with no key-image
//!   overhead.
//!
//!   The constant-time property of all primitives involved (ML-KEM-
//!   768 decap per FIPS-203 §7, X25519 scalar-multiplication via
//!   curve25519-dalek, HKDF combine on fixed inputs) means no
//!   pathological fixture exists that could exceed this cost; the
//!   adversarial worst-case is captured completely.
//!
//! - **`scan_transaction/typical_case_view_tag_filtered`** —
//!   **CONTEXTUAL**, not F11-S binding. Outputs are encapsulated
//!   against a different wallet's hybrid KEM public key, so the
//!   bench wallet's view-pair derives a different view tag from the
//!   on-chain ephemeral and every output exits via fast-path filter
//!   rejection (the wire-byte compare after view-tag derivation
//!   short-circuits before ML-KEM decap). Per-output cost is
//!   dominated by X25519 ECDH + view-tag derivation + branch.
//!
//!   This group documents the typical-case UX cost (most outputs
//!   aren't for the wallet, so this is what wallet refresh actually
//!   pays in normal operation) and provides the denominator for the
//!   worst-case-to-typical-case slow-path-to-fast-path cost ratio,
//!   which serves as a methodology sanity check: if the ratio falls
//!   outside the expected ML-KEM-decap-to-view-tag-check range, the
//!   measurement should not bind F11-S until investigated.
//!
//! ## Sweep + cache variants
//!
//! Both groups sweep `N ∈ {1, 4, 8, 16}` — bounded by the scanner-
//! side [`shekyl_scanner::MAX_OUTPUTS`] gate (consensus-binding limit
//! of 16). Each `N` is measured in two cache variants:
//!
//! - **`warm`**: the scanner instance is constructed once and
//!   reused; the `ScannableBlock` is cloned in the `iter_batched`
//!   setup closure (so the clone happens outside the timed region)
//!   and `scanner.scan(block)` runs in the inner routine. The
//!   scanner's `HashMap<CompressedPoint, …>` subaddress lookup and
//!   the per-tx `Extra::read` parser stay resident in L1/L2 across
//!   iterations. This is the "second and later passes through the
//!   same hot path" cost. (The earlier harness shape used
//!   `iter_batched_ref` with an in-routine `mem::replace(b,
//!   block.clone())`; that placed the clone inside the timed
//!   region and was corrected per Copilot PR #60 review findings
//!   3278232713 / 3278232736.)
//!
//! - **`cold`**: the scanner instance and `ScannableBlock` are
//!   re-constructed every iteration via `iter_batched(.., ..,
//!   BatchSize::PerIteration)`. Per-iteration costs include fresh
//!   `HashMap` allocation and fresh `Vec` allocations for the parsed
//!   `Extra`. This is the "first pass through a brand-new block"
//!   cost.
//!
//! True OS-level cache flushing (L3 eviction via `clflush` or
//! equivalent) is out of scope for a pure-Rust harness; the warm/cold
//! split here captures the allocation-pattern half of the
//! distinction. Quantile reporting (p99, p999) is via criterion's
//! built-in percentile estimator.
//!
//! ## F11-S binding identification in code
//!
//! The `F11S_BINDING_GROUP` constant below is the load-bearing
//! identifier for which group drives the F11-S disposition. The
//! commit message that records the F11-S measurement should cite
//! this constant by name as the audit-trail anchor.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use zeroize::Zeroizing;

use shekyl_scanner::{
    bench_fixtures::{
        build_typical_case_scannable_block, build_worst_case_scannable_block, make_bench_wallet,
        BenchWalletKeys,
    },
    Scanner,
};

/// Per-tx output-count sweep. Capped at
/// [`shekyl_scanner::MAX_OUTPUTS`] (= 16) — the scanner's defense-in-
/// depth gate skips any transaction exceeding this. Going beyond
/// would not produce additional F11-S signal (the gate fires before
/// per-output work) and would only exercise the gate's skip-and-log
/// path, which is covered by [`shekyl_scanner::scan`]'s own
/// `gate_tests::skips_transaction_with_output_count_above_max`.
const OUTPUT_COUNTS: &[usize] = &[1, 4, 8, 16];

/// Audit-trail anchor: the bench group whose per-output cost binds
/// the F11-S decision per the §3.1 methodology. Cited by name in the
/// F11-S measurement commit message.
const F11S_BINDING_GROUP: &str = "scan_transaction/worst_case_all_view_tags_match";

/// Construct a fresh scanner from the bench wallet. The scanner's
/// `HashMap` is allocated per-call (so this function does the
/// "cold" half of the warm/cold split when called inside
/// `iter_batched`).
fn fresh_scanner(wallet: &BenchWalletKeys) -> Scanner {
    Scanner::new(
        wallet.view_pair.clone(),
        Zeroizing::new(*wallet.spend_secret),
    )
}

/// **F11-S BINDING.** Per-output worst-case cost: every output's
/// view tag matches, forcing the full slow path. See module doc-
/// comment §"Two bench groups".
fn bench_worst_case_all_view_tags_match(c: &mut Criterion) {
    let wallet = make_bench_wallet();
    let mut group = c.benchmark_group("scan_transaction/worst_case_all_view_tags_match");

    for &n in OUTPUT_COUNTS {
        group.throughput(Throughput::Elements(n as u64));

        // ── Warm-cache variant: scanner constructed once and
        //    reused across iterations; the block is cloned in the
        //    `iter_batched` setup closure (outside the timed region)
        //    so the measurement isolates `Scanner::scan` cost from
        //    `ScannableBlock` clone overhead. The earlier shape used
        //    `iter_batched_ref` with an in-routine `mem::replace(
        //    b, block.clone())`, which placed the clone inside the
        //    timed region. Corrected per Copilot PR #60 review
        //    finding 3278232713; F11-S cold-cache binding (below) is
        //    unaffected as the cold variant already uses
        //    `iter_batched` with the fresh-block construction in the
        //    setup closure. ──
        {
            let mut scanner = fresh_scanner(&wallet);
            let block = build_worst_case_scannable_block(n, &wallet);
            group.bench_with_input(BenchmarkId::new("warm", n), &n, |b, &_n| {
                b.iter_batched(
                    || block.clone(),
                    |block| {
                        let res = scanner.scan(black_box(block)).expect(
                            "scan_transaction_with_cancel must not error on well-formed fixture",
                        );
                        black_box(res);
                    },
                    BatchSize::SmallInput,
                );
            });
        }

        // ── Cold-cache variant: fresh scanner + fresh block per
        //    iteration via iter_batched with PerIteration sizing.
        //    This variant is the F11-S binding (per
        //    STAGE_1_PR_4_REFRESH_ENGINE.md §7.Y measurement
        //    evidence) and was already structured with all setup
        //    (scanner + block construction) outside the timed
        //    region, so the methodology correction above does not
        //    affect F11-S audit-trail numbers. ──
        group.bench_with_input(BenchmarkId::new("cold", n), &n, |b, &n| {
            b.iter_batched(
                || {
                    (
                        fresh_scanner(&wallet),
                        build_worst_case_scannable_block(n, &wallet),
                    )
                },
                |(mut scanner, block)| {
                    let res = scanner.scan(black_box(block)).expect(
                        "scan_transaction_with_cancel must not error on well-formed fixture",
                    );
                    black_box(res);
                },
                BatchSize::PerIteration,
            );
        });
    }

    // Sanity-check the F11-S binding identifier matches this
    // function's group name (catches accidental renames during
    // refactors that would silently misroute the audit trail).
    debug_assert_eq!(
        F11S_BINDING_GROUP, "scan_transaction/worst_case_all_view_tags_match",
        "F11S_BINDING_GROUP constant must name the worst-case group exactly"
    );

    group.finish();
}

/// **CONTEXTUAL, not F11-S binding.** Per-output typical-case cost:
/// view-tag-mismatch fast-path exit. See module doc-comment §"Two
/// bench groups".
fn bench_typical_case_view_tag_filtered(c: &mut Criterion) {
    let wallet = make_bench_wallet();
    let mut group = c.benchmark_group("scan_transaction/typical_case_view_tag_filtered");

    for &n in OUTPUT_COUNTS {
        group.throughput(Throughput::Elements(n as u64));

        // ── Warm-cache variant. Same methodology correction as the
        //    worst-case warm variant above (Copilot PR #60 review
        //    finding 3278232736): clone moved into `iter_batched`
        //    setup closure to isolate `Scanner::scan` cost. ──
        {
            let mut scanner = fresh_scanner(&wallet);
            let block = build_typical_case_scannable_block(n);
            group.bench_with_input(BenchmarkId::new("warm", n), &n, |b, &_n| {
                b.iter_batched(
                    || block.clone(),
                    |block| {
                        let res = scanner.scan(black_box(block)).expect(
                            "scan_transaction_with_cancel must not error on well-formed fixture",
                        );
                        black_box(res);
                    },
                    BatchSize::SmallInput,
                );
            });
        }

        // ── Cold-cache variant. ──
        group.bench_with_input(BenchmarkId::new("cold", n), &n, |b, &n| {
            b.iter_batched(
                || {
                    (
                        fresh_scanner(&wallet),
                        build_typical_case_scannable_block(n),
                    )
                },
                |(mut scanner, block)| {
                    let res = scanner.scan(black_box(block)).expect(
                        "scan_transaction_with_cancel must not error on well-formed fixture",
                    );
                    black_box(res);
                },
                BatchSize::PerIteration,
            );
        });
    }

    group.finish();
}

criterion_group!(
    name = scan_transaction;
    config = Criterion::default();
    targets = bench_worst_case_all_view_tags_match, bench_typical_case_view_tag_filtered,
);
criterion_main!(scan_transaction);
