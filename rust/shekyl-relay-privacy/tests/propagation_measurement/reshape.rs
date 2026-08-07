// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Measurement instruments — reshape family.
//!
//! Part of the `propagation_measurement` suite. Run with `--nocapture` for tables.

#![allow(clippy::cast_precision_loss)]

use shekyl_relay_privacy::params::DandelionParams;
use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;
use shekyl_relay_privacy::{EmbargoTimer, SplitMix64};

/// **Round 3 — can we reach ≤0.3% exposure by tuning the levers together, and
/// which lever does it efficiently?** The passive leak decomposes as
/// `P(preempt) × neighbour × origin-attribution`, and every term is a separate
/// lever: the embargo mean (moved), the fluff-return `F` (F-4's second, unspotted
/// correction), `q` (deferred), and the reshape mechanism (Q-8a). This measures
/// the worst-case (whole-prefix supernode) origin exposure and shows reshape is
/// the efficient lever — it hits the target without the liveness cost of a
/// longer embargo.
#[test]
fn origin_exposure_meets_target_via_reshape_not_embargo() {
    use shekyl_relay_privacy::conformance::simulate_origin_exposure;

    const TARGET: f64 = 0.003; // ≤ 0.3% exposure = ≥ 99.7% protected
    let base = DandelionParams::inherited();
    let e144 = EmbargoTimer::geometric_from_ticks(576, DEFAULT_EMBARGO_TICK_MILLIS);

    // (1) Reshape retry cap — the efficient lever, no embargo lengthening.
    println!(
        "\nWorst-case origin exposure vs reshape retry cap (embargo 144s, whole-prefix supernode)"
    );
    let r0 =
        simulate_origin_exposure(&base, &e144, 0, 400_000, &mut SplitMix64::new(1)).exposure_rate;
    let r1 =
        simulate_origin_exposure(&base, &e144, 1, 400_000, &mut SplitMix64::new(2)).exposure_rate;
    let r2 =
        simulate_origin_exposure(&base, &e144, 2, 400_000, &mut SplitMix64::new(3)).exposure_rate;
    println!("  retry_cap=0 (current): {r0:.5}  ({:.2}%)", r0 * 100.0);
    println!("  retry_cap=1 (reshape): {r1:.5}  ({:.3}%)", r1 * 100.0);
    println!("  retry_cap=2 (reshape): {r2:.5}  ({:.3}%)", r2 * 100.0);
    assert!(
        r0 > TARGET,
        "current design should be above target worst-case: {r0:.5}"
    );
    assert!(
        r1 < TARGET,
        "one reshape retry should meet the target: {r1:.5}"
    );
    assert!(
        r1 < r0 / 10.0,
        "reshape should drop exposure by an order of magnitude+"
    );

    // (2) F is a lever, and F-4 already moved it (memoryless flood ≪ Poisson).
    println!("\nExposure vs fluff-return F (embargo 144s, no reshape) — F-4's second correction");
    let f_lo = {
        let p = DandelionParams {
            fluff_return_ms: 2_250,
            ..base
        };
        simulate_origin_exposure(&p, &e144, 0, 300_000, &mut SplitMix64::new(4)).exposure_rate
    };
    let f_hi = {
        let p = DandelionParams {
            fluff_return_ms: 13_750,
            ..base
        };
        simulate_origin_exposure(&p, &e144, 0, 300_000, &mut SplitMix64::new(5)).exposure_rate
    };
    println!("  F=2250ms  (memoryless, F-4 fixed): {f_lo:.5}");
    println!("  F=13750ms (inherited Poisson flood): {f_hi:.5}");
    assert!(
        f_hi > f_lo * 3.0,
        "F is a lever: the inherited Poisson flood exposed several-fold more ({f_hi:.5} vs {f_lo:.5})"
    );

    // (3) The embargo-only path to the target is a liveness disaster — the
    // inefficient lever, for contrast.
    //
    // The thesis is that the target is NOT reachable at a liveness-plausible
    // mean. F-7's "0 s" artifact (§44) is the cautionary history here: at
    // F′ = 3250 no rung of the old [144..1050] ladder reached the target, the
    // sentinel stayed 0, and "got 0s" was reported as if the solve had gone
    // trivial when it had gone infeasible. The ladder now extends to 2100 s,
    // the solve is reachable again (~1500 s, §14's re-measured pin), and the
    // leg asserts unconditionally below — a never-reached ladder must fail
    // loudly, because it is indistinguishable in shape from an exposure model
    // that stopped responding to the embargo lever.
    println!("\nEmbargo-only path to the target (no reshape) — the INEFFICIENT lever");
    let mut embargo_only_secs: Option<u32> = None;
    for secs in [144_u32, 300, 600, 1050, 1500, 2100] {
        let ticks = u32::try_from(u64::from(secs) * 1000 / DEFAULT_EMBARGO_TICK_MILLIS).unwrap();
        let e = EmbargoTimer::geometric_from_ticks(ticks, DEFAULT_EMBARGO_TICK_MILLIS);
        let x =
            simulate_origin_exposure(&base, &e, 0, 300_000, &mut SplitMix64::new(u64::from(secs)))
                .exposure_rate;
        let p90_recovery = f64::from(ticks) * 2.302 * DEFAULT_EMBARGO_TICK_MILLIS as f64 / 1000.0;
        println!("  embargo={secs:>4}s: exposure {x:.5}, p90 origin recovery ~{p90_recovery:.0}s");
        if x < TARGET && embargo_only_secs.is_none() {
            embargo_only_secs = Some(secs);
        }
    }
    let embargo_only_secs = embargo_only_secs.expect(
        "embargo-only never reached the target on the [144..2100] ladder — §14 pins \
         ~1500 s. A broken exposure model (stuck high at every rung) lands exactly \
         here; if a future re-measure legitimately pushes the solve past 2100 s, \
         extend the ladder and re-pin rather than making this leg conditional",
    );
    assert!(
        embargo_only_secs >= 600,
        "embargo-only reached the target at {embargo_only_secs}s — a liveness-plausible \
         mean here would undermine the reshape adoption argument (§14)"
    );

    println!(
        "\n  Answer: ≤0.3% worst-case exposure is reachable, and reshape (Q-8a)\n  \
         reaches it EFFICIENTLY — one retry takes {r0:.4} → {r1:.5} with NO\n  \
         embargo lengthening (cost is ~1 extra stem hop of latency). The\n  \
         embargo-only path needs ~{embargo_only_secs}s (p90 recovery ~{:.0}s,\n  \
         several× MIN_RELAY_TIME) and would break the P2P liveness the mechanism\n  \
         depends on. So the levers tune together as: keep the embargo at its\n  \
         derived 190s (the black-hole backstop — the 144s point measured above\n  \
         is pre-F-7, and reshape meets the target even there), F already\n  \
         handled by F-4, reshape carries the origin-exposure target. ε is a\n  \
         target on the COMPOSED leak with freedom in (embargo, F, reshape) —\n  \
         it must not over-constrain the embargo to carry the whole burden.",
        f64::from(embargo_only_secs) * 2.302
    );
}

/// **§13 verified by re-run — verification, not a decision target.** The δ
/// increment-form adopt-criterion, measured end-to-end (RD-4 stem support,
/// STEMS=2, 144 s embargo) rather than composed by hand. Reproduces the review's
/// table and confirms reshape drives δ→0.
///
/// This test's permanence is the point *and* the hazard: it keeps the number
/// honest (RD-4) but must not be read as canonical decision authority. The leak
/// it pins belongs to *fluff-on-expiry*, which §14 replaces with reshape; picking
/// `ρ`/`δ_max` against this table tunes a leak we remove. The δ a decision is
/// taken against is the W3 residual (two-slot occupancy instrument, §12.5). Kept
/// because RD-4 says measure your numbers — not because every measured number
/// votes.
#[test]
fn precision_increment_reproduces_delta_table() {
    use shekyl_relay_privacy::conformance::simulate_precision_increment;

    let base = DandelionParams::inherited();
    // The ADOPTED configuration: F-7-corrected `fluff_return_ms` and its
    // derived 190 s embargo, obtained through the production derivation path —
    // not a hand-transcribed tick count, so when `fluff_return_ms` next moves
    // this test measures what ships by construction and the δ pins below go
    // red for a deliberate re-pin. The review's table was measured at the
    // F = 2250 / 144 s pair; re-measured here at the shipping pair the values
    // are nearly unchanged (0.0010/0.0021/0.0048 vs 0.0010/0.0019/0.0045)
    // because the derivation lengthens the embargo in step with F, holding the
    // prefix-fire leak at its designed level (§44.3).
    let e = EmbargoTimer::adopted(&base);

    println!("\nδ increment re-run (independent-neighbour lower bound, 190s embargo)");
    println!(
        "{:>6} {:>12} {:>14} {:>12} {:>12}",
        "f", "Prec(C1)", "Prec(C1+C3)", "δ", "review"
    );
    println!("{}", "-".repeat(60));

    // (f, δ at the adopted F′/190 s pair). The review's §13 column
    // (0.0010, 0.0019, 0.0045 at F=2250/144 s) is retained in the printout
    // header comment above; the pinned values are the shipping pair's.
    let cases = [(0.05_f64, 0.0010), (0.10, 0.0021), (0.30, 0.0048)];
    for (i, (f, review_delta)) in cases.iter().enumerate() {
        let mut rng = SplitMix64::new(0xD17A + i as u64);
        let p = simulate_precision_increment(&base, &e, *f, 0, 1_000_000, &mut rng);
        println!(
            "{f:>6.2} {:>12.4} {:>14.4} {:>12.4} {review_delta:>12.4}",
            p.precision_c1, p.precision_c1_c3, p.delta
        );

        // Precision(C1) ≈ f, by construction (the origin's successor is a spy).
        assert!(
            (p.precision_c1 - f).abs() < 0.003,
            "Precision(C1) should be ~f: {:.4} vs {f}",
            p.precision_c1
        );
        // δ reproduces the review's value (Monte-Carlo band).
        assert!(
            (p.delta - review_delta).abs() < 0.0005,
            "δ at f={f} was {:.4}, adopted-pair pin has {review_delta}",
            p.delta
        );
    }

    // §13.4: reshape (retry_cap=1) drives δ toward zero — the residual is only
    // the both-slots-adversarial cases (W3), which this independent model does
    // not include, so it collapses to near-zero here.
    let mut rng = SplitMix64::new(0xBEEF);
    let reshaped = simulate_precision_increment(&base, &e, 0.30, 1, 1_000_000, &mut rng);
    println!(
        "\n  reshape (cap=1) at f=0.30: δ = {:.5} (was 0.0047 without) — reshape drives δ→0",
        reshaped.delta
    );
    assert!(
        reshaped.delta < 0.0003,
        "reshape should collapse δ toward zero, got {:.5}",
        reshaped.delta
    );
}

/// **§14 — reshape's recovery latency is a cost, not a break.** The one place
/// "reshape strictly dominates fluff-on-expiry under the priority order" can
/// fail: if re-stem recovery is *catastrophic* (not merely worse), it becomes a
/// liveness problem that outranks performance. It is not — the cap bounds it.
#[test]
fn reshape_recovery_is_a_cost_not_a_break() {
    use shekyl_relay_privacy::conformance::simulate_reshape_recovery;

    let e = EmbargoTimer::geometric_from_ticks(576, DEFAULT_EMBARGO_TICK_MILLIS); // 144 s
    let mut rng = SplitMix64::new(0x5EC0);
    let r = simulate_reshape_recovery(&e, 1, 300_000, &mut rng);

    const MEMPOOL_LIVETIME_S: f64 = 86_400.0 * 3.0; // CRYPTONOTE_MEMPOOL_TX_LIVETIME
    const MIN_RELAY_S: f64 = 300.0;

    println!("\nRecovery latency for a black-holed tx (embargo 144s, cap=1)");
    println!(
        "  fluff-on-expiry (1 cycle):    p50 {:.0}s  p90 {:.0}s  p99 {:.0}s",
        r.fluff_p50_s, r.fluff_p90_s, r.fluff_p99_s
    );
    println!(
        "  reshape worst case (W3, 2c):  p50 {:.0}s  p90 {:.0}s  p99 {:.0}s",
        r.reshape_worst_p50_s, r.reshape_worst_p90_s, r.reshape_worst_p99_s
    );
    println!(
        "  reshape worst p99 = {:.2}% of the 3-day mempool lifetime",
        r.reshape_worst_p99_s / MEMPOOL_LIVETIME_S * 100.0
    );

    // It IS a cost: reshape's worst case exceeds fluff (an extra embargo cycle).
    assert!(
        r.reshape_worst_p99_s > r.fluff_p99_s,
        "reshape worst-case should exceed fluff (it is a real cost)"
    );
    // It is NOT a break: the worst case is a tiny fraction of the tx's lifetime,
    // so the tx always propagates well within its mempool residence.
    assert!(
        r.reshape_worst_p99_s < MEMPOOL_LIVETIME_S * 0.01,
        "reshape worst-case recovery {:.0}s must be << mempool lifetime (a cost, not a break)",
        r.reshape_worst_p99_s
    );
    // And it is bounded by ~(cap+1) embargo means, not unbounded — the whole
    // point of the retry cap.
    assert!(
        r.reshape_worst_p50_s < 4.0 * MIN_RELAY_S,
        "reshape median recovery should stay within a few relay cycles, got {:.0}s",
        r.reshape_worst_p50_s
    );

    println!(
        "\n  Reshape's worst-case recovery (~{:.0}s p99) is {:.2}% of the tx's 3-day\n  \
         mempool lifetime — a cost (a slower recovery, bounded by the retry cap),\n  \
         not a break (the tx never fails to propagate). Fluff-on-expiry already\n  \
         recovers slowly (p99 {:.0}s, the 144s memoryless embargo); reshape's\n  \
         marginal cost is the rare W3 second cycle. The priority order lets us pay\n  \
         this to stop spending privacy on recovery speed.",
        r.reshape_worst_p99_s,
        r.reshape_worst_p99_s / MEMPOOL_LIVETIME_S * 100.0,
        r.fluff_p99_s
    );
}
