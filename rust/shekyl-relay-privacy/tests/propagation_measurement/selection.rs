// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Measurement instruments — selection family.
//!
//! Part of the `propagation_measurement` suite. Run with `--nocapture` for tables.

#![allow(clippy::cast_precision_loss)]

use shekyl_relay_privacy::params::P2P_DEFAULT_OUT_PEERS;
use shekyl_relay_privacy::SplitMix64;

/// **§12 W3 residual — the δ a `ρ` decision is actually taken against (Round-3
/// build 1).** The one exposure reshape cannot route around: an adversary holding
/// *both* of the origin's outbound stem slots (`out_mapping_`). Grounded as an
/// OUTBOUND-occupancy channel (peer selection, the costly direction), not the
/// inbound diffusion reach `simulate_transport_observation` measures — importing
/// that reach would measure a phantom. `D_out` is `P2P_DEFAULT_OUT_PEERS`, consumed
/// from the Rust owner rather than re-typed (§70).
#[test]
fn two_slot_occupancy_is_the_reshape_residual() {
    use shekyl_relay_privacy::conformance::simulate_two_slot_occupancy;

    const D_OUT: usize = P2P_DEFAULT_OUT_PEERS as usize;
    let trials = 1_000_000;

    println!("\nW3 residual: P(adversary holds BOTH outbound stem slots), D_out={D_OUT}");
    println!(
        "{:>8} {:>6} {:>12} {:>14} {:>16}",
        "g", "a", "both (W3)", ">=1 slot", "indep (a/D)^2"
    );
    println!("{}", "-".repeat(60));

    // (g, a) — g is the adversary's OUTBOUND share; a = round(g·12) is the
    // integer peers it holds (carried explicitly to keep the display cast-free).
    let cases: [(f64, usize); 4] = [(0.10, 1), (0.20, 2), (0.30, 4), (0.50, 6)];
    let mut results = Vec::new();
    for (idx, &(g, a)) in cases.iter().enumerate() {
        let mut rng = SplitMix64::new(0x2510_0000 + idx as u64);
        let o = simulate_two_slot_occupancy(g, D_OUT, trials, &mut rng);
        println!(
            "{:>8.2} {:>6} {:>12.4} {:>14.4} {:>16.4}",
            g, a, o.both_slots, o.at_least_one_slot, o.independent_reference
        );
        results.push((g, o));
    }

    // 1. BASELINE (g = f = 0.10): the adversary holds ~1 of 12 outbound peers, so
    //    it CANNOT fill two slots. W3 is essentially zero without enrichment —
    //    the honest finite-pool result the "same enrichment as inbound" framing
    //    missed.
    let (_, base) = &results[0];
    assert!(
        base.both_slots < 0.001,
        "at g=f=0.10 the adversary holds ~1 outbound peer and cannot occupy both \
         stem slots; W3 should be ~0, got {:.4}",
        base.both_slots
    );

    // 2. ANTI-CORRELATION: choosing two DISTINCT peers from a finite pool makes W3
    //    sit strictly below the independent (with-replacement) draw at the same
    //    effective share — bounded above by it, not equal to it.
    for (g, o) in &results {
        if o.both_slots > 0.0 {
            assert!(
                o.both_slots <= o.independent_reference + 1e-3,
                "W3 at g={g:.2} ({:.4}) must sit at/below the independent draw ({:.4})",
                o.both_slots,
                o.independent_reference
            );
        }
    }

    // 3. ENRICHMENT IS REQUIRED and COSTLY: to lift W3 even to the ~0.09 range the
    //    adversary must reach g=0.30 — control ~4 of the origin's 12 outbound
    //    peers — and even then W3 stays well under the inbound supernode's first-
    //    spy precision at the same nominal reach (π0 ≈ 0.45 at 0.30, §6.5). The
    //    outbound both-slots channel is far costlier for far less occupancy.
    let (_, g30) = &results[2];
    assert!(
        g30.both_slots < 0.12,
        "W3 at g=0.30 should be ~0.09, well below the inbound pi0=0.45, got {:.4}",
        g30.both_slots
    );
    assert!(
        results[3].1.both_slots > results[2].1.both_slots
            && results[2].1.both_slots > results[1].1.both_slots,
        "W3 must rise with outbound share g (monotone in g; g itself is not bounded here)"
    );

    println!(
        "\n  W3 (both outbound stem slots adversarial) is the ONLY delta reshape\n  \
         cannot route around, so it is the number a rho decision is taken against.\n  \
         It is a function of g = the adversary's OUTBOUND-selection share -- and g\n  \
         is NOT f. The outbound pool is 70% white-list, then gray for the\n  \
         remainder (P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT); the 2 anchor\n  \
         slots this line once named were deleted with the anchor mechanism\n  \
         (2026-09-06). The white list is gossip-fed, so an eclipse-\n  \
         capable adversary poisons it and drives g ABOVE f cheaply. So W3 ~= 0\n  \
         holds only under HONEST selection (g ~= f); the g=0.30->0.077 and\n  \
         g=0.50->0.192 rows are what an eclipse attacker buys. This instrument\n  \
         measures W3(g) but does NOT bound g -- that bound is owed by the anti-\n  \
         eclipse peer-selection grounding (Q-10, sec 12.6), which does not exist\n  \
         yet. So rho is BLOCKED on the g bound, not decidable against g=f. The\n  \
         table is sound; which row we live on is what is deferred."
    );
}

/// **Q1 layering discriminator (§12.8) — pinning the eligible set is NOT free.**
/// Turns the pin-vs-epoch-layering call from an argument into a number: an adversary
/// holding a fixed peer count `a` is exposed differently in the ~12-peer pool vs a
/// pinned set of `K`. Answers the advisor's sign question — does shrinking the set
/// help or harm — and it harms on the dominant (direct-successor) axis by `D/K`.
#[test]
fn epoch_layering_pinning_amplifies_direct_successor_exposure() {
    use shekyl_relay_privacy::conformance::simulate_epoch_layering;

    const D_OUT: usize = P2P_DEFAULT_OUT_PEERS as usize;
    const M: usize = 30; // ~5 h of 10-min epochs
    let trials = 200_000;

    // Single adversary peer (a=1): the advisor's scenario. Pool successor ~1/12 of
    // epochs; pinned to K ~1/K — amplified by D/K.
    println!("\nQ1 layering: single adversary peer (a=1), M={M} epochs, D_out={D_OUT}");
    println!(
        "{:>6} {:>10} {:>14} {:>16} {:>12}",
        "set", "a/set", "P(id direct)", "distinct succ", "amp vs pool"
    );
    let pool = simulate_epoch_layering(D_OUT, 1, M, trials, &mut SplitMix64::new(0x1A1));
    println!(
        "{:>6} {:>10.4} {:>14.4} {:>16.2} {:>11.2}x",
        D_OUT, pool.direct_successor_rate, pool.p_identified_direct, pool.distinct_successors, 1.0
    );
    let mut pinned = std::collections::BTreeMap::new();
    for &k in &[6_usize, 4, 3, 2] {
        let mut rng = SplitMix64::new(0x1A1 + k as u64);
        let o = simulate_epoch_layering(k, 1, M, trials, &mut rng);
        println!(
            "{:>6} {:>10.4} {:>14.4} {:>16.2} {:>11.2}x",
            k,
            o.direct_successor_rate,
            o.p_identified_direct,
            o.distinct_successors,
            o.direct_successor_rate / pool.direct_successor_rate
        );
        pinned.insert(k, o);
    }

    // 1. AMPLIFICATION is D/K on the direct-successor axis: pinning a single captured
    //    slot to K=3 makes it ~4x more present than in the 12-pool.
    let amp3 = pinned[&3].direct_successor_rate / pool.direct_successor_rate;
    assert!(
        (amp3 - 4.0).abs() < 0.15,
        "K=3 should amplify direct-successor exposure ~D/K=4x, got {amp3:.2}x"
    );

    // 2. It is monotone: smaller K, larger amplification (strictly worse on this axis).
    assert!(
        pinned[&2].direct_successor_rate > pinned[&3].direct_successor_rate
            && pinned[&3].direct_successor_rate > pinned[&6].direct_successor_rate,
        "smaller K must amplify direct-successor exposure more"
    );

    // 3. The intersection axis moves the OTHER way but is secondary: pinned uses far
    //    fewer distinct successors (protective, slows the §6.8 collapse), yet a
    //    captured slot's precision-1 direct identification dominates.
    assert!(
        pinned[&3].distinct_successors < pool.distinct_successors * 0.5,
        "pinned-K must use far fewer distinct successors than the pool"
    );
    assert!(
        pinned[&3].p_identified_direct > pool.p_identified_direct,
        "over M epochs the pinned single-adversary is identified-as-successor MORE often"
    );

    println!(
        "\n  Pinning to K amplifies a captured slot's cross-epoch presence by D/K on\n  \
         the DOMINANT direct-successor axis (precision-1 identification), while only\n  \
         slowing the SECONDARY intersection axis (fewer distinct successors). So the\n  \
         advisor's sign question resolves: shrinking the set HARMS on the axis that\n  \
         matters. 'Pin the set' is safe ONLY if the pin-admission bound (g_max, Q4)\n  \
         makes holding a slots in K harder than in D by MORE than D/K. K must not be\n  \
         << D, or admission must pay for the amplification. NOT a free simplification."
    );
}

/// **§12.11 C — pure preference ossifies to a self-inflicted eclipse.** Reproduces
/// in-crate the `ε → distinct-peers` result §12.11 cited from an external model: pure
/// exploit (`ε = 0`) collapses the stem graph to STEMS=2 peers; `ε ≈ 0.05` restores
/// the full pool. Epsilon-greedy, `ε ≈ 0.05` = the RL/ARPANET value.
#[test]
fn epsilon_greedy_pure_preference_ossifies_to_two_peers() {
    use shekyl_relay_privacy::conformance::simulate_epsilon_greedy_selection;

    const POOL: usize = 12;
    const M: usize = 2000; // enough epochs for eps=0.05 to cover the pool

    println!("\n§12.11 ossification: epsilon -> distinct peers exercised (pool=12, STEMS=2)");
    println!(
        "{:>8} {:>16} {:>18}",
        "epsilon", "distinct peers", "top2 traffic share"
    );
    let mut rows = std::collections::BTreeMap::new();
    for &pct in &[0_u64, 1, 5, 10] {
        let eps = pct as f64 / 100.0;
        let mut rng = SplitMix64::new(0x0E95_0000 + pct);
        let o = simulate_epsilon_greedy_selection(eps, POOL, M, 200, &mut rng);
        println!(
            "{:>8.2} {:>16.2} {:>18.3}",
            eps, o.distinct_peers, o.top2_traffic_share
        );
        rows.insert(pct, o);
    }

    // eps=0 ossifies to EXACTLY STEMS=2 peers — the eligible pool collapses 12->2.
    assert!(
        (rows[&0].distinct_peers - 2.0).abs() < 1e-9,
        "pure preference must ossify to 2 peers, got {}",
        rows[&0].distinct_peers
    );
    // eps=0.05 restores ~the full pool.
    assert!(
        rows[&5].distinct_peers > 11.9,
        "eps=0.05 must restore ~full pool (12), got {}",
        rows[&5].distinct_peers
    );
    // Concentration barely moves (top-2 still carry ~1 - eps/2): exploration buys
    // full-pool DIVERSITY + the eps/2 eclipse-escape, not a bulk redistribution.
    assert!(
        rows[&5].top2_traffic_share > 0.95 && rows[&0].top2_traffic_share > 0.999,
        "top-2 still carry the bulk at eps=0.05 (concentration is not the mechanism)"
    );
    // Monotone: more exploration, more distinct peers exercised.
    assert!(
        rows[&1].distinct_peers > rows[&0].distinct_peers
            && rows[&5].distinct_peers >= rows[&1].distinct_peers,
        "distinct peers must rise with epsilon"
    );

    println!(
        "\n  Pure preference (eps=0) is a DEGENERATE 2-peer stem graph — a self-\n  \
         inflicted eclipse (the eligible pool collapses 12->2, §12.10 regime 3). eps=\n  \
         0.05 restores all 12 exercised while the top-2 still carry ~97.5% of traffic\n  \
         -- so exploration buys full-pool DIVERSITY + the eps/2 eclipse-escape (a top-2\n  \
         occupier no longer sees 100%), not a bulk redistribution. epsilon-greedy,\n  \
         eps~0.05 = the RL/ARPANET value, reproduced in-crate (§13.5 discipline)."
    );
}

/// **§19.3 W3c — induced-churn exposure, the number the churn-stable successor
/// is specified against.** `simulate_two_slot_occupancy` measures one stable
/// epoch map and says so ("this instrument does not model churn"); this is that
/// model. All three arms run on the same trial, so differences are the mechanism
/// and not the draws.
///
/// Pinned because the *shape in `k`* is the finding: today's exposure compounds
/// with every induced re-roll, the frozen-set arm saturates at the source's own
/// initial peers, and the re-pin-on-exhaustion arm tracks the unfixed baseline
/// (the reason terminal exhaustion shipped). If any of those shapes break, the
/// mechanism under §19.2 changed.
#[test]
fn induced_churn_compounds_today_and_saturates_under_a_frozen_set() {
    use shekyl_relay_privacy::conformance::simulate_induced_churn_exposure;

    const D_OUT: usize = P2P_DEFAULT_OUT_PEERS as usize;
    const STEMS: usize = 2; // CRYPTONOTE_DANDELIONPP_STEMS
    const G: f64 = 0.10; // baseline outbound share
    let trials = 200_000;

    // Reference column uses g_eff = round(g·D)/D, not nominal g (0.10 → 1/12).
    println!("  k   today   frozen   re-pin   1-(1-g_eff)^(k+1)");
    let mut fresh_curve = Vec::new();
    let mut frozen_curve = Vec::new();
    let mut repin_curve = Vec::new();
    for k in [0_usize, 1, 2, 4, 8, 16] {
        let mut rng = SplitMix64::new(0xC0FFEE + k as u64);
        let r = simulate_induced_churn_exposure(G, D_OUT, STEMS, k, trials, &mut rng);
        println!(
            "  {:>2}  {:.4}  {:.4}  {:.4}   {:.4}",
            k,
            r.fresh_draw_exposure,
            r.frozen_set_exposure,
            r.frozen_repin_exposure,
            r.independent_reference
        );
        fresh_curve.push(r.fresh_draw_exposure);
        frozen_curve.push(r.frozen_set_exposure);
        repin_curve.push(r.frozen_repin_exposure);

        // Nominal g is 0.10; effective integer share is 1/12.
        assert!(
            (r.effective_share - (1.0 / 12.0)).abs() < 1e-12,
            "g_eff must be round(g·D)/D = 1/12, got {}",
            r.effective_share
        );

        // With no churn the three arms are the same initial pin.
        if k == 0 {
            assert!(
                (r.fresh_draw_exposure - r.frozen_set_exposure).abs() < 1e-9
                    && (r.frozen_set_exposure - r.frozen_repin_exposure).abs() < 1e-9,
                "with k = 0 the mechanisms are indistinguishable by construction"
            );
        }
    }

    // Today: strictly compounding in k.
    for w in fresh_curve.windows(2) {
        assert!(
            w[1] > w[0] + 0.01,
            "today's exposure must rise with every induced re-roll: {w:?}"
        );
    }
    assert!(
        fresh_curve.last().copied().unwrap() > 0.90,
        "~16 induced re-rolls must reach the origin's stem path >90% of the time"
    );

    // Frozen: flat from k = 2, once the source has walked its STEMS peers.
    let saturated = &frozen_curve[2..];
    for e in saturated {
        assert!(
            (e - saturated[0]).abs() < 0.01,
            "the frozen set must saturate — more churn buys the adversary nothing: {frozen_curve:?}"
        );
    }
    // And it saturates at P(>=1 of the source's OWN initial stems is adversarial),
    // ~2g for small g — NOT at the single-draw g. §19.2's first draft said g; the
    // measurement corrected it, and this assertion is what keeps that correction.
    assert!(
        (saturated[0] - 0.167).abs() < 0.01,
        "frozen saturation is the two-slot at-least-one bound (~2g), not g: {}",
        saturated[0]
    );

    // Re-pin-on-exhaustion (rejected arm): once sweeps begin it tracks the
    // *unfixed* baseline, not the frozen arm — the measurement that made
    // terminal exhaustion all-or-nothing at STEMS=2 (§19.3 correction 3).
    assert!(
        (repin_curve[0] - frozen_curve[0]).abs() < 1e-9,
        "k=0: re-pin arm matches frozen"
    );
    // At k=8 a full sweep has happened repeatedly; re-pin must sit near today,
    // far above the saturated frozen arm.
    assert!(
        (repin_curve[4] - fresh_curve[4]).abs() < 0.05,
        "at k=8 re-pin tracks the unfixed baseline ({:.4}), not frozen ({:.4}): re-pin={:.4}",
        fresh_curve[4],
        frozen_curve[4],
        repin_curve[4]
    );
    assert!(
        repin_curve[4] > frozen_curve[4] + 0.4,
        "re-pin must be far above frozen at k=8 or the terminal-exhaustion decision loses its evidence"
    );
    // At k=16 re-pin can exceed today (keeps drawing from a pool whose adversarial
    // fraction rises) — the §19.3 table's 1.0000 vs 0.9167.
    assert!(
        repin_curve[5] >= fresh_curve[5] - 0.02,
        "at k=16 re-pin must not fall below the unfixed baseline: re-pin={:.4} today={:.4}",
        repin_curve[5],
        fresh_curve[5]
    );
}
