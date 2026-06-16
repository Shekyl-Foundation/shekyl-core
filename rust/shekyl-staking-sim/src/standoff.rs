//! Funding-seam entry-standoff anonymity model — Gate 6 §10.12 pass-4 BUILD target.
//!
//! The firewall's charter is **P ↔ principal**, not **P ↔ its own rewards**
//! (`docs/design/ARCHIVAL_FIREWALL_GATE6.md` §10.12 pass-4 organizing principle).
//! `P_canonical_id` is a conceded-public earner; the load-bearing seam is GF-7:
//! the temporal correlation between `P`'s observable funding/entry events and the
//! principal's on-chain activity. A randomized **standoff window** decorrelates
//! the entry event from the bond-post, and the **inversion** (`P` may appear
//! *before* its bond is staked) removes the adversary's ordering prior
//! ("the bond-post follows a recent principal spend").
//!
//! This harness answers the pass-4 sim question, sharpened past "smooth vs surge":
//!
//! 1. **Anonymity-set sizing, not window width.** The metric is candidate
//!    funding-shaped chain spends *inside the search window an adversary must
//!    consider*, not the nominal window in blocks. We Monte-Carlo the candidate-set
//!    distribution (Poisson background) and report the mean **and the thin-cover
//!    tail** — the worst-case an averaged window hides.
//! 2. **The low-activity principal is the worst case.** Background decoys do not
//!    depend on the target's own spend rate, so a rarely-spending principal gets
//!    exactly the network-decoy cover and nothing more — which is precisely where
//!    only the inversion helps (it removes the prior set-enlargement cannot).
//! 3. **Clustering = trigger independence.** Independent uniform draws smooth
//!    entries into the *background* funding traffic (large decoy pool); a shared
//!    trigger (everyone jittering off an epoch boundary) concentrates entries into
//!    a **detectable surge** separable from background, collapsing the decoy pool
//!    to co-entrants only. This is the knob that decides smooth vs surge.
//! 4. **Inversion as its own arm.** Reported as the share of mass where the
//!    bond-post *precedes* the entry event — the fraction of cases the causal
//!    "spend-just-before-bond" heuristic cannot even include the true funder.
//!
//! **Homeostasis is analytical, not re-simmed.** The economic model is
//! epoch-quantized at `SETTLEMENT_EPOCH_BLOCKS` (~13.9 d); an obfuscation-useful
//! standoff is tens-to-hundreds of blocks (minutes-to-hours). The standoff adds at
//! most `window_blocks` of entry latency, so its cost is `window/epoch` of one
//! settlement epoch — negligible across the useful range. Re-running the
//! epoch-granularity sweep to "resolve" a sub-epoch effect would over-read the
//! model (cf. the float-vs-integer over-read, `ARCHIVAL_SIM_ECONOMICS_VERDICT.md`).
//! We report the bound and flag where the window would *start* to bite.
//!
//! **Conditionality — what these numbers mean (review pass 2026-06-13).** Four
//! caveats bound the harness's claims; the first two change what the number
//! *means*, not just its value:
//!
//! - **Cover is conditional on §10.9 isolation, multiplicatively.** The decoys
//!   model assumes the target is *indistinguishable* from background — which is
//!   exactly what circuit/key isolation buys. Without isolation the principal's
//!   activity is attributable directly (the target is *named*, not in a crowd),
//!   so no window helps. Formally `P(link) = P(link|iso)·P(iso) +
//!   P(link|¬iso)·P(¬iso)` with `P(link|¬iso) ≈ 1`; this harness measures only
//!   `P(link|iso)`. The standoff is a **multiplier on isolation, never additive**.
//! - **The harness is channel-agnostic; the rate must bind to the *actual*
//!   channel.** "Candidate events in a window" is not specific to on-chain
//!   funding spends. Post-isolation the residual correlation channel is
//!   concurrent *network* activity, so the correct decoy rate is the
//!   network-event rate, not the funding-tx rate swept here (a proxy). Testnet
//!   must measure the rate of the channel that actually carries the leak.
//! - **The window cap is anti-griefing (liveness), not privacy.** A maximum
//!   announce↔bond separation is a *ceiling* (don't let announced-but-unbonded
//!   `P`s linger); privacy wants the separation *large and random* — a floor.
//!   The privacy-load-bearing controls (minimum effective spread + the
//!   uniform-independent draw) are **wallet-only and consensus-unenforceable**
//!   (consensus sees neither the FCMP++-hidden funding source nor off-chain
//!   principal activity). Per finding 4 a shared trigger both loses its own
//!   cover and injects a surge that degrades everyone's — so the draw is a hard
//!   conformance requirement (published test vector), not a "default."
//! - **These are nominal cover under honest traffic — an upper bound.** Poisson
//!   decoys are honest background. Against an adversary that *observes* (marks
//!   which background it can attribute elsewhere) and *injects* (announce-then-
//!   not-bond seeding, bounded by the membership-only backing requirement),
//!   effective cover is lower and unquantified (the RingCT nominal-vs-effective
//!   lesson). S-3's modeled observer, not a passive rate measurement, is the
//!   testnet target.
//!
//! **Construction the harness assumes (conformance-critical).** The model assumes the
//! gap between the two seam events is drawn *directly* as `s ~ U[0, window]` with a
//! random order (the inversion coin). The obvious wrong implementation —
//! independently jittering both event-times in `[0, window]` around a common
//! intent anchor `t0` — yields a separation that is the *difference of two
//! uniforms*: **triangular, peaked at zero**, i.e. the events cluster together
//! most of the time, the precise opposite of a standoff. That wrong build
//! satisfies "both within `window`" and "separation ≤ `window`" on paper while
//! delivering near-zero effective standoff. Correct shape: at `t0`, flip a coin
//! for order, place the first event at `t0`, draw `s ~ U[0, window]`, place the
//! second at `t0 + s` (uniform separation, free inversion, max latency `window`,
//! per-`P` independence since `t0` is the principal's private intent). The
//! published conformance test vector must reject the triangular construction.
//!
//! **`window` is per-seam.** This harness models the *entry* seam
//! (announce↔bond, order-symmetric, inversion-eligible). The *exit* seam
//! (terminal drain + recurring partial-unbond) is a separate standoff with its
//! own envelope, modeled nowhere here: it is **one-sided** (collateral is not
//! spendable before the 20_000-block release cooldown, so there is no
//! inversion), and its latency is measured **from cooldown expiry, not from the
//! unbond event** (the cooldown already pins the earliest spend deterministically;
//! the standoff's job is to break that fixed-offset tell).

use serde::Serialize;

use crate::timing_cluster::{BLOCK_TIME_SEC, SETTLEMENT_EPOCH_BLOCKS};

/// A surge from a shared trigger concentrates entries into this many blocks,
/// separable from un-clustered background funding traffic.
const SHARED_TRIGGER_CLUSTER_BLOCKS: f64 = 3.0;

/// Homeostasis is "free" while the standoff costs at most this fraction of one
/// settlement epoch in entry latency. 0.10 epoch ≈ 1000 blocks ≈ 1.4 d — two
/// orders of magnitude above any obfuscation-useful window.
const HOMEOSTASIS_FREE_FRAC_EPOCH: f64 = 0.10;

/// A candidate set this small or smaller is "thin cover" — the tail an averaged
/// anonymity-set mean hides.
const THIN_COVER_THRESHOLD: f64 = 2.0;

/// Default "reasonable obfuscation" target for the recommendation routine.
const TARGET_ANON_SET: f64 = 10.0;

#[derive(Debug, Clone, Serialize)]
pub struct StandoffConfig {
    pub name: String,
    pub axis: &'static str,
    /// Nominal standoff window width (blocks).
    pub window_blocks: u64,
    /// Background funding-shaped chain-spend rate (spends/block, network-wide).
    /// The decoy pool. Pre-testnet this is a swept assumption, not a measurement.
    pub net_funding_rate_per_block: f64,
    /// Rate of *new staking entries* network-wide (entries/block). Only the decoy
    /// pool under a shared trigger (co-entrants in the surge); ≪ funding rate.
    pub entry_rate_per_block: f64,
    /// Inversion allowed: the entry event may precede the bond-post (symmetric
    /// window), removing the ordering prior and doubling the search width.
    pub inversion: bool,
    /// Shared trigger (clustering) vs independent uniform draw.
    pub shared_trigger: bool,
    pub trials: u64,
    pub seed: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StandoffResult {
    pub name: String,
    pub axis: &'static str,
    pub window_blocks: u64,
    pub window_minutes: f64,
    pub net_funding_rate_per_block: f64,
    pub inversion: bool,
    pub shared_trigger: bool,
    /// Effective search width feeding the decoy model (blocks): the
    /// inversion-adjusted window in the normal path, or the surge cluster width
    /// under a shared trigger (where the separable surge collapses the effective
    /// width the adversary must consider).
    pub search_width_blocks: f64,
    /// Mean candidate-set size (1 target + background decoys).
    pub anon_set_mean: f64,
    /// 5th-percentile candidate set — the thin-cover tail.
    pub anon_set_p05: f64,
    /// Fraction of entries landing in thin cover (set ≤ THIN_COVER_THRESHOLD).
    pub thin_cover_frac: f64,
    /// Mean adversary single-guess link probability (1/set under uniform).
    pub link_prob_mean: f64,
    /// Share of mass where the bond-post *strictly* precedes the entry event
    /// (causal: 0; inversion: `0.5·W/(W+1)` under the discrete gap model) — cases
    /// the "spend-before-bond" heuristic cannot include.
    pub inversion_prior_break: f64,
    /// Standoff entry latency as a fraction of one settlement epoch.
    pub entry_latency_frac_epoch: f64,
    pub homeostasis_free: bool,
}

/// SplitMix64 — small, seeded, reproducible. No `rand` dependency (keeps the
/// crate's minimal-dep posture; the harness must be deterministic for replay).
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn unit(&mut self) -> f64 {
        // 53-bit mantissa in [0, 1).
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn gaussian(&mut self) -> f64 {
        // Box-Muller; one of the pair is enough here.
        let u1 = self.unit().max(1e-12);
        let u2 = self.unit();
        (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
    }

    /// Poisson draw. Knuth for small means; normal approximation for large means
    /// (where exp(-λ) underflows and Knuth's loop is slow).
    fn poisson(&mut self, mean: f64) -> u64 {
        if mean <= 0.0 {
            return 0;
        }
        if mean > 30.0 {
            let v = mean + mean.sqrt() * self.gaussian();
            return v.round().max(0.0) as u64;
        }
        let l = (-mean).exp();
        let mut k = 0u64;
        let mut p = 1.0;
        loop {
            k += 1;
            p *= self.unit();
            if p <= l {
                return k - 1;
            }
        }
    }
}

/// Blocks → wall-clock minutes in `f64`. Casting before the multiply avoids a
/// `u64 * u64` intermediate overflow, and the `u64::MAX` "no finite window"
/// sentinel from `recommended_window_blocks` maps to infinity (consistent with
/// `funding_spend_interval_minutes`).
fn blocks_to_minutes(blocks: u64) -> f64 {
    if blocks == u64::MAX {
        f64::INFINITY
    } else {
        blocks as f64 * BLOCK_TIME_SEC as f64 / 60.0
    }
}

fn run(cfg: &StandoffConfig) -> StandoffResult {
    assert!(cfg.trials > 0, "standoff::run requires trials > 0");
    let search_width = if cfg.inversion {
        2.0 * cfg.window_blocks as f64
    } else {
        cfg.window_blocks as f64
    };

    // Under a shared trigger the entry surge is separable from background, so the
    // decoy pool collapses to co-entrants inside the cluster width; otherwise the
    // target hides in the full background over the search width.
    let (decoy_rate, decoy_width) = if cfg.shared_trigger {
        (cfg.entry_rate_per_block, SHARED_TRIGGER_CLUSTER_BLOCKS)
    } else {
        (cfg.net_funding_rate_per_block, search_width)
    };
    let decoy_mean = decoy_rate * decoy_width;

    let mut rng = SplitMix64(cfg.seed);
    let mut sets: Vec<f64> = Vec::with_capacity(cfg.trials as usize);
    let mut link_sum = 0.0;
    let mut thin = 0u64;
    for _ in 0..cfg.trials {
        let decoys = rng.poisson(decoy_mean);
        let set = 1.0 + decoys as f64; // target + decoys
        sets.push(set);
        link_sum += 1.0 / set;
        if set <= THIN_COVER_THRESHOLD {
            thin += 1;
        }
    }
    sets.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = sets.len();
    let mean = sets.iter().sum::<f64>() / n as f64;
    let p05 = sets[(0.05 * n as f64) as usize];

    let entry_latency_frac_epoch = cfg.window_blocks as f64 / SETTLEMENT_EPOCH_BLOCKS as f64;

    StandoffResult {
        name: cfg.name.clone(),
        axis: cfg.axis,
        window_blocks: cfg.window_blocks,
        window_minutes: blocks_to_minutes(cfg.window_blocks),
        net_funding_rate_per_block: cfg.net_funding_rate_per_block,
        inversion: cfg.inversion,
        shared_trigger: cfg.shared_trigger,
        search_width_blocks: decoy_width,
        anon_set_mean: mean,
        anon_set_p05: p05,
        thin_cover_frac: thin as f64 / n as f64,
        link_prob_mean: link_sum / n as f64,
        // Discrete gap model: P(bond strictly precedes entry) = P(bond_first)·P(s>0)
        // = 0.5·W/(W+1). Zero at W=0, where the two events always coincide and no
        // inversion is possible — so the constant 0.5 over-reported that edge.
        inversion_prior_break: if cfg.inversion {
            0.5 * cfg.window_blocks as f64 / (cfg.window_blocks as f64 + 1.0)
        } else {
            0.0
        },
        entry_latency_frac_epoch,
        homeostasis_free: entry_latency_frac_epoch <= HOMEOSTASIS_FREE_FRAC_EPOCH,
    }
}

/// Smallest window (blocks) reaching `TARGET_ANON_SET` mean candidate set at the
/// given background rate under independent triggers, no inversion (the
/// conservative arm). Closed-form inverse of `1 + rate * W = target`; the MC
/// confirms the mean and exposes the tail.
fn recommended_window_blocks(rate: f64) -> u64 {
    if rate <= 0.0 {
        return u64::MAX;
    }
    ((TARGET_ANON_SET - 1.0) / rate).ceil() as u64
}

#[derive(Debug, Clone, Serialize)]
pub struct StandoffRecommendation {
    pub net_funding_rate_per_block: f64,
    pub funding_spend_interval_minutes: f64,
    pub recommended_window_blocks: u64,
    pub recommended_window_minutes: f64,
    pub entry_latency_frac_epoch: f64,
    pub homeostasis_free: bool,
}

fn recommendation(rate: f64) -> StandoffRecommendation {
    let w = recommended_window_blocks(rate);
    // u64::MAX is the "no finite window" sentinel (rate <= 0); keep the latency
    // fraction infinite (not a huge finite number) so homeostasis_free stays
    // meaningful and consistent with recommended_window_minutes = ∞.
    let frac = if w == u64::MAX {
        f64::INFINITY
    } else {
        w as f64 / SETTLEMENT_EPOCH_BLOCKS as f64
    };
    StandoffRecommendation {
        net_funding_rate_per_block: rate,
        funding_spend_interval_minutes: if rate > 0.0 {
            (BLOCK_TIME_SEC as f64 / 60.0) / rate
        } else {
            f64::INFINITY
        },
        recommended_window_blocks: w,
        recommended_window_minutes: blocks_to_minutes(w),
        entry_latency_frac_epoch: frac,
        homeostasis_free: frac <= HOMEOSTASIS_FREE_FRAC_EPOCH,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StandoffReport {
    pub settlement_epoch_blocks: u64,
    pub homeostasis_free_frac_epoch: f64,
    pub target_anon_set: f64,
    pub results: Vec<StandoffResult>,
    pub recommendations: Vec<StandoffRecommendation>,
}

pub fn build_configs() -> Vec<StandoffConfig> {
    let mut cfgs = Vec::new();
    let trials = 200_000u64;
    let mut seed = 0xA5A5_0001u64;

    // Plausible background funding-shaped spend rates (spends/block). Pre-testnet
    // these are swept assumptions, flagged as such — the recommendation is
    // conditional on the measured rate, like fetch_latency_per_unit (L10).
    //   0.005 = 1 every 200 blk (~6.7 h)   0.02 = 1 every 50 blk (~1.7 h)
    //   0.05  = 1 every 20 blk  (~40 min)  0.10 = 1 every 10 blk (~20 min)
    let rates = [0.005_f64, 0.02, 0.05, 0.10];
    // Entry rate (new stakers/block) — the shared-trigger decoy pool; ≪ funding.
    let entry_rate = 0.002_f64;

    // Arm A — window sweep at a mid background rate, independent trigger, no
    // inversion (the conservative baseline: how wide for a reasonable set?).
    for &w in &[0u64, 5, 10, 30, 60, 120, 300, 600, 1200] {
        cfgs.push(StandoffConfig {
            name: format!("win_{w}_r0.02"),
            axis: "standoff_window",
            window_blocks: w,
            net_funding_rate_per_block: 0.02,
            entry_rate_per_block: entry_rate,
            inversion: false,
            shared_trigger: false,
            trials,
            seed,
        });
        seed += 1;
    }

    // Arm B — background-rate sweep at a fixed mid window (anonymity is rate-driven).
    for &r in &rates {
        cfgs.push(StandoffConfig {
            name: format!("rate_{r}_w300"),
            axis: "standoff_rate",
            window_blocks: 300,
            net_funding_rate_per_block: r,
            entry_rate_per_block: entry_rate,
            inversion: false,
            shared_trigger: false,
            trials,
            seed,
        });
        seed += 1;
    }

    // Arm C — inversion on/off at a thin (low-rate) regime, the low-activity worst
    // case where set-enlargement cannot help and only the inversion does.
    for &inv in &[false, true] {
        cfgs.push(StandoffConfig {
            name: format!("thin_inv_{}", if inv { "on" } else { "off" }),
            axis: "standoff_inversion",
            window_blocks: 300,
            net_funding_rate_per_block: 0.005,
            entry_rate_per_block: entry_rate,
            inversion: inv,
            shared_trigger: false,
            trials,
            seed,
        });
        seed += 1;
    }

    // Arm D — trigger independence (clustering) at a mid window/rate.
    for &shared in &[false, true] {
        cfgs.push(StandoffConfig {
            name: format!("trigger_{}", if shared { "shared" } else { "indep" }),
            axis: "standoff_trigger",
            window_blocks: 300,
            net_funding_rate_per_block: 0.05,
            entry_rate_per_block: entry_rate,
            inversion: false,
            shared_trigger: shared,
            trials,
            seed,
        });
        seed += 1;
    }

    cfgs
}

pub fn run_full_report() -> StandoffReport {
    let results: Vec<StandoffResult> = build_configs().iter().map(run).collect();
    let recommendations = [0.005_f64, 0.02, 0.05, 0.10]
        .iter()
        .map(|&r| recommendation(r))
        .collect();
    StandoffReport {
        settlement_epoch_blocks: SETTLEMENT_EPOCH_BLOCKS,
        homeostasis_free_frac_epoch: HOMEOSTASIS_FREE_FRAC_EPOCH,
        target_anon_set: TARGET_ANON_SET,
        results,
        recommendations,
    }
}

// ---------------------------------------------------------------------------
// The conformance-correct entry-seam draw and its goodness-of-fit instruments
// were single-sourced out of this `#[cfg(test)]`-local code into the
// `shekyl-standoff` crate (draw, build-float-free) and `shekyl-stats` (generic
// GoF). The sim now exercises the *same* draw the wallet and the published KAT
// import — "what we validated is what ships" by construction. The
// distributional / instrument-validity tests moved to
// `shekyl-standoff/tests/conformance_grading.rs`; the sim keeps only a smoke
// test that its `SplitMix64` conforms through the shared self-cert harness, and
// the `run()` Monte-Carlo economics below (which are sim-only, not single-
// sourced). See `docs/design/STAKER_ARCHIVAL_SIM.md` and
// `docs/design/ARCHIVAL_FIREWALL_GATE6.md` §10.12.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The sim's reproducible PRNG satisfies the standoff draw conformance trait,
    /// so `run()`'s reference stream is the same one the wallet self-certifies
    /// against. Reference determinism, not a PRNG mandate.
    impl shekyl_standoff::GapRng for SplitMix64 {
        fn next_u64(&mut self) -> u64 {
            SplitMix64::next_u64(self)
        }
    }

    #[test]
    fn zero_window_is_no_cover() {
        let cfg = StandoffConfig {
            name: "t".into(),
            axis: "t",
            window_blocks: 0,
            net_funding_rate_per_block: 0.05,
            entry_rate_per_block: 0.002,
            inversion: false,
            shared_trigger: false,
            trials: 10_000,
            seed: 1,
        };
        let r = run(&cfg);
        // No window ⇒ only the target ⇒ set ≈ 1, link ≈ 1.
        assert!((r.anon_set_mean - 1.0).abs() < 1e-9);
        assert!((r.link_prob_mean - 1.0).abs() < 1e-9);
    }

    #[test]
    fn wider_window_grows_anon_set() {
        let base = StandoffConfig {
            name: "t".into(),
            axis: "t",
            window_blocks: 60,
            net_funding_rate_per_block: 0.05,
            entry_rate_per_block: 0.002,
            inversion: false,
            shared_trigger: false,
            trials: 50_000,
            seed: 7,
        };
        let wide = StandoffConfig {
            window_blocks: 600,
            ..base.clone()
        };
        assert!(run(&wide).anon_set_mean > run(&base).anon_set_mean);
    }

    #[test]
    fn shared_trigger_shrinks_the_decoy_pool() {
        let indep = StandoffConfig {
            name: "t".into(),
            axis: "t",
            window_blocks: 300,
            net_funding_rate_per_block: 0.05,
            entry_rate_per_block: 0.002,
            inversion: false,
            shared_trigger: false,
            trials: 50_000,
            seed: 11,
        };
        let shared = StandoffConfig {
            shared_trigger: true,
            ..indep.clone()
        };
        // A detectable surge separates entries from background ⇒ fewer decoys ⇒
        // higher link probability for the same nominal window.
        assert!(run(&shared).link_prob_mean > run(&indep).link_prob_mean);
    }

    #[test]
    fn inversion_breaks_the_ordering_prior() {
        let causal = StandoffConfig {
            name: "t".into(),
            axis: "t",
            window_blocks: 300,
            net_funding_rate_per_block: 0.02,
            entry_rate_per_block: 0.002,
            inversion: false,
            shared_trigger: false,
            trials: 10_000,
            seed: 3,
        };
        let inv = StandoffConfig {
            inversion: true,
            ..causal.clone()
        };
        assert_eq!(run(&causal).inversion_prior_break, 0.0);
        assert!(run(&inv).inversion_prior_break > 0.4);
        // Inversion also widens the search width ⇒ larger set.
        assert!(run(&inv).anon_set_mean > run(&causal).anon_set_mean);
    }

    #[test]
    fn homeostasis_free_below_epoch_tenth() {
        // 600-block standoff (~20 h) is well under 0.10 epoch ⇒ economically free.
        let cfg = StandoffConfig {
            name: "t".into(),
            axis: "t",
            window_blocks: 600,
            net_funding_rate_per_block: 0.02,
            entry_rate_per_block: 0.002,
            inversion: false,
            shared_trigger: false,
            trials: 1000,
            seed: 2,
        };
        let r = run(&cfg);
        assert!(r.homeostasis_free);
        assert!(r.entry_latency_frac_epoch < 0.10);
    }

    #[test]
    fn sim_rng_conforms_via_shared_self_cert() {
        // Single-sourcing smoke test: the sim's `SplitMix64` reference stream
        // passes the *same* self-certification harness a wallet runs against its
        // CSPRNG (uniform spread, fair order, serial independence). The full
        // distributional + instrument-validity vector lives in
        // `shekyl-standoff/tests/conformance_grading.rs`.
        let mut rng = SplitMix64(0xC0FF_EE12_3456_789A);
        let report = shekyl_standoff::conformance::certify_draw(&mut rng, 600, 200_000);
        assert!(
            report.passed(),
            "sim RNG failed standoff self-cert: {report:?}"
        );
    }
}
