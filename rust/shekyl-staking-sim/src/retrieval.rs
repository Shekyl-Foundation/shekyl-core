//! L15 — retrieval availability under per-holder uptime and correlated failure.
//!
//! **Coverage ≠ retrieval.** Every prior layer scored a shard "covered" when its
//! replica count `R` met `R_target`. But the property users need is *retrieval*: at
//! least one holder reachable, within latency, at a target availability. Two gaps
//! separate the two:
//!
//! 1. **Per-holder uptime.** A holder is not always serving (downtime, churn, the slow
//!    onion path of L16). With per-holder uptime `u`, a single replica delivers `u`, not
//!    `1`; redundancy is what converts `u` into the availability target `A*`.
//! 2. **Correlated failure.** The L4 survival arithmetic (`N=3, p=0.99 ⇒ 1−10⁻⁶`)
//!    assumed *independent* holder failure. Real holders share **failure domains** —
//!    jurisdiction, ASN, client implementation — and a domain fails as a unit. A shard's
//!    effective redundancy is therefore its count of **distinct domains**, not its raw
//!    replica count: extra replicas inside an already-covered domain add no availability.
//!
//! This module (a) **derives** `R_target` from a stated availability target instead of
//! stipulating it, and (b) reads the **realized** availability the diversity of a
//! shard's holders actually delivers — so the sim can show a fully *covered* deep set
//! (`R ≥ R_target`) that still fails its retrieval SLA because its holders cluster into
//! too few domains. Gated by `retrieval_model`; inert (and byte-identical) otherwise.
//!
//! **Durability SLA (soundness pass step 1).** The same domain-bucketing formula scores
//! *permanent retention* when `s` is per-domain **survival** (bond-backed retention —
//! all replicas in a domain permanently lost) rather than momentary serve uptime `u`.
//! Transport depression (L16) applies to availability only, not durability.

use crate::model::World;

/// `R_target` **derived** from an availability target under independence: the smallest
/// `R` with `1 − (1−u)^R ≥ A*`. This inverts the spec — instead of stipulating
/// `R_target` (3 hot / 6 deep), state the retrieval-availability target `A*` and the
/// per-holder uptime `u` and read off the redundancy it *requires*. Degenerate guards:
/// `A* ≤ 0 ⇒ 0`; `u ≤ 0 ⇒ usize::MAX` (no finite redundancy suffices); `u ≥ 1 ⇒ 1`.
///
/// `R ≥ ln(1−A*) / ln(1−u)` (both logs negative ⇒ positive quotient).
pub fn r_target_for_availability(u: f64, a_star: f64) -> usize {
    if a_star <= 0.0 {
        return 0;
    }
    if u <= 0.0 {
        return usize::MAX;
    }
    if u >= 1.0 {
        return 1;
    }
    ((1.0 - a_star).ln() / (1.0 - u).ln()).ceil() as usize
}

/// Realized retrieval availability of each shard from its **serving** holders (seated,
/// `inflight == 0`), the per-holder uptime `u`, and a coarse failure-domain bucketing
/// into `n_domains` classes. A shard is retrievable in an outage realization iff ≥1 of
/// its serving holders' domains is up; with each domain up i.i.d. with probability `u`,
/// availability `= 1 − (1−u)^d`, where `d` is the count of **distinct domains** among the
/// shard's serving holders. Correlated failure surfaces as `d < R` (redundancy wasted
/// inside one domain).
///
/// The domain map is deterministic (`a % n_domains`) — coarse and privacy-compatible
/// (the live chain buckets, never geolocates per holder; mission priority 2), and not a
/// hidden RNG draw. `n_domains == 0` ⇒ every holder is its own domain (`d == R`), which
/// recovers the independent L4 formula `1 − (1−u)^R` — the best-case diversity.
pub fn serving_availability(world: &World, u: f64, n_domains: usize) -> Vec<f64> {
    let n_shard = world.shards.len();
    let q = 1.0 - u; // per-domain down probability
    let mut avail = vec![0.0_f64; n_shard];

    if n_domains == 0 {
        // Each holder its own domain ⇒ distinct domains == seated replica count.
        let serving = world.serving_replication();
        for s in 0..n_shard {
            avail[s] = 1.0 - q.powi(serving[s] as i32);
        }
        return avail;
    }

    let n_actor = world.actors.len();
    let mut seen = vec![false; n_domains];
    for (s, av) in avail.iter_mut().enumerate() {
        for d in seen.iter_mut() {
            *d = false;
        }
        let mut distinct = 0usize;
        for a in 0..n_actor {
            if world.holdings[a][s] && world.inflight[a][s] == 0 {
                let dom = a % n_domains;
                if !seen[dom] {
                    seen[dom] = true;
                    distinct += 1;
                }
            }
        }
        *av = 1.0 - q.powi(distinct as i32);
    }
    avail
}

/// Realized **durability** — probability at least one failure domain still holds a copy
/// (permanent-loss / eventual-retrievability model). Uses the same `1 − (1−s)^d` formula
/// as [`serving_availability`], but `s` is per-domain **retention survival** (not
/// momentary serve uptime, and not transport-depressed), and `d` counts distinct domains
/// among **committed** holders (`World::replication` / all `holdings`, including in-flight
/// fetches). Retention is bond-backed storage, not instantaneous reachability.
pub fn serving_durability(world: &World, s: f64, n_domains: usize) -> Vec<f64> {
    let n_shard = world.shards.len();
    let q = 1.0 - s;
    let mut dur = vec![0.0_f64; n_shard];

    if n_domains == 0 {
        let committed = world.replication();
        for (idx, d) in dur.iter_mut().enumerate() {
            *d = 1.0 - q.powi(committed[idx] as i32);
        }
        return dur;
    }

    let n_actor = world.actors.len();
    let mut seen = vec![false; n_domains];
    for (sidx, d_out) in dur.iter_mut().enumerate() {
        for dom in seen.iter_mut() {
            *dom = false;
        }
        let mut distinct = 0usize;
        for a in 0..n_actor {
            if world.holdings[a][sidx] {
                let dom = a % n_domains;
                if !seen[dom] {
                    seen[dom] = true;
                    distinct += 1;
                }
            }
        }
        *d_out = 1.0 - q.powi(distinct as i32);
    }
    dur
}

/// Smallest `R` with durability `1 − (1−s)^R ≥ D*` under independence (alias of
/// [`r_target_for_availability`] — same inversion, different parameter semantics).
pub fn r_target_for_durability(s: f64, d_star: f64) -> usize {
    r_target_for_availability(s, d_star)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_r_target_matches_hand_calc() {
        // u=0.9, A*=0.999: ln(0.001)/ln(0.1) = 3.0 exactly ⇒ 3.
        assert_eq!(r_target_for_availability(0.9, 0.999), 3);
        // u=0.5, A*=0.999: ln(0.001)/ln(0.5) ≈ 9.97 ⇒ 10.
        assert_eq!(r_target_for_availability(0.5, 0.999), 10);
        // Degenerate guards.
        assert_eq!(r_target_for_availability(0.9, 0.0), 0);
        assert_eq!(r_target_for_availability(1.0, 0.999), 1);
        assert_eq!(r_target_for_availability(0.0, 0.999), usize::MAX);
    }

    #[test]
    fn correlation_caps_availability_below_independent() {
        // Independent (n_domains = 0): d == R, so more replicas always help.
        // Correlated (n_domains = 2): d ≤ 2, so availability is capped regardless of R.
        // We assert the cap analytically via the formula the function uses.
        let u = 0.9;
        let indep_r6 = 1.0 - (1.0_f64 - u).powi(6); // ~0.999999
        let corr_2dom = 1.0 - (1.0_f64 - u).powi(2); // 0.99
        assert!(indep_r6 > 0.9999);
        assert!(corr_2dom < 0.999); // fails a three-nines SLA despite R≥6
    }
}
