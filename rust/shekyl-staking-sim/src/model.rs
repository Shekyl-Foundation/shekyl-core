//! Core model types for the staker-archival coverage simulation.
//!
//! Canonical model: `docs/design/STAKER_ARCHIVAL_SIM.md` §*Iteration 1 — coverage
//! dynamics*. The reward under test is age-weighted scarcity
//! `scarcity(shard) ∝ (1/R) · g(age)` + a per-pseudonym banded plateau-cap + the
//! competitive-share `Σwork` servo, with per-shard retention bonds on deep
//! history. This module defines the world (shards, actors, holdings) and the
//! age-dependent functions; reward computation lives in `reward.rs`, agent
//! best-response in `agent.rs`, metrics in `metrics.rs`.
//!
//! **Actor vs. pseudonym.** The firewall makes pseudonyms unlinkable, so coverage
//! and spread must be measured at the *actor* level (ground truth the live chain
//! cannot see). Holdings are tracked per actor; the reward/`R` economics are what
//! the protocol sees per pseudonym. Under rational play no actor self-replicates a
//! shard (it doubles storage cost and lowers its own `1/R` reward — self-defeating),
//! so per-shard distinct-pseudonym count equals distinct-actor count, and `R` here
//! is the actor-distinct count. The actor/pseudonym divergence that *does* matter is
//! the spread of shards-held: an actor spreading holdings over many pseudonyms to
//! evade the per-pseudonym cap looks egalitarian under a pseudonym-level Gini and
//! concentrated under the actor-level one (see `metrics.rs`).

/// A deterministic small-state PRNG (splitmix64). Inlined to avoid a new
/// dependency (per `17-dependency-discipline.mdc`); determinism is load-bearing so
/// sweep results are reproducible across runs.
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        // splitmix64
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    /// Uniform f64 in `[0, 1)`.
    pub fn next_f64(&mut self) -> f64 {
        // 53-bit mantissa
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform integer in `[0, n)`.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }

    /// In-place Fisher–Yates shuffle.
    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        let len = slice.len();
        for i in (1..len).rev() {
            let j = self.below(i + 1);
            slice.swap(i, j);
        }
    }
}

/// A shard of historical curve-tree state. `age ∈ [0, 1]`: 0 = hot/recent
/// (widely held anyway), 1 = deepest history (irreplaceable). `query_rate` decays
/// with age but is *not* a reward input (reward is retention-based, not
/// retrieval-based — the load-bearing reason iteration 1 can be single-region; see
/// the spec's resolved open-question 4). It is reported only as context.
#[derive(Debug, Clone)]
pub struct Shard {
    pub age: f64,
}

impl Shard {
    /// Deep-history shards require a per-shard retention bond. Hot shards do not.
    pub fn is_deep(&self, deep_threshold: f64) -> bool {
        self.age >= deep_threshold
    }
}

/// An actor: one real entity, possibly running many pseudonyms. `storage_capacity`
/// bounds total shards held; `capital` bounds total deep-shard bonds posted
/// (`deep_held · bond_rate ≤ capital`). The keystone: total bond scales with
/// shards-held × rate, *independent of pseudonym count*, so a Sybil whale gains
/// nothing from splitting — its only lever is more capital. The whale is modeled as
/// one actor with a large endowment, and the actor-level spread metric is what
/// catches it.
#[derive(Debug, Clone)]
pub struct Actor {
    pub storage_capacity: usize,
    pub capital: f64,
    pub is_whale: bool,
}

/// The simulated world: shards, actors, and per-actor holdings (sets of shard ids).
pub struct World {
    pub shards: Vec<Shard>,
    pub actors: Vec<Actor>,
    /// `holdings[a]` = set of shard ids actor `a` currently retains.
    pub holdings: Vec<Vec<bool>>,
    /// `locks[a][s]` = epochs remaining on actor `a`'s retention commitment to deep
    /// shard `s` (0 = unlocked/free to drop). A locked holding cannot be dropped
    /// without slashing the bond, so a rational actor retains it — this is how the
    /// age-scaled **duration** (L9) damps churn. Always 0 in the static iteration-1
    /// model (no `dynamic`/duration), so iteration-1 behavior is unchanged.
    pub locks: Vec<Vec<u32>>,
}

impl World {
    pub fn new(shards: Vec<Shard>, actors: Vec<Actor>) -> Self {
        let n_shard = shards.len();
        let holdings = vec![vec![false; n_shard]; actors.len()];
        let locks = vec![vec![0u32; n_shard]; actors.len()];
        Self {
            shards,
            actors,
            holdings,
            locks,
        }
    }

    /// Advance the world one epoch in the **dynamic frontier-window** model (L9 churn
    /// source): every shard ages by `age_step`; any shard reaching `age ≥ 1.0` is
    /// retired and its slot recycled as a fresh `age = 0` shard (holdings + locks on
    /// that slot cleared — a retired shard is out of the active window). Remaining
    /// locks decrement by one epoch. This is the realistic churn pressure (the chain
    /// grows; shards transit hot→deep), and it is the only thing that gives the
    /// duration knob something to damp.
    ///
    /// **Modeling simplification (documented):** the window models the *churn
    /// frontier* (the hot→deep transit where acquisition/drop decisions happen).
    /// Permanent archival of the truly-oldest state is a gate-5 foundation concern,
    /// out of this window — so "retire at age 1" is a window boundary, not a claim
    /// that irreplaceable data is discarded.
    pub fn advance_epoch(&mut self, age_step: f64) {
        for (s, shard) in self.shards.iter_mut().enumerate() {
            shard.age += age_step;
            if shard.age >= 1.0 {
                // Retire + recycle the slot.
                shard.age = 0.0;
                for a in 0..self.actors.len() {
                    self.holdings[a][s] = false;
                    self.locks[a][s] = 0;
                }
            }
        }
        // Decrement remaining locks.
        for a in 0..self.actors.len() {
            for l in self.locks[a].iter_mut() {
                *l = l.saturating_sub(1);
            }
        }
    }

    /// Replication count per shard = number of distinct actors holding it.
    /// (Equals distinct-pseudonym count under rational no-self-replication; see the
    /// module docstring.)
    pub fn replication(&self) -> Vec<usize> {
        let mut r = vec![0usize; self.shards.len()];
        for held in &self.holdings {
            for (s, &h) in held.iter().enumerate() {
                if h {
                    r[s] += 1;
                }
            }
        }
        r
    }

    pub fn actor_shard_count(&self, a: usize) -> usize {
        self.holdings[a].iter().filter(|&&h| h).count()
    }
}

/// Age-weighted scarcity multiplier `g(age)`. `age_weight = 0` gives `g ≡ 1`
/// (the pure-`1/R` baseline included specifically to *confirm* the predicted
/// deep-history failure — sim-validating the equilibrium analysis). `age_weight > 0`
/// gives `g = 1 + age_weight · age`, the privacy-clean premium (age is a public
/// shard property, carrying no tier oracle) that pays deep shards more to overcome
/// the bond asymmetry.
pub fn g_age(age: f64, age_weight: f64) -> f64 {
    1.0 + age_weight * age
}

/// Per-deep-shard bond cost as a function of age. `bond_age_scale = 0` gives a
/// **flat** bond (`bond_rate` for every deep shard — iteration-1's model). `> 0`
/// gives a **mean-preserving age-tilted** bond that *redistributes* bond demand
/// toward older shards while holding the average deep bond at `bond_rate`:
/// `bond_rate · (1 + scale·(age − deep_mid))`, with `deep_mid = (deep_threshold+1)/2`
/// the mean deep age under a uniform age distribution. Mean-preservation is what makes
/// flat vs. tilted comparable at equal *aggregate* capital demand, so the L4 question
/// (does tilting concentrate affording-actor scarcity onto the oldest tail?) is
/// isolated from a mere total-cost increase. Clamped to a small positive floor so the
/// youngest deep shards never bond free. Hot shards carry no bond (callers guard).
pub fn bond_age(age: f64, bond_rate: f64, bond_age_scale: f64, deep_threshold: f64) -> f64 {
    let deep_mid = (deep_threshold + 1.0) / 2.0;
    let factor = (1.0 + bond_age_scale * (age - deep_mid)).max(0.05);
    bond_rate * factor
}

/// Per-deep-shard bond **duration** (retention-commitment horizon, in epochs) as a
/// function of age — the L9 second bond axis, orthogonal to magnitude. `base` is the
/// flat horizon; `dur_age_scale > 0` makes older shards carry a *longer* commitment
/// (`base · (1 + dur_age_scale · age)`), encoding the tier system's old
/// commitment-horizon job. Unlike magnitude, duration is an opportunity-cost on
/// *willingness* (the same capital committed longer), not a hard affordability gate —
/// it does not shrink the affording pool, so it damps tail churn without concentrating
/// distinct holders (see `docs/design/STAKER_ARCHIVAL_SIM.md` L4/L9). Returns whole
/// epochs (rounded, floored at 1 for deep shards).
pub fn bond_duration(age: f64, base: f64, dur_age_scale: f64) -> u32 {
    let d = base * (1.0 + dur_age_scale * age);
    (d.round() as i64).max(1) as u32
}

/// Age-dependent durability replication floor `R_target(age)`. Higher for deep
/// history because deep state is irreplaceable (lose every copy → gone forever),
/// while hot state is widely held anyway. Linear from `r_target_hot` (age 0) to
/// `r_target_deep` (age 1).
pub fn r_target(age: f64, r_target_hot: f64, r_target_deep: f64) -> usize {
    let t = r_target_hot + (r_target_deep - r_target_hot) * age;
    // Round to nearest; floor at 1 (every shard needs at least one copy).
    (t.round() as usize).max(1)
}
