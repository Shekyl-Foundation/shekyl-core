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
    /// Composition control key: an independent per-shard draw used **only** by the
    /// decorrelated arm of the composition axis (`CompositionParams::decorrelated`).
    /// `0.0` in every other scenario, and never drawn there, so the RNG stream — and
    /// therefore every pre-composition result — is byte-identical.
    pub size_seed: f64,
    /// Storage units this shard occupies, relative to the mean shard — **fixed at
    /// birth**. A shard's bytes are determined when it closes and never change again, so
    /// this is stored state, not a function of the shard's *current* age: keying it on
    /// current age would make a shard shrink as it ages under a dynamic window
    /// (`advance_epoch`), which is physically wrong. `1.0` under a flat composition.
    pub size: f64,
}

impl Shard {
    /// Deep-history shards require a per-shard retention bond. Hot shards do not.
    pub fn is_deep(&self, deep_threshold: f64) -> bool {
        self.age >= deep_threshold
    }
}

/// **Composition axis** (`PDM-Q-F34`) — per-shard storage cost, rebuilt for the
/// domain `SHT-Q1` ruled.
///
/// **What the ruling changed.** `SHT-Q1` (Rick, 2026-09-27) put the partition over
/// **transactions that carry archival good**, so a shard is `T` such transactions
/// **in any era**. The first version of this axis modelled *coinbase dilution* — a
/// quiet era packing ~180 coinbases and ~20 spends into one shard — and that
/// mechanism **exists only under the storage-id domain**. It is gone here.
///
/// *The cutover has not landed:* `prune.rs` still partitions storage ids at this
/// pin. The sim models the **ruled** design because its job is to price what will
/// ship, not the interim state.
///
/// **Two axes, because they answer different questions**, and collapsing them is
/// what made L19's result hard to read:
///
/// 1. **Per-transaction shape** ([`Self::cv_tx`]) — a shard's good is a sum over
///    `T` transactions, so dispersion in per-transaction size (mainly input count)
///    is suppressed by `√T`. This is `L1`'s form exactly, and under the ruled
///    domain it is the **only** composition term that survives on its own.
/// 2. **Era-level mean shift** ([`Self::spread`] with [`Self::era_shape`]) — the
///    *typical transaction* can still differ era to era: a busy era's transactions
///    carry more inputs than a quiet one's. So "a heavy era" survives the ruling
///    with a **different mechanism** — bigger transactions, not fuller blocks.
///
/// > `size_at_birth = era_mean(birth_era) · (1 + cv_tx · z / √T)`
///
/// Both default to off (`spread = 1.0`, `cv_tx = 0.0`), so every pre-`F34` scenario
/// is byte-identical — including the RNG stream, since `z` is drawn **only** when
/// `cv_tx > 0`.
///
/// Sizes are normalized so the mean shard is one storage unit: the axis
/// **redistributes** cost, it does not add it (adding it is `storage_scale`).
///
/// `decorrelated` is the control for the **era** axis alone: the same era marginal
/// keyed on an independent draw, which separates "heavy shards are under-held" from
/// "old shards are under-held".
#[derive(Debug, Clone, Copy)]
pub struct CompositionParams {
    /// Era-level heavy/light mean ratio `S` (`1.0` = flat).
    pub spread: f64,
    /// How the era mean moves with the birth era.
    pub era_shape: EraShape,
    /// Coefficient of variation of **per-transaction** good. Suppressed by `√T`, so
    /// the per-shard dispersion it produces is `cv_tx / √T`. `0.0` = off, and no
    /// RNG is drawn for it.
    pub cv_tx: f64,
    /// Key the era mean on an independent draw instead of the birth era.
    pub decorrelated: bool,
}

/// How a shard's **era mean** moves with the era it was born in — the shape the
/// heavy-era arm drives.
///
/// `key = 0` is the newest era, `key = 1` the oldest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EraShape {
    /// Monotone growth: newest heaviest, oldest lightest. L19's shape, and the one
    /// its own residue flagged as **mean-preserving** — its heavy end is capped just
    /// under `2 ×` the mean at every `S`, which is why it could not express a
    /// genuinely heavy band.
    Monotone,
    /// Growth to a plateau: usage rises, then levels. The realistic steady state, and
    /// the shape under which a heavy era **ages into the deep band** rather than
    /// always sitting at the frontier.
    Plateau,
    /// A burst: one era markedly heavier than its neighbours, the rest flat. The
    /// shape that puts a heavy band at a *chosen* depth, which is what grades the
    /// `g(age)` premium against real bytes.
    Burst,
}

impl EraShape {
    /// The unnormalized era mean at `key`.
    fn raw(self, key: f64, spread: f64) -> f64 {
        match self {
            // Newest heaviest, falling linearly to 1.0 at the oldest.
            Self::Monotone => 1.0 + (spread - 1.0) * (1.0 - key),
            // Heavy for the newest third, then levelling to 1.0 — so the heavy band
            // is a *band*, not a single frontier shard.
            Self::Plateau => {
                let t = (key / 0.5).min(1.0);
                1.0 + (spread - 1.0) * (1.0 - t)
            }
            // One heavy era centred at key 0.5 — mid-depth, so it is deep enough to
            // be graded against `r_target_deep` and old enough to carry a premium.
            Self::Burst => {
                let d = (key - 0.5).abs();
                if d < 0.125 {
                    spread
                } else {
                    1.0
                }
            }
        }
    }

    /// Mean of [`Self::raw`] over a uniform key — the divisor that holds total
    /// storage demand fixed as `S` moves.
    fn norm(self, spread: f64) -> f64 {
        match self {
            Self::Monotone => 1.0 + (spread - 1.0) / 2.0,
            // The ramp occupies the first half and averages `(spread + 1)/2` there.
            Self::Plateau => 1.0 + (spread - 1.0) / 4.0,
            // The burst occupies a quarter of the key range.
            Self::Burst => 1.0 + (spread - 1.0) / 4.0,
        }
    }
}

impl CompositionParams {
    /// `T`, read from the partition constant rather than duplicated
    /// (`shekyl_types::SHARD_TX_COUNT`).
    fn shard_tx_count() -> f64 {
        shekyl_types::SHARD_TX_COUNT as f64
    }

    /// Neither axis is on.
    pub fn is_flat(&self) -> bool {
        self.spread <= 1.0 && self.cv_tx <= 0.0
    }

    /// Whether a per-shard shape draw is consumed. **Load-bearing for byte
    /// identity:** the RNG stream must not move for a scenario that does not use
    /// this axis.
    pub fn draws_shape(&self) -> bool {
        self.cv_tx > 0.0
    }

    /// The era mean a shard born at `key` carries.
    fn era_mean(&self, key: f64) -> f64 {
        if self.spread <= 1.0 {
            return 1.0;
        }
        self.era_shape.raw(key, self.spread) / self.era_shape.norm(self.spread)
    }

    /// Storage units a shard born in era `key` occupies, relative to the mean shard,
    /// with `z` its standard-normal-ish shape draw (`0.0` when [`Self::draws_shape`]
    /// is false).
    ///
    /// Called **once per shard, at birth**; the result is stored in [`Shard::size`].
    /// A shard's bytes are fixed when it closes, so this must never be re-evaluated
    /// against a live shard's current age.
    pub fn size_at_birth(&self, key: f64, z: f64) -> f64 {
        if self.is_flat() {
            return 1.0;
        }
        // `√T` suppression: a shard's good is a sum over `T` transactions, so
        // per-transaction dispersion shrinks by `√T` at the shard level. This is
        // exactly `L1`'s form, and it is why an iid per-tx spread cannot produce a
        // band-level effect on its own.
        let shape = if self.draws_shape() {
            1.0 + self.cv_tx * z / Self::shard_tx_count().sqrt()
        } else {
            1.0
        };
        (self.era_mean(key) * shape).max(0.0)
    }

    /// The era key a shard is born under: its age at birth, or — in the control —
    /// an independent draw.
    pub fn birth_key(&self, age_at_birth: f64, size_seed: f64) -> f64 {
        if self.decorrelated {
            size_seed
        } else {
            age_at_birth
        }
    }

    /// The size a shard was born with.
    pub fn size(&self, shard: &Shard) -> f64 {
        if self.is_flat() {
            return 1.0;
        }
        shard.size
    }

    /// Realized mean size over a shard set (`1.0` when flat).
    pub fn mean_size(&self, shards: &[Shard]) -> f64 {
        if self.is_flat() || shards.is_empty() {
            return 1.0;
        }
        shards.iter().map(|s| self.size(s)).sum::<f64>() / shards.len() as f64
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
    /// **Reservation yield** (L11): the per-epoch risk-adjusted return this actor's
    /// staking capital could earn elsewhere (its opportunity cost). The actor
    /// participates as a bonded archiver only while its realized archival yield
    /// (`net token reward ÷ committed bond capital`) clears this. Heterogeneous across
    /// actors (different capital has different alternatives). Ignored when the scenario
    /// is not `endogenous` (fixed population — every prior iteration), so legacy
    /// behavior is unchanged.
    pub reservation: f64,
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
    /// `inflight[a][s]` = epochs remaining until actor `a`'s *fetch* of shard `s`
    /// completes (0 = seated/serving, or not held). The L10 **backfill-lag** state:
    /// a freshly-acquired deep shard is *committed* (consumes storage + posts the
    /// bond) but is **not yet serving** — it does not count toward replication or
    /// reward until the fetch finishes (`shard size ÷ anonymizing-transport
    /// throughput`, the post-testnet measurement). Drops are instant; backfill is
    /// lagged. This is what makes coverage **timing-bound**, not merely
    /// capacity-bound, so the model can finally exhibit (or fail to exhibit) the
    /// drop-without-standing-replacement oscillation age-scaled duration would damp.
    /// Always 0 when `fetch_latency == 0` (every prior scenario), so iteration-1/2
    /// behavior is byte-identical.
    pub inflight: Vec<Vec<u32>>,
    /// `active[a]` = whether actor `a` is currently participating (L11 endogenous
    /// participation). An inactive actor holds nothing and earns nothing; it is a
    /// *potential* entrant the free-entry dynamics may admit. Initialized all-`true`
    /// (the fixed-population model of every prior iteration); `run_sim` overrides it
    /// only when the scenario is `endogenous`, so legacy behavior is byte-identical.
    pub active: Vec<bool>,
    /// `below_streak[a]` = consecutive epochs actor `a`'s realized yield has failed its
    /// reservation (or it has deployed zero bond capital). Exit fires after the
    /// scenario's patience window — hysteresis that damps entry/exit thrashing, the
    /// same async-update discipline the shard game uses. Inert unless `endogenous`.
    pub below_streak: Vec<u32>,
    /// `cooling[a]` = per-actor list of `(frozen_amount, epochs_remaining)` release-
    /// cooldown escrow entries (L18 — `HoldingsUpdate` mobility friction). When actor
    /// `a` **voluntarily** drops a deep shard, the released bond collateral does not
    /// return to its spendable `capital` at once: it is frozen for
    /// `RELEASE_COOLDOWN_EPOCHS` (gate-4 §4.4 per-shard release cooldown) before it can
    /// fund a new bond. `frozen_capital(a)` (the sum of live entries) is subtracted from
    /// the agent's capital budget each epoch, so in the capital-poor deep tail a dropped
    /// shard's collateral cannot instantly recycle into a replacement — the optimism the
    /// pre-L18 model carried (instant redeploy). **Flat amount:** each entry is the flat
    /// `ARCHIVAL_BOND_FLOOR` (modeled as `bond_rate`), per gate-4 §8.1
    /// (`bond_floor = ARCHIVAL_BOND_FLOOR × |set|` — per-shard capital is depth-flat); the
    /// freeze's *coverage incidence* is age-stratified (deep capital is least mobile via
    /// the L9 lock, and the deep tail is thinnest), not its *amount*. Always empty when
    /// `release_cooldown_epochs == 0` (every pre-L18 scenario), so legacy behavior is
    /// byte-identical. Slash (L11 exit / age-1 recycle) forfeits collateral to burn
    /// (gate-4 §4.5) and never escrows — only voluntary drops cool.
    pub cooling: Vec<Vec<(f64, u32)>>,
}

impl World {
    pub fn new(shards: Vec<Shard>, actors: Vec<Actor>) -> Self {
        let n_shard = shards.len();
        let n_actor = actors.len();
        let holdings = vec![vec![false; n_shard]; n_actor];
        let locks = vec![vec![0u32; n_shard]; n_actor];
        let inflight = vec![vec![0u32; n_shard]; n_actor];
        let active = vec![true; n_actor];
        let below_streak = vec![0u32; n_actor];
        let cooling = vec![Vec::new(); n_actor];
        Self {
            shards,
            actors,
            holdings,
            locks,
            inflight,
            active,
            below_streak,
            cooling,
        }
    }

    /// Capital currently frozen in actor `a`'s release-cooldown escrow (L18). The sum
    /// of live entry amounts; subtracted from the actor's spendable bond budget in
    /// `best_response`. `0.0` whenever no voluntary drop is cooling (every pre-L18
    /// scenario, since entries are pushed only when `release_cooldown_epochs > 0`).
    pub fn frozen_capital(&self, a: usize) -> f64 {
        self.cooling[a].iter().map(|&(amt, _)| amt).sum()
    }

    /// Deactivate actor `a` (L11 exit): clears its holdings, locks, and in-flight
    /// fetches. Exit forfeits any posted bond (a slash) and overrides retention locks —
    /// duration (L9) deters *voluntary drop while staying*, not *capital flight*, so an
    /// exiting actor abandons even locked shards. Resets its streak.
    pub fn deactivate(&mut self, a: usize) {
        self.active[a] = false;
        self.below_streak[a] = 0;
        for h in self.holdings[a].iter_mut() {
            *h = false;
        }
        for l in self.locks[a].iter_mut() {
            *l = 0;
        }
        for f in self.inflight[a].iter_mut() {
            *f = 0;
        }
        // L18: clear release-cooldown escrow. Exit is a full slash/clean-release event,
        // not a voluntary mid-life drop; the actor's capital state resets, and a
        // re-entrant starts fresh (no carried freeze). Clearing here prevents a stale
        // escrow from double-freezing capital on the exit→re-entry path (the clean
        // `Release` already requires the cooldown to have elapsed as a precondition —
        // gate-4 §3.2/§4.3 — so re-entering capital is not still cooling).
        self.cooling[a].clear();
    }

    /// Append a fresh `age` shard to the frontier — the L12 **growing-window**
    /// (bootstrap) primitive. The steady-state `advance_epoch` recycles a *fixed-size*
    /// window in place; bootstrap instead starts from a small genesis core and grows the
    /// window toward its steady-state size as the chain produces blocks, so deep history
    /// accrues *from zero* rather than being present at `t=0`. Extends every actor's
    /// holdings/locks/inflight by one (unheld, unlocked, not-in-flight) slot so the new
    /// shard is consistently indexable. No-op on legacy scenarios (never called when
    /// `!bootstrap`).
    pub fn append_shard(&mut self, age: f64, comp: &CompositionParams, birth_era_key: f64) {
        self.shards.push(Shard {
            age,
            size_seed: 0.0,
            size: comp.size_at_birth(comp.birth_key(birth_era_key, 0.0), 0.0),
        });
        for a in 0..self.actors.len() {
            self.holdings[a].push(false);
            self.locks[a].push(0);
            self.inflight[a].push(0);
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
    /// `birth_era_key` is the era a **recycled** slot is born into — simulation time,
    /// not the shard's age. Keying it on age instead collapses the era distribution:
    /// every recycled slot is born at age 0, so under a dynamic window *every* shard
    /// eventually carries the newest era's size and the axis stops modelling eras at
    /// all. (Measured: it drove the realized mean size to 2.22 at `S = 4` under
    /// `Plateau` and 0.57 under `Burst`, starving or gifting coverage wholesale.)
    /// A static snapshot is the special case where age *is* the birth era.
    pub fn advance_epoch(&mut self, age_step: f64, comp: &CompositionParams, birth_era_key: f64) {
        for (s, shard) in self.shards.iter_mut().enumerate() {
            shard.age += age_step;
            if shard.age >= 1.0 {
                // Retire + recycle the slot. The slot becomes a NEW shard, so it is
                // re-sized at birth — a shard's bytes are fixed when it closes, so the
                // one it replaces does not carry its size forward, and this one does not
                // shrink as it ages.
                shard.age = 0.0;
                shard.size =
                    comp.size_at_birth(comp.birth_key(birth_era_key, shard.size_seed), 0.0);
                for a in 0..self.actors.len() {
                    self.holdings[a][s] = false;
                    self.locks[a][s] = 0;
                    self.inflight[a][s] = 0;
                }
            }
        }
        // Decrement remaining locks and advance in-flight fetches (a fetch in
        // progress gets one epoch closer to seated; at 0 it begins serving).
        for a in 0..self.actors.len() {
            for l in self.locks[a].iter_mut() {
                *l = l.saturating_sub(1);
            }
            for (s, f) in self.inflight[a].iter_mut().enumerate() {
                // Only count down fetches the actor is still committed to.
                if self.holdings[a][s] {
                    *f = f.saturating_sub(1);
                } else {
                    *f = 0;
                }
            }
            // L18 release-cooldown escrow: tick each frozen entry one epoch closer to
            // release; drop entries that reach 0 (capital returns to spendable). This
            // decrement runs *before* this epoch's best-responses, so an entry pushed with
            // `epochs_remaining = release_cooldown_epochs` is observed frozen for
            // `release_cooldown_epochs - 1` of these later best-responses; the drop epoch
            // itself is the first frozen epoch, enforced separately in `best_response` by
            // pre-charging the dropped shard's collateral (it cannot refund a same-epoch
            // acquisition). Pre-charge (drop epoch) + escrow (the next C-1) span the full
            // `RELEASE_COOLDOWN_EPOCHS` — the faithful-freeze fix for Copilot PR#148 #4/#5
            // that closes the pre-genesis off-by-one (escrow alone froze only C-1). No-op
            // when no escrow is live.
            for e in self.cooling[a].iter_mut() {
                e.1 = e.1.saturating_sub(1);
            }
            self.cooling[a].retain(|&(_, rem)| rem > 0);
        }
    }

    /// **Committed** replication per shard = number of distinct actors holding it
    /// (in-flight or seated). This is what the economic game and reward see — an actor
    /// is paid to *store* (committed), not for instantaneous retrievability. (Equals
    /// distinct-pseudonym count under rational no-self-replication; see the module
    /// docstring.) Unchanged from iterations 1–2.
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

    /// **Serving** replication per shard = distinct actors holding it *and seated*
    /// (`inflight == 0`). In-flight fetches are committed but not yet retrievable —
    /// the L10 backfill lag. This is the *retrieval-coverage* view, decoupled from the
    /// economic game (`replication`): a drop removes a serving copy instantly, but the
    /// backfilling actor's copy is not serving until its fetch seats, so serving
    /// coverage can dip below committed coverage for `fetch_latency` epochs — the
    /// timing-bound oscillation channel. Equals `replication()` when no shard is
    /// in-flight (`fetch_latency == 0`, all prior scenarios).
    pub fn serving_replication(&self) -> Vec<usize> {
        let mut r = vec![0usize; self.shards.len()];
        for (a, held) in self.holdings.iter().enumerate() {
            for (s, &h) in held.iter().enumerate() {
                if h && self.inflight[a][s] == 0 {
                    r[s] += 1;
                }
            }
        }
        r
    }

    pub fn actor_shard_count(&self, a: usize) -> usize {
        self.holdings[a].iter().filter(|&&h| h).count()
    }

    /// **L18 causal freeze-harm predicate** — is some active actor a
    /// *willing-and-able-but-frozen* archiver for shard `s`? True iff an active actor
    /// (i) is not already holding `s`, (ii) holds at least one floor (`bond_rate`) of
    /// **frozen** capital, and (iii) has a spare storage slot. This is the
    /// structural-necessary condition for the *freeze* — rather than absolute capital
    /// shortage — to be what keeps `s` under target: an actor who would re-cover `s` but
    /// for collateral locked in release cooldown.
    ///
    /// **It never fires in the L18 sweep — but the preclusion is a rationality property of
    /// the cooldown-aware `best_response`, not a structural impossibility**
    /// (`STAKER_ARCHIVAL_SIM.md` §L18 detector validation). `best_response` budgets on
    /// `effective_capital = capital − Σ frozen` and additionally **pre-charges** the
    /// collateral of every deep shard held at epoch start (it *sees* the cooldown from the
    /// drop epoch onward, not just the epoch after), so it never makes the one move that
    /// strands an actor — the futile drop-to-reallocate (drop A to fund B while A's freed
    /// collateral is frozen and useless this window, the drop epoch included). It instead
    /// points
    /// scarce budget at the *thinnest* (most scarcity-profitable) shards and *holds* them
    /// (condition i fails); the shards that stay under target are in absolute shortage
    /// (nobody can afford them), never frozen-but-idle. So a sweep reading of `0` means the
    /// willing-and-able-but-frozen state is **precluded under cooldown-aware optimization**,
    /// **not** "the computation is dead": the unit tests `freeze_predicate_fires_when_blocked`
    /// / `..._silent_when_*` are the positive/negative control proving the predicate fires
    /// when the state *is* constructed. The state stays **reachable by a naive operator** who
    /// drops A intending to immediately bond B without modeling the cooldown — that
    /// residual is routed to operator-education + a wallet-conformance guard (§L18), not the
    /// consensus floor. Consequently the freeze-harm bracket
    /// (`freeze_harm_co − freeze_harm_causal`) is maximally wide in this sweep ⇒ maximal
    /// entanglement ⇒ causal attribution carries no marginal information; the trustworthy
    /// reads are the co-occurrence upper bound and the structural `oldest_min_committed`
    /// floor, which *are* complementary detectors.
    pub fn freeze_blocks_recoverage(&self, s: usize, bond_rate: f64) -> bool {
        // A zero (or absent) bond floor is not "one floor of frozen capital": with
        // `bond_rate <= 0` no release-cooldown escrow is ever pushed (`best_response` only
        // escrows on a *bonded* actor's voluntary deep drop), so `frozen_capital` is
        // identically 0 and the willing-and-able-but-frozen state cannot exist. Without this
        // guard the `frozen_capital(a) + 1e-9 >= bond_rate` conjunct would be trivially true
        // at `bond_rate <= 0` (any non-negative frozen total clears a non-positive floor),
        // reporting spurious causal freeze-harm in the released arms where no freeze occurs.
        if bond_rate <= 0.0 {
            return false;
        }
        (0..self.actors.len()).any(|a| {
            self.active[a]
                && !self.holdings[a][s]
                && self.frozen_capital(a) + 1e-9 >= bond_rate
                && self.actor_shard_count(a) < self.actors[a].storage_capacity
        })
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

/// Fetch latency in **epochs** to seat a freshly-acquired shard — the L10 backfill
/// lag. Hot shards are small and widely held, so they seat instantly (`0`). A deep
/// shard's latency scales with its size over the anonymizing transport's throughput:
/// `round(deep_shard_size · latency_per_unit)`, where `latency_per_unit` is the
/// post-testnet measurement (epochs of fetch per storage unit). `latency_per_unit = 0`
/// ⇒ instant seating ⇒ the capacity-bound iteration-1/2 model (byte-identical).
pub fn fetch_latency(deep: bool, deep_shard_size: f64, latency_per_unit: f64) -> u32 {
    if !deep || latency_per_unit <= 0.0 {
        return 0;
    }
    (deep_shard_size * latency_per_unit).round().max(1.0) as u32
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

#[cfg(test)]
mod composition_tests {
    use super::{Actor, CompositionParams, EraShape, Shard, World};

    fn shard(age: f64) -> Shard {
        Shard {
            age,
            size_seed: 0.0,
            size: 1.0,
        }
    }

    /// `spread = 1.0` is the pre-composition model: every shard costs exactly one unit.
    /// This is what makes every pre-`PDM-Q-F34` scenario byte-identical, so it is pinned
    /// rather than assumed.
    #[test]
    fn flat_spread_is_exactly_one_unit_per_shard() {
        let c = CompositionParams {
            spread: 1.0,
            era_shape: EraShape::Monotone,
            cv_tx: 0.0,
            decorrelated: false,
        };
        for age in [0.0, 0.25, 0.5, 0.75, 1.0] {
            assert_eq!(c.size_at_birth(age, 0.0), 1.0, "age {age}");
            assert_eq!(c.size(&shard(age)), 1.0, "age {age}");
        }
        assert_eq!(c.mean_size(&[shard(0.0), shard(1.0)]), 1.0);
    }

    /// The axis REDISTRIBUTES cost, it does not add it: the mean shard stays one unit over
    /// a uniform age distribution at every spread. Without this the arm would be a
    /// disguised `storage_scale` sweep and a coverage change would be unattributable.
    #[test]
    fn spread_is_mean_preserving_over_uniform_ages() {
        for spread in [2.0, 4.0, 10.0, 60.0] {
            let c = CompositionParams {
                spread,
                era_shape: EraShape::Monotone,
                cv_tx: 0.0,
                decorrelated: false,
            };
            let shards: Vec<Shard> = (0..1000)
                .map(|i| {
                    let age = i as f64 / 999.0;
                    Shard {
                        age,
                        size_seed: 0.0,
                        size: c.size_at_birth(age, 0.0),
                    }
                })
                .collect();
            let mean = c.mean_size(&shards);
            assert!(
                (mean - 1.0).abs() < 1e-3,
                "spread {spread}: mean size {mean} is not ~1.0"
            );
        }
    }

    /// Size tracks era density, so the young end is heavy and the old end light — the
    /// direction that puts the `g(age)` premium on the CHEAP shards. A sign flip here
    /// inverts the whole reading of the arm.
    #[test]
    fn young_shards_are_heavier_than_old_ones() {
        let c = CompositionParams {
            spread: 60.0,
            era_shape: EraShape::Monotone,
            cv_tx: 0.0,
            decorrelated: false,
        };
        let young = c.size_at_birth(0.0, 0.0);
        let old = c.size_at_birth(1.0, 0.0);
        assert!(young > old, "young {young} must exceed old {old}");
        // The extremes are the stated ratio apart; the mean-preserving normalizer is what
        // keeps the heavy END near 2x the MEAN, which is why `S` is a ratio between bands
        // and not a multiple of the mean.
        assert!((young / old - 60.0).abs() < 1e-6, "ratio {}", young / old);
        assert!(young < 2.5, "heavy end {young} is not near 2x the mean");
    }

    /// **A shard's bytes are fixed when it closes.** Size is therefore stored at birth and
    /// must not track the shard's *current* age: under a dynamic window `advance_epoch`
    /// ages every shard, and an age-keyed size would make a shard SHRINK as it aged, which
    /// is physically wrong and would silently invert the arm's reading. Pinned because the
    /// primitive is what a later dynamic-window increment will be built on — no scenario on
    /// this branch reaches it.
    #[test]
    fn size_is_fixed_at_birth_and_does_not_track_current_age() {
        let comp = CompositionParams {
            spread: 60.0,
            era_shape: EraShape::Monotone,
            cv_tx: 0.0,
            decorrelated: false,
        };
        // Born at the oldest era (light), then aged forward.
        let born_old = comp.size_at_birth(comp.birth_key(1.0, 0.0), 0.0);
        let mut w = World::new(
            vec![Shard {
                age: 0.40,
                size_seed: 0.0,
                size: born_old,
            }],
            vec![Actor {
                storage_capacity: 4,
                capital: 100.0,
                is_whale: false,
                reservation: 0.0,
            }],
        );
        for _ in 0..5 {
            w.advance_epoch(0.05, &comp, 0.0);
        }
        assert!(w.shards[0].age > 0.60, "the shard must have aged");
        assert_eq!(
            comp.size(&w.shards[0]),
            born_old,
            "size must not change as the shard ages"
        );
    }

    /// A recycled slot is a NEW shard, so it is re-sized at birth — at the newest era,
    /// which under monotone growth is the heaviest. Without this, a retiring light shard
    /// would hand its size to the fresh frontier shard replacing it.
    #[test]
    fn a_recycled_slot_is_reborn_at_the_newest_era() {
        let comp = CompositionParams {
            spread: 60.0,
            era_shape: EraShape::Monotone,
            cv_tx: 0.0,
            decorrelated: false,
        };
        let light = comp.size_at_birth(1.0, 0.0);
        let mut w = World::new(
            vec![Shard {
                age: 0.99,
                size_seed: 0.0,
                size: light,
            }],
            vec![Actor {
                storage_capacity: 4,
                capital: 100.0,
                is_whale: false,
                reservation: 0.0,
            }],
        );
        w.advance_epoch(0.05, &comp, 0.0);
        assert_eq!(w.shards[0].age, 0.0, "the slot must have recycled");
        assert_eq!(
            comp.size(&w.shards[0]),
            comp.size_at_birth(0.0, 0.0),
            "a reborn slot carries the newest era's size, not the retired shard's"
        );
        assert!(comp.size(&w.shards[0]) > light);
    }

    /// The control keys on the independent draw, so age carries no size information —
    /// the one thing that separates a cost-band finding from an age-band one.
    #[test]
    fn decorrelated_keys_on_the_seed_not_the_age() {
        let c = CompositionParams {
            spread: 10.0,
            era_shape: EraShape::Monotone,
            cv_tx: 0.0,
            decorrelated: true,
        };
        // Young but seeded light vs old but seeded heavy: the seed must decide.
        let young_light = c.size_at_birth(c.birth_key(0.0, 1.0), 0.0);
        let old_heavy = c.size_at_birth(c.birth_key(1.0, 0.0), 0.0);
        assert!(
            young_light < old_heavy,
            "seed must dominate age in the control arm"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two deep shards, one actor with capacity 2. `s = 0` is the under-target shard
    /// the predicate is asked about.
    fn one_actor_world(capacity: usize) -> World {
        let shards = vec![
            Shard {
                age: 1.0,
                size_seed: 0.0,
                size: 1.0,
            },
            Shard {
                age: 1.0,
                size_seed: 0.0,
                size: 1.0,
            },
        ];
        let actors = vec![Actor {
            storage_capacity: capacity,
            capital: 100.0,
            is_whale: false,
            reservation: 0.0,
        }];
        World::new(shards, actors)
    }

    /// **Positive control for the L18 causal freeze-harm detector.** Constructs exactly
    /// the willing-and-able-but-frozen state — active, not holding `s = 0`, one floor
    /// (`bond_rate = 10`) frozen, a spare slot — and confirms the predicate fires. This is
    /// the analogue of the `double_jitter_trap_fails_the_same_check` discipline: it proves a
    /// sweep reading of `0` means the state is "precluded under cooldown-aware optimization"
    /// (reachable by a naive drop-to-reallocate operator), not "the metric is dead".
    #[test]
    fn freeze_predicate_fires_when_blocked() {
        let mut w = one_actor_world(2);
        w.cooling[0].push((10.0, 2)); // one floor frozen
        assert!(
            w.freeze_blocks_recoverage(0, 10.0),
            "predicate must fire: active, not holding s, ≥1 floor frozen, spare storage"
        );
    }

    /// **Negative controls** — each of the four conjuncts, individually falsified, must
    /// silence the predicate. Confirms the detector is selective (not always-true), the
    /// other half of the validation.
    #[test]
    fn freeze_predicate_silent_when_any_conjunct_fails() {
        // (i) already holding s → not a re-coverage candidate.
        let mut holding = one_actor_world(2);
        holding.cooling[0].push((10.0, 2));
        holding.holdings[0][0] = true;
        assert!(!holding.freeze_blocks_recoverage(0, 10.0));

        // (ii) no frozen capital → freeze is not the binding constraint.
        let unfrozen = one_actor_world(2);
        assert!(!unfrozen.freeze_blocks_recoverage(0, 10.0));

        // (iii) frozen below one floor → cannot fund even one seat.
        let mut thin = one_actor_world(2);
        thin.cooling[0].push((9.0, 2));
        assert!(!thin.freeze_blocks_recoverage(0, 10.0));

        // (iv) storage full → no spare slot to seat the re-cover.
        let mut full = one_actor_world(1);
        full.cooling[0].push((10.0, 2));
        full.holdings[0][1] = true; // occupies the single slot (a different shard)
        assert!(!full.freeze_blocks_recoverage(0, 10.0));

        // (v) inactive → not a participant.
        let mut inactive = one_actor_world(2);
        inactive.cooling[0].push((10.0, 2));
        inactive.active[0] = false;
        assert!(!inactive.freeze_blocks_recoverage(0, 10.0));
    }
}
