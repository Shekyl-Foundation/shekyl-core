// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! TJ-4 and TJ-7 — the two inequalities the `(m, n)` re-pin needs and nobody
//! had derived (`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md` §10.4, §11.6).
//!
//! Both were **asserted** in the design round and registered in `FOLLOWUPS.md`
//! as underived. They share a structure — a gain that saturates against a cost
//! that grows — so they share this module and one report.
//!
//! First-slash *timing* is not re-derived here: it comes from
//! [`crate::proxy::expected_epochs_to_first_slash`], which walks the same
//! absorbing chain A5 prices. This module owns only the economics layered on
//! that moment (break-even attestation fraction, sybil dilution rate).
//!
//! # TJ-4 — the slash/`Rebond` cycle
//!
//! The claim was: no minimum observation count means a fresh or reinstated pair
//! is unslashable for its first `m − 1` observations, so a free-rider's steady
//! state is *"zero service, 10 free epochs, slash, `Rebond`, 10 more"* — a
//! subscription fee if `free_epochs × reward` exceeds `BOND_FLOOR + friction`.
//!
//! **The left-hand side needed correcting before it could be derived, and the
//! correction comes from the reward path itself.** A zero-service `P` earns
//! **nothing**: [`shekyl_archival_retention::consensus_state::shard_work_micro`]
//! returns `0` without serve credit, `r_market_count` skips uncredited rows, and
//! `reward_share_floor` pays on credited work. So the `m − 1` epochs are free of
//! **slash**, not free **money**, and the inequality is only non-trivial when
//! the pair *is* being credited — i.e. when some fraction `f` of its epochs draw
//! a friendly (falsely attesting) witness.
//!
//! So the derived quantity is not a yes/no but a **break-even `f`**: the
//! attestation fraction at which the cycle's earnings cover the burned bond.
//!
//! **A second correction fell out of building it.** §9.6 read
//! `f ≈ (n − m + 1)/n` as the point above which the window never slashes. That
//! bounds an adversary who can **place** its passing epochs; §8.2's draw is
//! **unchooseable**, so friendly witnesses arrive at random and windows with
//! `m` misses still occur. Absorption is **deferred, not prevented** — the
//! unchooseable draw is doing more work than §9.6 credited, and the cycle
//! question stays live across the whole range.
//!
//! **A third correction (2026-07-30): the friction term is derived, not
//! assumed.** The first cut zeroed it and mislabelled the zero
//! "attacker-favourable" — deleting a real term favours no one's analysis.
//! `Rebond` closes the slash's bad interval at `end_exclusive = E_rebond + 1`
//! (`bond_connect.rs`), so the record is out of `r_market` from the slash
//! epoch through the rebond epoch **inclusive** — a structural downtime floor
//! no attacker speed avoids, derived from the production connect plus the
//! fold/dispatch ordering ([`rebond_structural_downtime_epochs`], which also
//! records what a `Rebond` IS: reinstatement, not re-entry — the slash burns
//! one `FLOOR` and removes the shard atomically). The forgone earnings are priced at
//! the **credited** rate `f · R`, not the full-service reward: a free-rider
//! forgoes only what it would have drawn, so pricing downtime at full `R`
//! overstates the deterrent `1/f`-fold. The report extends the floor with a
//! hypothetical post-slash cooldown and quotes break-even as a function of its
//! length — the remedy curve the `(m, n)` re-pin needs. `BOND_FLOOR` is
//! `f`-independent while the downtime term scales with `f`, so the bond bounds
//! the low-`f` attacker and downtime the high-`f` one: "floor problem vs
//! cooldown problem" is a **false dichotomy**.
//!
//! # TJ-7 — sybil-per-shard dilution
//!
//! `r_market_count` counts every credited row — no `(P, shard)` uniqueness, no
//! operator dedup — so sybil-per-shard is bounded only by capital. But per-shard
//! work is `C·g/r` across `r` credited bonds, so **the shard's pool is
//! conserved**: `N` sybils against `h` honest co-holders take `N/(N+h)·g`, not
//! `N·g`. The attack is **dilution**: total take saturates at `g`, the
//! *marginal* gain over one bond saturates at `h/(1+h)·g`, and cost is
//! **linear in `N`** — so it has a finite optimum and is priceable.
//!
//! Rather than invent an opportunity-cost rate, this module reports the
//! **break-even rate**: the annual return on locked capital below which the
//! dilution attack pays. A reader supplies their own rate and reads off the
//! verdict.

use core::fmt;

use shekyl_archival_retention::bond_floor::bond_floor_of;
use shekyl_archival_retention::{
    rebond_connect, BadInterval, HoldingsKind, FAILURE_WINDOW_M, FAILURE_WINDOW_N,
    MAX_HOLDINGS_SHARDS,
};

use crate::proxy::{bond_at_risk_skl, epochs_per_year, expected_epochs_to_first_slash};

/// Horizon for TJ-4 first-slash timing.
///
/// Must be long enough that a randomly-drawn cartel still shows measurable
/// absorption **above** the deterministic no-slash fraction (§9.6 ceiling).
/// A5's reward-stream horizon ([`crate::proxy::A5_REWARD_HORIZON_EPOCHS`] ≈ 131,
/// ~5 y) prices forgone reward after a slash; it is too short for the late tail
/// of a low-miss process. 4 000 epochs is ~150 y at the settlement cadence —
/// enough that the 99 % mass gate fails only where absorption is genuinely
/// deferred past any practical rebond cycle.
pub const TJ4_ABSORPTION_HORIZON_EPOCHS: u64 = 4_000;

/// Table / search attestation fractions used by the report and tests.
const REPORT_F_GRID: [f64; 6] = [0.0, 0.02, 0.05, 0.10, 0.15, 0.20];

/// Highest attestation fraction the break-even search will consider. Above this
/// the mass gate almost always fails inside [`TJ4_ABSORPTION_HORIZON_EPOCHS`];
/// the measurable upper bound is found inside the interval, not assumed equal
/// to it.
const BREAKEVEN_F_SEARCH_HI: f64 = 0.95;

/// Absolute tolerance on `f` for break-even / measurable-edge bisection.
///
/// The report quotes break-even to four decimals; half a unit in the last place
/// (`5e-5`) is enough, and stops the search before the epoch-cache quantisation
/// (`1e-6`) collapses midpoints onto the same key. Cap iterations so a pathological
/// floating-point plateau cannot spin.
const BREAKEVEN_F_TOL: f64 = 5e-5;
const BISECT_STEPS_MAX: u32 = 32;

/// The **deterministic** no-slash threshold: `(n − m + 1)/n` — §9.6's
/// `f ≈ 0.23` at `m=11/n=13`.
///
/// **It is a bound on a PLACING adversary, not on a random one, and the
/// distinction is load-bearing** (finding from building this arm, 2026-07-29).
/// An adversary that can *choose which* epochs pass needs only `n − m + 1`
/// passes per window and never slashes. But §8.2's draw is **unchooseable** —
/// friendly witnesses arrive at the cartel's hashrate share, at random — so the
/// cartel faces a **stochastic** process, and a random pattern still hits
/// windows with `m` misses. Absorption therefore still occurs above this
/// fraction; it merely takes longer ([`expected_epochs_to_slash`] measures how
/// much longer).
///
/// So the unchooseable draw is doing **more** work than §9.6 credited: it
/// converts a hard threshold into a soft one, and the cartel needs not just a
/// share of draws but the ability to *place* them, which the derivation denies.
#[must_use]
pub fn no_slash_attestation_fraction() -> f64 {
    f64::from(FAILURE_WINDOW_N - FAILURE_WINDOW_M + 1) / f64::from(FAILURE_WINDOW_N)
}

/// Expected epochs until a slash absorbs, for a pair credited on fraction `f`
/// of its epochs (so miss rate `q = 1 − f`).
///
/// Thin adapter over [`expected_epochs_to_first_slash`]: attestation fraction
/// is the TJ-4 natural coordinate; the proxy primitive speaks miss rate.
///
/// Returns `None` when less than 99 % of the mass has absorbed within
/// `horizon_epochs` — the honest report that the horizon is truncating the
/// tail. Note this happens at `f` well **above**
/// [`no_slash_attestation_fraction`], not at it: random friendly draws do not
/// prevent absorption, they defer it.
#[must_use]
pub fn expected_epochs_to_slash(f: f64, horizon_epochs: u64) -> Option<f64> {
    let q = (1.0 - f).clamp(0.0, 1.0);
    expected_epochs_to_first_slash(q, horizon_epochs)
}

/// Memoized `f → E[epochs to slash]` for one horizon.
///
/// The report evaluates the same `f` many times (table row, net, break-even
/// bisection, measurable-domain edge). Each evaluation is a full absorbing DP;
/// caching by a stable quantisation of `f` keeps the report O(distinct f) DPs
/// instead of O(table × bisection × operands).
struct EpochCache {
    horizon: u64,
    /// `(quantised f key, E[epochs])` — linear scan is fine at report scale.
    entries: Vec<(u64, Option<f64>)>,
}

impl EpochCache {
    fn new(horizon: u64) -> Self {
        Self {
            horizon,
            entries: Vec::with_capacity(128),
        }
    }

    /// Quantise `f` so bisection midpoints and table points collide when equal
    /// at micro-attestation precision.
    fn key(f: f64) -> u64 {
        (f.clamp(0.0, 1.0) * 1_000_000.0).round() as u64
    }

    fn epochs(&mut self, f: f64) -> Option<f64> {
        let k = Self::key(f);
        if let Some((_, e)) = self.entries.iter().find(|(kk, _)| *kk == k) {
            return *e;
        }
        let e = expected_epochs_to_slash(f, self.horizon);
        self.entries.push((k, e));
        e
    }
}

/// Structural downtime of one slash/`Rebond` cycle: the epochs of `r_market`
/// exclusion even a maximally fast attacker cannot avoid.
///
/// **What a `Rebond` IS (gate-4 §3.4 / P2B-9; `bond_post.rs`): reinstatement,
/// not re-entry.** The slash burns one `FLOOR` and removes the failed shard
/// **atomically** (floor-equality is preserved), so a `Rebond`'s credit is
/// owed only for growth — zero for the common standing-only reinstatement.
/// The single-shard cycle pair is therefore slash-EMPTIED and its `Rebond` is
/// necessarily the growth form: re-adding the shard at `FLOOR`, with the
/// re-added shard taking `add_epoch = E_rebond` (Pin 7 — its age resets).
///
/// The floor has two legs, and only the first is a code probe:
///
/// 1. **Validation leg (probed from [`rebond_connect`], dep-don't-mirror):**
///    the connect closes the open interval at `end_exclusive = E_rebond + 1`,
///    and its ordering check admits `E_rebond = e` — a one-epoch span. That is
///    validation SLACK, not a route.
/// 2. **Reachability leg (+1 epoch):** a `Rebond` verifies only against an
///    interval that already EXISTS (`blockchain.cpp`: "Rebond requires an open
///    bad interval"), the interval is appended by the slash fold at the failed
///    epoch's settlement (the window verdict needs epoch `e`'s serve-credit
///    outcome), and connect dispatch precedes the slash fold within a block
///    (gate-4: `add_transaction` before the per-block slash hook). So the
///    earliest reachable `E_rebond` is the NEXT epoch: excluded span
///    `[e, e+1]` = TWO epochs.
///
/// If production grows a post-slash cooldown gate in the connect, leg 1
/// follows it; if the fold/dispatch ordering changes, leg 2's `+1` is the pin
/// to re-derive.
///
/// (`release_cooldown.rs` is the VOLUNTARY-EXIT gate — `Unbond` /
/// `HoldingsUpdate`-drop, gate-4 §4.3/§4.4 — and is not on the slash path;
/// verified at source 2026-07-29. Nothing today enforces a longer wait.)
#[must_use]
pub fn rebond_structural_downtime_epochs() -> f64 {
    const SLASH_EPOCH: u64 = 100;
    let held = [0u64];
    let bonded = bond_floor_of(HoldingsKind::ShardSetCompact, held.len());
    let open = [BadInterval {
        start_epoch: SLASH_EPOCH,
        end_exclusive: u64::MAX,
    }];
    let validation_span = (SLASH_EPOCH..SLASH_EPOCH + 64)
        .find_map(|e_rebond| {
            rebond_connect(bonded, &held, &open, &held, bonded, e_rebond)
                .ok()
                .map(|c| (c.interval_end_exclusive - SLASH_EPOCH) as f64)
        })
        .expect("rebond_connect admits no reinstatement within 64 epochs of a slash");
    // Reachability: the slash exists only from the failed epoch's settlement
    // fold onward and dispatch precedes the fold, so E_rebond >= e + 1.
    validation_span + 1.0
}

/// One cycle's friction, SKL: the credited earnings forgone while the record
/// is out of `r_market` — `downtime · f · R`.
///
/// Priced at the **credited** rate `f · R`, NOT the full-service reward `R`
/// (the correction to the downtime-is-3–6×-collateral estimate, which priced
/// the exclusion as if the free-rider were earning full service): a pair
/// credited on fraction `f` of its epochs forgoes only what it would have
/// drawn. At `f = 0` downtime costs nothing — which is exactly right, because
/// a never-credited pair has nothing to forgo.
#[must_use]
pub fn rebond_friction_skl(f: f64, downtime_epochs: f64, reward_per_epoch_skl: f64) -> f64 {
    downtime_epochs * f * reward_per_epoch_skl
}

/// One slash/`Rebond` cycle's net, SKL, for a pair credited on fraction `f`.
///
/// `earnings = E[epochs to slash] · f · reward_per_epoch_skl`;
/// `cost = bond_at_risk + friction`, with the friction **derived** from the
/// cycle's downtime ([`rebond_friction_skl`]) rather than passed as an opaque
/// number. `downtime_epochs` is the full `r_market` exclusion per cycle: the
/// structural floor ([`rebond_structural_downtime_epochs`]) plus any
/// hypothetical post-slash cooldown. Positive net means the cycle pays — the
/// "subscription fee" TJ-4 warned about.
///
/// `reward_per_epoch_skl` is what a **sole credited** holder earns on a credited
/// epoch (pool `g` at `r = 1`). That is the attacker-favourable end: co-holders
/// would dilute earnings and raise the break-even `f`.
///
/// The stage-2 report inlines [`expected_epochs_to_slash`] + [`cycle_net_from_epochs`]
/// so a single DP fills both the E[epochs] and net columns. This one-shot form is
/// the stable unit API (tests, composition by future arms).
#[must_use]
// Binary package: unit tests are a separate crate, so a pub helper used only
// from `#[cfg(test)]` trips `-D dead-code` on the non-test bin.
#[cfg_attr(not(test), allow(dead_code))]
pub fn rebond_cycle_net_skl(
    f: f64,
    reward_per_epoch_skl: f64,
    downtime_epochs: f64,
    horizon_epochs: u64,
) -> Option<f64> {
    let epochs = expected_epochs_to_slash(f, horizon_epochs)?;
    Some(cycle_net_from_epochs(
        f,
        epochs,
        reward_per_epoch_skl,
        rebond_friction_skl(f, downtime_epochs, reward_per_epoch_skl),
    ))
}

fn cycle_net_from_epochs(f: f64, epochs: f64, reward_per_epoch_skl: f64, friction_skl: f64) -> f64 {
    epochs * f * reward_per_epoch_skl - (bond_at_risk_skl() + friction_skl)
}

/// Highest `f` in `[0, BREAKEVEN_F_SEARCH_HI]` at which absorption is still
/// measurable within the horizon. Monotone in `f` (more friendly draws ⇒ later
/// slash ⇒ less mass inside a fixed window), so binary search finds the edge
/// without an O(n) linear probe of the DP.
fn measurable_f_hi(cache: &mut EpochCache) -> f64 {
    if cache.epochs(0.0).is_none() {
        return 0.0;
    }
    if cache.epochs(BREAKEVEN_F_SEARCH_HI).is_some() {
        return BREAKEVEN_F_SEARCH_HI;
    }
    let mut lo = 0.0_f64;
    let mut hi = BREAKEVEN_F_SEARCH_HI;
    for _ in 0..BISECT_STEPS_MAX {
        if hi - lo <= BREAKEVEN_F_TOL {
            break;
        }
        let mid = 0.5 * (lo + hi);
        if cache.epochs(mid).is_some() {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    lo
}

/// Break-even search core against a caller-supplied cache and measurable edge.
///
/// Split out so one cache (and one `measurable_f_hi` probe — the high-`f`
/// DPs are the slowest) can serve the headline break-evens AND every
/// `(cooldown, operand)` cell of the remedy curve: `E[f]` depends on neither
/// the downtime nor the reward. Single-crossing holds with the downtime term —
/// once `(E(f) − d) · f · R` clears the bond it stays cleared, because `E` is
/// monotone in `f`.
fn breakeven_in_measurable(
    cache: &mut EpochCache,
    hi_bound: f64,
    reward_per_epoch_skl: f64,
    downtime_epochs: f64,
) -> Option<f64> {
    let net_at = |f: f64, cache: &mut EpochCache| -> Option<f64> {
        let e = cache.epochs(f)?;
        Some(cycle_net_from_epochs(
            f,
            e,
            reward_per_epoch_skl,
            rebond_friction_skl(f, downtime_epochs, reward_per_epoch_skl),
        ))
    };

    // Even at the latest measurable f the cycle still loses the bond.
    if net_at(hi_bound, cache).is_none_or(|v| v < 0.0) {
        return None;
    }
    // Degenerate: already non-negative at f = 0 (zero bond / infinite reward).
    if net_at(0.0, cache).is_some_and(|v| v >= 0.0) {
        return Some(0.0);
    }

    let mut lo = 0.0_f64;
    let mut hi = hi_bound;
    for _ in 0..BISECT_STEPS_MAX {
        if hi - lo <= BREAKEVEN_F_TOL {
            break;
        }
        let mid = 0.5 * (lo + hi);
        match net_at(mid, cache) {
            Some(v) if v >= 0.0 => hi = mid,
            _ => lo = mid,
        }
    }
    Some(hi)
}

/// The attestation fraction at which the cycle first breaks even, at a given
/// per-cycle downtime ([`rebond_friction_skl`] prices it per probed `f`).
///
/// Searched across the whole regime where absorption is measurable, **not**
/// capped at [`no_slash_attestation_fraction`] — see this module's second
/// correction: a randomly-drawn cartel still absorbs above that fraction.
///
/// `None` means the burned bond is never covered anywhere the cycle completes
/// within the horizon — the window is **not** a subscription fee at this
/// reward level and downtime.
///
/// Memoizes `E[epochs](f)` for the bisection so each distinct `f` runs the
/// absorbing DP at most once (the search probes the measurable edge and then
/// the break-even root).
#[must_use]
// Binary package: unit tests are a separate crate, so a pub helper used only
// from `#[cfg(test)]` trips `-D dead-code` on the non-test bin (the report
// shares one cache via [`breakeven_in_measurable`] instead).
#[cfg_attr(not(test), allow(dead_code))]
pub fn rebond_breakeven_f(
    reward_per_epoch_skl: f64,
    downtime_epochs: f64,
    horizon_epochs: u64,
) -> Option<f64> {
    let mut cache = EpochCache::new(horizon_epochs);
    // No measurable absorption even at f = 0 (should not happen for m-of-n).
    cache.epochs(0.0)?;
    let hi_bound = measurable_f_hi(&mut cache);
    breakeven_in_measurable(&mut cache, hi_bound, reward_per_epoch_skl, downtime_epochs)
}

/// TJ-7 *marginal* gain: extra share of shard pool `g` that `n_sybil` bonds
/// take from `h_honest` co-holders, relative to a single bond among the same
/// honest set.
///
/// `[ N/(N+h) − 1/(1+h) ] · g`. This is the cartel's **extra** take from
/// diluting honest co-holders, not total take `N/(N+h)·g`. Saturates at
/// `h/(1+h)·g` as `N → ∞` (strictly below `g`).
#[must_use]
pub fn sybil_dilution_gain(n_sybil: u64, h_honest: u64, pool_g_skl: f64) -> f64 {
    if n_sybil == 0 {
        return 0.0;
    }
    let n = n_sybil as f64;
    let h = h_honest as f64;
    (n / (n + h) - 1.0 / (1.0 + h)) * pool_g_skl
}

/// The **annual** return on locked capital below which sybil-per-shard pays.
///
/// The cartel locks `(N − 1)` extra bond floors for a year to gain
/// `epochs_per_year · gain_per_epoch`. Reporting the break-even rate rather
/// than assuming one keeps the modeling parameter out of the verdict.
#[must_use]
pub fn sybil_breakeven_opportunity_rate(
    n_sybil: u64,
    h_honest: u64,
    pool_g_per_epoch_skl: f64,
) -> Option<f64> {
    if n_sybil <= 1 {
        return None;
    }
    let locked = (n_sybil - 1) as f64 * bond_at_risk_skl();
    if locked <= 0.0 {
        return None;
    }
    let annual_gain =
        sybil_dilution_gain(n_sybil, h_honest, pool_g_per_epoch_skl) * epochs_per_year();
    Some(annual_gain / locked)
}

fn fmt_breakeven_f(f: Option<f64>) -> String {
    f.map_or_else(|| "none".to_string(), |x| format!("{x:.4}"))
}

fn fmt_rate_pct(rate: Option<f64>) -> String {
    rate.map_or_else(|| "—".to_string(), |r| format!("{:.1}%", r * 100.0))
}

/// Write one TJ-7 rate table for a single pool operand.
fn write_sybil_table(
    out: &mut impl fmt::Write,
    pool_g_per_epoch_skl: f64,
    label: &str,
) -> fmt::Result {
    writeln!(
        out,
        "  TJ-7 at {label} pool g = {G:.4} SKL/epoch (sole credited holder; pool is\n\
         CONSERVED — N sybils vs h honest take N/(N+h)*g, NOT N*g):",
        G = pool_g_per_epoch_skl,
    )?;
    writeln!(
        out,
        "{:<8} {:>8} {:>16} {:>22}",
        "N", "h", "gain SKL/epoch", "break-even rate/yr"
    )?;
    for &(n, h) in &[(2u64, 1u64), (5, 1), (5, 5), (20, 5), (100, 5), (100, 50)] {
        let gain = sybil_dilution_gain(n, h, pool_g_per_epoch_skl);
        let rate = sybil_breakeven_opportunity_rate(n, h, pool_g_per_epoch_skl);
        writeln!(
            out,
            "{:<8} {:>8} {:>16.5} {:>22}",
            n,
            h,
            gain,
            fmt_rate_pct(rate)
        )?;
    }
    Ok(())
}

/// TJ-4 + TJ-7 report — the two underived inequalities, derived.
///
/// Both operands are **per-shard pool per epoch** (what a sole credited holder
/// earns at `r = 1`). That quantity is also the conserved pool `g` TJ-7
/// dilutes — one concept, two economic readings.
///
/// - `reward_median_per_epoch_skl` — representative cell of the scenario family
/// - `reward_max_per_epoch_skl` — family maximum (alarm-raising for TJ-4/TJ-7:
///   larger flow makes the cycle and the dilution more profitable)
pub fn tj_inequalities_report(
    out: &mut impl fmt::Write,
    reward_median_per_epoch_skl: f64,
    reward_max_per_epoch_skl: f64,
) -> fmt::Result {
    let horizon = TJ4_ABSORPTION_HORIZON_EPOCHS;
    let ceiling = no_slash_attestation_fraction();
    let bond = bond_at_risk_skl();

    writeln!(
        out,
        "\nTJ-4/TJ-7 — the two inequalities the (m,n) re-pin needs (m={M}/n={N}).\n\
         BOND_FLOOR = {BF:.3} SKL per shard. Deterministic no-slash fraction {C:.4}\n\
         bounds a PLACING adversary only; under an unchooseable draw absorption is\n\
         deferred, not prevented, so the cycle question stays live across the range.\n\
         OPERAND DIRECTION (labelled at the number): A5 uses the scenario-family MAX\n\
         per-shard pool because there a larger forfeit is a STRONGER deterrent, so\n\
         max is conservative. For TJ-4/TJ-7 it runs the OTHER WAY -- a larger reward\n\
         makes the slash/Rebond cycle and the dilution MORE profitable -- so max is\n\
         the ALARM-RAISING end. Tables below run the MEDIAN ({RM:.4} SKL/shard/epoch);\n\
         the max ({RX:.4}) is reported as the bound beneath each.",
        M = FAILURE_WINDOW_M,
        N = FAILURE_WINDOW_N,
        BF = bond,
        C = ceiling,
        RM = reward_median_per_epoch_skl,
        RX = reward_max_per_epoch_skl,
    )?;
    writeln!(
        out,
        "  TJ-4 CORRECTION (reward path, verified): a ZERO-service P earns NOTHING\n\
         (shard_work_micro returns 0 without serve credit; reward pays on credited\n\
         work), so the m-1 unslashable epochs are free of SLASH, not free MONEY.\n\
         The inequality is only non-trivial when the pair is being credited, i.e.\n\
         at attestation fraction f > 0 — so the derived quantity is a break-even f.\n\
         Earnings assume sole credited holder (r = 1) — attacker-favourable."
    )?;
    let d_struct = rebond_structural_downtime_epochs();
    writeln!(
        out,
        "  FRICTION (derived, not assumed). What a Rebond IS (gate-4 SS 3.4/P2B-9):\n\
         REINSTATEMENT, NOT RE-ENTRY — the slash burns one FLOOR and removes the\n\
         shard atomically, so Rebond credit is owed for growth only (zero for the\n\
         common standing-only form); the slash-EMPTIED single-shard cycle pair\n\
         must therefore re-add its shard at FLOOR. Rebond closes the bad interval\n\
         at end_exclusive = E_rebond + 1, so exclusion runs the slash epoch\n\
         THROUGH the rebond epoch inclusive — structural floor {D:.0} epochs:\n\
         the connect's validation admits a same-epoch close (probed; that is\n\
         SLACK, not a route) + 1 epoch of reachability, because the interval a\n\
         Rebond verifies against is appended at the failed epoch's settlement\n\
         fold and dispatch precedes the fold. Forgone earnings are priced at the\n\
         CREDITED rate f*R, not full R (full-R overstates the deterrent 1/f-fold).\n\
         Zeroing this term was mislabelled 'attacker-favourable' in the first cut\n\
         — the attacker-favourable end is this floor, not zero. LABELLED\n\
         APPROXIMATION (attacker-favourable): the re-added shard takes add_epoch =\n\
         E_rebond (Pin 7), so any age weighting of reward restarts each cycle;\n\
         using the steady-state per-shard pool as R OVERSTATES cycle earnings,\n\
         making every break-even below a LOWER BOUND. Table and break-evens run\n\
         downtime = {D:.0}.",
        D = d_struct,
    )?;
    writeln!(
        out,
        "{:<10} {:>14} {:>16} {:>14} {:>16}",
        "f", "E[epochs]", "earnings SKL", "friction SKL", "cycle net SKL"
    )?;
    // One shared cache for the table, the headline break-evens, and the remedy
    // curve: E[f] depends on neither the reward nor the downtime, and the
    // measurable-edge probe (the slowest, highest-f DPs) runs once.
    let mut cache = EpochCache::new(horizon);
    for &f in &REPORT_F_GRID {
        match cache.epochs(f) {
            Some(e) => {
                let earnings = e * f * reward_median_per_epoch_skl;
                let friction = rebond_friction_skl(f, d_struct, reward_median_per_epoch_skl);
                let net = cycle_net_from_epochs(f, e, reward_median_per_epoch_skl, friction);
                writeln!(
                    out,
                    "{:<10.3} {:>14.2} {:>16.4} {:>14.4} {:>16.4}",
                    f, e, earnings, friction, net
                )?;
            }
            None => writeln!(
                out,
                "{f:<10.3} {:>14} {:>16} {:>14} {:>16}",
                "no slash", "—", "—", "—"
            )?,
        }
    }

    let hi_bound = if cache.epochs(0.0).is_some() {
        measurable_f_hi(&mut cache)
    } else {
        0.0
    };
    let be_med =
        breakeven_in_measurable(&mut cache, hi_bound, reward_median_per_epoch_skl, d_struct);
    match be_med {
        Some(f) => writeln!(
            out,
            "  -> TJ-4 break-even f = {f:.4} (downtime at the structural floor of\n\
             {d_struct:.0} epochs; a cooldown only raises it — curve below). Below it the\n\
             burned bond is not covered and the window is NOT a subscription fee;\n\
             above it the cycle pays and attestation-resistance is what must carry\n\
             the deterrent.\n\
             NOTE: {ceiling:.4} is the DETERMINISTIC no-slash fraction, which bounds an\n\
             adversary that can PLACE its passing epochs. Under SS 8.2's unchooseable\n\
             draw the cartel cannot place them, so absorption still occurs above it\n\
             — deferred, not prevented."
        )?,
        None => writeln!(
            out,
            "  -> TJ-4: NO break-even f where the cycle completes — the burned bond is\n\
             never covered at this reward level and downtime, so the 'subscription\n\
             fee' shape does not arise and the binding constraint is entirely\n\
             attestation-resistance (the draw)."
        )?,
    }
    let be_max = breakeven_in_measurable(&mut cache, hi_bound, reward_max_per_epoch_skl, d_struct);
    writeln!(
        out,
        "     bound at the MAX operand ({RX:.4} SKL/shard/epoch): break-even f = {BX}.\n\
             Both ends of the family are reported so the verdict is a RANGE, not a\n\
             point chosen by which operand happened to be at hand.",
        RX = reward_max_per_epoch_skl,
        BX = fmt_breakeven_f(be_max),
    )?;

    // The ratio that makes the finding actionable: what a burned bond is WORTH,
    // denominated in the reward it is supposed to secure.
    if reward_median_per_epoch_skl > 0.0 {
        writeln!(
            out,
            "  -> WHY it breaks even so low: the burned bond is worth {E:.2} EPOCHS of the\n\
             per-shard reward it secures ({BF:.3} SKL vs {RM:.4} SKL/epoch at the median).\n\
             A slash that costs a fraction of one epoch's earnings is not a penalty,\n\
             which is TJ-4's BOND_FLOOR coupling made quantitative: the (m,n) re-pin\n\
             cannot carry attestation-resistance while the collateral it forfeits is\n\
             this cheap relative to the flow. Raising m/lowering n does not fix a\n\
             floor problem.",
            E = bond / reward_median_per_epoch_skl,
            BF = bond,
            RM = reward_median_per_epoch_skl,
        )?;
    }

    // The remedy curve the (m,n) re-pin needs: break-even f as a function of a
    // hypothetical post-slash cooldown, every cell off the one shared cache.
    let weeks_per_epoch = 52.0 / epochs_per_year();
    writeln!(
        out,
        "\n  REMEDY CURVE — break-even f vs a hypothetical POST-SLASH COOLDOWN c\n\
         (Rebond not admitted until c epochs after the slash; excluded span =\n\
         c + {D:.0}). f is the cartel's share of the UNCHOOSEABLE witness draw — its\n\
         hashrate share — so each row reads 'the cycle pays only above this\n\
         fraction of network hashrate'. 'none' = the cycle never pays anywhere\n\
         absorption is measurable within the horizon.",
        D = d_struct,
    )?;
    writeln!(
        out,
        "{:<10} {:>8} {:>20} {:>20}",
        "cooldown", "~weeks", "break-even f (med)", "break-even f (max)"
    )?;
    for &c in &[0u64, 1, 2, 4, 8, 16, 32, 64] {
        let d = d_struct + c as f64;
        let med = breakeven_in_measurable(&mut cache, hi_bound, reward_median_per_epoch_skl, d);
        let mx = breakeven_in_measurable(&mut cache, hi_bound, reward_max_per_epoch_skl, d);
        writeln!(
            out,
            "{:<10} {:>8.1} {:>20} {:>20}",
            c,
            c as f64 * weeks_per_epoch,
            fmt_breakeven_f(med),
            fmt_breakeven_f(mx),
        )?;
    }
    writeln!(
        out,
        "  -> READING THE CURVE (the false dichotomy dissolved): BOND_FLOOR is\n\
         f-INDEPENDENT, so it bounds the low-f attacker; the downtime term d*f*R\n\
         SCALES with f, so it does its work at high f. 'Floor problem vs cooldown\n\
         problem' names two regimes, not two rival remedies — and the low-f regime\n\
         is what the structural floor alone leaves unpriced. HONEST LIMIT: no\n\
         finite cooldown makes the cycle unprofitable at literally every f;\n\
         E[epochs] grows without bound toward the measurable ceiling, so a cartel\n\
         with enough of the draw outlasts any fixed exclusion. What a cooldown\n\
         does is push break-even INTO the hashrate-expensive regime, where f\n\
         itself is the deterrent. REMEDY STAKES: raising BOND_FLOOR is linear in\n\
         shard count (a {SH}-shard honest archiver already posts {POST:.0} SKL) and\n\
         taxes exactly the mid-size participants distribution depends on; a\n\
         post-slash cooldown costs nothing to anyone who is not slashed and\n\
         scales with the offense. The curve is an INPUT to the (m,n) re-pin\n\
         sweep, not a verdict — TJ-8's briefing constraint carries unchanged.",
        SH = MAX_HOLDINGS_SHARDS,
        POST = MAX_HOLDINGS_SHARDS as f64 * bond,
    )?;
    writeln!(
        out,
        "  -> ENFORCEMENT POINT (briefing constraint, TJ-8 shape): the x-axis is\n\
         EXCLUSION EPOCHS PER CYCLE, however enforced. A Rebond-only cooldown is\n\
         the WEAKEST enforcement: personas are free (G-1) and sybil-per-shard is\n\
         capital-bounded only (TJ-7), so a cartel abandons the slashed record and\n\
         bonds a FRESH pair on the same shard — same burned bond, no cooldown\n\
         served. A CREDIT-ONSET delay (minimum observation count — TJ-4's\n\
         original finding) yields the same per-cycle exclusion term on EVERY\n\
         route, fresh or reinstated; this curve prices both mechanisms\n\
         identically, so briefing it as 'add a Rebond cooldown' would claim\n\
         resistance the record-scoped gate cannot carry.\n\
         THE KNEE: E[epochs] >= m always (a slash needs m misses), so up to\n\
         c + {D:.0} = m = {M} the reward decides; past it break-even is FLOORED at\n\
         the f where E[epochs] = c + {D:.0} REGARDLESS of reward — the cycle is\n\
         excluded longer than it can possibly earn — which is why the median and\n\
         max columns converge once c + {D:.0} > {M}.",
        D = d_struct,
        M = FAILURE_WINDOW_M,
    )?;

    writeln!(
        out,
        "\n  TJ-7 sybil-per-shard: pool is CONSERVED (C*g/r over r credited bonds),\n\
         so N sybils vs h honest take N/(N+h)*g, NOT N*g — dilution, not\n\
         multiplication. Tables report MARGINAL gain over one bond\n\
         ([N/(N+h) - 1/(1+h)]*g), which saturates at h/(1+h)*g, not at g.\n\
         Cost is linear in N. Break-even = the ANNUAL return on locked capital\n\
         below which it pays. Same operand-direction rule as TJ-4: median first,\n\
         max as the alarm-raising bound."
    )?;
    write_sybil_table(out, reward_median_per_epoch_skl, "MEDIAN")?;
    write_sybil_table(out, reward_max_per_epoch_skl, "MAX")?;
    writeln!(
        out,
        "  -> the attack pays iff the cartel's real cost of locked capital is BELOW\n\
         the listed rate. Marginal gain saturating at h/(1+h)*g while cost grows\n\
         linearly gives a finite optimal N — priceable, not unbounded. NOTE\n\
         (§11.4): a single operator behind N personas is NOT a mechanism concern —\n\
         service is the product, the linkage is unobservable by design (G-1), and\n\
         participation distribution is a tacit-vote outcome. This table prices\n\
         DILUTION OF HONEST CO-HOLDERS, which is a reward-fairness question, not a\n\
         storage-accounting one."
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_attestation_earns_nothing_so_the_cycle_cannot_pay() {
        // The TJ-4 correction, as a test: at f = 0 the pair is credited on no
        // epoch, so earnings are 0 and the cycle is a pure loss of the bond at
        // ANY reward level. The "10 free epochs" are free of slash, not money.
        // Downtime is priced as FORGONE CREDITED earnings, so at f = 0 even an
        // enormous cooldown adds nothing — a never-credited pair has nothing
        // to forgo. Net is exactly -bond_at_risk at every (reward, downtime).
        for &reward in &[0.0_f64, 1.0, 100.0, 10_000.0] {
            for &downtime in &[0.0_f64, 1.0, 1_000.0] {
                let net =
                    rebond_cycle_net_skl(0.0, reward, downtime, TJ4_ABSORPTION_HORIZON_EPOCHS)
                        .expect("absorbs at f=0");
                assert!(
                    net < 0.0,
                    "f=0 must lose the bond at reward {reward}, got net {net}"
                );
                assert!(
                    (net + bond_at_risk_skl()).abs() < 1e-9,
                    "f=0 earnings and friction must both be exactly zero"
                );
            }
        }
    }

    #[test]
    fn structural_downtime_is_two_epochs_probe_plus_reachability() {
        // Two legs. The probe leg: rebond_connect's ordering check admits a
        // same-epoch close (one-epoch span) — validation slack, not a route.
        // The reachability leg: the interval a Rebond verifies against is
        // appended at the failed epoch's settlement fold, and dispatch
        // precedes the fold, so the earliest reachable E_rebond is the next
        // epoch — +1, total 2. If this pin goes red the connect grew a
        // cooldown gate (probe leg moved) or the fold/dispatch ordering
        // changed (reachability leg wrong) — re-read the remedy curve's
        // baseline from the new floor; do not patch the pin without doing so.
        assert!((rebond_structural_downtime_epochs() - 2.0).abs() < 1e-12);
    }

    #[test]
    fn friction_prices_downtime_at_the_credited_rate_not_full_service() {
        // The magnitude correction, as a test. Downtime was estimated at the
        // FULL-SERVICE reward (3-6x the collateral); the cycle forgoes only
        // what it would have DRAWN. Pin the delta exactly: d epochs of
        // downtime move the cycle net by d*f*R — at f = 0.05 that is 20x
        // smaller than the d*R the full-service pricing would charge.
        let (f, r, d) = (0.05, 2.0, 8.0);
        let base = rebond_cycle_net_skl(f, r, 0.0, TJ4_ABSORPTION_HORIZON_EPOCHS).expect("absorbs");
        let with = rebond_cycle_net_skl(f, r, d, TJ4_ABSORPTION_HORIZON_EPOCHS).expect("absorbs");
        let delta = base - with;
        assert!(
            (delta - d * f * r).abs() < 1e-9,
            "downtime must cost exactly d*f*R = {}, got {delta}",
            d * f * r
        );
        assert!(
            delta < d * r * 0.5,
            "full-service pricing (d*R = {}) must NOT be what is charged",
            d * r
        );
    }

    #[test]
    fn cooldown_raises_the_breakeven_monotonically() {
        // The remedy curve's shape: more downtime => the cycle needs a larger
        // attestation fraction to pay. Strictly rising, and every value in the
        // measurable range so the curve is well-defined where quoted.
        //
        // Horizon 800, not TJ4_ABSORPTION_HORIZON_EPOCHS: the break-evens here
        // live at f where E[epochs] is a few dozen, fully measurable at 800,
        // and the full horizon's only role is the far tail near the measurable
        // ceiling — paying its ~5x DP cost in a debug-mode test buys nothing.
        let horizon = 800;
        let r = 2.4;
        let mut prev = -1.0_f64;
        for &d in &[1.0_f64, 3.0, 9.0, 17.0] {
            let b =
                rebond_breakeven_f(r, d, horizon).expect("break-even exists at modest downtime");
            assert!(
                b > prev,
                "break-even must rise with downtime: {b} !> {prev}"
            );
            prev = b;
        }
    }

    #[test]
    fn the_deterministic_ceiling_does_not_stop_a_randomly_drawn_cartel() {
        // The finding this arm produced. §9.6's f ≈ 0.23 bounds an adversary
        // that CHOOSES which epochs pass. Under §8.2's unchooseable draw the
        // friendly witnesses arrive at random, so windows with m misses still
        // occur and absorption still happens ABOVE the deterministic ceiling —
        // it is deferred, not prevented. If this ever starts returning None at
        // the ceiling, the draw has become placeable and §9.6's hard reading
        // would be the correct one again.
        let ceiling = no_slash_attestation_fraction();
        let h = TJ4_ABSORPTION_HORIZON_EPOCHS;
        let at = expected_epochs_to_slash(ceiling, h);
        let above = expected_epochs_to_slash(ceiling + 0.05, h);
        assert!(at.is_some(), "random draws at the ceiling still absorb");
        assert!(above.is_some(), "and above it");
        // Deferred, though: the wait grows with f.
        assert!(above.unwrap() > at.unwrap());
        // Far above, the horizon truncates and we report None rather than a
        // horizon artifact.
        assert!(expected_epochs_to_slash(0.95, h).is_none());
    }

    #[test]
    fn expected_epochs_to_slash_is_monotone_in_attestation() {
        // More friendly draws => later slash. Monotonicity is what makes the
        // break-even bisection well-defined.
        let mut prev = 0.0;
        for i in 0..=8 {
            let f = f64::from(i) * 0.02;
            let e = expected_epochs_to_slash(f, TJ4_ABSORPTION_HORIZON_EPOCHS)
                .expect("absorbs below ceiling");
            assert!(e >= prev, "E[epochs] fell at f={f}: {e} < {prev}");
            prev = e;
        }
    }

    #[test]
    fn rebond_breakeven_pins_at_representative_reward() {
        // Representative run (2026-07-30): at ~2.4156 SKL/shard/epoch the cycle
        // broke even near f = 0.0274; at the max end it was ~0.0002. Pin the
        // order of magnitude so a DP or bond-scale regression cannot silently
        // move the binding claim. Exact digit drift inside the band is fine;
        // leaving the band is not.
        let f_med = rebond_breakeven_f(2.4156, 0.0, TJ4_ABSORPTION_HORIZON_EPOCHS)
            .expect("must break even at the median representative reward");
        assert!(
            (0.020..0.040).contains(&f_med),
            "median-reward break-even f={f_med} drifted from ~0.027"
        );

        // At a high reward the break-even f collapses toward zero but stays > 0
        // (f = 0 earns nothing). At a reward so low the bond is many epochs of
        // flow, the cycle never pays inside the measurable domain.
        let f_hi = rebond_breakeven_f(100.0, 0.0, TJ4_ABSORPTION_HORIZON_EPOCHS)
            .expect("high reward must still have a positive break-even f");
        assert!(f_hi > 0.0 && f_hi < 0.01, "high-reward f={f_hi}");

        // Bond is 0.75 SKL; at 0.001 SKL/epoch the bond is 750 epochs of flow —
        // far above E[T]·f for any measurable f.
        assert!(
            rebond_breakeven_f(0.001, 0.0, TJ4_ABSORPTION_HORIZON_EPOCHS).is_none(),
            "tiny reward must not cover the bond"
        );
    }

    #[test]
    fn epoch_cache_agrees_with_direct_evaluation() {
        let mut cache = EpochCache::new(TJ4_ABSORPTION_HORIZON_EPOCHS);
        for &f in &[0.0_f64, 0.05, 0.15, no_slash_attestation_fraction()] {
            let direct = expected_epochs_to_slash(f, TJ4_ABSORPTION_HORIZON_EPOCHS);
            let cached = cache.epochs(f);
            match (direct, cached) {
                (Some(a), Some(b)) => {
                    assert!((a - b).abs() < 1e-12, "cache mismatch at f={f}: {a} vs {b}")
                }
                (None, None) => {}
                (a, b) => panic!("cache presence mismatch at f={f}: {a:?} vs {b:?}"),
            }
            // Second lookup must hit the same entry.
            assert_eq!(
                cache.epochs(f).map(|x| x.to_bits()),
                cached.map(|x| x.to_bits())
            );
        }
    }

    #[test]
    fn sybil_gain_is_dilution_and_saturates_at_the_pool() {
        // The conservation property: N sybils take a *marginal* gain of
        // [N/(N+h) - 1/(1+h)]·g, never N·g, and the gain is bounded by g
        // however large N grows (actually by h/(1+h)·g).
        let g = 10.0;
        let h = 5;
        let one = sybil_dilution_gain(1, h, g);
        assert!(one.abs() < 1e-12, "a single bond gains nothing over itself");
        let mut prev = 0.0;
        for &n in &[2u64, 10, 100, 10_000, 1_000_000] {
            let gain = sybil_dilution_gain(n, h, g);
            assert!(gain > prev, "gain must rise in N");
            assert!(
                gain < g,
                "gain must saturate below the pool g={g}, got {gain}"
            );
            prev = gain;
        }
        // Explicitly NOT multiplication: 100 sybils do not take 100x a single bond.
        assert!(sybil_dilution_gain(100, h, g) < 100.0 * (g / (1.0 + h as f64)));
        // Asymptote: lim N→∞ gain = h/(1+h)·g.
        let asymptote = (h as f64) / (1.0 + h as f64) * g;
        assert!((sybil_dilution_gain(1_000_000, h, g) - asymptote).abs() < 1e-4);
    }

    #[test]
    fn sybil_breakeven_rate_falls_as_the_cartel_grows() {
        // Cost linear in N against a saturating gain => the break-even rate
        // falls, which is what gives the attack a finite optimum.
        let g = 1.0;
        let r2 = sybil_breakeven_opportunity_rate(2, 5, g).expect("N=2");
        let r100 = sybil_breakeven_opportunity_rate(100, 5, g).expect("N=100");
        assert!(
            r100 < r2,
            "break-even rate must fall with N: {r100} !< {r2}"
        );
        assert!(sybil_breakeven_opportunity_rate(1, 5, g).is_none());
    }

    #[test]
    fn bond_at_risk_is_the_canonical_floor() {
        // No local bond_floor_skl alias: the cartel arm prices the same
        // per-shard floor A5 exposes through bond_at_risk_skl.
        assert!(bond_at_risk_skl() > 0.0);
        assert!((bond_at_risk_skl() - 0.75).abs() < 1e-12);
    }
}
