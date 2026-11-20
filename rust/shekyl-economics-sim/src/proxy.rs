// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! W10 **proxy free-rider** margin (A5, §12.2 / §11.1), at the test≡job
//! payload (`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md` R1).
//!
//! A challenge obliges the responder to move the **whole shard**
//! ([`SHARD_BYTES`]): the read it serves is the job (TJ R1). A thin **proxy**
//! that holds nothing re-fetches every challenged shard on demand; the
//! question is whether that costs more than holding the shard.
//!
//! **Named margin (DQ-2E):** `margin/epoch = proxy_cost/epoch −
//! honest_storage_cost/epoch`, where `proxy_cost = T_bandwidth + T_risk`:
//! the re-fetch bandwidth, and the expected cost of the m-of-n slash the
//! proxy's fetch failures run up. Honest holding is the cheaper strategy iff
//! the margin is positive.
//!
//! **What the margin rests on (TJ §5.3, §5.4).** At metered bandwidth the
//! whole-shard re-fetch alone puts the proxy above storage. The bandwidth leg
//! is price- and transport-contingent, though: at zero byte price (free
//! ingress, flat-rate residential) it vanishes, and the deterrent rests on
//! `T_risk` alone — the failure rate the deadline must force for the slash
//! exposure to cover storage, [`q_risk_star`].
//!
//! **L14 exposure rides the m-of-n slash.** A single missed re-fetch is
//! *absorbed* — the ratified failure model is sliding-window **m-of-n**
//! (`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md`, provisional `m=11`, `n=13`), not a
//! single strike. So the proxy is slashed only on *sustained* re-fetch
//! failure, which makes the deterrent **weaker**, not stronger.

use std::fmt;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use shekyl_archival_retention::{
    failure_window_slashable, ArchivalParams, BaselineObservation, MAX_HOLDINGS_SHARDS,
};

use crate::burden::{COIN, SHARD_BYTES};
use crate::engine::SimParams;
use crate::secret_draw::COUNTED_DRAWS;

/// Settlement epochs per year under the run: its year in blocks
/// ([`SimParams::blocks_per_year`]) over its settlement epoch.
///
/// For the report and fiat layers only: a storage cost, a sybil gain, a
/// cooldown in weeks. No chain quantity is divided by it; an epoch's
/// budget in atomic units is [`crate::stage2::per_epoch_atomic`] (DQ-2G,
/// ESR-14).
#[must_use]
pub fn epochs_per_year(run: &SimParams) -> f64 {
    run.blocks_per_year() as f64 / run.archival().settlement_epoch_blocks as f64
}

/// Bytes an archiver would hold at the per-bond cap (`MAX_HOLDINGS_SHARDS` ·
/// `SHARD_BYTES` = 4096 · W ≈ 12.3 GB) — the honest side the proxy avoids
/// (§7.4/W10).
#[must_use]
pub fn max_holdings_bytes() -> f64 {
    MAX_HOLDINGS_SHARDS as f64 * SHARD_BYTES
}

/// Storage cost basis, fiat `$/byte/year` (mirrors `burden::BASE_STORAGE_FIAT_PER_BYTE_YEAR`
/// — amortized commodity HDD ≈ `1e-11 $/B/yr`). The honest holder pays this on
/// the full capped holding ([`max_holdings_bytes`], ~12.3 GB) every epoch.
pub const STORAGE_FIAT_PER_BYTE_YEAR: f64 = 1.0e-11;

/// Bandwidth (egress) cost band, fiat `$/byte` **transferred**. `1e-11` ≈
/// `$0.01/GB` (bulk transit) … `1e-10` ≈ `$0.10/GB` (retail egress). The proxy
/// pays this only on the re-fetched shards, not on the capped holding's
/// standing storage.
pub const FETCH_FIAT_PER_BYTE_BAND: [f64; 2] = [1.0e-11, 1.0e-10];

/// Cloud-class storage basis (`~$0.02/GB-month` ≈ `2.4e-10 $/B/yr`) — the
/// within-class comparison partner for the metered-egress fetch band above.
/// One actor has ONE infrastructure class (review F-1): pairing consumer-disk
/// storage against cloud egress overstates the hold-vs-fetch ratio by ~24×,
/// and the cell a §5.3-style reopen must watch is the WITHIN-cloud cheap-transit
/// one, where the ratio is ~1.1× and would quietly invert if either term moved.
pub const CLOUD_STORAGE_FIAT_PER_BYTE_YEAR: f64 = 2.4e-10;

/// Honest storage cost per epoch, fiat: hold the full `max_holdings_bytes` at the
/// storage basis, prorated to one settlement epoch.
#[must_use]
pub fn honest_storage_cost_per_epoch(storage_fiat_per_byte_year: f64, run: &SimParams) -> f64 {
    max_holdings_bytes() * storage_fiat_per_byte_year / epochs_per_year(run)
}

/// Proxy re-fetch bandwidth cost per epoch, fiat: the counted draws
/// ([`COUNTED_DRAWS`], the draws a pair is issued at the count rule's
/// target) per held shard, each re-fetching one `payload_bytes` response.
///
/// `payload_bytes` is what one challenge obliges the responder to move:
/// [`SHARD_BYTES`] under test≡job R1 (`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md`
/// §0), or zero for the zero-byte-price world. The slash machinery below is
/// payload-independent (it prices `q`, not bytes).
#[must_use]
pub fn proxy_refetch_cost_per_epoch(payload_bytes: f64, fetch_fiat_per_byte: f64) -> f64 {
    let responses = MAX_HOLDINGS_SHARDS as f64 * f64::from(COUNTED_DRAWS);
    responses * payload_bytes * fetch_fiat_per_byte
}

#[cfg(test)]
/// Per-epoch slash probability under the **shipped consensus predicate** — not a
/// re-expression of it (DQ-2G dep-don't-mirror).
///
/// Enumerates every length-`n` observation pattern (2^13 = 8 192), hands each to
/// `failure_window_slashable`, and weights the slashing ones by their binomial
/// probability under an iid per-observation miss rate `q`. Calling the real
/// predicate rather than a formula captures the semantics a hand-written binomial
/// misses — chiefly that **the head observation must itself be a miss** (the
/// window is only consulted on a missed baseline), so the hazard is
/// `q · P(≥ m−1 of the other n−1)`, not `P(≥ m of n)`.
///
/// A5 originally modelled the latter and thereby **overstated** the slash
/// exposure by ~18 % (the shipped predicate is ~0.85× the naive binomial across
/// the whole crossover band). Lower exposure ⇒ weaker deterrent ⇒ the free-rider
/// is *more* viable, so this correction moves against the comfortable direction.
///
/// **Demoted to a test oracle** by the absorption-DP fix: the live model is
/// [`expected_slash_cost_per_epoch`], and this independent construction now
/// *checks* it (`dp_one_step_hazard_matches_enumeration`) — two constructions
/// guarding each other, the pattern the hoist's parity test uses.
///
/// The window is the run's (`m`, `n` in [`ArchivalParams`]); the predicate
/// reads them from the set it is handed.
#[must_use]
pub fn slash_prob_per_epoch(q: f64, run: &SimParams) -> f64 {
    let archival = run.archival();
    let q = q.clamp(0.0, 1.0);
    let width = archival.failure_window_n as usize;
    let mut p = 0.0_f64;
    for mask in 0u32..(1u32 << width) {
        // bit i set = a MISS at position i; position 0 is the head (decision epoch).
        let obs: Vec<BaselineObservation> = (0..width)
            .map(|i| {
                let epoch = (width - i) as u64; // strictly descending
                if (mask >> i) & 1 == 1 {
                    BaselineObservation::missed(epoch)
                } else {
                    BaselineObservation::served(epoch)
                }
            })
            .collect();
        // A served head is `HeadNotAMiss`: consensus never consults the window that
        // epoch, so it contributes no slash hazard.
        if failure_window_slashable(&obs, archival).unwrap_or(false) {
            let k = mask.count_ones() as i32;
            p += q.powi(k) * (1.0 - q).powi(width as i32 - k);
        }
    }
    p
}

/// Prior-window width: the `n − 1` observations preceding the decision epoch.
fn prior_width(archival: &ArchivalParams) -> usize {
    archival.failure_window_n as usize - 1
}

/// Negligible state mass; skipping it keeps the DP sweep cheap without changing
/// verdicts at the precision the arms quote. Set at the underflow floor rather
/// than a "small enough" guess because [`first_slash_probability`] validates
/// tail probabilities down to ~1e-43 (the `(m, n)` union-bound license): a
/// perf-motivated 1e-18 here silently zeroed exactly the mass that validation
/// exists to measure.
const DP_MASS_EPS: f64 = 1e-300;

/// Minimum absorbed probability mass required before a first-slash *mean* is
/// treated as a property of `q` rather than a horizon truncation artifact.
const ABSORPTION_MASS_THRESHOLD: f64 = 0.99;

/// For each prior-window state, does a **miss at the head** trigger a slash?
///
/// Built by **calling `failure_window_slashable`** on every state (not by
/// re-deriving its rule), so the DP's absorption condition *is* the production
/// predicate — the fix removes the aggregation approximation without trading away
/// dep-don't-mirror. Bit `i` of the state is a miss at the `i`-th preceding
/// observation.
///
/// Private: consumers must go through [`fold_first_slash_mass`] /
/// [`expected_epochs_to_first_slash`] / [`expected_slash_cost_per_epoch`] so the
/// window bitset does not leak into sibling arms.
///
/// One table per archival set (`2^(n−1)` states, 4 096 at the shipped
/// `n = 13`), built on first use and kept: a run asks for its own set's
/// table many times, and a sweep holds a handful of sets.
fn absorb_table(archival: &ArchivalParams) -> Arc<Vec<bool>> {
    static TABLES: OnceLock<Mutex<HashMap<ArchivalParams, Arc<Vec<bool>>>>> = OnceLock::new();
    let tables = TABLES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut tables = tables.lock().expect("absorb-table cache poisoned");
    Arc::clone(tables.entry(*archival).or_insert_with(|| {
        let width = prior_width(archival);
        let base = u64::from(archival.failure_window_n) + 1;
        Arc::new(
            (0..1usize << width)
                .map(|state| {
                    let mut obs = Vec::with_capacity(width + 1);
                    obs.push(BaselineObservation::missed(base)); // the head IS a miss
                    for i in 0..width {
                        let epoch = base - 1 - i as u64;
                        if (state >> i) & 1 == 1 {
                            obs.push(BaselineObservation::missed(epoch));
                        } else {
                            obs.push(BaselineObservation::served(epoch));
                        }
                    }
                    failure_window_slashable(&obs, archival).unwrap_or(false)
                })
                .collect(),
        )
    }))
}

/// Fold over first-slash absorption events of the trailing-window Markov chain.
///
/// Starts from a clean prior (no misses). Each epoch, a miss from a prior-window
/// state that is already at the slash threshold contributes mass at that epoch
/// and is removed; non-absorbing misses and all passes advance the sliding
/// window. Invokes `on_absorb(epoch, mass)` for every absorbed packet.
///
/// Returns total absorbed mass in `[0, 1]`. This is the **single** transition
/// kernel for every arm that needs first-slash timing or pricing (A5 exposure,
/// TJ-4 cycle length) — dep-don't-mirror on the production predicate, and
/// one place to fix the chain if the window pin moves.
fn fold_first_slash_mass(
    q: f64,
    horizon_epochs: u64,
    run: &SimParams,
    mut on_absorb: impl FnMut(u64, f64),
) -> f64 {
    if horizon_epochs == 0 {
        return 0.0;
    }
    let q = q.clamp(0.0, 1.0);
    let absorb = absorb_table(run.archival());
    let states = absorb.len();
    let mask = states - 1;
    let mut dist = vec![0.0_f64; states];
    dist[0] = 1.0; // a pair that has been serving: no prior misses
    let mut next = vec![0.0_f64; states];
    let mut absorbed = 0.0_f64;
    for epoch in 1..=horizon_epochs {
        next.iter_mut().for_each(|v| *v = 0.0);
        for (state, &p) in dist.iter().enumerate() {
            if p < DP_MASS_EPS {
                continue;
            }
            let miss = p * q;
            if absorb[state] {
                on_absorb(epoch, miss);
                absorbed += miss;
            } else {
                next[((state << 1) | 1) & mask] += miss;
            }
            next[(state << 1) & mask] += p * (1.0 - q);
        }
        std::mem::swap(&mut dist, &mut next);
    }
    absorbed
}

/// Total first-slash probability within `draws` window observations at
/// per-observation miss `q` — [`fold_first_slash_mass`]'s total absorbed mass.
///
/// The chain is frame-agnostic: a step is one draw against the trailing
/// window (this file's consumers draw once per epoch; the `(m, n)` arm draws
/// once per settled observation, and the ratified miss fact caps those at one
/// per epoch). Exposed so sibling arms validate against the SAME
/// production-predicate-backed kernel instead of re-implementing the DP —
/// the `(m, n)` union-bound license test is the consumer (review,
/// 2026-08-02: that arm previously carried a duplicate of this chain plus a
/// rule-re-deriving twin table).
#[must_use]
// Binary package: unit tests compile in-crate under `cfg(test)`, so a
// validation-only entry trips `-D dead-code` on the non-test bin (the
// `cartel.rs` precedent).
#[cfg_attr(not(test), allow(dead_code))]
pub fn first_slash_probability(q: f64, draws: u64, run: &SimParams) -> f64 {
    fold_first_slash_mass(q, draws, run, |_, _| {})
}

/// Expected epochs until first slash under per-epoch miss rate `q`, conditioned
/// on absorption within `horizon_epochs`.
///
/// Returns [`None`] when less than 99 % of the mass has absorbed inside the
/// horizon — any mean would then be a horizon artifact, not a property of `q`.
/// Callers that need attestation fraction `f` (friendly-draw share) pass
/// `q = 1 − f`.
///
/// Used by the TJ-4 slash/`Reinstate` cycle arm; the chain itself lives here so
/// sibling modules never touch the window bitset.
#[must_use]
pub fn expected_epochs_to_first_slash(q: f64, horizon_epochs: u64, run: &SimParams) -> Option<f64> {
    let mut sum_t = 0.0_f64;
    let absorbed = fold_first_slash_mass(q, horizon_epochs, run, |epoch, mass| {
        sum_t += mass * epoch as f64;
    });
    if absorbed < ABSORPTION_MASS_THRESHOLD {
        return None;
    }
    Some(sum_t / absorbed)
}

/// Expected slash cost **per epoch** for ONE shard, from the first-slash
/// distribution of an **absorbing** Markov chain over the trailing window.
///
/// `(P, shard)` is an absorbing state, so summing per-epoch hazards would
/// double-count and *overstate the deterrent* — direction-safe only at today's
/// `(m, n)`. Since this arm re-prices automatically at the Round-2 re-pin, that
/// overstatement could silently flip a marginal verdict; the exposure therefore
/// comes from [`fold_first_slash_mass`]'s absorbing Markov chain, priced
/// at the actual first-slash epoch.
#[must_use]
pub fn expected_slash_cost_per_epoch(
    q: f64,
    bond_loss_fiat: f64,
    reward_per_epoch_fiat: f64,
    horizon_epochs: u64,
    run: &SimParams,
) -> f64 {
    if horizon_epochs == 0 {
        return 0.0;
    }
    let mut expected = 0.0_f64;
    fold_first_slash_mass(q, horizon_epochs, run, |epoch, mass| {
        // Absorbed at `epoch`: bond forfeited + the remaining stream lost.
        let remaining = horizon_epochs.saturating_sub(epoch) as f64;
        expected += mass * (bond_loss_fiat + reward_per_epoch_fiat * remaining);
    });
    expected / horizon_epochs as f64
}

pub fn proxy_cost_per_epoch(
    payload_bytes: f64,
    fetch_fiat_per_byte: f64,
    q: f64,
    bond_loss_fiat: f64,
    reward_per_epoch_fiat: f64,
    horizon_epochs: u64,
    run: &SimParams,
) -> f64 {
    let shards_at_risk = MAX_HOLDINGS_SHARDS as f64;
    proxy_refetch_cost_per_epoch(payload_bytes, fetch_fiat_per_byte)
        + shards_at_risk
            * expected_slash_cost_per_epoch(
                q,
                bond_loss_fiat,
                reward_per_epoch_fiat,
                horizon_epochs,
                run,
            )
}

/// The W10 margin per epoch: `proxy_cost − honest_storage_cost`. **> 0 passes**
/// (honest holding is cheaper, so the proxy does not dominate).
#[must_use]
// CLIPPY: too_many_arguments — the run is the eighth: the other seven are
// the W10 margin's own operands, and the run carries the archival set
// (window, challenges, epoch) they are priced under (ESR-16 completion,
// ruling 6).
#[allow(clippy::too_many_arguments)]
pub fn margin_per_epoch(
    payload_bytes: f64,
    fetch_fiat_per_byte: f64,
    storage_fiat_per_byte_year: f64,
    q: f64,
    bond_loss_fiat: f64,
    reward_per_epoch_fiat: f64,
    horizon_epochs: u64,
    run: &SimParams,
) -> f64 {
    proxy_cost_per_epoch(
        payload_bytes,
        fetch_fiat_per_byte,
        q,
        bond_loss_fiat,
        reward_per_epoch_fiat,
        horizon_epochs,
        run,
    ) - honest_storage_cost_per_epoch(storage_fiat_per_byte_year, run)
}

/// The crossover re-fetch-failure rate `q*` at which the margin first turns
/// non-negative — i.e. how *unreliable* re-fetch must be (how *tight* the gate-4
/// grace window must be forced) for honest holding to win.
///
/// Returns **`Some(0.0)`** when the margin is already ≥ 0 at `q = 0` — the
/// margin is closed with no deadline pressure at all. At the test≡job shard
/// payload it is the routine result across the modeled fetch band, and the
/// report reads `Some(0.0)` as exactly that fact. Returns **`None`** only
/// when even `q = 1` (re-fetch impossible — the PoRep limit) cannot close it.
/// The two ends are opposite facts and must not be conflated: `Some(0.0)` =
/// already closed, `None` = unclosable.
#[must_use]
pub fn crossover_q(
    payload_bytes: f64,
    fetch_fiat_per_byte: f64,
    storage_fiat_per_byte_year: f64,
    bond_loss_fiat: f64,
    reward_per_epoch_fiat: f64,
    horizon_epochs: u64,
    run: &SimParams,
) -> Option<f64> {
    let f = |q: f64| {
        margin_per_epoch(
            payload_bytes,
            fetch_fiat_per_byte,
            storage_fiat_per_byte_year,
            q,
            bond_loss_fiat,
            reward_per_epoch_fiat,
            horizon_epochs,
            run,
        )
    };
    if f(0.0) >= 0.0 {
        return Some(0.0);
    }
    if f(1.0) < 0.0 {
        return None; // even perfect deterrence (re-fetch always fails) can't close it
    }
    // Bisection: margin is monotone increasing in q (slash_prob is).
    let (mut lo, mut hi) = (0.0_f64, 1.0_f64);
    for _ in 0..60 {
        let mid = 0.5 * (lo + hi);
        if f(mid) < 0.0 {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Some(hi)
}

/// Bond collateral at risk on **one** sustained-failure slash, SKL.
///
/// **Scope pinned at source (`FOUNDATION_GENESIS_IDENTITY_SET.md` §3.2).** For a
/// **`ShardSetCompact`** record — the *market archiver* this arm models — a failed
/// challenge on shard `s` slashes ***shard `s`'s bond*; other shards stay
/// bonded**; the post-slash holding is *"still bonded on remaining shards"*
/// (per-shard bonds). Only the foundation's `CompleteTree` kind takes the *whole*
/// bond ("floor-or-whole"). So the exposure is **one** `ARCHIVAL_BOND_FLOOR`, not
/// the holding's `4096 ×` total — a correction of ~1/`MAX_HOLDINGS_SHARDS`.
///
/// This *understates* nothing in the verdict (a smaller forfeit is a weaker
/// deterrent ⇒ the proxy FAIL is a fortiori), but it is load-bearing for the
/// remedy: it raises the crossover `q*` the gate-4 grace window must force.
///
/// The record-level bad interval `[E_slash, ∞)` is the *serve-credit* consequence
/// (it blocks `good_through` until `Reinstate`), **not** the collateral scope — the
/// two are separate and must not be conflated.
#[must_use]
pub fn bond_at_risk_skl(run: &SimParams) -> f64 {
    run.archival().bond_floor_atomic as f64 / COIN as f64
}

/// Settlement epochs of forgone reward folded into the slash loss (`~5 y` at
/// `epochs_per_year`). The slash forfeits future reward; this bounds the stream
/// the exposure prices (undiscounted — deterrence-favourable).
pub const A5_REWARD_HORIZON_EPOCHS: f64 = 131.0;

/// Fetch price at which the shard-payload bandwidth leg alone stops closing the
/// margin: below it, `T_bandwidth < S` and the deterrent must be carried by
/// `T_risk` (TJ §5.3's price-contingency made a number).
#[must_use]
pub fn shard_breakeven_fetch_fiat_per_byte(
    storage_fiat_per_byte_year: f64,
    run: &SimParams,
) -> f64 {
    honest_storage_cost_per_epoch(storage_fiat_per_byte_year, run)
        / (MAX_HOLDINGS_SHARDS as f64 * f64::from(COUNTED_DRAWS) * SHARD_BYTES)
}

/// A crossover `q` for the narration: `digits` decimals, or the PoRep limit
/// when no `q <= 1` closes the margin (`crossover_q` / `q_risk_star` return
/// `None`). Never a number in that case: `0.000` would read as "closes at any
/// rate".
fn q_or_porep_limit(q: Option<f64>, digits: usize) -> String {
    q.map_or_else(
        || "none (PoRep limit)".to_string(),
        |q| format!("{q:.digits$}"),
    )
}

/// The `q` at which `T_risk` ALONE (zero bandwidth cost — the flat-rate-residential
/// world where the §5.3 price leg inverts) covers honest storage: the failure
/// rate the deadline must force for the deterrent to be carried entirely by the
/// m-of-n slash exposure. `None` if even `q = 1` cannot (the PoRep limit).
#[must_use]
pub fn q_risk_star(
    storage_fiat_per_byte_year: f64,
    bond_loss_fiat: f64,
    reward_per_epoch_fiat: f64,
    horizon_epochs: u64,
    run: &SimParams,
) -> Option<f64> {
    let storage = honest_storage_cost_per_epoch(storage_fiat_per_byte_year, run);
    let shards = MAX_HOLDINGS_SHARDS as f64;
    let t_risk = |q: f64| {
        shards
            * expected_slash_cost_per_epoch(
                q,
                bond_loss_fiat,
                reward_per_epoch_fiat,
                horizon_epochs,
                run,
            )
    };
    if t_risk(1.0) < storage {
        return None;
    }
    let (mut lo, mut hi) = (0.0_f64, 1.0_f64);
    for _ in 0..60 {
        let mid = 0.5 * (lo + hi);
        if t_risk(mid) < storage {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Some(hi)
}

/// The A5 (W10) report, at the **test≡job payload**
/// (`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md` §6.2, TJ deliverable 2): the
/// bandwidth leg priced at `SHARD_BYTES`, and `T_risk` — the price-independent
/// term the margin rests on where bandwidth is free (§5.4).
/// `reward_per_epoch_skl` is **one shard's** post-D1/D2 reward **per epoch**
/// (the §3.2 per-shard slash scope): the absorption DP prices the stream
/// forgone *from the slash epoch onward*. `skl_price` converts SKL losses to
/// fiat.
///
/// Honesty labels (stage-2 discipline — label the approximation at the number):
/// the fiat bands are the §5.3-ambiguous legs (cloud/bulk-transit anchored; a
/// flat-rate-residential fetcher sits BELOW the band and is priced by the
/// `T_risk`-only line); `q` is swept, not asserted — the Tor-tail model that
/// would pick a point on the curve is PD-F-2's measurement, not this sim's.
pub fn tj_shard_payload_report(
    out: &mut impl fmt::Write,
    reward_per_epoch_skl: f64,
    skl_price: f64,
    run: &SimParams,
) -> fmt::Result {
    let storage = honest_storage_cost_per_epoch(STORAGE_FIAT_PER_BYTE_YEAR, run);
    let bond_loss_fiat = bond_at_risk_skl(run) * skl_price;
    let reward_per_epoch_fiat = reward_per_epoch_skl * skl_price;
    let horizon = A5_REWARD_HORIZON_EPOCHS as u64;
    writeln!(
        out,
        "\nA5 — W10 proxy free-rider margin (SS 12.2/SS 11.1) at the test=job payload (TJ R1:\n\
         a challenge moves the whole shard, SHARD_BYTES = {SH:.2e} B). margin/epoch =\n\
         proxy(re-fetch + L14 slash exposure) - honest storage; L14 rides the m-of-n slash\n\
         (m={M}/n={N}: a single missed re-fetch is absorbed). The slash machinery is\n\
         payload-independent; the payload moves only the bandwidth leg.\n\
         S (SS 5.1 marginal threshold, one epoch of holding {GB:.1} GB) = ${STOR:.5}.",
        SH = SHARD_BYTES,
        M = run.archival().failure_window_m,
        N = run.archival().failure_window_n,
        GB = max_holdings_bytes() / 1.0e9,
        STOR = storage,
    )?;
    writeln!(
        out,
        "{:<22} {:>13} {:>14} {:>13} {:>12}",
        "fetch $/GB", "refetch/epoch", "margin@q=0", "q* bond-only", "q* +reward"
    )?;
    for &fp in &FETCH_FIAT_PER_BYTE_BAND {
        let refetch = proxy_refetch_cost_per_epoch(SHARD_BYTES, fp);
        let margin0 = margin_per_epoch(
            SHARD_BYTES,
            fp,
            STORAGE_FIAT_PER_BYTE_YEAR,
            0.0,
            bond_loss_fiat,
            0.0,
            horizon,
            run,
        );
        let qc_bond = crossover_q(
            SHARD_BYTES,
            fp,
            STORAGE_FIAT_PER_BYTE_YEAR,
            bond_loss_fiat,
            0.0,
            horizon,
            run,
        );
        let qc_rew = crossover_q(
            SHARD_BYTES,
            fp,
            STORAGE_FIAT_PER_BYTE_YEAR,
            bond_loss_fiat,
            reward_per_epoch_fiat,
            horizon,
            run,
        );
        writeln!(
            out,
            "{:<22} {:>13.6} {:>14.6} {:>13} {:>12}",
            format!("{:.2}", fp * 1.0e9),
            refetch,
            margin0,
            qc_bond.map_or("none".to_string(), |q| format!("{q:.3}")),
            qc_rew.map_or("none".to_string(), |q| format!("{q:.3}")),
        )?;
    }
    let breakeven = shard_breakeven_fetch_fiat_per_byte(STORAGE_FIAT_PER_BYTE_YEAR, run);
    writeln!(
        out,
        "  -> break-even fetch price (T_bandwidth == S): {BE:.2e} $/B ({BEG:.4} $/GB). ABOVE\n\
         it the bandwidth leg alone closes the margin (both band ends are above it at the\n\
         modeled prices); BELOW it — the flat-rate/residential world where SS 5.3's price\n\
         leg inverts — the deterrent is carried by T_risk alone:",
        BE = breakeven,
        BEG = breakeven * 1.0e9,
    )?;
    writeln!(
        out,
        "{:<10} {:>18} {:>18}",
        "q", "T_risk bond-only", "T_risk +reward"
    )?;
    for &q in &[0.001_f64, 0.01, 0.05, 0.10, 0.278] {
        let shards = MAX_HOLDINGS_SHARDS as f64;
        let t_bond = shards * expected_slash_cost_per_epoch(q, bond_loss_fiat, 0.0, horizon, run);
        let t_full = shards
            * expected_slash_cost_per_epoch(q, bond_loss_fiat, reward_per_epoch_fiat, horizon, run);
        writeln!(out, "{q:<10.3} {t_bond:>18.6} {t_full:>18.6}")?;
    }
    let qr_bond = q_risk_star(
        STORAGE_FIAT_PER_BYTE_YEAR,
        bond_loss_fiat,
        0.0,
        horizon,
        run,
    );
    let qr_full = q_risk_star(
        STORAGE_FIAT_PER_BYTE_YEAR,
        bond_loss_fiat,
        reward_per_epoch_fiat,
        horizon,
        run,
    );
    writeln!(
        out,
        "  -> q_risk* (T_risk alone covers S; storage cheap-side worst case): bond-only {QB},\n\
         +reward {QF}. The slash model is payload-independent: the zero-payload crossover\n\
         EQUALS q_risk* identically (welded by test).",
        QB = q_or_porep_limit(qr_bond, 4),
        QF = q_or_porep_limit(qr_full, 4),
    )?;
    let cloud_s = honest_storage_cost_per_epoch(CLOUD_STORAGE_FIAT_PER_BYTE_YEAR, run);
    writeln!(
        out,
        "  -> WITHIN-CLASS restatement (F-1 -- one actor, one infrastructure class; the\n\
         cross-class {RXL:.0}-{RXH:.0}x pairs the cheapest storage against the dearest bandwidth):\n\
         cloud-class: S = ${CS:.4}/epoch (@{CB:.1e} $/B/yr) vs T = ${TL:.3}-${TH:.3}\n\
           -> ratio {RL:.1}x-{RH:.1}x -- MARGINAL at cheap transit ({RL:.1}x); this is the\n\
           cell the SS 5.3 price-contingency reopen watches, not the {RXL:.0}x one.\n\
         consumer/flat-rate: S = ${HS:.4}/epoch, T_marginal ~= 0 -> INVERTED; T_risk\n\
           decides (q_risk* above). Headline, honestly: bandwidth closes it decisively\n\
           for a metered-egress fetcher, marginally for a cheap-transit cloud actor,\n\
           and not at all for a flat-rate one.\n\
         -> A5 of record (TJ SS 5.3, SS 5.4): at metered bandwidth, whole-shard reads put\n\
         the proxy above storage at q = 0. At zero byte price (free ingress, flat-rate\n\
         residential) the bandwidth leg vanishes and the deterrent rests on T_risk: the\n\
         deadline must force a re-fetch failure rate of q_risk* = {QF} (+reward) for the\n\
         slash exposure to cover storage.",
        CS = cloud_s,
        CB = CLOUD_STORAGE_FIAT_PER_BYTE_YEAR,
        TL = proxy_refetch_cost_per_epoch(SHARD_BYTES, FETCH_FIAT_PER_BYTE_BAND[0]),
        TH = proxy_refetch_cost_per_epoch(SHARD_BYTES, FETCH_FIAT_PER_BYTE_BAND[1]),
        RL = proxy_refetch_cost_per_epoch(SHARD_BYTES, FETCH_FIAT_PER_BYTE_BAND[0]) / cloud_s,
        RH = proxy_refetch_cost_per_epoch(SHARD_BYTES, FETCH_FIAT_PER_BYTE_BAND[1]) / cloud_s,
        HS = honest_storage_cost_per_epoch(STORAGE_FIAT_PER_BYTE_YEAR, run),
        RXL = proxy_refetch_cost_per_epoch(SHARD_BYTES, FETCH_FIAT_PER_BYTE_BAND[0]) / honest_storage_cost_per_epoch(STORAGE_FIAT_PER_BYTE_YEAR, run),
        RXH = proxy_refetch_cost_per_epoch(SHARD_BYTES, FETCH_FIAT_PER_BYTE_BAND[1]) / honest_storage_cost_per_epoch(STORAGE_FIAT_PER_BYTE_YEAR, run),
        QF = q_or_porep_limit(qr_full, 2),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unclosable crossover prints as the PoRep limit, never as a rate:
    /// `Some(0.0)` (closed with no deadline pressure) and `None` (unclosable)
    /// are opposite facts (`crossover_q`).
    #[test]
    fn an_unclosable_crossover_prints_as_the_porep_limit() {
        assert_eq!(q_or_porep_limit(None, 3), "none (PoRep limit)");
        assert_eq!(q_or_porep_limit(Some(0.0), 3), "0.000");
        assert_eq!(q_or_porep_limit(Some(0.10349), 3), "0.103");
        assert_eq!(q_or_porep_limit(Some(0.10349), 4), "0.1035");
    }

    #[test]
    fn slash_prob_absorbs_single_miss_and_is_monotone() {
        // m-of-n absorbs isolated misses: a small q gives a tiny slash prob …
        assert!(slash_prob_per_epoch(0.05, &SimParams::default()) < 1e-6);
        // … and it rises monotonically toward 1 as q → 1 (sustained failure).
        let mut prev = -1.0;
        for i in 0..=10 {
            let q = i as f64 / 10.0;
            let p = slash_prob_per_epoch(q, &SimParams::default());
            assert!(p >= prev, "slash prob must be monotone in q");
            prev = p;
        }
        assert!((slash_prob_per_epoch(1.0, &SimParams::default()) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn dp_one_step_hazard_matches_enumeration() {
        // The two independent constructions check each other (the hoist-parity
        // pattern): the DP's absorption table, driven from the iid stationary
        // state distribution, must reproduce the 2^13 enumeration of the shipped
        // predicate — q · P(≥ m−1 of the other n−1).
        let absorb = absorb_table(SimParams::default().archival());
        for &q in &[0.05_f64, 0.1, 0.2, 0.35, 0.6] {
            // Stationary distribution of the prior window under iid misses.
            let mut hazard = 0.0_f64;
            for (state, &slashes) in absorb.iter().enumerate() {
                if !slashes {
                    continue;
                }
                let k = (state as u32).count_ones() as i32;
                let p_state = q.powi(k)
                    * (1.0 - q).powi(prior_width(SimParams::default().archival()) as i32 - k);
                hazard += p_state * q; // head must miss for the window to be consulted
            }
            let enumerated = slash_prob_per_epoch(q, &SimParams::default());
            assert!(
                (hazard - enumerated).abs() <= 1e-12 * enumerated.max(1e-12),
                "DP table vs enumeration disagree at q={q}: {hazard} vs {enumerated}"
            );
        }
    }

    #[test]
    fn first_slash_timing_and_cost_share_one_absorbing_chain() {
        // Both consumers of [`fold_first_slash_mass`] must agree on when mass
        // absorbs: at q = 1 every epoch misses, so first slash is deterministic
        // and early; at low q the mean stretches and the mass gate can trip.
        let horizon = 500_u64;
        let e_sure = expected_epochs_to_first_slash(1.0, horizon, &SimParams::default())
            .expect("q=1 absorbs");
        // m-of-n with a clean prior: need m consecutive misses to fill the window.
        assert!(
            (e_sure - f64::from(SimParams::default().archival().failure_window_m)).abs() < 1e-9,
            "sure-miss first slash at epoch m={}, got {e_sure}",
            SimParams::default().archival().failure_window_m
        );
        // Cost path: bond-only exposure at q=1 must be positive and scale with bond.
        let c1 = expected_slash_cost_per_epoch(1.0, 10.0, 0.0, horizon, &SimParams::default());
        let c2 = expected_slash_cost_per_epoch(1.0, 20.0, 0.0, horizon, &SimParams::default());
        assert!(c1 > 0.0 && (c2 - 2.0 * c1).abs() < 1e-9);

        // Low miss rate: mean is later; very low may be a horizon artifact.
        let e_low = expected_epochs_to_first_slash(0.05, horizon, &SimParams::default());
        if let Some(e) = e_low {
            assert!(e > e_sure, "rarer misses must delay first slash");
        }
        assert!(expected_epochs_to_first_slash(0.0, horizon, &SimParams::default()).is_none());
        // q=0 never misses
    }

    /// One shard's bond at risk in fiat (per-shard slash scope, §3.2).
    fn bond_loss_fiat(skl_price: f64) -> f64 {
        bond_at_risk_skl(&SimParams::default()) * skl_price
    }

    #[test]
    fn exposure_scope_matches_holding_not_single_shard() {
        // Scope-matching guard: the margin weighs a FULL holding proxied vs held,
        // so the slash exposure must sum over MAX_HOLDINGS_SHARDS independently
        // challenged shards. Pairing one shard's loss against the whole holding's
        // storage saving would understate the deterrent by MAX_HOLDINGS_SHARDS×.
        let per_shard = bond_loss_fiat(0.10);
        let q = 0.9; // sustained failure ⇒ absorption is near-certain
        let cost = proxy_cost_per_epoch(
            SHARD_BYTES,
            FETCH_FIAT_PER_BYTE_BAND[0],
            q,
            per_shard,
            0.0,
            131,
            &SimParams::default(),
        );
        let exposure =
            cost - proxy_refetch_cost_per_epoch(SHARD_BYTES, FETCH_FIAT_PER_BYTE_BAND[0]);
        let single_shard_exposure =
            expected_slash_cost_per_epoch(q, per_shard, 0.0, 131, &SimParams::default());
        assert!(
            (exposure / single_shard_exposure - MAX_HOLDINGS_SHARDS as f64).abs() < 1e-6,
            "exposure must scale by shards at risk"
        );
    }

    #[test]
    fn shard_payload_flips_the_margin_on_bandwidth_alone() {
        // A5's metered-bandwidth half: at the test=job payload the re-fetch
        // leg moves a whole shard per challenge, and at BOTH
        // modeled band ends it exceeds one epoch of holding — the margin is
        // positive at q = 0 and q* = 0 (no deadline pressure needed at these
        // prices). Price-contingent by SS 5.3 and labeled so in the report;
        // the below-break-even world is covered by q_risk_star instead.
        let storage =
            honest_storage_cost_per_epoch(STORAGE_FIAT_PER_BYTE_YEAR, &SimParams::default());
        for &fp in &FETCH_FIAT_PER_BYTE_BAND {
            let refetch = proxy_refetch_cost_per_epoch(SHARD_BYTES, fp);
            assert!(
                refetch > storage,
                "shard-payload re-fetch {refetch} must exceed storage {storage} at {fp}"
            );
            let qc = crossover_q(
                SHARD_BYTES,
                fp,
                STORAGE_FIAT_PER_BYTE_YEAR,
                1.0,
                0.0,
                131,
                &SimParams::default(),
            );
            assert_eq!(
                qc,
                Some(0.0),
                "bandwidth alone closes it at the modeled band"
            );
        }
    }

    #[test]
    fn breakeven_fetch_price_sits_below_the_modeled_band() {
        // The number that scopes when T_risk becomes load-bearing: only a
        // fetcher paying LESS per byte than this (flat-rate/residential —
        // below bulk transit) escapes the bandwidth closure.
        let be =
            shard_breakeven_fetch_fiat_per_byte(STORAGE_FIAT_PER_BYTE_YEAR, &SimParams::default());
        assert!(
            be < FETCH_FIAT_PER_BYTE_BAND[0],
            "break-even {be} must sit below the band's bulk-transit end"
        );
        // And it is exactly S / (challenged bytes per epoch) by construction.
        let expected =
            honest_storage_cost_per_epoch(STORAGE_FIAT_PER_BYTE_YEAR, &SimParams::default())
                / (MAX_HOLDINGS_SHARDS as f64 * f64::from(COUNTED_DRAWS) * SHARD_BYTES);
        assert!((be - expected).abs() < 1e-24);
    }

    #[test]
    fn q_risk_star_exists_and_t_risk_is_monotone() {
        // In the zero-bandwidth-cost world the deterrent is T_risk alone;
        // it must be monotone in q and able to cover storage at SOME q with
        // the +reward forfeit (otherwise the arm would be claiming the PoRep
        // limit at every price, which the bond+reward magnitudes refute).
        let bond = bond_at_risk_skl(&SimParams::default()) * 1.0; // 1 $/SKL scale point
        let reward = 0.01;
        let shards = MAX_HOLDINGS_SHARDS as f64;
        let mut prev = -1.0;
        for i in 0..=10 {
            let q = f64::from(i) / 10.0;
            let t =
                shards * expected_slash_cost_per_epoch(q, bond, reward, 131, &SimParams::default());
            assert!(t >= prev, "T_risk must be monotone in q");
            prev = t;
        }
        let qr = q_risk_star(
            STORAGE_FIAT_PER_BYTE_YEAR,
            bond,
            reward,
            131,
            &SimParams::default(),
        );
        assert!(qr.is_some(), "bond+reward T_risk must cover S at some q");
        let qr = qr.unwrap();
        assert!(qr > 0.0 && qr < 1.0, "q_risk* interior: {qr}");
    }

    #[test]
    fn zero_payload_crossover_equals_q_risk_star() {
        // The F-2 identity, welded: with the bandwidth term zeroed the
        // margin crossover IS q_risk* — the slash model is payload-
        // independent, so A5's zero-byte-price half is exactly q_risk*. Any
        // payload coupling into the risk path breaks this equality.
        let bond = bond_at_risk_skl(&SimParams::default()) * 1.0;
        let reward = 0.01;
        for &fp in &FETCH_FIAT_PER_BYTE_BAND {
            let via_crossover = crossover_q(
                0.0,
                fp,
                STORAGE_FIAT_PER_BYTE_YEAR,
                bond,
                reward,
                131,
                &SimParams::default(),
            )
            .expect("zero-payload crossover exists");
            let via_q_risk = q_risk_star(
                STORAGE_FIAT_PER_BYTE_YEAR,
                bond,
                reward,
                131,
                &SimParams::default(),
            )
            .expect("q_risk* exists");
            assert!(
                (via_crossover - via_q_risk).abs() < 1e-9,
                "zero-payload crossover {via_crossover} must equal q_risk* {via_q_risk}"
            );
        }
    }

    #[test]
    fn within_cloud_class_cheap_transit_cell_is_decisive_at_lambda_three() {
        // TJ §8.2 (TJ-A2d) named this cell as the one the challenge count
        // could move: raising the per-pair count multiplies the free-rider's
        // per-epoch transfer while honest storage is unchanged — "exactly the
        // lever that could lift §5.7c's marginal cheap-transit cell (~1.1×)
        // out of coin-flip territory ... a measurable claim, not an argument:
        // it re-runs by changing one operand."
        //
        // The 2-of-3 ruling set λ = 3 and this is that measurement, collected:
        // the cell moves 1.095× → 3.285×, linear in λ as predicted. The §5.3
        // reopen's watch-cell is no longer a coin flip — within the cloud
        // class the F-1 headline is now decisive at BOTH ends of the fetch
        // band, and the deterrent no longer leans on the §5.7b labor
        // threshold nobody should lean on.
        let cloud_s =
            honest_storage_cost_per_epoch(CLOUD_STORAGE_FIAT_PER_BYTE_YEAR, &SimParams::default());
        let t_cheap = proxy_refetch_cost_per_epoch(SHARD_BYTES, FETCH_FIAT_PER_BYTE_BAND[0]);
        let ratio = t_cheap / cloud_s;
        assert!(
            ratio > 3.0 && ratio < 3.6,
            "within-cloud cheap-transit ratio at lambda = 3 must be ~3.3x, got {ratio}"
        );
        // Linear in λ, and dividing the challenge count back out returns the
        // ~1.1× cell TJ-A2d called marginal — the pre-ruling fact is retained
        // here rather than deleted, so the lever's size stays legible.
        let per_challenge = ratio / f64::from(COUNTED_DRAWS);
        assert!(
            per_challenge > 1.0 && per_challenge < 1.5,
            "per-challenge cell is the ~1.1x TJ-A2d called marginal, got {per_challenge}"
        );
        // And the retail end stays decisively closed within-class too.
        let t_retail = proxy_refetch_cost_per_epoch(SHARD_BYTES, FETCH_FIAT_PER_BYTE_BAND[1]);
        assert!(
            t_retail / cloud_s > 5.0,
            "retail end must remain decisive within-class"
        );
    }
}
