// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! W10 **proxy free-rider** margin (A5, §12.2 / §11.1).
//!
//! **Scope — GATE2-conformant, this is the reopen trigger, not a redesign.** The
//! genesis ruling is *"foundation owns durability; market owns reach"*
//! (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` §11.1): the serve-challenge is a
//! **cheap curve-tree opening** (`VerifyPath` of one 128-byte leaf + a *shallow*
//! segment co-path, `ARCHIVAL_RETENTION_GATE2.md` §0–3), and *"fetch-on-demand at
//! test time **is** providing the service"* — serve-credit is explicitly *"not
//! continuous storage"*. A thin **proxy** that holds nothing and re-fetches the
//! ~KB opening on demand within the gate-4 grace window therefore passes the
//! challenge by design. PoRep / actual-possession is a **named non-genesis path**.
//! This arm does **not** model the whole-shard challenge (that would deviate from
//! GATE2); it models the cheap opening and asks whether the **fetch-cost-vs-
//! deadline margin still binds** under the post-D1/D2 economics. A FAIL is the
//! §11.1 trigger: *tighten the gate-4 grace window* **or** *accelerate the PoRep
//! reopen* — never a D2 redesign.
//!
//! **Named margin (DQ-2E):** `margin/epoch = proxy_cost/epoch −
//! honest_storage_cost/epoch`, where `proxy_cost = re-fetch bandwidth + L14
//! slash exposure`. **Pass iff margin > 0** (honest holding is the cheaper
//! strategy, so the free-rider does not dominate).
//!
//! **L14 exposure rides the CORRECTED m-of-n slash.** A single missed re-fetch is
//! *absorbed* — the ratified failure model is sliding-window **m-of-n**
//! (`ARCHIVAL_FAILURE_CONFIRMATION_PIN.md`, provisional `m=11`, `n=13`), not the
//! single-strike an earlier draft assumed. So the proxy is slashed only on
//! *sustained* re-fetch failure (`P(≥m misses in n)`), which makes the deterrent
//! **weaker**, not stronger — the free-rider is more viable, not less.

use shekyl_archival_retention::{
    ARCHIVAL_BOND_FLOOR_ATOMIC, CHALLENGES_PER_EPOCH, MAX_HOLDINGS_SHARDS, SETTLEMENT_EPOCH_BLOCKS,
};

use crate::burden::{COIN, SHARD_BYTES};

/// Blocks per year — the sim's economic year (mirrors `SimParams::default`).
pub const BLOCKS_PER_YEAR: u64 = 262_800;

/// Settlement epochs per year: `blocks_per_year / SETTLEMENT_EPOCH_BLOCKS`.
#[must_use]
pub fn epochs_per_year() -> f64 {
    BLOCKS_PER_YEAR as f64 / SETTLEMENT_EPOCH_BLOCKS as f64
}

/// Bytes an archiver would hold at the per-bond cap (`MAX_HOLDINGS_SHARDS` ·
/// `SHARD_BYTES` ≈ 13.6 GB) — the honest side the proxy avoids (§7.4/W10).
#[must_use]
pub fn max_holdings_bytes() -> f64 {
    MAX_HOLDINGS_SHARDS as f64 * SHARD_BYTES
}

/// Bytes in one serve-challenge response: the 128-byte challenged leaf
/// (`ArchivalServeCreditResponse::leaf_bytes`) + the **shallow** segment co-path
/// (`SegmentPathOpening`). The segment is `SELENE·HELIOS·SELENE = 38·18·38`
/// (`SEGMENT_LEAF_COUNT`), so the opening is ~3 layers of sibling commitments:
/// `(38 + 18 + 38) · 32 B ≈ 3.0 KB`. A model estimate (scenario layer) — the
/// verdict is robust to it: any KB-scale opening is ≪ the 3.33 MB segment, which
/// is the whole point (`wire.rs`: *"segment paths are shallow"*).
pub const RESPONSE_BYTES: f64 = 128.0 + (38.0 + 18.0 + 38.0) * 32.0;

/// Storage cost basis, fiat `$/byte/year` (mirrors `burden::BASE_STORAGE_FIAT_PER_BYTE_YEAR`
/// — amortized commodity HDD ≈ `1e-11 $/B/yr`). The honest holder pays this on
/// the full ~13.6 GB every epoch.
pub const STORAGE_FIAT_PER_BYTE_YEAR: f64 = 1.0e-11;

/// Bandwidth (egress) cost band, fiat `$/byte` **transferred**. `1e-11` ≈
/// `$0.01/GB` (bulk transit) … `1e-10` ≈ `$0.10/GB` (retail egress). The proxy
/// pays this only on the re-fetched openings, not on 13.6 GB of standing storage.
pub const FETCH_FIAT_PER_BYTE_BAND: [f64; 2] = [1.0e-11, 1.0e-10];

/// Ratified sliding-window failure-confirmation params (provisional; re-pinned at
/// the Round-2 testnet stressnet — `ARCHIVAL_FAILURE_CONFIRMATION_PIN.md` §1). A
/// slash needs `m` misses within the last `n` baseline observations.
pub const SLASH_M: u32 = 11;
/// … `n` window length.
pub const SLASH_N: u32 = 13;

/// Honest storage cost per epoch, fiat: hold the full `max_holdings_bytes` at the
/// storage basis, prorated to one settlement epoch.
#[must_use]
pub fn honest_storage_cost_per_epoch(storage_fiat_per_byte_year: f64) -> f64 {
    max_holdings_bytes() * storage_fiat_per_byte_year / epochs_per_year()
}

/// Proxy re-fetch bandwidth cost per epoch, fiat: one challenge per held shard
/// (`CHALLENGES_PER_EPOCH`), each re-fetching one `RESPONSE_BYTES` opening.
#[must_use]
pub fn proxy_refetch_cost_per_epoch(fetch_fiat_per_byte: f64) -> f64 {
    let responses = MAX_HOLDINGS_SHARDS as f64 * f64::from(CHALLENGES_PER_EPOCH);
    responses * RESPONSE_BYTES * fetch_fiat_per_byte
}

/// `P(≥ m misses in the last n)` for iid per-epoch re-fetch-failure prob `q` — the
/// sliding-window slash probability at any epoch (upper binomial tail). This is
/// the corrected m-of-n exposure: a single miss is absorbed; only sustained
/// failure slashes.
#[must_use]
pub fn slash_prob_per_epoch(q: f64, m: u32, n: u32) -> f64 {
    let q = q.clamp(0.0, 1.0);
    let mut p = 0.0;
    for k in m..=n {
        p += binom(n, k) * q.powi(k as i32) * (1.0 - q).powi((n - k) as i32);
    }
    p
}

/// Exact binomial coefficient `C(n, k)` as f64 (n ≤ 13 here, no overflow).
fn binom(n: u32, k: u32) -> f64 {
    if k > n {
        return 0.0;
    }
    let k = k.min(n - k);
    let mut c = 1.0_f64;
    for i in 0..k {
        c = c * f64::from(n - i) / f64::from(i + 1);
    }
    c
}

/// The proxy's total cost per epoch, fiat: re-fetch bandwidth + the L14 slash
/// exposure (`P(slash) · slash_loss`). `slash_loss` is the one-time loss on a
/// sustained-failure slash — bond collateral + the forgone post-D1/D2 reward
/// stream — passed in from the caller (the reward is the §12.2 "against the
/// post-D1/D2 reward" input).
#[must_use]
pub fn proxy_cost_per_epoch(
    fetch_fiat_per_byte: f64,
    q: f64,
    slash_loss_fiat: f64,
    m: u32,
    n: u32,
) -> f64 {
    proxy_refetch_cost_per_epoch(fetch_fiat_per_byte)
        + slash_prob_per_epoch(q, m, n) * slash_loss_fiat
}

/// The W10 margin per epoch: `proxy_cost − honest_storage_cost`. **> 0 passes**
/// (honest holding is cheaper, so the proxy does not dominate).
#[must_use]
pub fn margin_per_epoch(
    fetch_fiat_per_byte: f64,
    storage_fiat_per_byte_year: f64,
    q: f64,
    slash_loss_fiat: f64,
    m: u32,
    n: u32,
) -> f64 {
    proxy_cost_per_epoch(fetch_fiat_per_byte, q, slash_loss_fiat, m, n)
        - honest_storage_cost_per_epoch(storage_fiat_per_byte_year)
}

/// The crossover re-fetch-failure rate `q*` at which the margin first turns
/// non-negative — i.e. how *unreliable* re-fetch must be (how *tight* the gate-4
/// grace window must be forced) for honest holding to win. `None` if the margin is
/// already ≥ 0 at `q = 0` (never happens while re-fetch is cheaper than storage),
/// or if even `q = 1` (re-fetch impossible — the PoRep limit) cannot close it.
#[must_use]
pub fn crossover_q(
    fetch_fiat_per_byte: f64,
    storage_fiat_per_byte_year: f64,
    slash_loss_fiat: f64,
    m: u32,
    n: u32,
) -> Option<f64> {
    let f = |q: f64| {
        margin_per_epoch(
            fetch_fiat_per_byte,
            storage_fiat_per_byte_year,
            q,
            slash_loss_fiat,
            m,
            n,
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

/// Bond collateral at risk on a sustained-failure slash, SKL: the full holding's
/// per-shard floor. Concrete (always present); the forgone reward stream is added
/// by the caller from the sim's post-D1/D2 pool.
#[must_use]
pub fn bond_at_risk_skl() -> f64 {
    MAX_HOLDINGS_SHARDS as f64 * (ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / COIN as f64)
}

/// Settlement epochs of forgone reward folded into the slash loss (`~5 y` at
/// `epochs_per_year`). The slash forfeits future reward; this bounds the stream
/// the exposure prices (undiscounted — deterrence-favourable).
pub const A5_REWARD_HORIZON_EPOCHS: f64 = 131.0;

/// A5 (W10) report. `forgone_reward_skl` is a **max-archiver's** post-D1/D2
/// reward stream over the horizon (from the sim's pool, §12.2 "against the
/// post-D1/D2 reward"); `skl_price` prices SKL losses to the fiat margin.
pub fn a5_proxy_report(forgone_reward_skl: f64, skl_price: f64) {
    let storage = honest_storage_cost_per_epoch(STORAGE_FIAT_PER_BYTE_YEAR);
    eprintln!(
        "\nA5 — W10 proxy free-rider margin (§12.2/§11.1): GATE2-conformant cheap opening\n\
         (128-B leaf + shallow ~{RB:.0}-B segment co-path; fetch-on-demand IS service, NOT\n\
         durability). margin/epoch = proxy(re-fetch + L14 slash exposure) − honest storage.\n\
         PASS iff margin > 0. L14 rides the CORRECTED m-of-n slash (m={M}/n={N}: a single\n\
         missed re-fetch is ABSORBED — deterrent is WEAKER than single-strike).\n\
         honest storage/epoch = ${STOR:.5} (hold {GB:.1} GB @ {SB:.0e} $/B/yr).",
        RB = RESPONSE_BYTES,
        M = SLASH_M,
        N = SLASH_N,
        STOR = storage,
        GB = max_holdings_bytes() / 1.0e9,
        SB = STORAGE_FIAT_PER_BYTE_YEAR,
    );
    eprintln!(
        "{:<22} {:>13} {:>14} {:>13} {:>12}",
        "fetch $/GB", "refetch/epoch", "margin@q=0", "q* bond-only", "q* +reward"
    );
    let bond_loss_fiat = bond_at_risk_skl() * skl_price;
    let reward_loss_fiat = forgone_reward_skl * skl_price;
    for &fp in &FETCH_FIAT_PER_BYTE_BAND {
        let refetch = proxy_refetch_cost_per_epoch(fp);
        let margin0 = margin_per_epoch(
            fp,
            STORAGE_FIAT_PER_BYTE_YEAR,
            0.0,
            bond_loss_fiat,
            SLASH_M,
            SLASH_N,
        );
        let qc_bond = crossover_q(
            fp,
            STORAGE_FIAT_PER_BYTE_YEAR,
            bond_loss_fiat,
            SLASH_M,
            SLASH_N,
        );
        let qc_rew = crossover_q(
            fp,
            STORAGE_FIAT_PER_BYTE_YEAR,
            bond_loss_fiat + reward_loss_fiat,
            SLASH_M,
            SLASH_N,
        );
        eprintln!(
            "{:<22} {:>13.6} {:>14.6} {:>13} {:>12}",
            format!("{:.2}", fp * 1.0e9),
            refetch,
            margin0,
            qc_bond.map_or("none".to_string(), |q| format!("{q:.3}")),
            qc_rew.map_or("none".to_string(), |q| format!("{q:.3}")),
        );
    }
    eprintln!(
        "  -> W10 gate: FAILS at the current grace window (margin@q=0 < 0 — re-fetch is ~KB\n\
         vs 13.6 GB held, so honest holding is the DEARER strategy: the proxy free-rides).\n\
         'q*' = the per-epoch re-fetch-FAILURE rate the gate-4 grace window must force for\n\
         the m-of-n slash exposure to flip the margin positive — i.e. how tight grace must\n\
         get. A large post-D2 reward lowers q* (bigger forfeit deters more) — the one way\n\
         D2 helps here — but the current hours-long grace gives q≈0, so it does not bind.\n\
         §11.1 disposition (NOT a D2 redesign): tighten gate-4 grace to force q ≥ q*, OR\n\
         accelerate the PoRep reopen (q→1: re-fetch cannot substitute for sealed possession\n\
         — the whole-shard/actual-possession test, a NAMED non-genesis path)."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refetch_is_far_cheaper_than_storage() {
        // The crux: one epoch of holding 13.6 GB dwarfs re-fetching ~4096 KB-scale
        // openings, at any bandwidth band member — so at q=0 the margin is negative
        // (the proxy free-rides), which is exactly the W10 concern.
        let storage = honest_storage_cost_per_epoch(STORAGE_FIAT_PER_BYTE_YEAR);
        for &fp in &FETCH_FIAT_PER_BYTE_BAND {
            let refetch = proxy_refetch_cost_per_epoch(fp);
            assert!(
                refetch < storage,
                "re-fetch {refetch} must be < storage {storage} at fetch price {fp}"
            );
        }
    }

    #[test]
    fn slash_prob_absorbs_single_miss_and_is_monotone() {
        // m-of-n absorbs isolated misses: a small q gives a tiny slash prob …
        assert!(slash_prob_per_epoch(0.05, SLASH_M, SLASH_N) < 1e-6);
        // … and it rises monotonically toward 1 as q → 1 (sustained failure).
        let mut prev = -1.0;
        for i in 0..=10 {
            let q = i as f64 / 10.0;
            let p = slash_prob_per_epoch(q, SLASH_M, SLASH_N);
            assert!(p >= prev, "slash prob must be monotone in q");
            prev = p;
        }
        assert!((slash_prob_per_epoch(1.0, SLASH_M, SLASH_N) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn w10_fails_at_loose_grace_and_crossover_is_defined() {
        // At q≈0 (loose grace, reliable re-fetch) the margin is negative — W10 FAILS.
        let fp = FETCH_FIAT_PER_BYTE_BAND[1]; // retail egress (proxy-unfavourable)
        let slash_loss = bond_loss_fiat(0.10) + 0.0; // bond only, mid SKL price
        assert!(
            margin_per_epoch(
                fp,
                STORAGE_FIAT_PER_BYTE_YEAR,
                0.0,
                slash_loss,
                SLASH_M,
                SLASH_N
            ) < 0.0
        );
        // A crossover q* exists (bond exposure can close it if re-fetch is forced
        // unreliable enough) — the "how tight must grace be" number.
        let qc = crossover_q(fp, STORAGE_FIAT_PER_BYTE_YEAR, slash_loss, SLASH_M, SLASH_N);
        assert!(qc.is_some_and(|q| q > 0.0 && q < 1.0));
    }

    fn bond_loss_fiat(skl_price: f64) -> f64 {
        MAX_HOLDINGS_SHARDS as f64 * (ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / COIN as f64) * skl_price
    }
}
