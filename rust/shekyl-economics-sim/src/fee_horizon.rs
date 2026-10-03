// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The fee-era clearance horizon.
//!
//! For a fee that does not depend on height, `H` is a closed form: fees grow
//! with traffic and the corpus grows with traffic times time, so traffic
//! cancels for a share of all fees and cancels only up to `burn_pct`'s `√V`
//! for a share of the burn. The production fee follows the block reward, so
//! it has no such `H`; [`write_report`] says that instead of printing a number
//! that would not be one.

use std::fmt;

use shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;
use shekyl_economics::{burn::calc_burn_pct, params::SCALE, TxVolume};

use crate::burden::{
    honest_leaves_at_closed_shards, normal_tx_archival_bytes, COIN as ATOMIC, OPP_COST_RATE_BAND,
    REPLICAS_PER_SHARD,
};
use crate::engine::SimParams;
use crate::escalation::KNEE_BAND;
use crate::scenarios::SCENARIO_9_TAIL_TX_PER_BLOCK;

/// SKL per atomic, the reporting conversion. The integer is `burden::COIN`.
const COIN: f64 = ATOMIC as f64;

/// The fee-era clearance horizon in traffic-years, closed form: for constant
/// traffic `V`, fees `∝ V` and corpus `∝ V·t`, so
///
/// `ratio(t) ≈ fee · base · share · W / (bond · R · rate · bytes_per_tx · t)`
///
/// clears for `t ≤ H`. Returns `H` in years. `base` is the fraction of fees
/// the share is taken of: `1` for a share of all fees, or the burn fraction
/// for a share of the burn. The traffic `V` cancels **only through the
/// factors written here**: `base` is where it does not cancel for the burn,
/// because `calc_burn_pct` rises as `√V` until `burn_cap` binds — so a burn
/// lever's `H` is a function of `V` ([`fee_era_burn_fraction`] evaluates it
/// at a named volume) and an all-fees lever's is not.
#[must_use]
pub fn fee_horizon_years(
    fee_per_tx_atomic: u64,
    base_fraction: f64,
    share_fraction: f64,
    rate: f64,
    bytes_per_tx: u64,
    shard_bytes: u64,
) -> f64 {
    let fee_skl = fee_per_tx_atomic as f64 / COIN;
    let bond_skl = ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / COIN;
    fee_skl * base_fraction * share_fraction * shard_bytes as f64
        / (bond_skl * REPLICAS_PER_SHARD as f64 * rate * bytes_per_tx as f64)
}

/// The fee-era burn fraction at a constant traffic of `tx_per_block`, with
/// the supply emitted — the `base` of a burn lever's horizon, read from the
/// production `calc_burn_pct` at that volume, not restated. `SCALE` units.
pub(crate) fn fee_era_burn_pct(params: &SimParams, tx_per_block: u64) -> u64 {
    calc_burn_pct(
        TxVolume::per_block(tx_per_block),
        params.tx_volume_baseline,
        params.emission_curve_asymptote,
        params.emission_curve_asymptote,
        params.burn_base_rate,
        params.burn_cap,
    )
}

/// [`fee_era_burn_pct`] as a fraction.
pub(crate) fn fee_era_burn_fraction(params: &SimParams, tx_per_block: u64) -> f64 {
    fee_era_burn_pct(params, tx_per_block) as f64 / SCALE as f64
}

/// The lowest constant traffic (tx/block) at which the fee-era burn fraction
/// reaches `burn_cap` — found by asking the production `calc_burn_pct`, never
/// by inverting its formula here. Above it a burn lever's horizon stops rising
/// with traffic. Walks up from the baseline one tx/block at a time; the cap is
/// a few multiples of the baseline, so the walk is short.
fn burn_cap_volume(params: &SimParams) -> u64 {
    let baseline = params.tx_volume_baseline;
    (baseline..=baseline.saturating_mul(10_000))
        .find(|&v| fee_era_burn_pct(params, v) >= params.burn_cap)
        .expect("burn_cap is reached within 10,000x the baseline volume")
}

/// Shards the whole perpetual tail funds at a rate, if every tail SKL went to
/// archival bonds' opportunity cost.
pub(crate) fn shards_funded_by_tail(tail_skl_per_year: f64, rate: f64) -> f64 {
    let bond_skl = ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / COIN;
    tail_skl_per_year / (bond_skl * REPLICAS_PER_SHARD as f64 * rate)
}

/// A1-T's fee-horizon paragraph. The closed form on a flat fee; one line
/// saying there is none on any other arm.
pub(crate) fn write_report(out: &mut impl fmt::Write, params: &SimParams) -> fmt::Result {
    match params.fee.flat_per_tx_atomic() {
        Some(fee) => write_closed_form(out, params, fee),
        None => writeln!(
            out,
            "  -> FEE HORIZON: no closed form on this fee arm. H = fee x base x share x W /\n\
             (bond x R x rate x bytes/tx) needs a fee that is constant in height; the\n\
             production fee follows the block reward. The control arm prints it."
        ),
    }
}

/// The fee-era clearance horizon in closed form, printed for a **flat** fee
/// only: `H` is a constant because the fee is, which is the control arm's
/// property and not the chain's.
fn write_closed_form(out: &mut impl fmt::Write, params: &SimParams, fee: u64) -> fmt::Result {
    let bytes_per_tx = normal_tx_archival_bytes(honest_leaves_at_closed_shards(KNEE_BAND[2]));
    let w = shekyl_types::SHARD_LENGTH.to_raw();
    let cap_volume = burn_cap_volume(params);
    writeln!(
        out,
        "  -> FEE HORIZON (closed form, constant traffic V): the fee leg clears a corpus no\n\
         deeper than H = fee x base x share x W / (bond x R x rate x bytes/tx) traffic-years.\n\
         fee {fee:.3} SKL/tx, W {w} B, bond {bond:.2} SKL x R{R}, {bpt} archival B/tx (1in/2out,\n\
         deep). V cancels between fees and corpus; for a share of ALL fees H is therefore\n\
         traffic-independent. For a share of the BURN, base = burn_pct rises as sqrt(V)\n\
         (calc_burn_pct, supply emitted) until burn_cap binds at V = {cap_v} tx/block, so H\n\
         rises with traffic up to the cap ({cap_ratio:.1}x the baseline figure) and is flat above:",
        fee = fee as f64 / COIN,
        bond = ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / COIN,
        R = REPLICAS_PER_SHARD,
        bpt = bytes_per_tx,
        cap_v = cap_volume,
        cap_ratio = params.burn_cap as f64 / params.burn_base_rate as f64,
    )?;
    let volumes = [
        ("scen. 9 tail", SCENARIO_9_TAIL_TX_PER_BLOCK),
        ("baseline", params.tx_volume_baseline),
        ("at burn_cap", cap_volume),
    ];
    let horizons = |base: f64, share: f64| -> String {
        OPP_COST_RATE_BAND
            .iter()
            .map(|&r| {
                format!(
                    "{:.0}y @{:.0}%",
                    fee_horizon_years(fee, base, share, r, bytes_per_tx, w),
                    r * 100.0
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    for (label, share) in [("burn x flat 25%", 0.25), ("burn x 100%", 1.0)] {
        for (vlabel, v) in volumes {
            let base = fee_era_burn_fraction(params, v);
            writeln!(
                out,
                "       {label:<16} {vlabel:<12} ({v:>4} tx/blk, burn_pct {base:.2})  H = {}",
                horizons(base, share)
            )?;
        }
    }
    writeln!(
        out,
        "       {:<16} {:<12} ({:>4} tx/blk, base 1.00)  H = {}",
        "ALL fees x 100%",
        "any V",
        "any",
        horizons(1.0, 1.0)
    )?;
    writeln!(
        out,
        "     Corpus older than H is unfunded by fees, and past the cap no amount of traffic\n\
         moves H; a busier chain crosses the same line later only because its corpus is\n\
         younger. No FLOW — fee share, burn share, or the constant tail — funds a\n\
         fixed-per-shard bond held forever on a corpus that grows forever; the operand to\n\
         question is the bond (§12.14 Ruling: bond sizing vs per-shard reward)."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burn_horizon_rises_with_sqrt_traffic_until_the_cap() {
        // A burn lever's H is NOT traffic-independent: its base is the
        // production burn fraction, which rises as sqrt(V) until burn_cap. An
        // all-fees lever's H is. Both read off the same closed form, which
        // exists only on the flat arm.
        let params = SimParams::section_12_14_control();
        let baseline = params.tx_volume_baseline;
        let cap_v = burn_cap_volume(&params);
        assert!(cap_v > baseline);
        assert_eq!(fee_era_burn_pct(&params, cap_v), params.burn_cap);
        assert!(fee_era_burn_pct(&params, cap_v - 1) < params.burn_cap);

        let bytes = normal_tx_archival_bytes(honest_leaves_at_closed_shards(KNEE_BAND[2]));
        let w = shekyl_types::SHARD_LENGTH.to_raw();
        let fee = params
            .fee
            .flat_per_tx_atomic()
            .expect("the control arm is flat");
        let h_at = |v: u64| {
            fee_horizon_years(fee, fee_era_burn_fraction(&params, v), 0.25, 0.10, bytes, w)
        };
        let h_tail = h_at(SCENARIO_9_TAIL_TX_PER_BLOCK);
        let h_base = h_at(baseline);
        let h_cap = h_at(cap_v);
        assert!(
            h_tail < h_base && h_base < h_cap,
            "{h_tail} {h_base} {h_cap}"
        );
        // Below the cap, sqrt(V).
        let mid = baseline * 9 / 4;
        assert!(mid < cap_v, "the sqrt check must sit below the cap");
        let ratio = h_at(mid) / h_base;
        let expected = (mid as f64 / baseline as f64).sqrt();
        assert!((ratio - expected).abs() < 0.01, "{ratio} vs {expected}");
        // Above the cap, flat.
        assert_eq!(h_at(cap_v * 10), h_cap);
        // The cap/base ratio from the params is where it tops out.
        let top = params.burn_cap as f64 / params.burn_base_rate as f64;
        assert!(((h_cap / h_base) - top).abs() < 0.01);
        // All fees: the same at every volume.
        let all = |_v: u64| fee_horizon_years(fee, 1.0, 1.0, 0.10, bytes, w);
        assert_eq!(all(SCENARIO_9_TAIL_TX_PER_BLOCK), all(cap_v * 10));
    }
}
