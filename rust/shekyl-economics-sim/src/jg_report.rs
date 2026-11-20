// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `--jg-grid` narration. A line is one signal, one traffic family,
//! one zone and one `w_ref`; its figures are the seeds of that family.
//!
//! Child of [`super`]: it renders the groups the grid folded.

use std::fmt;

use shekyl_wire::transaction::COINBASE_RESERVE;

use crate::engine::SimParams;

use super::{
    design_load_txs, family_name, CampaignGroup, CampaignRow, HonestGroup, HonestRow, Zone,
    DESIGN_LOAD_SPENDS,
};
use crate::window_stuffer::MEASURED_BLOCKS;

/// The lower-middle median of `values` and its range, or `None` when empty.
fn spread(values: &[f64]) -> Option<(f64, f64, f64)> {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mid = *sorted.get((sorted.len().max(1) - 1) / 2)?;
    Some((mid, sorted[0], sorted[sorted.len() - 1]))
}

/// `values`' median, and its range in brackets when there is more than one.
pub(super) fn show(values: &[f64], digits: usize) -> String {
    match spread(values) {
        None => "-".into(),
        Some((mid, _, _)) if values.len() == 1 => format!("{mid:.digits$}"),
        Some((mid, lo, hi)) => format!("{mid:.digits$} [{lo:.digits$}, {hi:.digits$}]"),
    }
}

/// A figure across the seeds of one line.
///
/// No seed has it: `none`. Every seed has it: [`show`]. A seed lacks it:
/// each seed's value, or `-`, in seed order.
pub(super) fn figure(values: &[Option<f64>], digits: usize, none: &str) -> String {
    let present: Vec<f64> = values.iter().flatten().copied().collect();
    if present.is_empty() {
        return none.to_string();
    }
    if present.len() == values.len() {
        return show(&present, digits);
    }
    values
        .iter()
        .map(|value| match value {
            Some(value) => format!("{value:.digits$}"),
            None => "-".to_string(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// One label when every seed agrees, otherwise each seed's label.
pub(super) fn same_label(labels: &[String]) -> String {
    assert!(!labels.is_empty(), "a printed line has a seed");
    if labels.iter().skip(1).all(|label| label == &labels[0]) {
        labels[0].clone()
    } else {
        labels.join("/")
    }
}

pub(super) fn write_opening(
    out: &mut impl fmt::Write,
    derived: u64,
    reference: u64,
    w_refs: [u64; 2],
    seeds: &[String],
) -> fmt::Result {
    let seed_clause = match seeds {
        [] => String::new(),
        [one] => format!(", at seed {one}"),
        many => format!(
            ", at seeds {}, each figure its median across them and [its range]",
            many.join(", ")
        ),
    };
    writeln!(
        out,
        "J x G — THE VOLUME SIGNAL CROSSED WITH THE ZONE (ECONOMICS_SIM_PRODUCTION_REBASE.md §5.33, §5.34).\n\
         Measures only. Signals: SMA (production's window sum), median (the window's lower-middle\n\
         per-block count against the shipped baseline), median-r (the median against the baseline\n\
         restated as the median of variable traffic at the baseline's mean, {derived}; variable traffic\n\
         only), median+floor (the median, the stuffer paying the relay floor on its own bodies),\n\
         decoupled (the baseline in place of volume: release, the burn and C read none), rails-only\n\
         (release rails at 1.0; the burn and C still read the sum). Traffic: steady (the schedule's\n\
         demand every block) or variable (the sim's standard traffic, §5.35: each block's interval drawn\n\
         exponential at its height, and each fee rung's Poisson arrivals over it; the pool carries what a\n\
         block does not list){seed_clause}. Zone: N 2-in/2-out\n\
         spends of {reference} B (genesis depth and Standard fee) plus the coinbase reserve ({} B), beside\n\
         the inherited and re-derived zones; w_ref at {} and {} B, each fixed across N. Not re-derived:\n\
         TX_WEIGHT_LIMIT (the sim does not read it; it caps one transaction, not a count) and\n\
         COINBASE_RESERVE (it does not depend on the zone). A ratio is the operand over the baseline\n\
         before the release rails clamp it to [0.8, 1.3].",
        COINBASE_RESERVE,
        w_refs[0],
        w_refs[1]
    )
}

pub(super) fn write_honest(
    out: &mut impl fmt::Write,
    base: &SimParams,
    derived: u64,
    zones: &[Zone],
    groups: &[HonestGroup],
    rows: &[Vec<HonestRow>],
) -> fmt::Result {
    writeln!(
        out,
        "\nTHE HONEST CHAIN. Per signal, traffic, zone and w_ref: the ratio the chain rests at (the window\n\
         before the step), the year-1 Standard fee (SKL, and over the ceiling), a day's blocks filled to\n\
         the zone at the year-1 relay floor (SKL), the first year blocks carry the design load\n\
         ({DESIGN_LOAD_SPENDS} spends, {} ordinary transactions a block), the declared step's up-edge (M_r over the\n\
         window before it and the trace's last window, and the blocks until that window mean covers 95 % of\n\
         the move), year 1's room after the window's first fill (the cap in transactions, least to most:\n\
         the effective median less the coinbase reserve over the Standard ordinary transaction; the share\n\
         of blocks whose own arrivals exceed it; the share leaving a backlog; the median offered and\n\
         carried), and for a median arm on variable traffic its count over year 1 after the window's first\n\
         fill, per seed: the mean, and the share of blocks at {} and at {derived}, the derived median.",
        design_load_txs(base),
        derived - 1
    )?;
    for (group, rows) in groups.iter().zip(rows) {
        let zone = &zones[group.zone];
        let fees: Vec<Option<f64>> = rows
            .iter()
            .map(|row| row.year_one_standard_fee_skl)
            .collect();
        let overs: Vec<Option<f64>> = rows.iter().map(|row| row.over_ceiling).collect();
        let fee = figure(&fees, 4, "none carried");
        let fee = if fee == "none carried" {
            fee
        } else {
            format!("{fee} ({}x)", figure(&overs, 2, "none carried"))
        };
        let settles = figure(
            &rows
                .iter()
                .map(|row| row.step_settles_blocks.map(|blocks| blocks as f64))
                .collect::<Vec<_>>(),
            0,
            "no move",
        );
        let settles = if settles == "no move" {
            settles
        } else {
            format!("{settles} blocks")
        };
        let years = same_label(
            &rows
                .iter()
                .map(|row| {
                    row.design_load_year
                        .map_or("never".to_string(), |year| format!("y{year}"))
                })
                .collect::<Vec<_>>(),
        );
        write!(
            out,
            "  {:<12} {:<8} {:<12} {:>9} B w_ref {:>5}: rests {} ; fee {fee} ; fill a day {} ; design load {years} ; step M_r {}->{} in {settles}",
            group.signal.name(),
            family_name(&group.traffic),
            zone.label,
            zone.bytes,
            group.w_ref,
            show(&rows.iter().map(|row| row.resting_ratio).collect::<Vec<_>>(), 3),
            show(&rows.iter().map(|row| row.fill_a_day_skl).collect::<Vec<_>>(), 1),
            show(&rows.iter().map(|row| row.step_m_r.0).collect::<Vec<_>>(), 3),
            show(&rows.iter().map(|row| row.step_m_r.1).collect::<Vec<_>>(), 3),
        )?;
        let capacity = |pick: fn(&HonestRow) -> f64, digits| {
            show(&rows.iter().map(pick).collect::<Vec<_>>(), digits)
        };
        write!(
            out,
            " ; room cap {}-{} txs, arrivals over it {} %, backlog {} %, median offered {} carried {}",
            capacity(|row| row.capacity.cap.0 as f64, 0),
            capacity(|row| row.capacity.cap.1 as f64, 0),
            capacity(|row| row.capacity.overflow_pct, 1),
            capacity(|row| row.capacity.backlog_pct, 1),
            capacity(|row| row.capacity.median_offered as f64, 0),
            capacity(|row| row.capacity.median_carried as f64, 0),
        )?;
        for row in rows {
            if let Some(count) = row.median_count {
                write!(
                    out,
                    " ; {} count {:.2} ({}: {:.1} %, {}: {:.1} %)",
                    row.traffic,
                    count.mean,
                    count.derived - 1,
                    count.below_pct,
                    count.derived,
                    count.at_pct
                )?;
            }
        }
        writeln!(out)?;
    }
    Ok(())
}

pub(super) fn write_campaigns(
    out: &mut impl fmt::Write,
    zones: &[Zone],
    groups: &[CampaignGroup],
    rows_by_group: &[Vec<CampaignRow>],
) -> fmt::Result {
    writeln!(
        out,
        "\nTHE STUFFER. Per signal, traffic, zone, w_ref and start: a stuffer holding its share (100 = every\n\
         miner) for the whole measured span ({MEASURED_BLOCKS} blocks from the start of the year); the bodies\n\
         listed, M_r at the span's last block, M_r and the ratio over its last window (at rest), M_r's mean\n\
         over the span, the longest run of M_r > 1.0, the stuffer's payout less its fees against no\n\
         stuffing (SKL), the break-even burn (the burn rate on its own fees, had its bodies paid the\n\
         relay floor, at which that payout is zero: its gain before the burn of its own fees over the\n\
         floor fees on its bodies, percent; over 100 % no burn of floor fees deters it; - with no\n\
         bodies), and the burn and C at the span's last block. A share is an even proportion of the\n\
         blocks; the bodies are the ordinary 1-in/2-out, the lightest valid shape (CEN-I1)."
    )?;
    let mut heading = None;
    for (group, rows) in groups.iter().zip(rows_by_group) {
        let zone = &zones[group.zone];
        let family = family_name(&group.traffic);
        let key = (group.zone, group.w_ref, family);
        if heading != Some(key) {
            writeln!(
                out,
                "== {} ({} B) | w_ref {} | {}\n  {:<12} {:>3} {:>5} {:>7} {:>7} {:>7} {:>7} {:>7} {:>6} {:>12} {:>9} {:>7} {:>7}",
                zone.label,
                zone.bytes,
                group.w_ref,
                family,
                "signal",
                "y",
                "share",
                "bodies",
                "last",
                "at rest",
                "ratio",
                "mean",
                "run",
                "net gain SKL",
                "break-even",
                "burn %",
                "C"
            )?;
            heading = Some(key);
        }
        let column = |pick: fn(&CampaignRow) -> f64, digits: usize| {
            show(&rows.iter().map(pick).collect::<Vec<_>>(), digits)
        };
        let even = figure(
            &rows
                .iter()
                .map(|row| row.break_even_burn_pct)
                .collect::<Vec<_>>(),
            0,
            "-",
        );
        writeln!(
            out,
            "  {:<12} {:>3} {:>4}% {:>7} {:>7} {:>7} {:>7} {:>7} {:>6} {:>12} {:>9} {:>7} {:>7}",
            group.signal.name(),
            group.year,
            group.share,
            column(|row| row.bodies as f64, 0),
            column(|row| row.m_r_last, 4),
            column(|row| row.m_r_at_rest, 4),
            column(|row| row.ratio_at_rest, 3),
            column(|row| row.mean_m_r, 4),
            column(|row| row.longest_run_blocks as f64, 0),
            column(|row| row.net_gain_skl, 2),
            even,
            column(|row| row.burn_last_pct, 3),
            column(|row| row.c_last, 4),
        )?;
    }
    Ok(())
}
