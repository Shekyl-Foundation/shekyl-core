// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `print_blockchain_info` and `print_blockchain_dynamic_stats`.

use super::info::{chain_count, fetch_status};
use super::{human_readable_timestamp, trimmed};
use crate::daemon::DaemonClient;
use shekyl_rpc_client::wire;
use shekyl_rpc_types::kinds::{Height, NoParams};
use shekyl_rpc_types::wire::block::{BlockHeader, HeaderRange, HeaderRangeSelect};
use shekyl_rpc_types::wire::shared::Slot;
use shekyl_units::AtomicUnits;

/// `block_header_list` over `[from, to]`, inclusive. A height the daemon
/// does not hold is an error naming it: every caller here asked for heights
/// at or below the tip.
fn fetch_block_headers_range(
    src: &DaemonClient,
    from: u64,
    to: u64,
) -> Result<Vec<BlockHeader>, String> {
    let slots = super::call::<wire::BlockHeaderList>(
        src,
        &HeaderRange {
            select: HeaderRangeSelect::Range {
                from: Height(from),
                to: Height(to),
            },
            pow: false,
        },
    )?;
    slots
        .into_iter()
        .zip(from..)
        .map(|(slot, height)| match slot {
            Slot::Item(header) => Ok(header),
            _ => Err(format!("the daemon holds no header at block {height}")),
        })
        .collect()
}

/// `block header list --from <height> --to <height>`, inclusive.
///
/// Both ends are heights. A start after the end is refused by the grammar
/// before this function is called.
#[deny(clippy::arithmetic_side_effects)]
pub(super) fn print_blockchain_info(
    src: &DaemonClient,
    from: u64,
    to: u64,
) -> Result<String, String> {
    let headers = fetch_block_headers_range(src, from, to)?;
    Ok(headers
        .iter()
        .map(render_blockchain_info_entry)
        .collect::<Vec<_>>()
        .join("\n\n"))
}

/// One header as `print_blockchain_info` listed it: four lines, and a blank
/// line between entries supplied by the join above.
fn render_blockchain_info_entry(h: &BlockHeader) -> String {
    let longterm = h
        .weight_longterm
        .0
        .map_or_else(|| "none".to_owned(), |w| w.0.to_string());
    [
        format!(
            "block number: {}, timestamp: {} ({}), weight: {} (long term {longterm}), transactions: {}",
            h.height.0,
            h.time.0,
            human_readable_timestamp(h.time.0),
            h.weight.0,
            h.tx_count.0
        ),
        format!(
            "major version: {}, minor version: {}",
            h.version_major.0, h.version_minor.0
        ),
        format!("block id: {}, previous block id: {}", h.hash, h.parent),
        format!(
            "difficulty: {}, nonce {}, reward {}",
            h.difficulty.get(),
            h.nonce.0,
            h.reward.to_atomic_units().to_skl_string()
        ),
    ]
    .join("\n")
}

/// epee's `median`, which is what the C++ printed: the middle element of an
/// odd-length sample, and the **floor of the mean of the two middle
/// elements** of an even-length one (`misc_language.h`'s `get_mid`, whose
/// halve-then-add form exists to avoid overflowing the sum).
pub(super) fn median(values: &mut [u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    let n = values.len() / 2;
    if values.len() % 2 == 1 {
        values[n]
    } else {
        let (a, b) = (values[n.saturating_sub(1)], values[n]);
        // `a/2 + b/2 + (a%2 + b%2)/2` — the same identity, so the sum is
        // never formed and cannot overflow.
        (a / 2)
            .saturating_add(b / 2)
            .saturating_add(((a % 2).saturating_add(b % 2)) / 2)
    }
}

/// `print_blockchain_dynamic_stats <nblocks>`.
///
/// **The fee unit is per byte, with no query behind it.** The C++ chose
/// between `byte` and `kB` on a block-version test that is true from genesis
/// on every chain this daemon can run — Shekyl is v3-from-genesis with no
/// pre-v1 history for a `kB` arm to describe (rule 60) — so the unit is a
/// literal and the command makes two calls, `daemon_status` and `fee`,
/// before it reads any header.
#[deny(clippy::arithmetic_side_effects)]
pub(super) fn print_blockchain_dynamic_stats(
    src: &DaemonClient,
    nblocks: u64,
) -> Result<String, String> {
    let status = fetch_status(src)?;
    let height = chain_count(&status);
    let fees = super::call::<wire::Fee>(src, &NoParams)?;
    // The console has always read the lowest tier.
    let dynamic_fee = fees.economy.to_atomic_units().to_skl_string();
    let target = shekyl_economics::economic_params().daa_target_seconds;
    let mut out = Vec::new();
    out.push(format!(
        "Block count: {}, diff {}, cum. diff {}, target {target} sec, dyn fee {dynamic_fee}/byte",
        height,
        status.difficulty.get(),
        status.difficulty_cumulative.get(),
    ));
    if nblocks == 0 {
        return Ok(out.join("\n"));
    }
    // The window is the last `nblocks` below the tip; `height` is a count, so
    // the tip's own height is one below it.
    let window = nblocks.min(height);
    let start = height.saturating_sub(window);
    let end = height.saturating_sub(1);
    let headers = fetch_block_headers_range(src, start, end)?;
    // **The window is checked against what arrived, not assumed from what was
    // asked.** Every figure below is labelled `Last {window}`, so a reply with
    // the wrong count — or the right count for different heights — produces a
    // confidently mislabelled summary rather than a visible error. The native
    // handler guarantees exact correspondence; the *remote* arm is talking to
    // a daemon that need not.
    //
    // This is the `alt_chain_info` finding one command over. That one declared
    // a length the hashes did not support; this one requests a range the
    // headers need not fill. Same defect, and round 2 fixed only the instance
    // it was reported against — the correspondence rule is a property of every
    // reply read against a request, not of the command it was first noticed in.
    let expected: Vec<u64> = (start..=end).collect();
    if headers.len() != expected.len()
        || headers
            .iter()
            .zip(&expected)
            .any(|(h, want)| h.height.0 != *want)
    {
        return Err(format!(
            "the daemon answered {} headers for the {} blocks of [{start}, {end}]{}",
            headers.len(),
            expected.len(),
            headers.first().map_or(String::new(), |h| format!(
                ", starting at block {}",
                h.height.0
            ))
        ));
    }
    let Ok(sample) = u64::try_from(headers.len()) else {
        return Err("the daemon returned more headers than can be counted".to_owned());
    };
    if sample == 0 {
        return Ok(out.join("\n"));
    }

    // **Every accumulation below saturates and every divisor is `sample`,
    // which the guard above proves non-zero.** These are chain values, so
    // they are as large as a difficulty gets — the C++ summed `avgreward`
    // and `avgnumtxes` into `double`s, which above 2^53 stops being exact,
    // and printed the result through `print_money`, an integer renderer. The
    // means here are integer throughout for the money one and the divisor is
    // the count of headers actually returned rather than the count asked for.
    let mut difficulty_sum: u128 = 0;
    let mut tx_count: u64 = 0;
    let mut reward_sum: u64 = 0;
    let mut weights: Vec<u64> = Vec::with_capacity(headers.len());
    let mut earliest = u64::MAX;
    let mut latest = 0u64;
    for h in &headers {
        difficulty_sum = difficulty_sum.saturating_add(h.difficulty.get());
        tx_count = tx_count.saturating_add(h.tx_count.0);
        reward_sum = reward_sum.saturating_add(h.reward.to_atomic_units().to_raw());
        weights.push(h.weight.0);
        earliest = earliest.min(h.time.0);
        latest = latest.max(h.time.0);
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "a transaction count average for a human"
    )]
    let average_txes = tx_count as f64 / sample as f64;
    // The C++ divided the timestamp span by `nblocks` rather than by the
    // `nblocks - 1` intervals those blocks actually span. Preserved: it is
    // the number this command has always printed, it is not wrong enough to
    // have a victim, and an operator's baseline is worth more than a
    // one-block correction made in passing.
    // `checked_div` rather than `/`: the guard above already returned on a
    // zero sample, so the `None` arm is unreachable — but total by
    // construction is this file's rule for peer-influenced arithmetic, and a
    // guard three statements away is not construction. Same idiom as
    // `print_net_stats`; see `methods::average_kib`.
    let average_seconds = latest
        .saturating_sub(earliest)
        .checked_div(sample)
        .unwrap_or(0);
    out.push(format!(
        "Last {window}: avg. diff {}, {average_seconds} avg sec/block, avg num txes {}, \
         avg. reward {}, median block weight {}",
        difficulty_sum.checked_div(u128::from(sample)).unwrap_or(0),
        trimmed(average_txes, 6),
        AtomicUnits::from_raw(reward_sum.checked_div(sample).unwrap_or(0)).to_skl_string(),
        median(&mut weights)
    ));
    Ok(out.join("\n"))
}
