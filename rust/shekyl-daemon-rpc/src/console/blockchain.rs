// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `print_blockchain_info` and `print_blockchain_dynamic_stats`.

use super::info::{daa_target_seconds, fetch_get_info};
use super::{
    human_readable_timestamp, native_json_rpc, require_ok, trimmed, wide_difficulty_decimal,
    wide_difficulty_value, Source,
};
use crate::chain_facts::FfiChainFacts;
use shekyl_units::AtomicUnits;

/// Fetch `get_block_headers_range` — native here, over `/json_rpc` remotely.
fn fetch_block_headers_range(
    src: &Source,
    start_height: u64,
    end_height: u64,
) -> Result<Vec<shekyl_rpc_types::BlockHeader>, String> {
    let request = shekyl_rpc_types::GetBlockHeadersRangeRequest {
        start_height,
        end_height,
        fill_pow_hash: false,
    };
    // In-process the console is the operator's own terminal, so the
    // restricted rule does not apply — as `print_block` says.
    let reply = native_json_rpc(src, "get_block_headers_range", &request, |core| {
        crate::methods::get_block_headers_range(&FfiChainFacts::new(core.clone()), &request, false)
    })?;
    require_ok(&reply.status)?;
    Ok(reply.headers)
}

/// `print_blockchain_info <start> [end]`, and `print_blockchain_info -<n>`.
///
/// The negative form is why this command reads `/get_info`: the C++ parser
/// forwards `(-n, n)` and the executor resolves the window against the tip.
/// That resolution is the only arithmetic here and it is the arithmetic that
/// can be asked to describe a chain shorter than the window, which the C++
/// refused by name — kept, because "start offset is larger than blockchain
/// height" tells an operator what to type next and an empty listing does not.
#[deny(clippy::arithmetic_side_effects)]
pub(super) fn print_blockchain_info(src: &Source, start: i64, end: u64) -> Result<String, String> {
    let (start_height, end_height) = if start < 0 {
        let info = fetch_get_info(src)?;
        // `-start` as a magnitude, taken through `unsigned_abs` so
        // `i64::MIN` has no special case.
        let back = start.unsigned_abs();
        if back >= info.height {
            return Err("start offset is larger than blockchain height".to_owned());
        }
        let first = info.height.saturating_sub(back);
        // The C++ wrote `start + end - 1` with `end == -start`, i.e. the
        // window ends where the tip is. Saturating rather than wrapping: a
        // zero-length window would otherwise underflow past the tip.
        (first, first.saturating_add(end).saturating_sub(1))
    } else {
        // Non-negative: both indices are literal, and `end` defaults to 0 —
        // so `print_blockchain_info 5` asks for [5, 0] and is refused by the
        // method, exactly as the C++ was. RK-D8: the shape is preserved
        // because changing it is a separate decision from moving it.
        (start.unsigned_abs(), end)
    };
    let headers = fetch_block_headers_range(src, start_height, end_height)?;
    Ok(headers
        .iter()
        .map(render_blockchain_info_entry)
        .collect::<Vec<_>>()
        .join("\n\n"))
}

/// One header as `print_blockchain_info` listed it: four lines, and a blank
/// line between entries supplied by the join above.
fn render_blockchain_info_entry(h: &shekyl_rpc_types::BlockHeader) -> String {
    [
        format!(
            "height: {}, timestamp: {} ({}), size: {}, weight: {} (long term {}), transactions: {}",
            h.height,
            h.timestamp,
            human_readable_timestamp(h.timestamp),
            h.block_size,
            h.block_weight,
            h.long_term_weight,
            h.num_txes
        ),
        format!(
            "major version: {}, minor version: {}",
            h.major_version, h.minor_version
        ),
        format!("block id: {}, previous block id: {}", h.hash, h.prev_hash),
        format!(
            "difficulty: {}, nonce {}, reward {}",
            wide_difficulty_decimal(&h.wide_difficulty),
            h.nonce,
            AtomicUnits::from_raw(h.reward).to_skl_string()
        ),
    ]
    .join("\n")
}

/// Fetch `get_fee_estimate` — native here, over `/json_rpc` remotely.
fn fetch_fee_estimate(
    src: &Source,
    grace_blocks: u64,
) -> Result<shekyl_rpc_types::GetFeeEstimateResponse, String> {
    let request = shekyl_rpc_types::GetFeeEstimateRequest { grace_blocks };
    let reply = native_json_rpc(src, "get_fee_estimate", &request, |core| {
        crate::methods::get_fee_estimate(&FfiChainFacts::new(core.clone()), &request)
    })?;
    require_ok(&reply.status)?;
    Ok(reply)
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

/// A `count` of `version` byte tallies as the C++ listed them: `"3 v1, 1 v2"`,
/// ascending by version, versions with no votes omitted.
pub(super) fn version_tally(counts: &[u32; 256]) -> String {
    counts
        .iter()
        .enumerate()
        .filter(|(_, n)| **n > 0)
        .map(|(version, n)| format!("{n} v{version}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `print_blockchain_dynamic_stats <nblocks>`.
///
/// **The `hard_fork_info` leg is deleted rather than ported.** Its only use
/// was `hfres.enabled ? "byte" : "kB"` against `HF_VERSION_PER_BYTE_FEE`,
/// which is `1` (`cryptonote_config.h:282`), and `enabled` is
/// `get_current_version() >= 1`. `Blockchain` constructs its `HardFork` with
/// `original_version = 1` on all three networks
/// (`blockchain.cpp:474`/`:476`/`:478`), `init()` seeds `heights[0]` with
/// that version at height 0, and `current_fork_index` starts at 0 and only
/// advances — so the condition is true on every chain this daemon can be
/// running, and the `kB` arm is unreachable. Shekyl is v3-from-genesis with
/// no pre-v1 history for it to describe (rule 60). The unit is per byte; the
/// round trip that asked is gone with the branch it fed.
#[deny(clippy::arithmetic_side_effects)]
pub(super) fn print_blockchain_dynamic_stats(src: &Source, nblocks: u64) -> Result<String, String> {
    let info = fetch_get_info(src)?;
    let fees = fetch_fee_estimate(src, 0)?;
    // `res.fee = res.fees[0]` — `on_get_base_fee_estimate` set the scalar
    // from the first tier, which is why RK-5b could retire it. The console
    // read the scalar, so it reads tier 0.
    let dynamic_fee =
        AtomicUnits::from_raw(fees.fees.get(shekyl_rpc_types::FeeTier::Low)).to_skl_string();
    let (target, target_warning) = daa_target_seconds(info.target);
    let mut out = Vec::new();
    out.extend(target_warning);
    out.push(format!(
        "Height: {}, diff {}, cum. diff {}, target {target} sec, dyn fee {dynamic_fee}/byte",
        info.height,
        wide_difficulty_decimal(&info.wide_difficulty),
        wide_difficulty_decimal(&info.wide_cumulative_difficulty),
    ));
    if nblocks == 0 {
        return Ok(out.join("\n"));
    }
    // The window is the last `nblocks` below the tip; `height` is a count, so
    // the tip's own height is one below it.
    let window = nblocks.min(info.height);
    let start = info.height.saturating_sub(window);
    let end = info.height.saturating_sub(1);
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
            .any(|(h, want)| h.height != *want)
    {
        return Err(format!(
            "the daemon answered {} headers for the {} blocks of [{start}, {end}]{}",
            headers.len(),
            expected.len(),
            headers.first().map_or(String::new(), |h| format!(
                ", starting at height {}",
                h.height
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
    let mut major = [0u32; 256];
    let mut minor = [0u32; 256];
    for h in &headers {
        // An unreadable wide difficulty contributes nothing rather than
        // failing the whole listing; `wide_difficulty_decimal` shows the raw
        // string in the per-block view for the same reason.
        difficulty_sum =
            difficulty_sum.saturating_add(wide_difficulty_value(&h.wide_difficulty).unwrap_or(0));
        tx_count = tx_count.saturating_add(h.num_txes);
        reward_sum = reward_sum.saturating_add(h.reward);
        weights.push(h.block_weight);
        earliest = earliest.min(h.timestamp);
        latest = latest.max(h.timestamp);
        major[usize::from(h.major_version)] = major[usize::from(h.major_version)].saturating_add(1);
        minor[usize::from(h.minor_version)] = minor[usize::from(h.minor_version)].saturating_add(1);
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
    out.push(format!("Block versions: {}", version_tally(&major)));
    out.push(format!("Voting for: {}", version_tally(&minor)));
    Ok(out.join("\n"))
}
