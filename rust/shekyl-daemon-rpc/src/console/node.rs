// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `diff`, `version` and `print_pool_stats` — the three console commands
//! that were still rendered in C++ from `get_info` when that method moved
//! to Rust (RK-5c, `docs/design/DAEMON_RPC_KV_GET_INFO.md` §5 commit 4).
//!
//! Each prints what its C++ form printed. They are here, and not left for
//! the console's own retirement slice, because the C++ forms called the
//! `get_info` handler directly and that handler is deleted next.

use shekyl_rpc_types::pool::{GetTransactionPoolStatsResponse, TxpoolStats};
use shekyl_rpc_types::{core_rpc_version_string, daemon_rpc_version, CORE_RPC_VERSION};
use shekyl_units::AtomicUnits;

use super::identity::get_version_result;
use super::info::{decode_get_info_ok, fetch_get_info};
use super::Source;
use crate::ctl_client;

/// `diff`: the tip, the two difficulties, and the network hash rate.
///
/// The hash rate is the next difficulty over the build's own target, as
/// every other command here computes it; the C++ divided by the reply's
/// `target` member, which is the same constant.
#[deny(clippy::arithmetic_side_effects)]
pub(super) fn show_difficulty(src: &Source) -> Result<String, String> {
    let info = fetch_get_info(src)?;
    let target = u128::from(crate::consensus::DAA_TARGET_SECONDS);
    let hash_rate = info
        .chain
        .difficulty
        .checked_div(target)
        .ok_or_else(|| "the difficulty target is zero".to_owned())?;
    Ok(format!(
        "BH: {}, TH: {}, DIFF: {}, CUM_DIFF: {}, HR: {hash_rate} H/s",
        info.health.height,
        hex::encode(info.health.top_block_hash.to_bytes()),
        info.chain.difficulty,
        info.chain.cumulative_difficulty,
    ))
}

const VERSION_UNAVAILABLE: &str = "The daemon software version is not available.";

/// `version`: the daemon's software version.
///
/// **The remote arm does not run the identity handshake.** Every other
/// command refuses to render from a daemon whose identity does not match
/// this build; this one exists to show the operator what they reached, so
/// it asks without that check (`CLIENT_VERSION_CONSTANTS_VALIDATION.md`
/// §3.6.2).
///
/// It still reads the daemon's RPC version first, through the one reader
/// every client uses (`RK-D25`), and what it does next depends on the
/// answer:
///
/// - **The versions differ.** The reply names both and says which side is
///   older, and that is all: `get_info` is not read, because its shape is
///   another version's and this build decodes it strictly or not at all.
/// - **The versions agree.** `get_info` is decoded as every other reader
///   decodes it, and the software version is printed.
///
/// A daemon that does not disclose its version withholds the Status part,
/// and that is reported as such, and as a failure, as the C++ did. An empty
/// version is not that: the reply type refuses a shown Status whose version
/// is empty, so one never reaches this function.
pub(super) fn version(src: &Source) -> Result<String, String> {
    let info = match src {
        Source::Live(_) => fetch_get_info(src)?,
        Source::Remote {
            address, timeout, ..
        } => {
            let result = get_version_result(address, *timeout)?;
            let theirs = daemon_rpc_version(&result).map_err(|unreadable| {
                format!("the daemon's RPC version cannot be read: {unreadable}")
            })?;
            if theirs != CORE_RPC_VERSION {
                return Err(rpc_version_difference(CORE_RPC_VERSION, theirs));
            }
            let raw = ctl_client::post_blocking(address, "/get_info", b"{}".to_vec(), *timeout)
                .map_err(|(_, reason)| reason)?;
            decode_get_info_ok(&raw)?
        }
    };
    info.node
        .shown()
        .map(|status| status.version.clone())
        .ok_or_else(|| VERSION_UNAVAILABLE.to_owned())
}

/// What `version` says of a daemon on another RPC version.
fn rpc_version_difference(ours: u32, theirs: u32) -> String {
    let older = if theirs < ours {
        "the daemon"
    } else {
        "this console"
    };
    format!(
        "The daemon speaks RPC {}; this console speaks RPC {}. {older} is the older one. \
         The daemon's software version cannot be read across that difference.",
        core_rpc_version_string(theirs),
        core_rpc_version_string(ours),
    )
}

/// `/get_transaction_pool_stats`'s `pool_stats`. The pool does not record
/// when a transaction arrived (S7), so there is no age and no histogram.
fn fetch_pool_stats(src: &Source) -> Result<TxpoolStats, String> {
    match src {
        Source::Live(_) => {
            let handles =
                crate::handles::live_handles().ok_or_else(|| "the node is not open".to_owned())?;
            let reply = crate::pool_methods::get_transaction_pool_stats(
                handles.pool.as_ref(),
                crate::info_facts::PoolScope::WithUnbroadcast,
            )
            .map_err(|fault| format!("{fault:?}"))?;
            Ok(reply.pool_stats)
        }
        Source::Remote { .. } => {
            let raw = src.post_remote("/get_transaction_pool_stats", b"{}".to_vec())?;
            let reply: GetTransactionPoolStatsResponse = serde_json::from_slice(&raw)
                .map_err(|e| format!("malformed get_transaction_pool_stats reply: {e}"))?;
            if reply.status.is_ok() {
                Ok(reply.pool_stats)
            } else {
                Err(reply.status.0)
            }
        }
    }
}

fn money(atomic: u64) -> String {
    AtomicUnits::from_raw(atomic).to_skl_string()
}

/// `print_pool_stats`.
///
/// Two reads: the pool's statistics, and `get_info` for the block weight
/// limit the backlog estimate is measured against.
#[deny(clippy::arithmetic_side_effects)]
pub(super) fn print_transaction_pool_stats(src: &Source) -> Result<String, String> {
    let stats = fetch_pool_stats(src)?;
    let info = fetch_get_info(src)?;
    Ok(render_pool_stats(&stats, info.chain.block_weight_limit))
}

#[deny(clippy::arithmetic_side_effects)]
fn render_pool_stats(stats: &TxpoolStats, block_weight_limit: u64) -> String {
    let n = u64::from(stats.txs_total);
    let avg_bytes = stats.bytes_total.checked_div(n).unwrap_or(0);

    // The full reward zone is half the weight limit; the backlog is how many
    // such blocks the pool's bytes would fill.
    let full_reward_zone = block_weight_limit / 2;
    let backlog_message = if stats.bytes_total <= full_reward_zone {
        "no backlog".to_owned()
    } else if full_reward_zone == 0 {
        // A weight limit under two leaves no zone to measure against.
        "backlog unknown (the block weight limit is zero)".to_owned()
    } else {
        let backlog = stats.bytes_total.div_ceil(full_reward_zone);
        format!(
            "estimated {backlog} block ({} minutes) backlog",
            backlog.saturating_mul(crate::consensus::DAA_TARGET_SECONDS) / 60
        )
    };

    let lines = [
        format!(
            "{n} tx(es), {} bytes total (min {}, max {}, avg {avg_bytes}, median {})",
            stats.bytes_total, stats.bytes_min, stats.bytes_max, stats.bytes_med
        ),
        format!(
            "fees {} (avg {} per tx, {} per byte)",
            money(stats.fee_total),
            money(stats.fee_total.checked_div(n).unwrap_or(0)),
            money(stats.fee_total.checked_div(stats.bytes_total).unwrap_or(0)),
        ),
        format!("{} not relayed, {backlog_message}", stats.num_not_relayed),
        // The C++ ended with an empty line.
        String::new(),
    ];
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats() -> TxpoolStats {
        TxpoolStats {
            bytes_total: 9_000,
            bytes_min: 2_000,
            bytes_max: 4_000,
            bytes_med: 3_000,
            fee_total: 3_000_000_000,
            txs_total: 3,
            num_not_relayed: 1,
        }
    }

    /// The summary lines: averages by integer division, money with nine
    /// fractional digits, and a trailing empty line. The pool does not
    /// record age (S7), so the third line is the unrelayed count and the
    /// backlog.
    #[test]
    fn pool_stats_renders_the_summary() {
        let out = render_pool_stats(&stats(), 600_000);
        assert_eq!(
            out,
            "3 tx(es), 9000 bytes total (min 2000, max 4000, avg 3000, median 3000)\n\
             fees 3.000000000 (avg 1.000000000 per tx, 0.000333333 per byte)\n\
             1 not relayed, no backlog\n"
        );
    }

    /// An empty pool divides by nothing: every average is zero.
    #[test]
    fn an_empty_pool_renders_zero_averages() {
        let empty = TxpoolStats::default();
        let out = render_pool_stats(&empty, 600_000);
        assert!(
            out.starts_with("0 tx(es), 0 bytes total (min 0, max 0, avg 0, median 0)\n"),
            "{out}"
        );
        assert!(
            out.contains("(avg 0.000000000 per tx, 0.000000000 per byte)"),
            "{out}"
        );
        assert!(out.contains("0 not relayed, no backlog"), "{out}");
    }

    /// The backlog is the pool's bytes over half the weight limit, rounded
    /// up, and its minutes use the build's block target.
    #[test]
    fn a_pool_over_the_full_reward_zone_estimates_a_backlog() {
        let mut s = stats();
        s.bytes_total = 700_001;
        let out = render_pool_stats(&s, 600_000);
        // Zone 300_000; 700_001 bytes is 3 blocks; 3 * 120 / 60 minutes.
        assert!(
            out.contains("estimated 3 block (6 minutes) backlog"),
            "{out}"
        );
        // Exactly the zone is still no backlog.
        s.bytes_total = 300_000;
        assert!(render_pool_stats(&s, 600_000).contains("no backlog"));
    }

    /// A reply missing a member this command prints is refused, not
    /// rendered with a zero.
    #[test]
    fn a_pool_stats_reply_missing_a_member_is_refused() {
        let whole = serde_json::json!({
            "status": "OK",
            "pool_stats": {
                "bytes_total": 1, "bytes_min": 1, "bytes_max": 1, "bytes_med": 1,
                "fee_total": 1, "txs_total": 1, "num_not_relayed": 0
            }
        });
        assert!(serde_json::from_value::<GetTransactionPoolStatsResponse>(whole.clone()).is_ok());
        for member in ["bytes_total", "txs_total", "fee_total", "num_not_relayed"] {
            let mut doc = whole.clone();
            doc["pool_stats"].as_object_mut().unwrap().remove(member);
            let refusal = serde_json::from_value::<GetTransactionPoolStatsResponse>(doc)
                .expect_err("a missing member must not decode")
                .to_string();
            assert!(refusal.contains(member), "{refusal}");
        }
    }
}
