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

use shekyl_rpc_types::{core_rpc_version_string, daemon_rpc_version, RpcStatus, CORE_RPC_VERSION};
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
/// A daemon that does not disclose its version — a restricted listener
/// writes an empty string today — is reported as such, and as a failure,
/// as the C++ did.
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
    match info.node.shown() {
        Some(status) if !status.version.is_empty() => Ok(status.version.clone()),
        _ => Err(VERSION_UNAVAILABLE.to_owned()),
    }
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

/// One bucket of the pool's age histogram.
#[derive(serde::Deserialize)]
struct PoolHistoBucket {
    txs: u32,
    bytes: u64,
}

/// `/get_transaction_pool_stats`'s `pool_stats`, every member this command
/// prints.
///
/// **A bridged leg, on purpose**: the route is still served by the C++
/// dispatch table and moves with the pool routes (RK-6), which re-points
/// this. No member is defaulted except `histo`, which the C++ serializer
/// omits when it is empty — so a renamed or removed member is a decode
/// error naming it, never a confident zero.
#[derive(serde::Deserialize)]
struct PoolStats {
    bytes_total: u64,
    bytes_min: u32,
    bytes_max: u32,
    bytes_med: u32,
    fee_total: u64,
    oldest: u64,
    txs_total: u32,
    num_failing: u32,
    num_10m: u32,
    num_not_relayed: u32,
    histo_98pc: u64,
    #[serde(default)]
    histo: Vec<PoolHistoBucket>,
    num_double_spends: u32,
}

#[derive(serde::Deserialize)]
struct PoolStatsReplyProvisional {
    status: RpcStatus,
    pool_stats: PoolStats,
}

fn fetch_pool_stats(src: &Source) -> Result<PoolStats, String> {
    let raw = match src {
        Source::Live(core) => core
            .json_endpoint("/get_transaction_pool_stats", "{}")
            .ok_or_else(|| "no reply from /get_transaction_pool_stats".to_owned())?
            .into_bytes(),
        Source::Remote { .. } => src.post_remote("/get_transaction_pool_stats", b"{}".to_vec())?,
    };
    let reply: PoolStatsReplyProvisional = serde_json::from_slice(&raw)
        .map_err(|e| format!("malformed get_transaction_pool_stats reply: {e}"))?;
    if reply.status.is_ok() {
        Ok(reply.pool_stats)
    } else {
        Err(reply.status.0)
    }
}

/// `t` relative to `now`, as the C++ console phrased it.
#[deny(clippy::arithmetic_side_effects)]
fn human_time_ago(t: u64, now: u64) -> String {
    if t == now {
        return "now".to_owned();
    }
    let dt = t.abs_diff(now);
    let span = if dt < 90 {
        format!("{dt} seconds")
    } else if dt < 90 * 60 {
        format!("{} minutes", dt / 60)
    } else if dt < 36 * 3600 {
        format!("{} hours", dt / 3600)
    } else {
        format!("{} days", dt / (3600 * 24))
    };
    format!("{span} {}", if t > now { "in the future" } else { "ago" })
}

/// `HH:MM:SS`, hours unbounded.
#[deny(clippy::arithmetic_side_effects)]
fn time_hms(seconds: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

fn money(atomic: u64) -> String {
    AtomicUnits::from_raw(atomic).to_skl_string()
}

/// `print_pool_stats`.
///
/// Two reads: the pool's statistics, and `get_info` for the block weight
/// limit the backlog estimate is measured against.
#[deny(clippy::arithmetic_side_effects)]
pub(super) fn print_transaction_pool_stats(src: &Source, now: u64) -> Result<String, String> {
    let stats = fetch_pool_stats(src)?;
    let info = fetch_get_info(src)?;
    Ok(render_pool_stats(
        &stats,
        info.chain.block_weight_limit,
        now,
    ))
}

#[deny(clippy::arithmetic_side_effects)]
fn render_pool_stats(stats: &PoolStats, block_weight_limit: u64, now: u64) -> String {
    let n = u64::from(stats.txs_total);
    let avg_bytes = stats.bytes_total.checked_div(n).unwrap_or(0);

    // The full reward zone is half the weight limit; the backlog is how many
    // such blocks the pool's bytes would fill.
    let full_reward_zone = block_weight_limit / 2;
    let backlog_message = if stats.bytes_total <= full_reward_zone {
        "no backlog".to_owned()
    } else if full_reward_zone == 0 {
        // A weight limit under two leaves no zone to measure against. The
        // C++ divided by it.
        "backlog unknown (the block weight limit is zero)".to_owned()
    } else {
        let backlog = stats.bytes_total.div_ceil(full_reward_zone);
        format!(
            "estimated {backlog} block ({} minutes) backlog",
            backlog.saturating_mul(crate::consensus::DAA_TARGET_SECONDS) / 60
        )
    };

    let oldest = if stats.oldest == 0 {
        "-".to_owned()
    } else {
        human_time_ago(stats.oldest, now)
    };
    let mut lines = vec![
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
        format!(
            "{} double spends, {} not relayed, {} failing, {} older than 10 minutes (oldest \
             {oldest}), {backlog_message}",
            stats.num_double_spends, stats.num_not_relayed, stats.num_failing, stats.num_10m
        ),
    ];

    if n > 1 && !stats.histo.is_empty() {
        let buckets = stats.histo.len() as u64;
        let age = now.saturating_sub(stats.oldest);
        // Each bucket's upper age. With a 98th percentile the buckets below
        // the last divide that span evenly and the last reaches the oldest
        // transaction; without one they divide the whole age evenly.
        let upper_age = |i: u64| -> u64 {
            if stats.histo_98pc != 0 {
                let below = buckets.saturating_sub(1);
                if i < below {
                    i.saturating_mul(stats.histo_98pc)
                        .checked_div(below)
                        .unwrap_or(0)
                } else {
                    age
                }
            } else {
                i.saturating_mul(age).checked_div(buckets).unwrap_or(0)
            }
        };
        lines.push("   Age      Txes       Bytes".to_owned());
        for (i, bucket) in (0u64..).zip(&stats.histo) {
            lines.push(format!(
                "{}{:>8}{:>12}",
                time_hms(upper_age(i)),
                bucket.txs,
                bucket.bytes
            ));
        }
    }
    // The C++ ended with an empty line.
    lines.push(String::new());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats() -> PoolStats {
        PoolStats {
            bytes_total: 9_000,
            bytes_min: 2_000,
            bytes_max: 4_000,
            bytes_med: 3_000,
            fee_total: 3_000_000_000,
            oldest: 1_700_000_000,
            txs_total: 3,
            num_failing: 1,
            num_10m: 2,
            num_not_relayed: 1,
            histo_98pc: 0,
            histo: Vec::new(),
            num_double_spends: 0,
        }
    }

    /// The three summary lines, field for field, as the C++ console wrote
    /// them: averages by integer division, money with nine fractional
    /// digits, and a trailing empty line.
    #[test]
    fn pool_stats_renders_the_summary_the_cxx_console_printed() {
        let out = render_pool_stats(&stats(), 600_000, 1_700_000_600);
        assert_eq!(
            out,
            "3 tx(es), 9000 bytes total (min 2000, max 4000, avg 3000, median 3000)\n\
             fees 3.000000000 (avg 1.000000000 per tx, 0.000333333 per byte)\n\
             0 double spends, 1 not relayed, 1 failing, 2 older than 10 minutes (oldest 10 \
             minutes ago), no backlog\n"
        );
    }

    /// An empty pool divides by nothing: every average is zero and the
    /// oldest is a dash.
    #[test]
    fn an_empty_pool_renders_zero_averages_and_no_oldest() {
        let empty = PoolStats {
            bytes_total: 0,
            bytes_min: 0,
            bytes_max: 0,
            bytes_med: 0,
            fee_total: 0,
            oldest: 0,
            txs_total: 0,
            num_failing: 0,
            num_10m: 0,
            num_not_relayed: 0,
            histo_98pc: 0,
            histo: Vec::new(),
            num_double_spends: 0,
        };
        let out = render_pool_stats(&empty, 600_000, 1_700_000_600);
        assert!(
            out.starts_with("0 tx(es), 0 bytes total (min 0, max 0, avg 0, median 0)\n"),
            "{out}"
        );
        assert!(
            out.contains("(avg 0.000000000 per tx, 0.000000000 per byte)"),
            "{out}"
        );
        assert!(out.contains("(oldest -), no backlog"), "{out}");
    }

    /// The backlog is the pool's bytes over half the weight limit, rounded
    /// up, and its minutes use the build's block target.
    #[test]
    fn a_pool_over_the_full_reward_zone_estimates_a_backlog() {
        let mut s = stats();
        s.bytes_total = 700_001;
        let out = render_pool_stats(&s, 600_000, 1_700_000_600);
        // Zone 300_000; 700_001 bytes is 3 blocks; 3 * 120 / 60 minutes.
        assert!(
            out.contains("estimated 3 block (6 minutes) backlog"),
            "{out}"
        );
        // Exactly the zone is still no backlog.
        s.bytes_total = 300_000;
        assert!(render_pool_stats(&s, 600_000, 1_700_000_600).contains("no backlog"));
    }

    /// The histogram is printed only for more than one transaction, and its
    /// ages are the C++'s: with a 98th percentile the last bucket reaches
    /// the oldest transaction and the others divide the percentile; without
    /// one every bucket divides the whole age.
    #[test]
    fn the_histogram_rows_carry_the_buckets_upper_ages() {
        let mut s = stats();
        s.histo = vec![
            PoolHistoBucket {
                txs: 1,
                bytes: 2_000,
            },
            PoolHistoBucket {
                txs: 1,
                bytes: 3_000,
            },
            PoolHistoBucket {
                txs: 1,
                bytes: 4_000,
            },
        ];
        s.histo_98pc = 120;
        let out = render_pool_stats(&s, 600_000, 1_700_003_600);
        let rows: Vec<&str> = out.lines().skip(3).collect();
        assert_eq!(
            rows,
            vec![
                "   Age      Txes       Bytes",
                "00:00:00       1        2000",
                "00:01:00       1        3000",
                "01:00:00       1        4000",
            ]
        );

        s.histo_98pc = 0;
        let out = render_pool_stats(&s, 600_000, 1_700_003_600);
        let rows: Vec<&str> = out.lines().skip(4).collect();
        assert_eq!(
            rows,
            vec![
                "00:00:00       1        2000",
                "00:20:00       1        3000",
                "00:40:00       1        4000",
            ]
        );

        // One transaction: no histogram, whatever the reply carries.
        s.txs_total = 1;
        assert_eq!(
            render_pool_stats(&s, 600_000, 1_700_003_600)
                .lines()
                .count(),
            3
        );
    }

    #[test]
    fn human_time_ago_uses_the_cxx_consoles_thresholds() {
        assert_eq!(human_time_ago(100, 100), "now");
        assert_eq!(human_time_ago(11, 100), "89 seconds ago");
        assert_eq!(human_time_ago(10, 100), "1 minutes ago");
        assert_eq!(human_time_ago(0, 90 * 60 - 1), "89 minutes ago");
        assert_eq!(human_time_ago(0, 90 * 60), "1 hours ago");
        assert_eq!(human_time_ago(0, 36 * 3600 - 1), "35 hours ago");
        assert_eq!(human_time_ago(0, 36 * 3600), "1 days ago");
        assert_eq!(human_time_ago(130, 100), "30 seconds in the future");
    }

    #[test]
    fn time_hms_does_not_wrap_its_hours() {
        assert_eq!(time_hms(0), "00:00:00");
        assert_eq!(time_hms(3_661), "01:01:01");
        assert_eq!(time_hms(360_000), "100:00:00");
    }

    /// A reply missing a member this command prints is refused, not
    /// rendered with a zero; an absent histogram is the one exception,
    /// because the daemon omits an empty one.
    #[test]
    fn a_pool_stats_reply_missing_a_member_is_refused() {
        let whole = serde_json::json!({
            "status": "OK",
            "pool_stats": {
                "bytes_total": 1, "bytes_min": 1, "bytes_max": 1, "bytes_med": 1,
                "fee_total": 1, "oldest": 1, "txs_total": 1, "num_failing": 0,
                "num_10m": 0, "num_not_relayed": 0, "histo_98pc": 0,
                "num_double_spends": 0
            }
        });
        assert!(serde_json::from_value::<PoolStatsReplyProvisional>(whole.clone()).is_ok());
        for member in ["bytes_total", "txs_total", "fee_total", "num_double_spends"] {
            let mut doc = whole.clone();
            doc["pool_stats"].as_object_mut().unwrap().remove(member);
            let refusal = serde_json::from_value::<PoolStatsReplyProvisional>(doc)
                .err()
                .expect("a missing member must not decode")
                .to_string();
            assert!(refusal.contains(member), "{refusal}");
        }
    }
}
