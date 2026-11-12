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

use shekyl_rpc_client::wire;
use shekyl_rpc_types::kinds::NoParams;
use shekyl_rpc_types::wire::tx::TxpoolStats;
use shekyl_rpc_types::{core_rpc_version_string, daemon_rpc_version, CORE_RPC_VERSION};
use shekyl_units::AtomicUnits;

use super::info::{chain_count, fetch_status};
use crate::daemon::DaemonClient;

/// `diff`: the tip, the two difficulties, and the network hash rate.
///
/// The hash rate is the next difficulty over the build's own target, as
/// every other command here computes it; the C++ divided by the reply's
/// `target` member, which is the same constant.
#[deny(clippy::arithmetic_side_effects)]
pub(super) fn show_difficulty(daemon: &DaemonClient) -> Result<String, String> {
    let status = fetch_status(daemon)?;
    let target = u128::from(shekyl_economics::economic_params().daa_target_seconds);
    let hash_rate = status
        .difficulty
        .get()
        .checked_div(target)
        .ok_or_else(|| "the difficulty target is zero".to_owned())?;
    Ok(format!(
        "BH: {}, TH: {}, DIFF: {}, CUM_DIFF: {}, HR: {hash_rate} H/s",
        chain_count(&status),
        hex::encode(status.hash.to_bytes()),
        status.difficulty.get(),
        status.difficulty_cumulative.get(),
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
pub(super) fn version(daemon: &DaemonClient) -> Result<String, String> {
    let result = daemon
        .get_version_result()
        .map_err(|error| error.to_string())?;
    let theirs = daemon_rpc_version(&result)
        .map_err(|unreadable| format!("the daemon's RPC version cannot be read: {unreadable}"))?;
    if theirs != CORE_RPC_VERSION {
        return Err(rpc_version_difference(CORE_RPC_VERSION, theirs));
    }
    // `/get_info` without the handshake: this word exists to name a daemon
    // the handshake would refuse.
    let status = daemon
        .call_unchecked::<wire::DaemonStatus>(&NoParams)
        .map_err(|error| error.to_string())?;
    match status.revision.shown() {
        None => Err(VERSION_UNAVAILABLE.to_owned()),
        // A shown Status with an empty revision is contract drift, not an
        // undisclosed version (RK-D23).
        Some(revision) if revision.0.is_empty() => {
            Err("malformed daemon_status reply: a shown Status with an empty `revision`".to_owned())
        }
        Some(revision) => Ok(revision.0),
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

fn money(atomic: u64) -> String {
    AtomicUnits::from_raw(atomic).to_skl_string()
}

/// `print_pool_stats`.
///
/// Two reads: the pool's statistics, and `get_info` for the block weight
/// limit the backlog estimate is measured against.
#[deny(clippy::arithmetic_side_effects)]
pub(super) fn print_transaction_pool_stats(daemon: &DaemonClient) -> Result<String, String> {
    let stats = super::call::<wire::TxpoolStats>(daemon, &NoParams)?;
    let status = fetch_status(daemon)?;
    Ok(render_pool_stats(&stats, status.block_weight_max.0))
}

/// The pool's summary. Sizes are weights, as the wire carries them; the
/// count of entries not yet public is the host's alone (RT-O9.3), so a
/// caller that is not the host is told it was not disclosed.
#[deny(clippy::arithmetic_side_effects)]
fn render_pool_stats(stats: &TxpoolStats, block_weight_limit: u64) -> String {
    let n = stats.count.0;
    let total = stats.weight_total.0;
    let fee_total = stats.fee_total.to_atomic_units().to_raw();
    let avg_weight = total.checked_div(n).unwrap_or(0);

    let full_reward_zone = block_weight_limit / 2;
    let backlog_message = if total <= full_reward_zone {
        "no backlog".to_owned()
    } else if full_reward_zone == 0 {
        "backlog unknown (the block weight limit is zero)".to_owned()
    } else {
        let backlog = total.div_ceil(full_reward_zone);
        format!(
            "estimated {backlog} block ({} minutes) backlog",
            backlog.saturating_mul(shekyl_economics::economic_params().daa_target_seconds) / 60
        )
    };
    let not_relayed = stats
        .private_count
        .shown()
        .map_or_else(|| "not disclosed".to_owned(), |count| count.0.to_string());

    let lines = [
        format!(
            "{n} tx(es), {total} weight total (min {}, max {}, avg {avg_weight}, median {})",
            stats.weight_min.0, stats.weight_max.0, stats.weight_median.0
        ),
        format!(
            "fees {} (avg {} per tx, {} per unit of weight)",
            money(fee_total),
            money(fee_total.checked_div(n).unwrap_or(0)),
            money(fee_total.checked_div(total).unwrap_or(0)),
        ),
        format!("{not_relayed} not relayed, {backlog_message}"),
        String::new(),
    ];
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_rpc_types::kinds::{Count, Size, Withheld};

    fn stats() -> TxpoolStats {
        TxpoolStats {
            count: Count(3),
            weight_total: Size(9_000),
            weight_min: Size(2_000),
            weight_max: Size(4_000),
            weight_median: Size(3_000),
            fee_total: AtomicUnits::from_raw(3_000_000_000).into(),
            private_count: Withheld::Shown(Count(1)),
        }
    }

    #[test]
    fn pool_stats_renders_the_summary() {
        let out = render_pool_stats(&stats(), 600_000);
        assert_eq!(
            out,
            "3 tx(es), 9000 weight total (min 2000, max 4000, avg 3000, median 3000)\n\
             fees 3.000000000 (avg 1.000000000 per tx, 0.000333333 per unit of weight)\n\
             1 not relayed, no backlog\n"
        );
    }

    #[test]
    fn an_empty_pool_renders_zero_averages() {
        let empty = TxpoolStats {
            count: Count(0),
            weight_total: Size(0),
            weight_min: Size(0),
            weight_max: Size(0),
            weight_median: Size(0),
            fee_total: AtomicUnits::ZERO.into(),
            private_count: Withheld::Shown(Count(0)),
        };
        let out = render_pool_stats(&empty, 600_000);
        assert!(
            out.starts_with("0 tx(es), 0 weight total (min 0, max 0, avg 0, median 0)\n"),
            "{out}"
        );
        assert!(
            out.contains("(avg 0.000000000 per tx, 0.000000000 per unit of weight)"),
            "{out}"
        );
        assert!(out.contains("0 not relayed, no backlog"), "{out}");
    }

    #[test]
    fn a_pool_over_the_full_reward_zone_estimates_a_backlog() {
        let mut s = stats();
        s.weight_total = Size(700_001);
        let out = render_pool_stats(&s, 600_000);
        assert!(
            out.contains("estimated 3 block (6 minutes) backlog"),
            "{out}"
        );
        s.weight_total = Size(300_000);
        assert!(render_pool_stats(&s, 600_000).contains("no backlog"));
    }

    /// The count of entries not yet public is the host's alone: withheld,
    /// it is said not to be disclosed, never printed as zero. Red edit:
    /// read a withheld count as zero.
    #[test]
    fn a_withheld_not_relayed_count_is_not_disclosed_never_zero() {
        let mut s = stats();
        s.private_count = Withheld::Withheld;
        let out = render_pool_stats(&s, 600_000);
        assert!(out.contains("not disclosed not relayed"), "{out}");
    }

    #[test]
    fn a_pool_stats_reply_missing_a_member_is_refused() {
        let whole = serde_json::json!({
            "count": 1, "weight_total": 1, "weight_min": 1, "weight_max": 1,
            "weight_median": 1, "fee_total": "1",
        });
        assert!(serde_json::from_value::<TxpoolStats>(whole.clone()).is_ok());
        for member in ["count", "weight_total", "fee_total"] {
            let mut doc = whole.clone();
            doc.as_object_mut().unwrap().remove(member);
            let refusal = serde_json::from_value::<TxpoolStats>(doc)
                .expect_err("a missing member must not decode")
                .to_string();
            assert!(refusal.contains(member), "{refusal}");
        }
    }
}
