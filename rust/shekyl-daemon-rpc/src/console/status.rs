// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `show_status`.

use super::info::{fetch_get_info, network_label};
use super::Source;
use crate::ctl_client;

/// The `/mining_status` reply, as much of it as `show_status` reads.
///
/// **A bridged leg, on purpose** (§2.1.1): `/mining_status` is RK-7's and is
/// still served from the C++ table (`core_rpc_ffi.cpp:180`). Required fields
/// for the reason [`GetLimitReplyProvisional`] gives — a defaulted `active`
/// would report a mining daemon as idle.
#[derive(serde::Deserialize)]
struct MiningStatusProvisional {
    status: shekyl_rpc_types::RpcStatus,
    active: bool,
    speed: u64,
    is_background_mining_enabled: bool,
}

/// What `show_status` could learn about mining.
enum MiningReadout {
    /// The daemon answered. `BUSY` is its own arm because a syncing daemon
    /// answers the question with "ask me later", which is neither idle nor
    /// mining.
    Ready(MiningStatusProvisional),
    Syncing,
    /// The remote daemon would not say — a restricted listener does not serve
    /// `/mining_status`. Only reachable on the remote arm; see
    /// [`fetch_mining_status`].
    Unavailable,
}

/// Fetch `/mining_status`, and treat a failure differently on each arm.
///
/// **The asymmetry is the C++'s and it is carried on purpose.** In-process
/// the console *is* the daemon, so a `/mining_status` that will not answer is
/// a fault in this daemon and the command says so. Remotely the daemon may
/// simply be running a restricted listener, which does not serve the route at
/// all — an ordinary posture, not a failure, and the status line says "mining
/// info unavailable" rather than refusing to print the seven other things it
/// knows. Unifying the arms would either turn a normal restricted daemon into
/// an error or hide a real local fault.
fn fetch_mining_status(src: &Source) -> Result<MiningReadout, String> {
    let raw = match src {
        Source::Live(core) => core
            .json_endpoint("/mining_status", "{}")
            .ok_or_else(|| "no reply from /mining_status".to_owned())?,
        Source::Remote {
            address, timeout, ..
        } => {
            src.ensure_identity()?;
            match ctl_client::post_blocking(address, "/mining_status", b"{}".to_vec(), *timeout) {
                // **An empty body is the route declining to exist.** The
                // control transport does not surface the HTTP status — its
                // contract is "a response arrived", because every route the
                // daemon *serves* answers with a JSON body carrying its own
                // `status`. `/mining_status` is `Visibility::AdminOnly`
                // (`server.rs`), so a restricted listener has no such route
                // and axum's fallback answers 404 with no body at all. That
                // is the only way a zero-length body reaches here, and it is
                // exactly the case the C++'s `has_mining_info` keyed on.
                Ok(raw) if raw.is_empty() => return Ok(MiningReadout::Unavailable),
                Ok(raw) => String::from_utf8_lossy(&raw).into_owned(),
                // The daemon is not answering at all — no host, no listener.
                Err(_) => return Ok(MiningReadout::Unavailable),
            }
        }
    };
    let reply: MiningStatusProvisional =
        serde_json::from_str(&raw).map_err(|e| format!("malformed mining_status reply: {e}"))?;
    if reply.status.0 == shekyl_rpc_types::RpcStatus::BUSY {
        return Ok(MiningReadout::Syncing);
    }
    if !reply.status.is_ok() {
        return Err(reply.status.0);
    }
    Ok(MiningReadout::Ready(reply))
}

/// A hash rate for a human: `get_metric_prefix` + `get_mining_speed`.
///
/// Below 1000 the raw number in `H/s`; otherwise the largest metric prefix
/// that leaves the value under a million, to two decimals. A rate so large
/// that eight prefixes do not reach it prints raw — the C++ fell out of its
/// loop with `prefix = 0` and formatted the *original* value, which this
/// keeps.
#[deny(clippy::arithmetic_side_effects)]
pub(super) fn mining_speed(rate: u128) -> String {
    const PREFIXES: [char; 8] = ['k', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y'];
    if rate < 1000 {
        return format!("{rate} H/s");
    }
    let mut scaled = rate;
    for prefix in PREFIXES {
        if scaled < 1_000_000 {
            #[expect(
                clippy::cast_precision_loss,
                reason = "a hash rate for a human, below a million by the test above"
            )]
            let value = scaled as f64 / 1000.0;
            return format!("{value:.2} {prefix}H/s");
        }
        scaled /= 1000;
    }
    format!("{rate} H/s")
}

/// `get_sync_percentage`, including its refusal to round up to 100.
#[deny(clippy::arithmetic_side_effects)]
pub(super) fn sync_percentage(height: u64, target_height: u64) -> f64 {
    // A target below our height means we are ahead of it; `max(1)` keeps the
    // divisor non-zero on a chain with no blocks, which cannot occur but
    // costs nothing to make impossible here rather than three lines down.
    let target = target_height.max(height).max(1);
    #[expect(
        clippy::cast_precision_loss,
        reason = "a percentage for a human, from two heights"
    )]
    let pc = 100.0 * (height as f64) / (target as f64);
    // Not yet synced must not read as 100%: the last block is the one an
    // operator is waiting for.
    if height < target && pc > 99.9 {
        99.9
    } else {
        pc
    }
}

/// `status` / `show_status`.
#[deny(clippy::arithmetic_side_effects)]
pub(super) fn show_status(src: &Source, now: u64) -> Result<String, String> {
    let info = fetch_get_info(src)?;
    let mining = fetch_mining_status(src)?;
    let target = crate::consensus::DAA_TARGET_SECONDS;

    let (height, target_height) = (info.health.height, info.health.target_height);
    let net_height = target_height.max(height);
    let network = network_label(info.identity.nettype);
    // Status is a part a daemon may withhold. Today a restricted one writes
    // stand-ins there instead — a start time of zero, zero connections — and
    // a withheld part reads the same way here.
    let (start_time, outgoing, incoming) = info.node.shown().map_or((0, 0, 0), |status| {
        (
            status.start_time,
            status.outgoing_connections_count,
            status.incoming_connections_count,
        )
    });
    let mining_text = match &mining {
        MiningReadout::Unavailable => "mining info unavailable".to_owned(),
        MiningReadout::Syncing => "syncing".to_owned(),
        MiningReadout::Ready(m) if m.active => format!(
            "{}mining at {}",
            if m.is_background_mining_enabled {
                "smart "
            } else {
                ""
            },
            mining_speed(u128::from(m.speed))
        ),
        MiningReadout::Ready(_) => "not mining".to_owned(),
    };
    // Network hash rate as difficulty per target second. `checked_div` for
    // the same reason as everywhere else in this file: `T` is genesis-frozen
    // and generated; a zero would be a build defect, not a daemon value.
    let net_hash = info
        .chain
        .difficulty
        .checked_div(u128::from(target))
        .map_or_else(|| "unknown".to_owned(), mining_speed);
    let mut line = format!(
        "Height: {}/{net_height} ({:.1}%) on {network}, {mining_text}, net hash {net_hash}, \
         {}(out)+{}(in) connections",
        height,
        sync_percentage(height, target_height),
        outgoing,
        incoming
    );
    // A restricted listener does not disclose the start time, and the C++
    // omitted the whole clause rather than reporting an uptime of zero.
    if start_time != 0 {
        let uptime = now.saturating_sub(start_time);
        line.push_str(&format!(
            ", uptime {}d {}h {}m {}s",
            uptime / 86_400,
            (uptime / 3_600) % 24,
            (uptime / 60) % 60,
            uptime % 60
        ));
    }
    Ok(line)
}
