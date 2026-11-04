// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `show_status`.

use super::info::{fetch_get_info, network_label};
use crate::daemon::{DaemonClient, DaemonError};
use shekyl_rpc_types::mining::{MineSpeed, MiningStatusResponse};

/// Where [`mining_speed`] leaves raw hashes and starts a metric prefix.
const PREFIX_FROM_HASHES: u128 = 1_000;

/// The two fields the status line prints from `MiningStatusResponse`.
struct MiningLine {
    active: bool,
    speed: MineSpeed,
}

/// What `show_status` could learn about mining.
enum MiningReadout {
    /// The daemon answered. `BUSY` is its own arm because a syncing daemon
    /// answers the question with "ask me later", which is neither idle nor
    /// mining.
    Ready(MiningLine),
    Syncing,
    /// The daemon would not say. A view listener answers `/mining_status`
    /// with a grant refusal, and a daemon that does not serve the route
    /// answers an empty body. See [`fetch_mining_status`].
    Unavailable,
}

/// Fetch `/mining_status`.
///
/// The handshake inside [`DaemonClient::post`] is a refusal of the whole
/// command: a daemon on another network is not a daemon whose height this
/// line may print. A view listener answers `/mining_status`
/// (`mining-control`) with a grant refusal, an absent route is an empty
/// body, and a daemon that is not answering is the same. Any of those is
/// an ordinary posture: the status line says mining info is unavailable
/// and still prints everything else it knows.
fn fetch_mining_status(daemon: &DaemonClient) -> Result<MiningReadout, String> {
    let path = crate::daemon::posted_rest("/mining_status").map_err(|error| error.to_string())?;
    let raw = match daemon.post(path, b"{}".to_vec()) {
        Err(DaemonError::Identity(line)) => return Err(line),
        Ok(raw) if raw.is_empty() => return Ok(MiningReadout::Unavailable),
        Ok(raw) => raw,
        Err(_) => return Ok(MiningReadout::Unavailable),
    };
    if shekyl_rpc_types::errors::read_refusal(&raw)
        .is_some_and(|error| error.class == shekyl_rpc_types::errors::ErrorClass::OutsideTheGrant)
    {
        return Ok(MiningReadout::Unavailable);
    }
    let reply: MiningStatusResponse =
        serde_json::from_slice(&raw).map_err(|e| format!("malformed mining_status reply: {e}"))?;
    if reply.status.kind() == shekyl_rpc_types::StatusKind::Busy {
        return Ok(MiningReadout::Syncing);
    }
    if !reply.status.is_ok() {
        return Err(reply.status.0);
    }
    Ok(MiningReadout::Ready(MiningLine {
        active: reply.active,
        speed: reply.speed,
    }))
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
    if rate < PREFIX_FROM_HASHES {
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

/// The miner's rate for the status line. Below the prefix boundary the
/// hundredths stay, so eight hashes in ten seconds reads `0.80 H/s`.
fn mine_speed_text(speed: MineSpeed) -> String {
    let whole = u128::from(speed.whole_hashes_per_second());
    if whole >= PREFIX_FROM_HASHES {
        mining_speed(whole)
    } else {
        speed.hashes_per_second_text()
    }
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
pub(super) fn show_status(daemon: &DaemonClient, now: u64) -> Result<String, String> {
    let info = fetch_get_info(daemon)?;
    let mining = fetch_mining_status(daemon)?;
    let target = shekyl_economics::economic_params().daa_target_seconds;

    let height = info.health.height;
    // The core's target is shown, not judged. With none, or one this node
    // is already past, the line is measured against the node's own height.
    let net_height = info
        .health
        .target_height
        .into_option()
        .map_or(height, |target| target.max(height));
    // `get_info` does not name the network (RK-Q6). Remote, this is what
    // the handshake before the request above already read; no second call.
    // The handshake already required the daemon to report this network.
    let network = network_label(daemon.network());
    // Status is a part a daemon may withhold, and a restricted one does.
    // A withheld part is not a node with no connections and no uptime: the
    // line says the counts were not disclosed and leaves the uptime off.
    // Offline is the state, not zero connections (Rick, 2026-10-14), and it
    // is Health, which every caller is told: a daemon that withholds Status
    // still says it is offline.
    let status = info.node.shown();
    // Not decodable: Health and Status are both read against the reply's
    // `offline` (`P2pDisagreesWithOffline`, `ConnectionsDisagreeWithOffline`).
    // The state wins over a count, so a running health with an offline
    // connection block is still offline.
    let connections = match (
        info.health.p2p.is_offline(),
        status.map(|status| &status.connections),
    ) {
        (true, _) | (false, Some(shekyl_rpc_types::StatusConnections::Offline)) => {
            "P2P: offline".to_owned()
        }
        (false, Some(shekyl_rpc_types::StatusConnections::Running { outgoing, incoming })) => {
            format!("{outgoing}(out)+{incoming}(in) connections")
        }
        (false, None) => "connections not disclosed".to_owned(),
    };
    let mining_text = match &mining {
        MiningReadout::Unavailable => "mining info unavailable".to_owned(),
        MiningReadout::Syncing => "syncing".to_owned(),
        MiningReadout::Ready(m) if m.active => {
            format!("mining at {}", mine_speed_text(m.speed))
        }
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
         {connections}",
        height,
        sync_percentage(height, net_height),
    );
    // No Status, no start time, so no uptime clause: an uptime of zero
    // would be a claim. The C++ omitted the clause on the same grounds.
    if let Some(start_time) = status.map(|status| status.start_time) {
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
