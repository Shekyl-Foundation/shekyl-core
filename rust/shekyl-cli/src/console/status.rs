// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `show_status`.

use super::info::{chain_count, fetch_status, network_label};
use crate::daemon::{DaemonClient, DaemonError};
use shekyl_rpc_client::wire;
use shekyl_rpc_types::kinds::{NoParams, Text};
use shekyl_rpc_types::wire::daemon::{DaemonStatus, GrantName};
use shekyl_rpc_types::wire::node::{MineSpeed, OptionRow, OptionShow};
use shekyl_tor_status::{names_data_dir, render};

/// Where [`mining_speed`] leaves raw hashes and starts a metric prefix.
const PREFIX_FROM_HASHES: u128 = 1_000;

/// The two fields the status line prints from `mine_status`.
struct MiningLine {
    active: bool,
    speed: MineSpeed,
}

/// What `show_status` could learn about mining.
enum MiningReadout {
    /// The daemon answered.
    Ready(MiningLine),
    /// The node posts no job because it is not synced (`mine.syncing`):
    /// neither idle nor mining.
    Syncing,
    /// The daemon would not say. A caller without the `mining-control`
    /// grant is refused. See [`fetch_mining_status`].
    Unavailable,
}

/// Fetch `mine_status`.
///
/// The handshake inside [`DaemonClient::call`] is a refusal of the whole
/// command: a daemon on another network is not a daemon whose height this
/// line may print. A caller without the `mining-control` grant is refused,
/// and a daemon that is not answering is the same. Either is an ordinary
/// posture: the status line says mining info is unavailable and still
/// prints everything else it knows.
fn fetch_mining_status(daemon: &DaemonClient) -> Result<MiningReadout, String> {
    let status = match daemon.call::<wire::MineStatus>(&NoParams) {
        Ok(status) => status,
        Err(DaemonError::Identity(line)) => return Err(line),
        Err(_) => return Ok(MiningReadout::Unavailable),
    };
    // A node that is not synced posts no job and says why: neither idle
    // nor mining.
    if !status.active
        && status
            .cause
            .0
            .as_ref()
            .is_some_and(|cause| cause.code == SYNCING)
    {
        return Ok(MiningReadout::Syncing);
    }
    Ok(MiningReadout::Ready(MiningLine {
        active: status.active,
        speed: status.speed,
    }))
}

/// The cause a node that is not synced gives for posting no job.
const SYNCING: &str = "mine.syncing";

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
    let whole = u128::from(speed.count.0.checked_div(speed.window.0).unwrap_or(0));
    if whole >= PREFIX_FROM_HASHES {
        mining_speed(whole)
    } else {
        crate::commands::mine::hashes_per_second_text(speed)
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
    let info = fetch_status(daemon)?;
    let mining = fetch_mining_status(daemon)?;
    let target = shekyl_economics::economic_params().daa_target_seconds;

    // Block counts, as this line has always printed them: the tips plus
    // one.
    let height = chain_count(&info);
    // The core's target is shown, not judged. With none, or one this node
    // is already past, the line is measured against the node's own height.
    let net_height = info
        .target_height
        .0
        .map_or(height, |target| target.0.saturating_add(1).max(height));
    // `daemon_status` does not name the network (RK-Q6). Remote, this is
    // what the handshake before the request above already read; no second
    // call. The handshake already required the daemon to report this
    // network.
    let network = network_label(daemon.network());
    // Status is a part a daemon may withhold. A withheld part is not a node
    // with no connections and no uptime: the line says the counts were not
    // disclosed and leaves the uptime off. Offline is the state, not zero
    // connections (Rick, 2026-10-14), and it is Health, which every caller
    // is told: a daemon that withholds Status still says it is offline.
    let started = info.started.shown();
    let connections = if info.offline {
        "P2P: offline".to_owned()
    } else {
        match (
            info.peer_outbound_count.shown(),
            info.peer_inbound_count.shown(),
        ) {
            (Some(outgoing), Some(incoming)) => match (outgoing.0, incoming.0) {
                (Some(outgoing), Some(incoming)) => {
                    format!("{}(out)+{}(in) connections", outgoing.0, incoming.0)
                }
                // Counts are `null` only while P2P is off.
                _ => "P2P: offline".to_owned(),
            },
            _ => "connections not disclosed".to_owned(),
        }
    };
    let mining_text = match &mining {
        MiningReadout::Unavailable => "mining info unavailable".to_owned(),
        MiningReadout::Syncing => "syncing".to_owned(),
        MiningReadout::Ready(m) if m.active => {
            format!("mining at {}", mine_speed_text(m.speed))
        }
        MiningReadout::Ready(_) => "not mining".to_owned(),
    };
    // Network hash rate as difficulty per target second, from the chain's
    // part; a daemon that does not show it is "not disclosed", never a
    // zero. `checked_div` for the same reason as everywhere else in this
    // file: `T` is genesis-frozen and generated; a zero would be a build
    // defect, not a daemon value.
    let net_hash = info.difficulty.shown().map_or_else(
        || "not disclosed".to_owned(),
        |difficulty| {
            difficulty
                .get()
                .checked_div(u128::from(target))
                .map_or_else(|| "unknown".to_owned(), mining_speed)
        },
    );
    let mut line = format!(
        "Block count: {}/{net_height} ({:.1}%) on {network}, {mining_text}, net hash {net_hash}, \
         {connections}",
        height,
        sync_percentage(height, net_height),
    );
    // No Status, no start time, so no uptime clause: an uptime of zero
    // would be a claim. The C++ omitted the clause on the same grounds.
    if let Some(start_time) = started.map(|started| started.0) {
        let uptime = now.saturating_sub(start_time);
        line.push_str(&format!(
            ", uptime {}d {}h {}m {}s",
            uptime / 86_400,
            (uptime / 3_600) % 24,
            (uptime / 60) % 60,
            uptime % 60
        ));
    }
    // The Tor status, in the one renderer's words; a caller not shown
    // Status is told nothing of it, as of the counts above.
    if let Some(tor) = tor_sentence(daemon, &info)? {
        line.push('\n');
        line.push_str(&tor);
    }
    Ok(line)
}

/// The Tor status as `shekyl-tor-status` renders it, or `None` for a
/// caller not shown Status. The data directory is named only for a
/// connection that holds `config` (IG-Q97), and only when the sentence
/// speaks of it, so an ordinary status costs no second call.
fn tor_sentence(daemon: &DaemonClient, info: &DaemonStatus) -> Result<Option<String>, String> {
    let Some(tor) = info.tor_status() else {
        return Ok(None);
    };
    let data_dir = if names_data_dir(&tor) && info.grant.contains(&GrantName::Config) {
        data_dir(daemon)?
    } else {
        None
    };
    Ok(Some(render(&tor, data_dir.as_deref())))
}

/// The daemon's `data-dir`, with its control characters taken out: it is a
/// string the daemon supplies, and this prints it to a terminal (Rick,
/// 2026-11-12). `None` when the daemon shows no value for it.
fn data_dir(daemon: &DaemonClient) -> Result<Option<String>, String> {
    let rows = super::call::<wire::OptionShow>(
        daemon,
        &OptionShow {
            name: Some(vec![Text("data-dir".to_owned())]),
        },
    )?;
    Ok(rows.into_iter().find_map(|row| match row {
        OptionRow::Value(value) if value.name.0 == "data-dir" => {
            value.value.0.map(|path| printable(&path.0))
        }
        _ => None,
    }))
}

/// `text` with every control character removed, so a daemon-supplied
/// string cannot move the cursor, clear the screen or forge a line.
pub(super) fn printable(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}
