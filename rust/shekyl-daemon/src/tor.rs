// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The managed Tor, driven from the Rust `main()` (`DAEMON_CONFIG_CUTOVER.md`
//! §2.2 steps 6, 8 and 9; Rick, 2026-10-15): today's Rust owner,
//! `DaemonTorControl`, started, published and shut down here. The
//! supervisor of `TOR_SUPERVISOR.md` replaces this one call site in its
//! increment 5; until then the degrade is today's: a Tor that is not
//! found, not usable or does not bootstrap is a warning and a clearnet-only
//! boot, never a start refusal.
//!
//! Start is spawned on the owner's runtime at step 6, so bootstrap overlaps
//! the core's construction, and awaited at step 8; the onion is published
//! after the zone host's forward listener exists; teardown runs at step 9
//! after the remnant's `stop` was requested and before its thread is
//! joined, which is the parallel teardown.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use shekyl_daemon_config::sections::Tor;
use shekyl_tor_control_daemon::{
    DaemonTorConfig, DaemonTorControl, DaemonTorStartError, OnionPow, TorBinaryError, TorDeath,
};
use tokio::task::JoinHandle;

/// The bootstrap deadline, as the C++ path set it.
const BOOTSTRAP_DEADLINE: Duration = Duration::from_secs(300);
/// The control reply deadline.
const REPLY_DEADLINE: Duration = Duration::from_secs(30);
/// The onion's stream cap, as the C++ path set it.
const MAX_STREAMS: u16 = 8;

/// Why the managed Tor is not running this boot.
#[derive(Debug)]
pub enum NotRunning {
    /// No Tor binary was found.
    NotFound,
    /// This platform manages no Tor.
    Unavailable(&'static str),
    /// A Tor was found and is unusable.
    BadBinary(String),
    /// The start failed: spawn, bootstrap or discovery.
    Start(DaemonTorStartError),
}

impl std::fmt::Display for NotRunning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str(
                "no Tor was found, so this node is clearnet-only for this boot although Tor was not declined. \
                 Install the pinned Tor bundle in the tor/ directory beside the daemon or under \
                 /opt/shekyl/<bundle>-<target>/ (release packages carry it), name it with tor-file, \
                 or set tor = off to run clearnet-only on purpose",
            ),
            Self::Unavailable(reason) => write!(
                f,
                "Shekyl manages no Tor process on this platform ({reason}); this node is clearnet-only \
                 unless you attach a Tor of your own with tor = operator"
            ),
            Self::BadBinary(reason) => write!(
                f,
                "a Tor installation was found but is unusable: {reason}. This node is clearnet-only for this boot"
            ),
            Self::Start(e) => write!(
                f,
                "the managed Tor did not start ({e}); this node is clearnet-only for this boot"
            ),
        }
    }
}

/// Starts the managed Tor on the runtime behind `handle`, when the posture
/// is `Managed`: discovery, spawn and bootstrap run on that runtime while
/// the caller constructs the remnant. `None` for any other posture.
#[must_use]
pub fn begin(
    tor: &Tor,
    data_dir: &std::path::Path,
    handle: &tokio::runtime::Handle,
) -> Option<JoinHandle<Result<DaemonTorControl, NotRunning>>> {
    let Tor::Managed { binary } = tor else {
        return None;
    };
    let binary = binary.clone();
    let data_dir_parent: PathBuf = data_dir.to_path_buf();
    Some(handle.spawn(async move {
        let verified = match &binary {
            Some(path) => shekyl_tor_control_client::binary::discover_and_verify_at(path),
            None => shekyl_tor_control_client::binary::discover_and_verify(),
        };
        let tor_binary = match verified {
            Ok(b) => b,
            Err(TorBinaryError::NotFound) => return Err(NotRunning::NotFound),
            Err(TorBinaryError::Unavailable { reason }) => {
                return Err(NotRunning::Unavailable(reason))
            }
            Err(e) => return Err(NotRunning::BadBinary(e.to_string())),
        };
        DaemonTorControl::start(DaemonTorConfig {
            tor_binary,
            data_dir_parent,
            bootstrap_deadline: BOOTSTRAP_DEADLINE,
            reply_deadline: REPLY_DEADLINE,
        })
        .await
        .map_err(NotRunning::Start)
    }))
}

/// Publishes this node's onion on the managed Tor: `virtual_port` is the
/// network's p2p port, `forward` the zone host's loopback listener. On
/// success the onion is this node's own Tor address. A failure is today's
/// degrade: the Tor zone stays dial-only this boot.
pub async fn publish(
    control: &DaemonTorControl,
    virtual_port: u16,
    forward: SocketAddr,
) -> Option<String> {
    match control
        .publish(virtual_port, forward, MAX_STREAMS, OnionPow::Enabled)
        .await
    {
        Ok(service_id) => {
            shekyl_ffi::dialer_ffi::note_own_onion(service_id.as_str(), virtual_port);
            tracing::info!(
                target: "global",
                "Tor is up: the managed Tor is running and overlay inbound is published at {}.onion:{virtual_port} -> {forward} (a new address every boot; SOCKS {})",
                service_id.as_str(),
                control.socks_addr()
            );
            Some(service_id.as_str().to_owned())
        }
        Err(e) => {
            tracing::warn!(
                target: "global",
                "the onion publish failed ({e}); the Tor zone stays dial-only this boot (PWD-E7 ruled degrade)"
            );
            None
        }
    }
}

/// Watches the managed Tor's death. The zone host takes the Tor link down
/// at once, so the dialer draws no onion it cannot reach (`TSR-F1`). An
/// exit is also logged, once: the posture is gone for this boot (ruled: no
/// respawn until the supervisor), originated transactions stay fail-closed
/// on the Tor zone, and a restart mints a fresh address. The stop
/// [`DaemonTorControl::shutdown`] makes is not a death worth reporting.
pub fn watch_death(
    control: &DaemonTorControl,
    published: Option<String>,
    handle: &tokio::runtime::Handle,
) {
    if !shekyl_ffi::zone_ffi::watch_managed_tor(control.death()) {
        tracing::warn!(
            target: "global",
            "the managed Tor's death is not watched: the zone host has no Tor route"
        );
    }
    let death = control.death();
    handle.spawn(async move {
        if death.await == TorDeath::Stopped {
            return;
        }
        tracing::error!(
            target: "global",
            "the managed Tor died; the overlay posture is gone for this boot. {}. Originated transactions stay \
             fail-closed on the Tor zone (never diverted to clearnet), so sending from this node is broken \
             until the daemon restarts",
            match published {
                Some(id) => format!("{id}.onion is now unreachable"),
                None => "No onion was published, so only Tor-zone outbound is lost".to_owned(),
            }
        );
    });
}
