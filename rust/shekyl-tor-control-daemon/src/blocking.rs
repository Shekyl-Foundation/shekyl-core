// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Blocking facade over [`crate::ephemeral::DaemonTorControl`] — the shape the
//! C++ daemon consumes through `shekyl-ffi` (PWD-E7 piece 3).
//!
//! The C++ `node_server` configures its network zones **once, at init, on a
//! plain thread**: `--anonymous-inbound` / `--tx-proxy` are parsed and the
//! zone's bind address, advertised address and SOCKS proxy are all set before
//! any listener starts. There is no async context on that path and no later
//! point where a zone's addresses can change, so the ephemeral posture has to
//! deliver its addresses **synchronously at the same init point** — hence a
//! facade that owns its runtime rather than an async API the FFI cannot call.
//!
//! The runtime is a one-worker multi-thread runtime, NOT `current_thread`:
//! the control actor's spawned tasks (child exit watcher, bootstrap poller,
//! reply framer) must keep running between FFI calls — a `current_thread`
//! runtime only advances inside `block_on`, which would freeze the child
//! reaper the moment `start` returned. One worker thread is the whole load;
//! the daemon talks to this tor a handful of times per boot.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use shekyl_tor_control_client::binary::{self, TorBinaryError};
use shekyl_tor_control_client::control::{ServiceId, TorExit};

use crate::ephemeral::{DaemonTorConfig, DaemonTorControl, DaemonTorStartError};

/// Run the discovery-and-pin gate without spawning anything: is there a tor
/// this posture could use? The **default-on** consumer calls this before
/// [`BlockingDaemonTor::start`] to pick its log posture — a machine with no
/// tor installed skips calmly ([`TorBinaryError::NotFound`]), while a tor
/// that is present but unusable (pin mismatch — usually a distro build that
/// can never hash-match the pinned Expert Bundle — an unpinned target, an
/// unreadable file) warrants a loud warning naming what was found. `start`
/// re-runs the gate itself; this probe is advisory, not a capability token.
pub fn probe_binary(tor_binary_override: Option<&Path>) -> Result<PathBuf, TorBinaryError> {
    match tor_binary_override {
        Some(path) => binary::discover_and_verify_at(path),
        None => binary::discover_and_verify(),
    }
    .map(|verified| verified.as_path().to_path_buf())
}

/// Spawn-time configuration for [`BlockingDaemonTor::start`] — the same knobs
/// as [`DaemonTorConfig`] with the binary still a *path question* (the facade
/// runs the SP-T0c pin gate itself, so the C++ side never holds an unverified
/// path beyond argument passing).
pub struct BlockingDaemonTorConfig {
    /// Explicit `tor` binary path, or `None` to run the standard discovery
    /// order (`SHEKYL_TOR_BINARY` env → beside the executable →
    /// `/opt/shekyl/<version>-<target>/` staging → `PATH`).
    /// Either way the SP-T0c hash pin verifies before anything spawns.
    pub tor_binary_override: Option<PathBuf>,
    /// This instance's `DataDirectory` — daemon-owned, per-boot, never the
    /// wallet's (PWD-E9). Created if absent.
    pub data_dir: PathBuf,
    /// The port peers dial on the onion (the overlay's advertised port).
    pub virtual_port: u16,
    /// The loopback port the daemon's anon-zone listener binds; the onion
    /// forwards to `127.0.0.1:local_port`.
    pub local_port: u16,
    /// `MaxStreams=<n>` for the published service.
    pub max_streams: u16,
    /// How long tor gets to reach bootstrap 100% before start fails.
    pub bootstrap_deadline: Duration,
    /// Bound on each post-bootstrap control round-trip.
    pub reply_deadline: Duration,
}

/// Why [`BlockingDaemonTor::start`] failed. The posture on any of these is
/// ruled by PWD-E7's seam table: **no address ⇒ no overlay inbound; the node
/// is outbound-only on that zone** — the caller logs loudly and continues,
/// it does not abort the daemon.
#[derive(Debug)]
pub enum BlockingStartError {
    /// No pinned tor binary — not found, or found and failing the SP-T0c
    /// hash pin. The pin failure is deliberately not distinguished here
    /// beyond the inner error: both mean "no verified binary to spawn".
    Binary(TorBinaryError),
    /// The tokio runtime could not be built (resource exhaustion; loud and
    /// effectively unreachable in practice).
    Runtime(std::io::Error),
    /// The start sequence itself failed (spawn, bootstrap, discovery,
    /// publish). The incarnation was torn down before this returned.
    Start(DaemonTorStartError),
}

impl std::fmt::Display for BlockingStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Binary(e) => write!(f, "tor binary: {e}"),
            Self::Runtime(e) => write!(f, "tokio runtime: {e}"),
            Self::Start(e) => write!(f, "ephemeral onion start: {e}"),
        }
    }
}

impl std::error::Error for BlockingStartError {}

/// A live ephemeral posture plus the runtime that keeps it breathing. Owned
/// behind the FFI as a process singleton (the daemon has one P2P overlay);
/// the singleton discipline lives in `shekyl-ffi`, not here — this type is
/// an ordinary value with an ordinary lifecycle, and the crate's tests hold
/// several at once.
///
/// A handle dropped **without** [`Self::shutdown`] still tears the
/// incarnation down: dropping the runtime aborts the actor's tasks, and the
/// child reap is backstopped by `kill_on_drop`/`TAKEOWNERSHIP`. That is the
/// unclean path — no `DEL_ONION`, no bounded reap, no exit telemetry — but it
/// means no exit route leaks a running tor.
pub struct BlockingDaemonTor {
    /// Keeps the actor's spawned tasks (exit watcher, framer) polled between
    /// FFI calls. Declared first so a plain drop aborts the tasks before the
    /// handle goes; `shutdown` destructures and orders the teardown itself.
    runtime: tokio::runtime::Runtime,
    control: DaemonTorControl,
}

impl BlockingDaemonTor {
    /// Verify the binary, build the runtime, and run the full
    /// [`DaemonTorControl::start`] sequence, blocking until the onion is
    /// published (or the failure is terminal). Expect this to take tens of
    /// seconds on a cold tor bootstrap.
    pub fn start(config: BlockingDaemonTorConfig) -> Result<Self, BlockingStartError> {
        let tor_binary = match &config.tor_binary_override {
            Some(path) => binary::discover_and_verify_at(path),
            None => binary::discover_and_verify(),
        }
        .map_err(BlockingStartError::Binary)?;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("shekyl-daemon-tor")
            .enable_all()
            .build()
            .map_err(BlockingStartError::Runtime)?;

        let daemon_config = DaemonTorConfig {
            tor_binary,
            data_dir: config.data_dir,
            virtual_port: config.virtual_port,
            local_target: SocketAddr::from(([127, 0, 0, 1], config.local_port)),
            max_streams: config.max_streams,
            bootstrap_deadline: config.bootstrap_deadline,
            reply_deadline: config.reply_deadline,
        };
        let control = runtime
            .block_on(DaemonTorControl::start(daemon_config))
            .map_err(BlockingStartError::Start)?;
        Ok(Self { runtime, control })
    }

    /// The published v3 service id (56 base32 chars, no `.onion` suffix).
    #[must_use]
    pub fn service_id(&self) -> &ServiceId {
        self.control.service_id()
    }

    /// The managed tor's SOCKS listener — the zone's outbound proxy address.
    #[must_use]
    pub fn socks_addr(&self) -> SocketAddr {
        self.control.socks_addr()
    }

    /// Is the incarnation still up? `false` means the overlay posture is
    /// gone for this boot (no respawn — the crate doc's ruling).
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.control.is_alive()
    }

    /// Bounded teardown (`DEL_ONION`, SIGTERM→wait→SIGKILL, reap), then the
    /// exit telemetry. Consumes the value; the runtime shuts down after the
    /// teardown completes (destructured so the drop order is explicit).
    pub fn shutdown(self) -> Option<TorExit> {
        let Self { runtime, control } = self;
        runtime.block_on(control.shutdown())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::tor_binary;

    /// The blocking facade end-to-end on a plain (non-tokio) thread — the
    /// exact shape of the FFI consumer. Start, read the three addresses,
    /// shut down, observe a real reap.
    #[test]
    #[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY (bootstraps, network)"]
    fn blocking_facade_full_lifecycle_from_plain_thread() {
        // Unlike the ephemeral.rs lifecycle test, `unchecked_for_test` has no
        // seam here: the facade runs the REAL SP-T0c gate on the given path.
        // So this test requires the pinned Expert Bundle binary (which the
        // integration lane supplies anyway) and hard-fails on an unpinned
        // one — consistent with test_support's loud-misconfiguration stance.
        let path = tor_binary();
        let config = |dir: &std::path::Path| BlockingDaemonTorConfig {
            tor_binary_override: Some(path.clone()),
            data_dir: dir.to_path_buf(),
            virtual_port: 11021,
            local_port: 41021,
            max_streams: 64,
            bootstrap_deadline: Duration::from_secs(300),
            reply_deadline: Duration::from_secs(30),
        };

        let dir = tempfile::tempdir().unwrap();
        let started = match BlockingDaemonTor::start(config(dir.path())) {
            Ok(started) => started,
            Err(BlockingStartError::Binary(e)) => {
                panic!(
                    "SHEKYL_TEST_TOR_BINARY must be the PINNED bundle binary for \
                     the blocking-facade test (SP-T0c gate runs for real here): {e}"
                );
            }
            Err(other) => panic!("start failed: {other}"),
        };
        assert!(started.is_alive());
        assert_eq!(started.service_id().as_str().len(), 56);
        assert!(started.socks_addr().ip().is_loopback());
        let exit = started.shutdown();
        assert!(exit.is_some(), "graceful shutdown must observe a real reap");
    }
}
