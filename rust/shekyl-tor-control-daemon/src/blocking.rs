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
use std::path::PathBuf;
use std::time::Duration;

use shekyl_tor_control_client::binary::{self, TorBinaryError};
use shekyl_tor_control_client::control::{ServiceId, TorExit};

use crate::ephemeral::{
    DaemonTorConfig, DaemonTorControl, DaemonTorPublishError, DaemonTorStartError,
};

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
    /// Parent of this boot's unique `DataDirectory` — daemon-owned, never the
    /// wallet's (PWD-E9). A unique 0700 child is created and wiped on teardown.
    pub data_dir_parent: PathBuf,
    /// How long tor gets to reach bootstrap 100% before start fails.
    pub bootstrap_deadline: Duration,
    /// Bound on each post-bootstrap control round-trip.
    pub reply_deadline: Duration,
}

/// Why [`BlockingDaemonTor::start`] failed. The posture on any of these is
/// ruled by PWD-E7's seam table: a start failure means **no tor and no zone
/// this boot** — the caller logs loudly and continues, it does not abort the
/// daemon. (A [`BlockingDaemonTor::publish`] failure is the softer degrade:
/// tor and its SOCKS proxy stay up, the zone stays outbound-only.)
#[derive(Debug)]
pub enum BlockingStartError {
    /// No pinned tor binary — not found, or found and failing the SP-T0c
    /// hash pin. [`TorBinaryError::NotFound`] is the calm skip (nothing to
    /// spawn); every other variant is a loud "found but unusable".
    Binary(TorBinaryError),
    /// The tokio runtime could not be built (resource exhaustion; loud and
    /// effectively unreachable in practice).
    Runtime(std::io::Error),
    /// The start sequence itself failed (spawn, bootstrap, discovery). The
    /// incarnation was torn down and the DataDirectory wiped before this
    /// returned.
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
/// means no exit route leaks a running tor, and the DataDirectory wipe still
/// runs on `DaemonTorControl` drop.
pub struct BlockingDaemonTor {
    /// Keeps the actor's spawned tasks (exit watcher, framer) polled between
    /// FFI calls. Declared first so a plain drop aborts the tasks before the
    /// handle goes; `shutdown` destructures and orders the teardown itself.
    runtime: tokio::runtime::Runtime,
    control: DaemonTorControl,
}

impl BlockingDaemonTor {
    /// Verify the binary, build the runtime, and run the
    /// [`DaemonTorControl::start`] sequence (unique dir → spawn → bootstrap →
    /// SOCKS discovery), blocking until tor is up (or the failure is terminal).
    /// Expect this to take tens of seconds on a cold tor bootstrap. The onion
    /// publishes separately via [`Self::publish`], after the caller has bound
    /// its inbound listener.
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
            data_dir_parent: config.data_dir_parent,
            bootstrap_deadline: config.bootstrap_deadline,
            reply_deadline: config.reply_deadline,
        };
        let control = runtime
            .block_on(DaemonTorControl::start(daemon_config))
            .map_err(BlockingStartError::Start)?;
        Ok(Self { runtime, control })
    }

    /// Mint-and-publish the per-boot onion: `virtual_port` (what peers dial)
    /// forwarding to `127.0.0.1:local_port` (the caller's already-bound
    /// inbound listener), with `MaxStreams=max_streams`. Returns the published
    /// v3 service id (56 base32 chars, no `.onion` suffix).
    ///
    /// A failure leaves tor and its SOCKS proxy up — the caller's ruled
    /// degrade is outbound-only on the zone, not teardown.
    pub fn publish(
        &self,
        virtual_port: u16,
        local_port: u16,
        max_streams: u16,
    ) -> Result<ServiceId, DaemonTorPublishError> {
        self.runtime.block_on(self.control.publish(
            virtual_port,
            SocketAddr::from(([127, 0, 0, 1], local_port)),
            max_streams,
        ))
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

    /// Bounded teardown (`DEL_ONION`, SIGTERM→wait→SIGKILL, reap, DataDirectory
    /// wipe), then the exit telemetry. Consumes the value; the runtime shuts
    /// down after the teardown completes (destructured so the drop order is
    /// explicit).
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
            data_dir_parent: dir.to_path_buf(),
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
        assert!(started.socks_addr().ip().is_loopback());
        let service_id = started
            .publish(11021, 41021, 64)
            .expect("publish after start");
        assert_eq!(service_id.as_str().len(), 56);
        let exit = started.shutdown();
        assert!(exit.is_some(), "graceful shutdown must observe a real reap");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert!(
            leftovers.is_empty(),
            "shutdown must wipe the per-boot DataDirectory, leftover: {leftovers:?}"
        );
    }
}
