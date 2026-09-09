// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ephemeral per-boot onion — mint, publish, expose, die (PWD-E7 piece 2).
//!
//! Two phases, split where the consumer's degrade postures split:
//!
//! **[`DaemonTorControl::start`]** — the fallible-network half, run *before*
//! the daemon commits any zone state:
//!
//! 1. **Mint a unique DataDirectory** under the caller-named parent, wipe any
//!    leftover from a previous crashed boot, then **spawn** a managed pinned
//!    tor (`SocksPort auto`). The directory dies with the handle — tor must
//!    not persist entry guards across boots.
//! 2. **Gate on bootstrap** `Ready` within a deadline.
//! 3. **Discover SOCKS** via `GETINFO net/listeners/socks` — the zone's
//!    outbound proxy address.
//!
//! Failure anywhere here tears the spawned incarnation down (and wipes the
//! directory) before the error is returned — a failed start never leaks a
//! running tor, and the caller has committed nothing (the ruled degrade: the
//! posture is simply unavailable).
//!
//! **[`DaemonTorControl::publish`]** — run *after* the caller has bound its
//! local inbound listener (so the forward target names a port the OS actually
//! granted, rather than a guessed one):
//!
//! 4. **Mint** a 32-byte hs-id seed from the OS CSPRNG, derive the v3 identity,
//!    **publish** with `ADD_ONION … Flags=DiscardPK`, verify the returned
//!    `ServiceID` against the identity, and **drop the key material** — after
//!    this line the only holder of the service key is the tor incarnation, and
//!    both die together.
//!
//! A publish failure deliberately does **not** tear the incarnation down: the
//! tor is up and its SOCKS proxy works, so the ruled degrade is *outbound-only
//! on the zone* — the caller keeps the handle, logs loudly, and serves no
//! overlay inbound this boot. The handle exposes the SOCKS proxy, aliveness,
//! and a bounded teardown either way.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use kameo::actor::Spawn;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use shekyl_tor_control_client::binary::VerifiedTorBinary;
use shekyl_tor_control_client::control::{
    ask_timed, evaluate_add_onion_reply, parse_socks_listeners, wait_until_ready, AddOnion,
    AddOnionReplyError, AskError, BootstrapReadiness, Command, ControlError, EventSink, ManagedTor,
    OnionFlags, OnionPort, ServiceId, SocksPort, TorControlClient, TorControlClientConfig, TorExit,
    TorLaunch, WaitReadyError,
};
use shekyl_tor_control_client::onion_identity::OnionIdentity;

use crate::data_dir::EphemeralDataDir;

/// Bound on the whole teardown sequence (graceful actor stop + child reap),
/// mirroring the wallet supervisor's reap bound: `stop_gracefully` rides the
/// actor's bounded mailbox, so bounding only the reap wait could still hang a
/// caller. On timeout the actor is killed; `kill_on_drop` and `TAKEOWNERSHIP`
/// backstop the child reap.
const REAP_TIMEOUT: Duration = Duration::from_secs(15);

/// Spawn-time configuration for [`DaemonTorControl::start`].
///
/// Every instance-identifying input is a parameter (PWD-E9): the binary
/// witness and the DataDirectory *parent* arrive from the caller; this crate
/// creates a unique subdirectory and wipes it on teardown. The onion's ports
/// are *not* here — they belong to [`DaemonTorControl::publish`], which runs
/// after the caller has bound its inbound listener.
pub struct DaemonTorConfig {
    /// The `tor` binary to spawn — only a hash-pin-verified witness (SP-T0c).
    /// The caller runs `binary::discover_and_verify` (or `_at`); this crate
    /// cannot skip the gate because the type is the gate.
    pub tor_binary: VerifiedTorBinary,
    /// Parent of this boot's unique `DataDirectory`. Daemon-owned, **never**
    /// the wallet's (sharing it would share guard state and the instance
    /// itself, the PWD-E9 crossover). The crate creates a unique 0700 child
    /// and removes it on teardown, so a restart cannot reuse entry guards.
    pub data_dir_parent: PathBuf,
    /// How long tor gets to reach bootstrap 100% before start fails. The
    /// wallet supervisor's default is 300 s; the daemon consumer picks its own
    /// (a node operator watching a hung startup is a different UX than a
    /// background wallet incarnation retrying).
    pub bootstrap_deadline: Duration,
    /// Bound on each post-bootstrap control round-trip (`GETINFO`,
    /// `ADD_ONION`) — an alive tor answers these instantly, so a stall means a
    /// wedged control port, not a slow network.
    pub reply_deadline: Duration,
}

/// Why [`DaemonTorControl::start`] failed. Terminal for the boot: the caller
/// logs and continues with no tor zone (this crate does not retry — see the
/// crate doc's no-respawn rationale).
#[derive(Debug)]
pub enum DaemonTorStartError {
    /// Creating or locking down the per-boot DataDirectory failed.
    DataDir(std::io::Error),
    /// Spawning tor or driving the control connection failed.
    Control(ControlError),
    /// Tor did not reach bootstrap 100% within
    /// [`DaemonTorConfig::bootstrap_deadline`].
    BootstrapTimeout,
    /// The incarnation died before reaching `Ready` (control connection lost
    /// or the actor stopped). Carries the reaped exit when teardown observed
    /// it.
    Died(Option<TorExit>),
    /// Bootstrap reached `Ready` but `GETINFO net/listeners/socks` names no
    /// TCP listener — a tor the zone could not dial through.
    NoSocksListener,
}

impl std::fmt::Display for DaemonTorStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DataDir(e) => write!(f, "ephemeral tor data directory: {e}"),
            Self::Control(e) => write!(f, "tor control failure: {e:?}"),
            Self::BootstrapTimeout => write!(f, "tor did not bootstrap within the deadline"),
            Self::Died(exit) => write!(f, "tor died during start ({exit:?})"),
            Self::NoSocksListener => write!(f, "bootstrapped tor exposes no TCP SOCKS listener"),
        }
    }
}

impl std::error::Error for DaemonTorStartError {}

/// Why [`DaemonTorControl::publish`] failed. The incarnation stays up: the
/// ruled degrade is outbound-only on the zone.
#[derive(Debug)]
pub enum DaemonTorPublishError {
    /// The publish target is not a loopback address — refused before any
    /// control traffic (hard invariant: the onion must not forward to a
    /// routable address).
    TargetNotLoopback {
        /// The refused target.
        target: SocketAddr,
    },
    /// The OS CSPRNG refused to produce the hs-id seed. No fallback by
    /// design — a weaker source would mint a guessable service key.
    SeedRng,
    /// The control round-trip failed.
    Control(ControlError),
    /// The actor stopped before the reply arrived.
    Died,
    /// `ADD_ONION` was rejected, returned no `ServiceID`, or returned a
    /// different address than the held identity derives — the latter meaning
    /// the tor on the control port is not running our request.
    Publish(AddOnionReplyError),
}

impl std::fmt::Display for DaemonTorPublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TargetNotLoopback { target } => {
                write!(f, "onion target {target} is not a loopback address")
            }
            Self::SeedRng => write!(f, "OS CSPRNG unavailable for the hs-id seed"),
            Self::Control(e) => write!(f, "tor control failure: {e:?}"),
            Self::Died => write!(f, "tor died during publish"),
            Self::Publish(e) => write!(f, "ADD_ONION failed: {e:?}"),
        }
    }
}

impl std::error::Error for DaemonTorPublishError {}

/// A live managed-tor incarnation: bootstrapped, SOCKS address known, and —
/// after a successful [`Self::publish`] — an onion service published. Dropping
/// the handle without [`DaemonTorControl::shutdown`] still reaps the child
/// (`kill_on_drop`, `TAKEOWNERSHIP`) and wipes the DataDirectory, but the
/// bounded graceful path is the intended exit.
pub struct DaemonTorControl {
    actor: kameo::actor::ActorRef<TorControlClient>,
    exit_rx: Option<oneshot::Receiver<TorExit>>,
    socks_addr: SocketAddr,
    reply_deadline: Duration,
    /// Declared last so a plain drop wipes the directory after the actor
    /// (and therefore the child) has been dropped.
    data_dir: Option<EphemeralDataDir>,
}

impl DaemonTorControl {
    /// Run the pre-commitment start sequence (unique dir → spawn → bootstrap
    /// gate → SOCKS discovery). On any failure the spawned incarnation is torn
    /// down and the directory wiped before the error returns, so the caller
    /// has nothing to clean up.
    pub async fn start(config: DaemonTorConfig) -> Result<Self, DaemonTorStartError> {
        let DaemonTorConfig {
            tor_binary,
            data_dir_parent,
            bootstrap_deadline,
            reply_deadline,
        } = config;

        let data_dir = EphemeralDataDir::create_under(&data_dir_parent)
            .map_err(DaemonTorStartError::DataDir)?;

        // Spawn the incarnation with a wired exit observer — teardown awaits it
        // so no tor lingers holding the DataDirectory lock.
        let (exit_tx, exit_rx) = oneshot::channel();
        let (readiness, mut ready_rx) = BootstrapReadiness::new();
        let actor = TorControlClient::spawn(TorControlClientConfig {
            launch: TorLaunch::Managed(ManagedTor {
                tor_binary,
                data_dir: data_dir.path().to_path_buf(),
                socks_port: SocksPort::Auto,
                disable_network: false,
                exit_observer: Some(exit_tx),
            }),
            events: EventSink::unsubscribed(),
            readiness,
        });
        let mut handle = Self {
            actor,
            exit_rx: Some(exit_rx),
            socks_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            reply_deadline,
            data_dir: Some(data_dir),
        };

        let deadline = tokio::time::Instant::now() + bootstrap_deadline;
        match wait_until_ready(&handle.actor, &mut ready_rx, deadline).await {
            Ok(()) => {}
            Err(WaitReadyError::Timeout) => {
                handle.teardown().await;
                return Err(DaemonTorStartError::BootstrapTimeout);
            }
            Err(WaitReadyError::Died | WaitReadyError::Failed) => {
                let exit = handle.teardown().await;
                return Err(DaemonTorStartError::Died(exit));
            }
        }

        let reply = match handle
            .ask_bounded(
                Command::GetInfo(vec!["net/listeners/socks".to_owned()]),
                reply_deadline,
            )
            .await
        {
            Ok(reply) => reply,
            Err(err) => {
                handle.teardown().await;
                return Err(err);
            }
        };
        let Some(socks_addr) = parse_socks_listeners(&reply) else {
            handle.teardown().await;
            return Err(DaemonTorStartError::NoSocksListener);
        };
        handle.socks_addr = socks_addr;
        Ok(handle)
    }

    /// Mint-and-publish the per-boot onion, forwarding `virtual_port` to
    /// `local_target` (loopback only, enforced structurally by
    /// [`OnionPort::loopback`]). Runs after the caller has bound its inbound
    /// listener, so the target names a port the OS actually granted.
    ///
    /// The seed and the derived identity live exactly as long as this call;
    /// after the reply verifies, tor is the only holder of the service key.
    ///
    /// A failure does **not** tear the incarnation down: tor is up and its
    /// SOCKS proxy works, so the caller's ruled degrade is outbound-only on
    /// the zone. (If the failure was tor dying, [`Self::is_alive`] and the
    /// caller's liveness sweep observe that separately.)
    pub async fn publish(
        &self,
        virtual_port: u16,
        local_target: SocketAddr,
        max_streams: u16,
    ) -> Result<ServiceId, DaemonTorPublishError> {
        let port = OnionPort::loopback(virtual_port, local_target).ok_or(
            DaemonTorPublishError::TargetNotLoopback {
                target: local_target,
            },
        )?;

        let mut seed = Zeroizing::new([0u8; 32]);
        if getrandom::getrandom(seed.as_mut()).is_err() {
            return Err(DaemonTorPublishError::SeedRng);
        }
        let identity = OnionIdentity::from_hs_id_seed(&seed);
        let expected = identity.service_id().clone();
        let request = AddOnion::new(identity.mint_onion_key(), port, max_streams)
            .with_flags(OnionFlags { discard_pk: true });
        let reply = match ask_timed(&self.actor, Command::AddOnion(request), self.reply_deadline)
            .await
        {
            Ok(reply) => reply,
            Err(AskError::Timeout) => {
                return Err(DaemonTorPublishError::Control(ControlError::Timeout));
            }
            Err(AskError::Control(control)) => return Err(DaemonTorPublishError::Control(control)),
            Err(AskError::ActorGone) => return Err(DaemonTorPublishError::Died),
        };
        evaluate_add_onion_reply(&reply, &expected).map_err(DaemonTorPublishError::Publish)?;
        Ok(expected)
    }

    async fn ask_bounded(
        &self,
        command: Command,
        deadline: Duration,
    ) -> Result<shekyl_tor_control_client::control::ControlReply, DaemonTorStartError> {
        match ask_timed(&self.actor, command, deadline).await {
            Ok(reply) => Ok(reply),
            Err(AskError::Timeout) => Err(DaemonTorStartError::Control(ControlError::Timeout)),
            Err(AskError::Control(control)) => Err(DaemonTorStartError::Control(control)),
            Err(AskError::ActorGone) => Err(DaemonTorStartError::Died(None)),
        }
    }

    /// The managed tor's SOCKS listener — the zone's outbound proxy address.
    #[must_use]
    pub fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }

    /// Is the incarnation still up? `false` means the overlay posture is gone
    /// for this boot (no respawn — see the crate doc); the caller logs loudly.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.actor.is_alive()
    }

    /// Await the incarnation's death — the notification edge of
    /// [`Self::is_alive`], for a consumer that watches rather than polls.
    pub async fn wait_death(&self) {
        self.actor.wait_for_shutdown().await;
    }

    /// Bounded teardown: graceful actor stop (which `DEL_ONION`s the published
    /// service and SIGTERM→wait→SIGKILL→reaps the child), then the exit
    /// telemetry, then the DataDirectory wipe. On a wedged actor, kill and
    /// proceed — the child reap is backstopped by `kill_on_drop` /
    /// `TAKEOWNERSHIP`.
    pub async fn shutdown(mut self) -> Option<TorExit> {
        self.teardown().await
    }

    async fn teardown(&mut self) -> Option<TorExit> {
        let exit_rx = self.exit_rx.take();
        let teardown = async {
            self.actor.stop_gracefully().await.ok();
            match exit_rx {
                Some(rx) => rx.await.ok(),
                None => None,
            }
        };
        let exit = match tokio::time::timeout(REAP_TIMEOUT, teardown).await {
            Ok(exit) => exit,
            Err(_timeout) => {
                self.actor.kill();
                None
            }
        };
        if let Some(dir) = self.data_dir.take() {
            dir.wipe();
        }
        exit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::tor_binary;
    use shekyl_tor_control_client::binary::VerifiedTorBinary;

    fn config_with(binary: VerifiedTorBinary, data_dir_parent: PathBuf) -> DaemonTorConfig {
        DaemonTorConfig {
            tor_binary: binary,
            data_dir_parent,
            bootstrap_deadline: Duration::from_secs(300),
            reply_deadline: Duration::from_secs(30),
        }
    }

    /// A missing binary fails the spawn loudly — the `Control` error class,
    /// not a hang or a silent no-overlay posture — and leaves no DataDirectory.
    #[tokio::test]
    async fn missing_binary_fails_start_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_with(
            VerifiedTorBinary::unchecked_for_test(PathBuf::from("/nonexistent/tor")),
            dir.path().to_path_buf(),
        );
        match DaemonTorControl::start(config).await {
            Err(DaemonTorStartError::Control(_) | DaemonTorStartError::Died(_)) => {}
            other => panic!("expected Control/Died, got {other:?}"),
        }
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert!(
            leftovers.is_empty(),
            "a failed start must wipe the per-boot DataDirectory, leftover: {leftovers:?}"
        );
    }

    impl std::fmt::Debug for DaemonTorControl {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DaemonTorControl")
                .field("socks_addr", &self.socks_addr)
                .finish_non_exhaustive()
        }
    }

    /// The full posture, live: spawn a real tor, bootstrap, publish, verify the
    /// address shape and the SOCKS listener, then tear down and observe a real
    /// reap. Two boots yield two different addresses — the ephemeral property
    /// itself, observed rather than asserted. Also holds the two publish-side
    /// refusals against the live handle: a routable target is refused before
    /// any control traffic (hard invariant: the onion must not forward to a
    /// routable address), and the refusal does not disturb the incarnation.
    /// After shutdown the DataDirectory is gone — no guard state survives.
    #[tokio::test]
    #[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY (bootstraps twice, network)"]
    async fn ephemeral_onion_publishes_and_rotates_across_boots() {
        let binary = VerifiedTorBinary::unchecked_for_test(tor_binary());

        let dir1 = tempfile::tempdir().unwrap();
        let boot1 = DaemonTorControl::start(config_with(binary.clone(), dir1.path().to_path_buf()))
            .await
            .expect("first boot start");
        assert!(boot1.is_alive());
        assert!(boot1.socks_addr().ip().is_loopback());

        match boot1
            .publish(18080, "192.168.1.10:18080".parse().unwrap(), 64)
            .await
        {
            Err(DaemonTorPublishError::TargetNotLoopback { target }) => {
                assert_eq!(target, "192.168.1.10:18080".parse().unwrap());
            }
            other => panic!("expected TargetNotLoopback, got {other:?}"),
        }
        assert!(boot1.is_alive(), "a refused publish must not kill tor");

        let first_id = boot1
            .publish(18080, "127.0.0.1:48080".parse().unwrap(), 64)
            .await
            .expect("first boot publish");
        assert_eq!(first_id.as_str().len(), 56);
        let exit = boot1.shutdown().await;
        assert!(exit.is_some(), "teardown must observe a real reap");
        let leftovers: Vec<_> = std::fs::read_dir(dir1.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .collect();
        assert!(
            leftovers.is_empty(),
            "shutdown must wipe the per-boot DataDirectory, leftover: {leftovers:?}"
        );

        let dir2 = tempfile::tempdir().unwrap();
        let boot2 = DaemonTorControl::start(config_with(binary, dir2.path().to_path_buf()))
            .await
            .expect("second boot start");
        let second_id = boot2
            .publish(18080, "127.0.0.1:48080".parse().unwrap(), 64)
            .await
            .expect("second boot publish");
        assert_ne!(
            second_id.as_str(),
            first_id.as_str(),
            "a new boot mints a new key and therefore a new address"
        );
        boot2.shutdown().await;
    }
}
