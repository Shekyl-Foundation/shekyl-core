// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One managed Tor incarnation (PWD-E7 piece 2).
//!
//! [`DaemonTorControl::spawn_keeping`] creates a data directory under the
//! caller-named parent and returns when `GETINFO version` answers. Bootstrap
//! is not a gate. The directory is kept across a respawn in the same boot
//! and wiped when the daemon stops (`TSR-Q1`).
//!
//! The boot's onion seed is minted once, with [`DaemonTorControl::mint_seed`],
//! and passed to every [`DaemonTorControl::publish`]. A publish failure
//! leaves the incarnation up: Tor's SOCKS proxy still works, and the caller
//! serves no overlay inbound until a later publish succeeds.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use zeroize::{Zeroize, Zeroizing};

use shekyl_tor_control_client::binary::VerifiedTorBinary;
use shekyl_tor_control_client::control::{
    ask_timed, evaluate_add_onion_reply, AddOnion, AddOnionReplyError, AskError, BootstrapState,
    Command, ControlError, DiskWrites, EventSink, OnionFlags, OnionPort, OnionPow, ServiceId,
    TorControlClient, TorExit,
};
use shekyl_tor_control_client::directory_cache;
use shekyl_tor_control_client::onion_identity::OnionIdentity;

use crate::data_dir::EphemeralDataDir;

mod spawn;

pub use spawn::{KeptDataDir, LaunchFailure, SpawnError};

/// Bound on the whole teardown sequence (graceful actor stop + child reap),
/// mirroring the wallet supervisor's reap bound: `stop_gracefully` rides the
/// actor's bounded mailbox, so bounding only the reap wait could still hang a
/// caller. On timeout the actor is killed; `kill_on_drop` and the owning control
/// connection, whose close exits tor, backstop the child reap.
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
    /// Parent of this boot's data directory.
    pub data_dir_parent: PathBuf,
    /// Events the supervisor reads. One sink lives for the boot; each
    /// incarnation gets a clone.
    pub events: EventSink,
    /// Bound on a control round-trip. A miss is a process fault, not a
    /// bootstrap give-up.
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
    /// The incarnation died before reaching `Ready` (control connection lost
    /// or the actor stopped). Carries the reaped exit when teardown observed
    /// it.
    Died(Option<TorExit>),
}

impl std::fmt::Display for DaemonTorStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DataDir(e) => write!(f, "ephemeral tor data directory: {e}"),
            Self::Control(e) => write!(f, "tor control failure: {e:?}"),
            Self::Died(exit) => write!(f, "tor died during start ({exit:?})"),
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
    /// The operator's Tor refused a proof-of-work argument (status 512 or
    /// 513, and the reply named one). The onion is not published. There is
    /// no second attempt without PoW. The reply text is not kept.
    PowRefused {
        /// The status tor returned.
        status: u16,
    },
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
            Self::PowRefused { status } => write!(
                f,
                "this Tor refused onion-service proof-of-work (ADD_ONION status {status}). The onion was not published. Upgrade Tor. This node does not publish an onion without proof-of-work"
            ),
        }
    }
}

impl std::error::Error for DaemonTorPublishError {}

/// The `ADD_ONION` argument names we send. A refusal is `PowRefused` only
/// when the reply names one of these. The lines are read and not kept:
/// they are a forensic surface, and this error is logged.
const POW_ARGUMENT_NAMES: [&str; 3] = ["PoWDefensesEnabled", "PoWQueueRate", "PoWQueueBurst"];

/// `Some` only when a PoW publish was rejected as a syntax or unrecognised
/// argument (512 or 513) and the reply names a PoW argument. Any other
/// rejection, including a 512 that names a port or a key, is `None`: the
/// caller reports an ordinary publish failure. Neither path sends a second
/// `ADD_ONION` without PoW.
///
/// What an older Tor, or one built without the PoW module, actually writes
/// has not been observed. The live `ADD_ONION` test accepts these arguments
/// on the Tor CI has. The match is the argument names until a refusal is
/// pinned.
fn pow_refusal(pow: OnionPow, status: u16, lines: &[String]) -> Option<DaemonTorPublishError> {
    if matches!(pow, OnionPow::Disabled) || (status != 512 && status != 513) {
        return None;
    }
    let names_pow = lines
        .iter()
        .any(|line| POW_ARGUMENT_NAMES.iter().any(|name| line.contains(name)));
    if !names_pow {
        return None;
    }
    Some(DaemonTorPublishError::PowRefused { status })
}

/// How the managed Tor's incarnation ended, as [`DaemonTorControl::death`]
/// reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorDeath {
    /// [`DaemonTorControl::shutdown`] stopped it, or a spawn abandoned it.
    Stopped,
    /// It ended while it was meant to be running.
    Exited {
        /// The process exit code, when the reap reported one. A signal has none.
        code: Option<i32>,
    },
}

/// A live managed-tor incarnation: bootstrapped, SOCKS address known, and —
/// after a successful [`Self::publish`] — an onion service published. Dropping
/// the handle without [`DaemonTorControl::shutdown`] still reaps the child
/// (`kill_on_drop`, and the owning control connection, whose close exits tor) and
/// wipes the DataDirectory, but the
/// bounded graceful path is the intended exit.
pub struct DaemonTorControl {
    actor: kameo::actor::ActorRef<TorControlClient>,
    /// The reap, once the child watcher has published it. The bridge task
    /// owns the sender; this handle is how a stop and a death both read it.
    exit_watch: watch::Receiver<Option<TorExit>>,
    socks_addr: SocketAddr,
    reply_deadline: Duration,
    /// Set when [`Self::shutdown`] begins, so [`Self::death`] can tell that
    /// stop from Tor exiting on its own.
    stopping: Arc<AtomicBool>,
    /// Names copied into this boot from its one cache source. Empty when that
    /// source held nothing a boot is allowed to copy.
    copied: Vec<&'static str>,
    /// Set once Tor has reported bootstrap complete. Only a clean stop after
    /// that writes the cache back.
    bootstrapped: bool,
    /// Bootstrap as the actor's poll reports it. The supervisor reads it;
    /// launch does not wait on it.
    ready: watch::Receiver<BootstrapState>,
    /// Declared last so a plain drop wipes the directory after the actor
    /// (and therefore the child) has been dropped.
    data_dir: Option<EphemeralDataDir>,
}

/// The hs-id seed for one boot.
///
/// The bytes stay inside the `Zeroizing`. There is no `Deref`, so a caller
/// cannot hold a slice of them in async state. [`DaemonTorControl::publish`]
/// is the only function that reads them, and it borrows this value.
pub struct OnionSeed(Zeroizing<[u8; 32]>);

impl OnionSeed {
    fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for OnionSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for OnionSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OnionSeed")
    }
}

impl DaemonTorControl {
    /// The bootstrap watch. A clone, so the supervisor can select on it.
    #[must_use]
    pub fn watch_bootstrap(&self) -> watch::Receiver<BootstrapState> {
        self.ready.clone()
    }

    /// This incarnation's data directory.
    #[must_use]
    pub fn data_path(&self) -> &Path {
        self.data_dir
            .as_ref()
            .map(EphemeralDataDir::path)
            .unwrap_or(Path::new(""))
    }

    /// Bootstrap reached the ready gate.
    pub fn mark_bootstrapped(&mut self) {
        self.bootstrapped = true;
    }

    /// Record the SOCKS listener once `GETINFO` names it.
    pub fn set_socks(&mut self, socks: SocketAddr) {
        self.socks_addr = socks;
    }

    /// `SETCONF AvoidDiskWrites=1` on this owning connection.
    pub async fn defer_disk_writes(&self) -> Result<(), DaemonTorStartError> {
        self.ask_bounded(
            Command::SetConfDiskWrites(DiskWrites::Deferred),
            self.reply_deadline,
        )
        .await
        .map(|_| ())
    }

    async fn stop_actor(&mut self) -> Option<TorExit> {
        self.stopping.store(true, Ordering::Release);
        let actor = self.actor.clone();
        let mut exit_watch = self.exit_watch.clone();
        let stop = async {
            actor.stop_gracefully().await.ok();
            observed_exit(&mut exit_watch).await
        };
        match tokio::time::timeout(REAP_TIMEOUT, stop).await {
            Ok(exit) => exit,
            Err(_timeout) => {
                self.actor.kill();
                None
            }
        }
    }

    /// The boot's hs-id seed. The supervisor holds one until the daemon stops
    /// and passes that same value to every [`Self::publish`].
    pub fn mint_seed() -> Result<OnionSeed, DaemonTorPublishError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        if getrandom::getrandom(bytes.as_mut()).is_err() {
            return Err(DaemonTorPublishError::SeedRng);
        }
        Ok(OnionSeed(bytes))
    }

    /// Publish the onion from `seed`. The seed stays with the caller.
    /// `local_target` (loopback only, enforced structurally by
    /// [`OnionPort::loopback`]). Runs after the caller has bound its inbound
    /// listener, so the target names a port the OS actually granted.
    ///
    /// The caller keeps `seed` for the boot. This call derives an identity
    /// from it and drops that identity when the reply has been checked.
    ///
    /// A failure does **not** tear the incarnation down: tor is up and its
    /// SOCKS proxy works, so the caller's ruled degrade is outbound-only on
    /// the zone. (If the failure was tor dying, [`Self::is_alive`] and the
    /// caller's liveness sweep observe that separately.)
    /// `pow` is explicit. The daemon passes [`OnionPow::Enabled`].
    /// [`OnionPow::Disabled`] is a measurement arm. A 512 or 513 whose reply
    /// names a PoW argument is [`DaemonTorPublishError::PowRefused`]. Any
    /// other rejection is an ordinary publish failure. This function returns
    /// either one and does not send another `ADD_ONION`.
    pub async fn publish(
        &self,
        seed: &OnionSeed,
        virtual_port: u16,
        local_target: SocketAddr,
        max_streams: u16,
        pow: OnionPow,
    ) -> Result<ServiceId, DaemonTorPublishError> {
        let port = OnionPort::loopback(virtual_port, local_target).ok_or(
            DaemonTorPublishError::TargetNotLoopback {
                target: local_target,
            },
        )?;

        let identity = OnionIdentity::from_hs_id_seed(seed.bytes());
        let expected = identity.service_id().clone();
        let request = AddOnion::new(identity.mint_onion_key(), port, max_streams)
            .with_flags(OnionFlags { discard_pk: true })
            .with_pow(pow);
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
        if let Some(refused) = pow_refusal(pow, reply.status(), reply.lines()) {
            return Err(refused);
        }
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

    pub async fn ask(
        &self,
        command: Command,
    ) -> Result<shekyl_tor_control_client::control::ControlReply, DaemonTorStartError> {
        self.ask_bounded(command, self.reply_deadline).await
    }

    /// The managed tor's SOCKS listener — the zone's outbound proxy address.
    #[must_use]
    pub fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }

    /// Is the incarnation still up? `false` means this process has ended.
    /// The supervisor respawns; this handle does not.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.actor.is_alive()
    }

    /// Await the incarnation's death — the notification edge of
    /// [`Self::is_alive`], for a consumer that watches rather than polls.
    pub async fn wait_death(&self) {
        self.actor.wait_for_shutdown().await;
    }

    /// [`Self::wait_death`] without borrowing `self`, and saying how the
    /// incarnation ended. The future owns a clone of the control actor,
    /// so a watcher spawned beside this control outlives the call that
    /// started it. It resolves when the actor stops: [`TorDeath::Stopped`]
    /// when [`Self::shutdown`] (or a failed start) stopped it, and
    /// [`TorDeath::Exited`] when Tor ended while it was meant to run.
    /// The exit code is the reap's, read after the actor has stopped so the
    /// bridge has published it.
    pub fn death(&self) -> impl std::future::Future<Output = TorDeath> + Send + 'static {
        let actor = self.actor.clone();
        let stopping = Arc::clone(&self.stopping);
        let mut exit_watch = self.exit_watch.clone();
        async move {
            actor.wait_for_shutdown().await;
            if stopping.load(Ordering::Acquire) {
                return TorDeath::Stopped;
            }
            let exit = observed_exit(&mut exit_watch).await;
            TorDeath::Exited {
                code: exit.as_ref().and_then(exit_code),
            }
        }
    }

    /// Bounded teardown: graceful actor stop (which `DEL_ONION`s the published
    /// service and SIGTERM→wait→SIGKILL→reaps the child), then the exit
    /// telemetry, then the DataDirectory wipe. On a wedged actor, kill and
    /// proceed — the child reap is backstopped by `kill_on_drop` and by the owning
    /// control connection, whose close exits tor.
    pub async fn shutdown(mut self) -> Option<TorExit> {
        self.teardown().await
    }

    async fn teardown(&mut self) -> Option<TorExit> {
        let exit = self.stop_actor().await;
        // After the reap, before the directory goes away. A crash (Tor died,
        // or we had to kill it) saves nothing: the previous cache stays.
        self.save_if_clean(&exit).await;
        if let Some(dir) = self.data_dir.take() {
            dir.wipe();
        }
        exit
    }

    async fn save_if_clean(&self, exit: &Option<TorExit>) {
        if self.bootstrapped {
            if let (Some(TorExit::Reaped(_)), Some(dir)) = (exit, self.data_dir.as_ref()) {
                save_directory_cache(dir.path()).await;
            }
        }
    }

    /// The cache files copied into this boot's directory. Empty when the
    /// cache was missing or every file was refused.
    #[must_use]
    pub fn directory_cache_copied(&self) -> &[&'static str] {
        &self.copied
    }
}

/// The process exit code in a reap. A signal, a kill, and a reap that
/// reported no status have none.
fn exit_code(exit: &TorExit) -> Option<i32> {
    match exit {
        TorExit::Reaped(status) => status.code(),
        TorExit::Killed => None,
        TorExit::Died { status, .. } => status.and_then(|status| status.code()),
    }
}

/// The reap, once the bridge has published it. The oneshot is sent before
/// the actor's stop returns, and the bridge task may not have run yet, so a
/// watch that is still empty waits for that publish or for the sender to drop.
async fn observed_exit(exit_watch: &mut watch::Receiver<Option<TorExit>>) -> Option<TorExit> {
    if let Some(exit) = *exit_watch.borrow() {
        return Some(exit);
    }
    if exit_watch.changed().await.is_err() {
        return exit_watch.borrow().as_ref().copied();
    }
    *exit_watch.borrow()
}

/// Write the public directory cache back from a boot that reached the
/// network and was stopped cleanly. The copy runs on the blocking pool.
/// A failure leaves the previous files.
async fn save_directory_cache(data_dir: &Path) {
    let data_dir = data_dir.to_path_buf();
    let Some(parent) = data_dir.parent().map(Path::to_path_buf) else {
        return;
    };
    let cache = parent.join(crate::data_dir::CACHE_DIR_NAME);
    drop(
        tokio::task::spawn_blocking(move || {
            let cache = directory_cache::DirectoryCache::at(cache);
            if cache.ensure().is_err() {
                return;
            }
            drop(cache.save_from(&data_dir));
        })
        .await,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pow_refusal_is_terminal_and_a_disabled_publish_is_not_one() {
        let named = pow_refusal(
            OnionPow::Enabled,
            512,
            &["512 Unrecognized key \"PoWDefensesEnabled\"".to_owned()],
        );
        match named {
            Some(err @ DaemonTorPublishError::PowRefused { status: 512 }) => {
                let text = err.to_string();
                assert!(text.contains("proof-of-work"));
                assert!(!text.contains("Unrecognized"));
                assert!(!text.contains("PoWDefensesEnabled"));
            }
            other => panic!("expected PowRefused, got {other:?}"),
        }
        assert!(pow_refusal(
            OnionPow::Enabled,
            513,
            &["513 Unrecognized argument: PoWQueueRate".to_owned()],
        )
        .is_some());
        assert!(pow_refusal(
            OnionPow::Enabled,
            512,
            &["512 Syntax error in command argument: Port".to_owned()],
        )
        .is_none());
        assert!(pow_refusal(OnionPow::Disabled, 512, &["PoWDefensesEnabled".to_owned()]).is_none());
        assert!(pow_refusal(OnionPow::Enabled, 551, &["PoWDefensesEnabled".to_owned()]).is_none());
    }

    /// A normal exit keeps its code. A signal and a kill do not. Swapping the
    /// reap's arms fails this.
    #[cfg(unix)]
    #[test]
    fn a_reaped_status_keeps_its_exit_code() {
        use shekyl_tor_control_client::control::DeathSignal;
        use std::os::unix::process::ExitStatusExt;

        let exited = std::process::ExitStatus::from_raw(1 << 8);
        assert_eq!(exit_code(&TorExit::Reaped(exited)), Some(1));
        assert_eq!(exit_code(&TorExit::Killed), None);
        let signaled = std::process::ExitStatus::from_raw(9);
        assert_eq!(
            exit_code(&TorExit::Died {
                first: DeathSignal::ProcessExited,
                status: Some(signaled),
            }),
            None
        );
    }

    /// Debug names the type and not the seed. A derived `Debug` fails this.
    #[test]
    fn an_onion_seed_prints_no_bytes() {
        let seed = OnionSeed(Zeroizing::new([0xab; 32]));
        assert_eq!(format!("{seed:?}"), "OnionSeed");
    }

    use crate::test_support::tor_binary;
    use shekyl_tor_control_client::binary::VerifiedTorBinary;
    use shekyl_tor_control_client::control::BootstrapState;

    /// The ignored live tests wait here so a published onion has a network.
    /// A hang bound in a test is not a daemon deadline: nothing in the
    /// supervisor gives a bootstrap up.
    async fn wait_for_the_network(boot: &mut DaemonTorControl) {
        let hang = tokio::time::Instant::now() + Duration::from_secs(300);
        let mut watch = boot.watch_bootstrap();
        loop {
            match *watch.borrow() {
                BootstrapState::Ready => {
                    boot.mark_bootstrapped();
                    let reply = boot
                        .ask(shekyl_tor_control_client::control::Command::GetInfo(vec![
                            "net/listeners/socks".to_owned(),
                        ]))
                        .await
                        .expect("socks");
                    let socks = shekyl_tor_control_client::control::parse_socks_listeners(&reply)
                        .expect("a socks listener");
                    boot.set_socks(socks);
                    return;
                }
                BootstrapState::Failed => panic!("tor died before it reached the network"),
                BootstrapState::Connecting { .. } => {}
            }
            if tokio::time::Instant::now() >= hang {
                panic!("the live test stopped waiting");
            }
            tokio::select! {
                changed = watch.changed() => {
                    if changed.is_err() {
                        panic!("the bootstrap watch closed");
                    }
                }
                () = tokio::time::sleep(hang.saturating_duration_since(tokio::time::Instant::now())) => {}
            }
        }
    }

    fn config_with(binary: VerifiedTorBinary, data_dir_parent: PathBuf) -> DaemonTorConfig {
        DaemonTorConfig {
            tor_binary: binary,
            data_dir_parent,
            events: EventSink::unsubscribed(),
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
        match DaemonTorControl::launch(config).await {
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
    /// After shutdown the per-boot DataDirectory is gone. The public directory
    /// cache remains, and the next boot in that parent copies it.
    #[tokio::test]
    #[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY (bootstraps twice, network)"]
    async fn ephemeral_onion_publishes_and_rotates_across_boots() {
        let binary = VerifiedTorBinary::unchecked_for_test(tor_binary());

        let parent = tempfile::tempdir().unwrap();
        let mut boot1 =
            DaemonTorControl::launch(config_with(binary.clone(), parent.path().to_path_buf()))
                .await
                .expect("first boot start");
        wait_for_the_network(&mut boot1).await;
        let seed1 = DaemonTorControl::mint_seed().expect("seed");
        assert_eq!(
            boot1.directory_cache_copied().is_empty(),
            !lane_seed_holds_a_file(),
            "a fresh parent copies the lane seed when that seed holds a file, and nothing otherwise"
        );
        assert!(boot1.is_alive());
        assert!(boot1.socks_addr().ip().is_loopback());

        match boot1
            .publish(
                &seed1,
                18080,
                "192.168.1.10:18080".parse().unwrap(),
                64,
                OnionPow::Enabled,
            )
            .await
        {
            Err(DaemonTorPublishError::TargetNotLoopback { target }) => {
                assert_eq!(target, "192.168.1.10:18080".parse().unwrap());
            }
            other => panic!("expected TargetNotLoopback, got {other:?}"),
        }
        assert!(boot1.is_alive(), "a refused publish must not kill tor");

        let first_id = boot1
            .publish(
                &seed1,
                18080,
                "127.0.0.1:48080".parse().unwrap(),
                64,
                OnionPow::Enabled,
            )
            .await
            .expect("first boot publish");
        assert_eq!(first_id.as_str().len(), 56);
        let exit = boot1.shutdown().await;
        assert!(exit.is_some(), "teardown must observe a real reap");
        assert_only_directory_cache(parent.path());

        let mut boot2 = DaemonTorControl::launch(config_with(binary, parent.path().to_path_buf()))
            .await
            .expect("second boot start");
        wait_for_the_network(&mut boot2).await;
        assert!(
            !boot2.directory_cache_copied().is_empty(),
            "the second boot copies the cache the first stop saved"
        );
        let seed2 = DaemonTorControl::mint_seed().expect("seed");
        let second_id = boot2
            .publish(
                &seed2,
                18080,
                "127.0.0.1:48080".parse().unwrap(),
                64,
                OnionPow::Enabled,
            )
            .await
            .expect("second boot publish");
        assert_ne!(
            second_id.as_str(),
            first_id.as_str(),
            "a new boot mints a new key and therefore a new address"
        );
        boot2.shutdown().await;
    }

    /// The one cold start. It fails if the job cache already holds a directory
    /// file, which is how the lane keeps every later live test seeded from
    /// this run and this run only.
    #[tokio::test]
    #[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY (one cold bootstrap, network)"]
    async fn a_cold_boot_saves_the_public_directory_cache() {
        if let Some(cache) = std::env::var_os("SHEKYL_TEST_TOR_DIRECTORY_CACHE") {
            let cache = std::path::PathBuf::from(&cache);
            for file in shekyl_tor_control_client::directory_cache::FILES {
                assert!(
                    !cache.join(file.name).exists(),
                    "this boot is the job's cold start; {} is already seeded",
                    file.name
                );
            }
        }
        let binary = VerifiedTorBinary::unchecked_for_test(tor_binary());
        let parent = tempfile::tempdir().unwrap();
        let mut boot = DaemonTorControl::launch(config_with(binary, parent.path().to_path_buf()))
            .await
            .expect("cold start");
        assert!(
            boot.directory_cache_copied().is_empty(),
            "the cold boot has nothing to copy"
        );
        wait_for_the_network(&mut boot).await;
        assert!(
            boot.shutdown().await.is_some(),
            "the stop observes a real reap"
        );
        assert_only_directory_cache(parent.path());
        // The lane's seed is the cache a clean stop wrote. Copying it while
        // Tor still held the data directory would publish a journal Tor was
        // still appending.
        directory_cache::publish_job_seed(&parent.path().join(crate::data_dir::CACHE_DIR_NAME));
        if let Some(cache) = std::env::var_os("SHEKYL_TEST_TOR_DIRECTORY_CACHE") {
            let cache = std::path::PathBuf::from(cache);
            let seeded = shekyl_tor_control_client::directory_cache::FILES
                .iter()
                .any(|file| cache.join(file.name).is_file());
            assert!(seeded, "the cold stop writes the job cache");
            assert!(!cache.join("state").exists());
        }
    }

    fn lane_seed_holds_a_file() -> bool {
        std::env::var_os("SHEKYL_TEST_TOR_DIRECTORY_CACHE").is_some_and(|path| {
            !path.is_empty() && directory_cache::DirectoryCache::at(path).holds_a_file()
        })
    }

    fn assert_only_directory_cache(parent: &std::path::Path) {
        let mut names: Vec<_> = std::fs::read_dir(parent)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![std::ffi::OsString::from(crate::data_dir::CACHE_DIR_NAME)],
            "shutdown wipes the per-boot directory and leaves the cache"
        );
        let cache = parent.join(crate::data_dir::CACHE_DIR_NAME);
        assert!(!cache.join("state").exists(), "state is not a cache file");
        let kept = shekyl_tor_control_client::directory_cache::FILES
            .iter()
            .any(|file| cache.join(file.name).is_file());
        assert!(
            kept,
            "a bootstrapped stop saves at least one directory file"
        );
    }

    /// The tor process launched with `dir` as its DataDirectory parent.
    #[cfg(target_os = "linux")]
    fn tor_under(dir: &std::path::Path) -> Option<u32> {
        let needle = dir.to_string_lossy().into_owned();
        std::fs::read_dir("/proc").ok()?.find_map(|entry| {
            let entry = entry.ok()?;
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let cmdline = std::fs::read(entry.path().join("cmdline")).ok()?;
            String::from_utf8_lossy(&cmdline)
                .contains(&needle)
                .then_some(pid)
        })
    }

    /// The death edge (`TOR_SUPERVISOR.md` `TSR-F1`): a watcher hears the
    /// incarnation end. A tor killed from outside is `Exited`. A shutdown is
    /// `Stopped`.
    #[tokio::test]
    #[cfg(target_os = "linux")]
    #[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY (bootstraps twice, network)"]
    async fn a_death_watcher_hears_tor_exit_and_tells_it_from_a_stop() {
        let binary = VerifiedTorBinary::unchecked_for_test(tor_binary());
        let heard = |death| tokio::time::timeout(Duration::from_secs(30), death);

        let dir = tempfile::tempdir().unwrap();
        let killed =
            DaemonTorControl::launch(config_with(binary.clone(), dir.path().to_path_buf()))
                .await
                .expect("start");
        let death = tokio::spawn(killed.death());
        let pid = tor_under(dir.path()).expect("the tor under this directory");
        // Under the spawn lock, as every spawn in a crate that launches tor
        // is (TOR_SUPERVISOR.md 4.7): a child started in the launch window
        // would inherit tor's end.
        let status = shekyl_tor_control_client::spawn_lock::status(
            std::process::Command::new("kill").args(["-9", &pid.to_string()]),
        )
        .expect("kill");
        assert!(status.success());
        assert_eq!(
            heard(death).await.expect("heard").expect("watcher"),
            TorDeath::Exited { code: None }
        );
        assert!(!killed.is_alive());
        let _exit_after_kill = killed.shutdown().await;

        let dir = tempfile::tempdir().unwrap();
        let stopped = DaemonTorControl::launch(config_with(binary, dir.path().to_path_buf()))
            .await
            .expect("start");
        let death = tokio::spawn(stopped.death());
        assert!(
            stopped.shutdown().await.is_some(),
            "the stop observes a real reap"
        );
        assert_eq!(
            heard(death).await.expect("heard").expect("watcher"),
            TorDeath::Stopped
        );
    }
}
