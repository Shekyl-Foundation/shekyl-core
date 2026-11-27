// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The managed Tor supervisor (`TOR_SUPERVISOR.md` §4, increment 3).
//!
//! [`Drive`] is the manager's hands. The [`Core`] decides. This driver
//! performs each [`Action`] and reports what happened, including a publish
//! the endpoint was not ready for and a republish a liveness sample has
//! since ruled out. It keeps no second schedule.
//!
//! The Tor connector is not this driver. It reads the route a publish
//! installs and dials. Questions to Tor stay on the owning control
//! connection (`TSR-Q9`).
//!
//! A sleep is a wait this driver was in that returned more than
//! `control::RESUMED_AFTER` past the deadline it was armed with: the loop's
//! wait, whatever woke it, or a control ask. The core does not infer one
//! from a deadline that merely looks late. The wait itself lives in
//! [`mod@inbox`]: one queue of what happened, in order, and one doorbell for
//! the cells that hold state. Each pass folds the sleep the wait observed,
//! then every cell that changed, then the one arrival that woke it.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use shekyl_daemon_config::sections::Tor;
use shekyl_daemon_rpc::chain_facts::FactsFault;
use shekyl_daemon_rpc::tor_facts::{TorFacts, TorFuture, TorHandle};
use shekyl_node::Network;
use shekyl_p2p::{
    DownCause, LinkCensus, LinkTally, OriginVerdict, PathFact, PathReading as Reading,
    PerConnector, SupervisorFeeds, TOR_SOCKS_TIMEOUT,
};
use shekyl_timing_engine::{Clock, EngineError, MonotonicClock, OwnerClass};
use shekyl_tor_control_client::binary::{
    discover_and_verify, discover_and_verify_at, TorBinaryError,
};
use shekyl_tor_control_client::control::{
    parse_event, resume_lateness, BootstrapState, ControlReply, EventSink, LogEvent, LogSeverity,
    Resume, ServiceId, SocksTimeout, TorEvent, UploadRounds,
};
use shekyl_tor_control_client::directory_cache::GuardState;
use shekyl_tor_control_client::onion_identity::OnionIdentity;
use shekyl_tor_control_client::supervisor::{
    clock_evidence_of, directory_content_input_of, input_of, wire_cause, Action, Cause, Connectors,
    Core, DialTally, Input, ManagedRunning, NetworkView, OnionPath, OriginVerdict as FoldedOrigin,
    PathReading, Policy, Sessions, Space, Step, TorCensus as QuietCensus, TorSetting,
};
use shekyl_tor_control_daemon::{
    space_needed, sweep_stale_data_dirs, CacheSave, DaemonTorControl, DaemonTorStartError,
    IsolationPair, KeptDataDir, KeptLog, KeptSave, Retirement, TombstoneEnd, TorDeath,
};
use shekyl_tor_status::{held_at_start_sentence, install_sentence, render, TorStatus};
use tokio::sync::watch;
use tokio::task::JoinHandle;

mod inbox;
#[cfg(all(test, unix))]
mod loop_tests;
pub(crate) mod onion_key;
mod probe;
mod requests;

use self::inbox::{inbox, Arrival, Changed, Inbox, Owner, Timer, Wanted, Woken};

/// The managed Tor answers a SOCKS request it cannot attach just inside the
/// Tor dial deadline, so the dial's class is Tor's reply, never a race with
/// that deadline (`TOR_SUPERVISOR.md` §4.2).
const SOCKS_TIMEOUT: SocksTimeout = TOR_SOCKS_TIMEOUT;
/// The supervisor's waits.
fn policy() -> Policy {
    Policy::provisional()
}
/// The onion's stream cap.
const MAX_STREAMS: u16 = 8;
/// `GETINFO` key for the bootstrap phase. One sample asks this and the listener.
const BOOTSTRAP_PHASE: &str = "status/bootstrap-phase";
/// `GETINFO` key for the bytes Tor has read: with the bootstrap phase, it
/// tells a slow directory mirror from one that is not answering (§5).
const TRAFFIC_READ: &str = "traffic/read";
/// Tor's own view of its network (`TSR-Q14`). Asked only while Running.
const NETWORK_LIVENESS: &str = "network-liveness";
/// Whether Tor holds a built circuit. Asked with [`NETWORK_LIVENESS`].
const CIRCUIT_ESTABLISHED: &str = "status/circuit-established";
/// `GETINFO` key for the SOCKS listeners.
const SOCKS_LISTENERS: &str = "net/listeners/socks";
/// `GETINFO` key for the consensus's `valid-after`: the clock this machine's
/// is judged against (§4.2). Asked on its own: before Tor holds a consensus
/// it is an error, and one failing key fails the whole `GETINFO` (tor
/// 0.4.9.14 `control_getinfo.c:1760`).
const CONSENSUS_VALID_AFTER: &str = "consensus/valid-after";

/// Keys one sample asks. The network keys are Running only (§4.2).
fn sample_keys(reads_network: bool) -> Vec<String> {
    let mut keys = vec![
        BOOTSTRAP_PHASE.to_owned(),
        SOCKS_LISTENERS.to_owned(),
        TRAFFIC_READ.to_owned(),
    ];
    if reads_network {
        keys.extend([NETWORK_LIVENESS.to_owned(), CIRCUIT_ESTABLISHED.to_owned()]);
    }
    keys
}

/// The supervisor's inbox, made before the node opens: the network's
/// producers publish into it from their first value (`TOR_SUPERVISOR.md`
/// §5). [`begin`] starts the supervisor on it.
pub struct Prepared {
    owner: Owner,
    inbox: Inbox,
    /// The managed Tor's persistent onion, until [`begin`] takes it.
    persistent_onion: Option<OnionIdentity>,
}

impl Prepared {
    /// The RPC's two asks of this supervisor (`daemon_status`'s `hiding`
    /// and Tor status). Taken before the RPC starts: an ask posted before
    /// the loop runs is answered by its first pass, and one after the stop
    /// is refused as not ready. Holding it never holds off the stop.
    #[must_use]
    pub fn asks(&self) -> TorHandle {
        Arc::new(TorAsks(self.owner.asker()))
    }
}

/// The supervisor's asks, as `daemon_status` reads them.
struct TorAsks(Option<inbox::Asker>);

impl TorFacts for TorAsks {
    fn hiding(&self) -> TorFuture<'_, bool> {
        let answer = self.0.as_ref().and_then(inbox::Asker::ask_hiding);
        Box::pin(async move { answered(answer).await })
    }

    fn status(&self) -> TorFuture<'_, TorStatus> {
        let answer = self.0.as_ref().and_then(inbox::Asker::ask_status);
        Box::pin(async move { answered(answer).await })
    }
}

/// An ask's answer: not ready when the inbox is gone, or the loop ended
/// before it answered.
async fn answered<T>(answer: Option<tokio::sync::oneshot::Receiver<T>>) -> Result<T, FactsFault> {
    answer
        .ok_or(FactsFault::NotReady)?
        .await
        .map_err(|_| FactsFault::NotReady)
}

/// The supervisor's inbox, and the feeds the network publishes into, under
/// every `tor` setting: the supervisor answers the node's status whether
/// or not it runs the Tor (Rick, 2026-11-10). `persistent_onion` is the
/// managed Tor's key the walk loaded (`tor-onion-key-file`), held here
/// until [`begin`] hands it to the supervisor; `None`, the onion is new at
/// that boot.
#[must_use]
pub fn prepare(persistent_onion: Option<OnionIdentity>) -> (Prepared, SupervisorFeeds) {
    let (owner, inbox, feeds) = inbox();
    (
        Prepared {
            owner,
            inbox,
            persistent_onion,
        },
        feeds,
    )
}

/// The running supervisor. Dropping it stops the loop, as
/// [`Self::shutdown`] does, without waiting for Tor's directory to be torn
/// down.
pub struct Supervisor {
    owner: Owner,
    /// The loop's task, until [`Self::ended`] has read its end.
    task: Option<JoinHandle<Result<(), SupervisorEnd>>>,
    /// Whether it runs this node's Tor (`tor = managed`).
    managed: bool,
}

/// Why the supervisor ended while the daemon ran (rule 25: a long-lived task
/// reports its end). The daemon stops on it and exits failed: with `tor =
/// managed` and clearnet off, a node without its supervisor has no network,
/// and under every setting `daemon_status` answers "not ready".
///
/// Its own type, not a `shekyl_node::NodeEnd` variant: the daemon starts
/// the supervisor beside the node, not inside it, and the daemon's wait
/// reads it (`run.rs`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SupervisorEnd {
    /// The node's timing engine refused the supervisor's registration.
    NoScheduler(EngineError),
    /// The operating system's random source refused the managed Tor's
    /// per-boot onion key. There is no fallback: a weaker source would mint
    /// a guessable key.
    NoOnionKey,
    /// The operating system's random source refused the isolation pair the
    /// managed Tor's probe dials on.
    NoProbeIsolation,
    /// The loop returned though no stop was asked. The loop ends only when
    /// its queue closes, and only [`Supervisor::shutdown`] or dropping the
    /// supervisor closes it, so this is a broken promise, not an operating
    /// condition.
    Returned,
    /// The core asked for a Tor action under a `tor` setting that runs no
    /// Tor: a broken promise between the core and this driver.
    /// [`Drive::act`] returns it before that action runs, the loop tears
    /// down as at a stop, and the daemon stops and says why. A panic there
    /// would abort a shipped build with no teardown and no log line.
    NoTorToRun(TorAsk),
    /// The loop panicked, in the panic's own words. A shipped build aborts
    /// the process on a panic, so this arm is reached only where panics
    /// unwind.
    Panicked(String),
    /// The runtime cancelled the loop's task.
    Cancelled,
}

/// The Tor action the core asked for (see [`SupervisorEnd::NoTorToRun`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TorAsk {
    /// Check the Tor binary.
    Pin,
    /// Launch Tor.
    Launch,
    /// Publish this node's onion.
    Publish,
    /// Probe this node's onion.
    Probe,
}

impl TorAsk {
    fn verb(self) -> &'static str {
        match self {
            Self::Pin => "check a Tor binary",
            Self::Launch => "launch a Tor",
            Self::Publish => "publish an onion",
            Self::Probe => "probe an onion",
        }
    }

    /// The managed-Tor ask `action` is, when running it needs a
    /// [`ManagedBoot`]. Every other action runs under any `tor` setting.
    fn of(action: &Action) -> Option<Self> {
        match action {
            Action::CheckPin => Some(Self::Pin),
            Action::Spawn(_) => Some(Self::Launch),
            Action::RepublishOnion | Action::AddOnion => Some(Self::Publish),
            Action::Probe => Some(Self::Probe),
            _ => None,
        }
    }
}

impl SupervisorEnd {
    /// What the operator does about it (rule 82), said after the end.
    #[must_use]
    pub fn remedy(&self) -> &'static str {
        match self {
            Self::NoOnionKey | Self::NoProbeIsolation => {
                "Check that the system's random source works, then start the daemon again"
            }
            Self::NoScheduler(_)
            | Self::NoTorToRun(_)
            | Self::Returned
            | Self::Panicked(_)
            | Self::Cancelled => "Start the daemon again; if this repeats, report it with this log",
        }
    }
}

impl std::fmt::Display for SupervisorEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoScheduler(error) => write!(
                f,
                "the Tor supervisor did not start: the node's timing engine refused it ({error:?})"
            ),
            Self::NoOnionKey => f.write_str(
                "the Tor supervisor did not start: the system's random source refused this node's onion key",
            ),
            Self::NoProbeIsolation => f.write_str(
                "the Tor supervisor did not start: the system's random source refused its probe's isolation",
            ),
            Self::NoTorToRun(ask) => write!(
                f,
                "the Tor supervisor was asked to {} under a tor setting that runs none",
                ask.verb()
            ),
            Self::Returned => f.write_str("the Tor supervisor stopped though no stop was asked"),
            Self::Panicked(words) => write!(f, "the Tor supervisor panicked: {words}"),
            Self::Cancelled => f.write_str("the Tor supervisor's task was cancelled"),
        }
    }
}

/// The end a joined loop task reports. Read only while the daemon runs: the
/// supervisor's queue is still open, so an `Ok` is a return nobody asked for.
fn joined_end(joined: Result<Result<(), SupervisorEnd>, tokio::task::JoinError>) -> SupervisorEnd {
    match joined {
        Ok(Err(end)) => end,
        Ok(Ok(())) => SupervisorEnd::Returned,
        Err(error) if error.is_panic() => {
            let payload = error.into_panic();
            let words = payload
                .downcast_ref::<&str>()
                .map(|words| (*words).to_owned())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "a panic with no message".to_owned());
            SupervisorEnd::Panicked(words)
        }
        Err(_) => SupervisorEnd::Cancelled,
    }
}

impl Supervisor {
    /// Whether it runs this node's Tor (`tor = managed`): what its stop
    /// tears down.
    #[must_use]
    pub fn managed(&self) -> bool {
        self.managed
    }

    /// The zone host's forward listener, once step 8 has bound it.
    pub fn note_forward(&self, forward: SocketAddr) {
        self.owner.forward(forward);
    }

    /// The supervisor's status now. The loop answers it in its next pass,
    /// from the one place that holds the state: it never waits on Tor, so
    /// a Tor that does not answer does not hold this (Rick, 2026-11-10).
    /// `None` once the loop has stopped.
    pub async fn status(&self) -> Option<TorStatus> {
        self.owner.ask_status()?.await.ok()
    }

    /// Resolves when the loop has ended on its own, with why; never, once
    /// it has. Only the daemon's wait reads it, while the daemon runs: the
    /// stop ([`Self::shutdown`]) is not an end. Cancel-safe: dropped before
    /// the loop ends, it leaves the task to the next call or the stop.
    pub async fn ended(&mut self) -> SupervisorEnd {
        let Some(task) = self.task.as_mut() else {
            return std::future::pending().await;
        };
        let joined = task.await;
        self.task = None;
        joined_end(joined)
    }

    /// A supervisor over `task`, for the daemon's wait tests: the task
    /// stands in for the loop, and its end is the loop's.
    #[cfg(test)]
    pub(crate) fn over_task(task: JoinHandle<Result<(), SupervisorEnd>>) -> Self {
        let (owner, _inbox, _feeds) = inbox::inbox();
        Self {
            owner,
            task: Some(task),
            managed: false,
        }
    }

    /// Stop Tor and wait for the directory to be torn down.
    pub async fn shutdown(self) {
        let Self {
            mut owner, task, ..
        } = self;
        owner.stop();
        if let Some(task) = task {
            let _joined = task.await;
        }
    }
}

/// The pin half of a managed Tor's start, read for the configuration check
/// (`INPUT_GRAMMAR.md` IG-Q59): the binary is discovered and verified, and
/// not started.
///
/// `None` when the pin is accepted. Otherwise one warning. The cause is the
/// class the supervisor's pin takes, spoken with [`install_sentence`]; the
/// parenthetical is the pin error, which for a missed discovery names every
/// path it searched. The last sentence is [`held_at_start_sentence`]: no
/// session exists at a check, so it says what the node will do. Under TB-2
/// a pin that fails is announced and the daemon starts all the same.
#[must_use]
pub fn pin_warning(binary: Option<&Path>, clearnet_on: bool) -> Option<String> {
    let verified = match binary {
        Some(path) => discover_and_verify_at(path),
        None => discover_and_verify(),
    };
    verified
        .err()
        .map(|error| pin_warning_line(&error, clearnet_on))
}

/// What a refused pin means. The supervisor's core takes [`PinClass::input`];
/// the posture names [`PinClass::cause`]. One match produces both, so the
/// warning cannot speak a cause the core does not take.
struct PinClass {
    input: Input,
    cause: Cause,
}

/// The pin's classification. A missing discovery and a platform with no
/// managed Tor are their own inputs. Every other failure is a binary that
/// was found and refused, and it was not executed.
fn classify_pin(error: &TorBinaryError) -> PinClass {
    match error {
        TorBinaryError::NotFound { .. } => PinClass {
            input: Input::BundleMissing,
            cause: Cause::BundleMissing,
        },
        TorBinaryError::Unavailable { .. } => PinClass {
            input: Input::Unavailable,
            cause: Cause::Unavailable,
        },
        TorBinaryError::NotAFile(_)
        | TorBinaryError::NotExecutable(_)
        | TorBinaryError::NotTheExecutable(_)
        | TorBinaryError::Io { .. }
        | TorBinaryError::UnexpectedEntry { .. }
        | TorBinaryError::UnsafeLoaderPath(_)
        | TorBinaryError::MissingFile { .. }
        | TorBinaryError::HashMismatch { .. } => PinClass {
            input: Input::PinRefused,
            cause: Cause::PinRefused,
        },
    }
}

/// A pin error in words: the class's install sentence, then the error,
/// whose display is the detail. A refusal names the file and the reason; a
/// `NotFound` lists `searched`. The status carries neither (Rick,
/// 2026-11-12: the file stays in the daemon's log, IG-F26).
fn pin_refusal_line(error: &TorBinaryError) -> String {
    let class = classify_pin(error);
    let sentence = wire_cause(&class.cause)
        .as_ref()
        .and_then(install_sentence)
        .expect("a pin class is an install cause");
    format!("managed Tor: {sentence} ({error})")
}

/// The warning text for a pin error at a start or a check, with what the
/// node will do.
fn pin_warning_line(error: &TorBinaryError, clearnet_on: bool) -> String {
    let consequence = held_at_start_sentence(clearnet_on);
    format!("warning: {} {consequence}", pin_refusal_line(error))
}

/// Which check of the Tor binary a pin is. The start's refusal is the
/// start's announcement ([`pin_warning`]); a running re-check's refusal is
/// said only here, in full: the file and the reason (Rick, 2026-11-12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PinCheck {
    /// The first pin, which the start announces.
    Start,
    /// A pin while the daemon runs.
    Recheck,
}

impl PinCheck {
    /// Log a refusal this check's caller does not announce elsewhere.
    fn say_refusal(self, error: &TorBinaryError) {
        if self == Self::Recheck {
            tracing::warn!(target: "global", "{}", pin_refusal_line(error));
        }
    }
}

/// Start the supervisor on its inbox, under every `tor` setting. A managed
/// Tor is launched and supervised; under `off` or an operator's Tor the
/// supervisor runs nothing and answers the status from what the network
/// publishes. `network` is where the route, the onion and the inbound facet
/// are published, and whose timing engine the supervisor's waits are owned
/// by. The managed Tor's onion is the one `prepared` carries, or new at
/// this boot.
#[must_use]
pub fn begin(
    mut prepared: Prepared,
    tor: &Tor,
    clearnet_on: bool,
    virtual_port: u16,
    data_dir: &Path,
    handle: &tokio::runtime::Handle,
    network: Network,
) -> Supervisor {
    let supervises = match tor {
        Tor::Managed { binary, .. } => Supervises::Managed {
            pin: PinSource::Discover(binary.clone()),
            onion: prepared
                .persistent_onion
                .take()
                .map_or(OnionSource::PerBoot, OnionSource::Persistent),
        },
        Tor::Operator { .. } => Supervises::Unmanaged(TorSetting::Operator),
        Tor::Off => Supervises::Unmanaged(TorSetting::Off),
    };
    let managed = matches!(supervises, Supervises::Managed { .. });
    let Prepared { owner, inbox, .. } = prepared;
    let data_dir = data_dir.to_path_buf();
    let task = handle.spawn(drive(
        supervises,
        policy(),
        clearnet_on,
        virtual_port,
        data_dir,
        inbox,
        network,
    ));
    Supervisor {
        owner,
        task: Some(task),
        managed,
    }
}

/// Tor's log line in the daemon's log, under `tor` at Tor's severity
/// (§4.10). `TSR-M9` found no onion address in these lines at `notice`.
fn say_tor_log(line: &LogEvent) {
    let text = tor_log_text(&line.message);
    match line.severity {
        LogSeverity::Notice => tracing::info!(target: "tor", "Tor: {text}"),
        LogSeverity::Warn => tracing::warn!(target: "tor", "Tor: {text}"),
        LogSeverity::Err => tracing::error!(target: "tor", "Tor: {text}"),
    }
}

/// Tor's text with every control character replaced: the text can carry what
/// relays sent, and the daemon's log is read in a terminal.
fn tor_log_text(message: &str) -> String {
    message
        .chars()
        .map(|c| {
            if c.is_control() {
                char::REPLACEMENT_CHARACTER
            } else {
                c
            }
        })
        .collect()
}

/// Say a clean stop's write-back when it failed. The next start then fetches
/// the network directory again, or keeps the guards saved before this stop.
fn say_kept(saved: &KeptSave) {
    if let CacheSave::Failed(error) = &saved.cache {
        tracing::warn!(
            target: "global",
            "Tor's directory cache was not saved ({error}); the next start fetches the network directory again"
        );
    }
    if let Some(CacheSave::Failed(error)) = &saved.guards {
        tracing::warn!(
            target: "global",
            "this onion's Tor guards were not saved ({error}); the next start keeps the guards saved before"
        );
    }
}

/// Say what became of a retired directory. Tor's kept log is where a run
/// looks for why Tor stopped (§4.10); a failure leaves the next start's sweep
/// to finish.
fn say_retirement(retirement: &Retirement) {
    match &retirement.log {
        KeptLog::Kept(path) => tracing::info!(
            target: "tor",
            "Tor's log is kept at {}",
            path.display()
        ),
        KeptLog::Absent => {}
        KeptLog::NotMoved(error) => tracing::warn!(
            target: "tor",
            "Tor's log was not kept ({error}); it is removed with Tor's directory"
        ),
    }
    match &retirement.tombstone {
        TombstoneEnd::Deleted => {}
        TombstoneEnd::Outlived(path) => tracing::debug!(
            target: "tor",
            "Tor's old directory {} is still being deleted; the next start removes what is left",
            path.display()
        ),
        TombstoneEnd::NotDeleted(path, error) => tracing::warn!(
            target: "tor",
            "Tor's old directory {} was not deleted ({error}); the next start tries again",
            path.display()
        ),
        TombstoneEnd::NotRenamed(error) => tracing::warn!(
            target: "tor",
            "Tor's directory was not renamed for deletion ({error}); the next start removes it"
        ),
    }
}

fn dial_tally(tally: LinkTally) -> DialTally {
    DialTally {
        failed_attempt_began: tally.failed_attempt_began.map(|at| at.tick().get()),
        census: match tally.census {
            LinkCensus::Pending => QuietCensus::Pending,
            LinkCensus::Empty => QuietCensus::Empty,
            LinkCensus::Held { seats, since } => QuietCensus::Held {
                seats,
                since: since.tick().get(),
            },
        },
    }
}

/// The Tor connector's tally as the core's input (§4.2). Display only
/// (`TSR-Q14`).
fn tally_input(tally: LinkTally) -> Input {
    Input::DialEvidence(dial_tally(tally))
}

/// The Tor connector's onion-path fact as the core's input (§4.5a). A want
/// carries a CSPRNG draw for the check's delay, as a round's probe does.
fn path_input(fact: PathFact, network: &Network) -> Input {
    match fact {
        PathFact::OnionDialOpened(at) => Input::OnionDialOpened {
            at: at.tick().get(),
        },
        PathFact::InboundTorSession(at) => Input::InboundTorSession {
            at: at.tick().get(),
        },
        PathFact::Wanted(after) => Input::PathWanted {
            after: after.tick().get(),
            draw: network.probe_delay_draw(),
        },
    }
}

/// The relay's published verdict as the core's input.
///
/// The supervisor does not depend on the relay. The variants are the same
/// three states, mapped one for one.
fn verdict_input(verdict: OriginVerdict) -> Input {
    Input::AddressHidingOrigin(match verdict {
        OriginVerdict::Absent => FoldedOrigin::Absent,
        OriginVerdict::Connected => FoldedOrigin::Connected,
        OriginVerdict::Routable => FoldedOrigin::Routable,
    })
}

/// The sessions each connector holds, as the core's input (`TSR-Q12`).
fn sessions_input(held: PerConnector<u32>) -> Input {
    Input::Sessions(Sessions {
        clearnet: held.clearnet,
        tor: held.tor,
    })
}

/// What the supervisor supervises.
enum Supervises {
    /// A Tor this daemon launches, from this binary, publishing this onion.
    Managed {
        /// Where the binary comes from.
        pin: PinSource,
        /// Where the onion's key comes from.
        onion: OnionSource,
    },
    /// A Tor this node does not run: `off`, or an operator's.
    Unmanaged(TorSetting),
}

/// Where the managed Tor's onion key comes from.
enum OnionSource {
    /// A new key at this boot (PWD-E7), held for the boot.
    PerBoot,
    /// The operator's key (`tor-onion-key-file`), loaded by the walk: the
    /// same onion at every boot.
    Persistent(OnionIdentity),
}

/// Where the binary a launch runs comes from.
enum PinSource {
    /// Discovered and checked against the pin: at the configured path, or
    /// the bundle's.
    Discover(Option<PathBuf>),
    /// A binary a test names, not checked (`unpinned-tor-for-tests`).
    #[cfg(all(test, unix))]
    Unchecked(shekyl_tor_control_client::binary::VerifiedTorBinary),
}

/// The loop: started, then run until its stop. A start that cannot be made
/// is the supervisor's end.
async fn drive(
    supervises: Supervises,
    policy: Policy,
    clearnet_on: bool,
    virtual_port: u16,
    data_dir: PathBuf,
    inbox: Inbox,
    network: Network,
) -> Result<(), SupervisorEnd> {
    Drive::start(
        supervises,
        policy,
        clearnet_on,
        virtual_port,
        data_dir,
        inbox,
        network,
    )?
    .run()
    .await
}

/// What a managed Tor holds for the boot: the binary's source, the onion
/// and its guards, and the probe's isolation pair. Under `off` or an
/// operator's Tor the supervisor runs no Tor and holds none of it.
struct ManagedBoot {
    /// Where the binary comes from.
    pin: PinSource,
    /// The boot's onion identity: the keypair Tor is handed on every
    /// publish, held until the daemon stops. Shared with the publish's task,
    /// never copied.
    onion: Arc<OnionIdentity>,
    /// A persistent onion's kept guards, handed to every launch; `None` for
    /// a per-boot onion.
    guard_state: Option<GuardState>,
    /// The probe's isolation pair, held beside the onion for the boot.
    probe_pair: IsolationPair,
}

impl ManagedBoot {
    /// The boot's secrets for a managed Tor: a persistent onion and its
    /// guards, or a new onion; and the probe's isolation pair, minted beside
    /// the onion and held with it for the boot (§4.5), so the probe's
    /// circuits are its own.
    fn mint(pin: PinSource, onion: OnionSource, data_dir: &Path) -> Result<Self, SupervisorEnd> {
        // A persistent onion keeps its guards beside the directory cache, in
        // a directory of its own (`TSR-Q2` as amended); a per-boot onion keeps
        // none. Both mints fail only when the random source refuses.
        let (onion, guard_state) = match onion {
            OnionSource::Persistent(onion) => {
                let guards = GuardState::for_onion(data_dir, onion.service_id().as_str());
                (onion, Some(guards))
            }
            OnionSource::PerBoot => (
                DaemonTorControl::mint_identity().map_err(|_| SupervisorEnd::NoOnionKey)?,
                None,
            ),
        };
        let probe_pair = IsolationPair::mint().map_err(|_| SupervisorEnd::NoProbeIsolation)?;
        Ok(Self {
            pin,
            onion: Arc::new(onion),
            guard_state,
            probe_pair,
        })
    }
}

impl Drive {
    /// The driver, its core started and the network's state at start
    /// folded; the supervisor's end when a scheduler or a managed Tor's
    /// secrets are not to be had.
    fn start(
        supervises: Supervises,
        policy: Policy,
        clearnet_on: bool,
        virtual_port: u16,
        data_dir: PathBuf,
        inbox: Inbox,
        network: Network,
    ) -> Result<Self, SupervisorEnd> {
        let engine = network.engine();
        let owner = engine
            .register(OwnerClass::Housekeeping)
            .map_err(SupervisorEnd::NoScheduler)?;
        let (tor, managed) = match supervises {
            Supervises::Managed { pin, onion } => (
                TorSetting::Managed,
                Some(ManagedBoot::mint(pin, onion, &data_dir)?),
            ),
            Supervises::Unmanaged(setting) => (setting, None),
        };
        let connectors = Connectors { tor, clearnet_on };
        let clock = owner.clock().clone();
        let poster = inbox.poster();
        let timer = Timer::start(owner, poster.clone());
        let started = clock.now().get();
        let (core, step) = Core::start(policy, connectors, started);
        let mut drive = Drive {
            core,
            step,
            clock,
            managed,
            data_dir,
            events: poster.events(),
            poster,
            inbox,
            timer,
            forward: None,
            virtual_port,
            network,
            service: None,
            rounds: None,
            dropped_seen: 0,
            probe: None,
            network_view: NetworkView::default(),
            control: None,
            kept: None,
            next_pin: PinCheck::Start,
            incarnation: None,
            generation: 0,
            held: None,
            launch: None,
        };
        // What the network published before this loop: the relay's verdict,
        // the tally and the sessions at start. Folded after the start's own
        // step, so the pin check stays the first action. The tally's failures
        // were launched before this Tor ran, and the quiet line leaves them out
        // (`DIALER_OUTAGE_EVIDENCE.md` §6.1).
        let first = drive.changed_inputs();
        drive.fold_after_start(first, started);
        Ok(drive)
    }

    /// The managed Tor `ask` needs.
    ///
    /// The core asks for a pin, a launch, a publish or a probe only while it
    /// runs this node's Tor (`AbsentDuty::Unmanaged` asks for none). Without
    /// one the ask is [`SupervisorEnd::NoTorToRun`], and the caller returns
    /// that before it changes a launch, a publish or a probe.
    fn boot_for(&self, ask: TorAsk) -> Result<&ManagedBoot, SupervisorEnd> {
        self.managed.as_ref().ok_or(SupervisorEnd::NoTorToRun(ask))
    }
}

/// The process, the directory, and the route. The phase lives in [`Core`].
struct Drive {
    core: Core,
    step: Step,
    /// The process clock: the network's, which the dialer's stamps are on.
    clock: MonotonicClock,
    /// What a Tor this daemon launches holds for the boot; `None` under
    /// `off` or an operator's Tor.
    managed: Option<ManagedBoot>,
    data_dir: PathBuf,
    /// The sink Tor's control connection routes its events into. Each
    /// incarnation gets a clone; the drop count spans them all.
    events: EventSink,
    /// This loop's own producers post through this: deaths, bootstrap
    /// transitions.
    poster: inbox::Poster,
    /// What happened, and the cells.
    inbox: Inbox,
    /// The deadline's producer.
    timer: Timer,
    /// The zone host's forward listener, once bound.
    forward: Option<SocketAddr>,
    virtual_port: u16,
    /// The network the route, the onion and the inbound facet are
    /// published on, and the probe is minted and dialed through.
    network: Network,
    /// The onion as last sent to Tor (`ADD_ONION`).
    service: Option<ServiceId>,
    /// That onion's descriptor upload rounds (`TSR-Q5`).
    rounds: Option<UploadRounds>,
    /// The event sink's drop count already resynchronised.
    dropped_seen: u64,
    /// The probe in flight. The nonce lives on this driver; aborting the
    /// dial does not erase it ([`probe::Flight`]).
    probe: Option<probe::Flight>,
    /// Tor's sampled view at the last Running sample, logged when it changes.
    network_view: NetworkView,
    control: Option<DaemonTorControl>,
    kept: Option<KeptDataDir>,
    /// Which check of the Tor binary the next pin is.
    next_pin: PinCheck,
    incarnation: Option<u64>,
    /// The incarnation a death or a bootstrap transition must name to be
    /// folded. It moves at each spawn and each reap, so the stop's own
    /// death is not a second fault.
    generation: u64,
    /// The last task that holds a Tor or a directory: a launch, a reap, or
    /// the end of what a stale answer held. The next waits for it, and so
    /// does the stop ([`Self::hold`]).
    held: Option<JoinHandle<()>>,
    /// The launch in flight, by its number, and the signal that abandons
    /// its wait for Tor's first reply ([`Self::abandon_launch`]).
    launch: Option<(u64, watch::Sender<bool>)>,
}

/// What [`Drive::perform`] decided for the loop.
enum Performed {
    /// The queue ran out. Wait for the next arrival.
    Waiting,
    /// [`Action::StopChild`]: tear down and return.
    Stopping,
    /// Tear down as at a stop, then end with this. The action's inputs are
    /// not folded.
    Ending(SupervisorEnd),
}

/// What one action produced. A Tor ask with no managed Tor is the `Err` of
/// [`Drive::act`], and nothing here is folded.
enum Acted {
    /// Inputs to fold, in order.
    Fold(Vec<Input>),
    /// [`Action::StopChild`].
    Stop,
}

impl Acted {
    fn fold(inputs: Vec<Input>) -> Self {
        Self::Fold(inputs)
    }
}

impl Drive {
    /// Run until the daemon stops the loop, or until a Tor action is asked
    /// with no managed Tor. Either way the work that holds a Tor or a
    /// directory ends first. `Err` is that ask.
    async fn run(mut self) -> Result<(), SupervisorEnd> {
        let ending = loop {
            match self.perform() {
                Performed::Waiting => {}
                Performed::Stopping => break None,
                Performed::Ending(end) => break Some(end),
            }
            // A launch the core gave up on, in this pass or by what was
            // just performed, stops waiting.
            self.abandon_launch(false);
            // Captured before the wait. The wait's lateness is this
            // interval, not how late a deadline stored during `perform`
            // looks afterwards.
            let armed = self.step.deadline;
            let wanted = self.timer.want(armed);
            let entered = self.now();
            let woken = self.inbox.wait().await;
            let woke = self.now();
            let lead = slept(armed, entered, woke).map(|late_by| Input::Resumed { late_by });
            self.pass(woken, lead, woke, wanted);
        };
        // The stop. A launch still waiting for Tor stops waiting, and the
        // work that holds a Tor or a directory ends before the supervisor
        // does: what its answers hold is ended here, so no Tor and no
        // directory outlives the stop.
        self.abandon_launch(true);
        self.cancel_probe();
        if let Some(held) = self.held.take() {
            if let Err(error) = held.await {
                tracing::warn!(target: "tor", "Tor's process work ended abnormally at the stop: {error}");
            }
        }
        for answer in self.inbox.replies_left() {
            answer.discard().await;
        }
        if let Some(control) = self.control.take() {
            let teardown = control.shutdown().await;
            say_kept(&teardown.saved);
            if let Some(retirement) = teardown.retirement {
                say_retirement(&retirement);
            }
        }
        // Tor was down at the stop: the directory held for its respawn ends
        // here, the same way.
        if let Some(kept) = self.kept.take() {
            say_retirement(&kept.retire().await);
        }
        ending.map_or(Ok(()), Err)
    }

    /// Fold what the network published before the loop, after the start's
    /// own step: its actions follow the start's, and an empty batch leaves
    /// the start's deadline.
    fn fold_after_start(&mut self, inputs: Vec<Input>, at: u64) {
        let start = std::mem::replace(
            &mut self.step,
            Step {
                actions: Vec::new(),
                deadline: None,
            },
        );
        self.fold_at(inputs, at);
        let folded = std::mem::replace(&mut self.step, start);
        if !folded.actions.is_empty() || folded.deadline.is_some() {
            self.step.actions.extend(folded.actions);
            self.step.deadline = folded.deadline;
        }
    }

    /// Perform every action the last fold produced. Inputs from one action
    /// are folded in order and their actions run in that order, ahead of
    /// anything already queued. [`Performed::Stopping`] is the daemon's
    /// stop. [`Performed::Ending`] is a Tor action this supervisor cannot
    /// run, and nothing that action returned is folded.
    fn perform(&mut self) -> Performed {
        let mut queue: VecDeque<Action> = self.step.actions.drain(..).collect();
        while let Some(action) = queue.pop_front() {
            let inputs = match self.act(action) {
                Ok(Acted::Fold(inputs)) => inputs,
                Ok(Acted::Stop) => return Performed::Stopping,
                Err(end) => return Performed::Ending(end),
            };
            let mut produced = Vec::new();
            for input in inputs {
                self.fold(input);
                produced.append(&mut self.step.actions);
            }
            for action in produced.into_iter().rev() {
                queue.push_front(action);
            }
        }
        Performed::Waiting
    }

    /// Fold one observation. See [`Self::fold_many`].
    fn fold(&mut self, input: Input) {
        self.fold_many(vec![input]);
    }

    /// Fold `inputs` at the driver's clock. See [`Self::fold_at`].
    fn fold_many(&mut self, inputs: Vec<Input>) {
        self.fold_at(inputs, self.now());
    }

    /// Fold `inputs` as one step at `at`. Each transition's actions are kept,
    /// in order, and the deadline is the last transition's. An empty list
    /// leaves the step alone, so a batch that carried nothing does not
    /// disarm a wait that is already armed. A process that ended is reaped
    /// by the core's [`Action::Reap`] request, off the loop.
    fn fold_at(&mut self, inputs: Vec<Input>, at: u64) {
        if inputs.is_empty() {
            return;
        }
        let mut actions = Vec::new();
        let mut deadline = None;
        for input in inputs {
            let step = self.core.on(input, at);
            actions.extend(step.actions);
            deadline = step.deadline;
        }
        self.step = Step { actions, deadline };
    }

    /// A probe this core no longer wants is dropped. A request that no
    /// longer stands is withheld in the core, at its turn in the queue.
    fn withheld(&self, action: &Action) -> Option<Vec<Input>> {
        (matches!(action, Action::Probe) && !self.core.action_stands(action)).then(Vec::new)
    }

    /// Run `action`. `Err` is a Tor ask with no managed Tor: [`TorAsk::of`]
    /// names it, and a withdrawn probe or a request that is no longer in
    /// flight does not get to swallow the ask.
    fn act(&mut self, action: Action) -> Result<Acted, SupervisorEnd> {
        if let Some(ask) = TorAsk::of(&action) {
            self.boot_for(ask)?;
        }
        if let Some(instead) = self.withheld(&action) {
            return Ok(Acted::fold(instead));
        }
        Ok(match action {
            Action::Announce => {
                let text = self.said();
                if self.core.status().health {
                    tracing::info!(target: "global", "{text}");
                } else {
                    tracing::warn!(target: "global", "{text}");
                }
                Acted::fold(Vec::new())
            }
            // The progress line is news. The core only asks for it when no
            // cause is set, so this arm does not re-read the posture.
            Action::SayProgress => {
                let text = self.said();
                tracing::info!(target: "global", "{text}");
                Acted::fold(Vec::new())
            }
            Action::CheckPin => Acted::fold(vec![self.pin()?]),
            // A request: sent off the loop, answered as an arrival. The
            // action moves: a launch's binary is the driver's to spawn.
            action @ (Action::Reap
            | Action::Spawn(_)
            | Action::SubscribeEvents
            | Action::Sample
            | Action::SetConfAvoidDiskWrites
            | Action::RepublishOnion
            | Action::AddOnion
            | Action::RefetchDescriptor
            | Action::CheckDirectories
            | Action::FetchFromDirectory { .. }) => Acted::fold(self.send(action)?),
            Action::WatchState => Acted::fold(self.watch_state().into_iter().collect()),
            Action::Publish(route) => Acted::fold(vec![self.publish_route(route)]),
            Action::Probe => Acted::fold(vec![self.probe()?]),
            Action::CancelProbe => {
                self.cancel_probe();
                Acted::fold(Vec::new())
            }
            Action::RoundStuck { descriptor } => Acted::fold(self.round_stuck(descriptor)),
            Action::Resumed { late_by } => {
                // Milliseconds, not whole seconds: a wake 10 s and a
                // fraction late is past the threshold, and whole seconds
                // would record it as the threshold itself.
                let late_by_ms = u64::try_from(late_by.as_millis()).unwrap_or(u64::MAX);
                tracing::info!(
                    target: "tor",
                    late_by_ms,
                    "a timer the supervisor was waiting on came due late: this machine slept, and its windows start again from the wake"
                );
                Acted::fold(Vec::new())
            }
            Action::ProbeAfterJump => Acted::fold(vec![probe::jump_probe(&self.network)]),
            Action::DirectoriesUnmatched => {
                tracing::info!(
                    target: "tor",
                    "no directory the last upload round reached holds the descriptor Tor's client asks for; the probe alone decided"
                );
                Acted::fold(Vec::new())
            }
            Action::DirectoriesSettled(report) => {
                for line in report {
                    tracing::debug!(
                        target: "tor",
                        hsdir = ?line.hsdir,
                        upload = ?line.upload,
                        answer = ?line.answer,
                        counted = ?line.counted,
                        "this onion's descriptor at one directory, as the directory check counted it"
                    );
                }
                Acted::fold(Vec::new())
            }
            Action::DescriptorOverdue => {
                tracing::info!(
                    target: "tor",
                    "no descriptor upload began within the descriptor's lifetime"
                );
                Acted::fold(Vec::new())
            }
            Action::PublishInbound(inbound) => {
                self.publish_inbound(inbound);
                Acted::fold(Vec::new())
            }
            Action::PathReading(PathReading { path, at }) => {
                tracing::debug!(target: "tor", ?path, "the onion-path reading");
                let reading = match path {
                    OnionPath::Working => Reading::Working,
                    OnionPath::Impaired => Reading::Impaired,
                };
                self.network.publish_onion_path(reading, at);
                Acted::fold(Vec::new())
            }
            Action::TakeDown => {
                self.withdraw_route(DownCause::ProcessExited);
                Acted::fold(Vec::new())
            }
            Action::StopRoute => {
                self.withdraw_route(DownCause::ProcessStopped);
                Acted::fold(Vec::new())
            }
            Action::StopChild => Acted::Stop,
        })
    }

    /// Fold one pass: the sleep the wait observed first, so what woke the
    /// loop is judged on windows that start at the wake; then every cell
    /// that changed; then the arrival. A deadline is folded only when it
    /// names the generation the loop gave the deadline it waited with.
    fn pass(&mut self, woken: Woken, lead: Option<Input>, woke: u64, wanted: Option<Wanted>) {
        let changed = self.changed_inputs();
        let mut inputs = led(lead, changed);
        let arrival = match woken {
            Woken::Arrived(arrival) => arrival,
            Woken::Rang => {
                self.fold_at(inputs, woke);
                return;
            }
        };
        match arrival {
            Arrival::Deadline { generation } => {
                self.fold_at(inputs, woke);
                if wanted.is_some_and(|wanted| wanted.generation == generation) {
                    self.timer.spent();
                    let due = self.core.on_deadline(woke);
                    self.step.actions.extend(due.actions);
                    self.step.deadline = due.deadline;
                }
                return;
            }
            Arrival::Event(reply) => inputs.extend(self.event_inputs(&reply)),
            Arrival::Death { generation, how } => {
                if generation == self.generation {
                    inputs.extend(observed_death(how));
                }
            }
            Arrival::Bootstrap { generation, state } => {
                if generation == self.generation && self.control.is_some() {
                    inputs.push(self.bootstrap_input(state));
                }
            }
            Arrival::Probe(arrival) => {
                tracing::info!(target: "tor", "this node's onion probe arrived");
                inputs.push(Input::ProbeArrived {
                    minted_at: arrival.minted_at.get(),
                    arrived_at: arrival.arrived_at.get(),
                });
            }
            Arrival::Path(fact) => inputs.push(path_input(fact, &self.network)),
            Arrival::Reply { number, answer } => inputs.extend(self.answered(number, *answer)),
            Arrival::Status(reply) => {
                // Answered from the one place that holds the state, at once:
                // nothing on this loop waits on Tor. Every age is taken now.
                drop(reply.send(self.core.view(self.now())));
            }
            Arrival::Hiding(reply) => drop(reply.send(self.core.hiding())),
            Arrival::Stop => inputs.push(Input::Shutdown),
        }
        self.fold_at(inputs, woke);
    }

    /// The cells' values not yet folded, as inputs: the relay's verdict,
    /// the tally, the sessions. The forward listener is kept here; once
    /// bound, the endpoint is ready.
    fn changed_inputs(&mut self) -> Vec<Input> {
        let Changed {
            tally,
            verdict,
            sessions,
            forward,
        } = self.inbox.take_changed();
        let mut inputs = Vec::new();
        inputs.extend(verdict.map(verdict_input));
        inputs.extend(tally.map(tally_input));
        inputs.extend(sessions.map(sessions_input));
        if let Some(bound) = forward {
            self.forward = Some(bound);
            inputs.push(Input::EndpointReady);
        }
        inputs
    }

    /// One event batch from Tor: the round resync, this onion's descriptor
    /// line (one consumer), the clock evidence, and the statement, in that
    /// order, folded as one step.
    /// Folding each input on its own replaces the step, and the earlier
    /// actions, a recovery among them, would never be performed.
    fn event_inputs(&mut self, reply: &ControlReply) -> Vec<Input> {
        let mut inputs = self.round_resync();
        if let Some(parsed) = parse_event(reply) {
            // This onion's descriptor events, as Tor states them: which
            // directory, which descriptor (its blinded key), and how it
            // ended. A run reads them to see where a descriptor went.
            if let TorEvent::HsDesc(desc) = &parsed {
                if desc.address.is_some() && desc.address == self.service {
                    tracing::debug!(
                        target: "tor",
                        action = ?desc.action,
                        hsdir = ?desc.hsdir,
                        descriptor_id = ?desc.descriptor_id,
                        reason = ?desc.reason,
                        "Tor's descriptor event"
                    );
                    // One consumer: an upload's line is the round's, a fetch's
                    // is the directory check's.
                    inputs.extend(self.read_hs_desc(desc));
                }
            }
            // A directory's copy of this onion's descriptor, after a fetch:
            // its counter is the directory check's answer. The descriptor
            // itself is not logged.
            if let TorEvent::HsDescContent(content) = &parsed {
                if content.address.is_some() && content.address == self.service {
                    tracing::debug!(
                        target: "tor",
                        hsdir = ?content.hsdir,
                        descriptor_id = ?content.descriptor_id,
                        revision_counter = ?content.revision_counter,
                        "a directory's copy of this onion's descriptor"
                    );
                    inputs.extend(directory_content_input_of(content));
                }
            }
            // Tor's own log line, in the daemon's log (§4.10). A run reads
            // why Tor did what it did here, after the daemon has stopped.
            if let TorEvent::Log(line) = &parsed {
                say_tor_log(line);
            }
            // Evidence first: a problem that is also the blocked link is
            // judged against the clock it may already name.
            if let Some(input) = clock_evidence_of(&parsed) {
                tracing::debug!(target: "tor", "Tor's clock evidence {input:?}");
                inputs.push(input);
            }
            if let Some(input) = input_of(&parsed) {
                // A Tor statement the supervisor acts on, said as it
                // arrives: what a run records.
                tracing::info!(target: "tor", "Tor says {input:?}");
                inputs.push(input);
            }
        }
        inputs
    }

    /// Check the binary a managed Tor launches.
    fn pin(&mut self) -> Result<Input, SupervisorEnd> {
        let verified = {
            let source = &self.boot_for(TorAsk::Pin)?.pin;
            match source {
                PinSource::Discover(Some(path)) => discover_and_verify_at(path),
                PinSource::Discover(None) => discover_and_verify(),
                #[cfg(all(test, unix))]
                PinSource::Unchecked(binary) => Ok(binary.clone()),
            }
        };
        let input = match verified {
            Ok(binary) => Input::PinAccepted { binary },
            Err(error) => {
                self.next_pin.say_refusal(&error);
                classify_pin(&error).input
            }
        };
        self.next_pin = PinCheck::Recheck;
        Ok(input)
    }

    fn watch_state(&self) -> Option<Input> {
        let path = self.control.as_ref()?.data_path()?;
        path.join("state")
            .is_file()
            .then_some(Input::StateFileAppeared)
    }

    /// Publish the route on the network's Tor link. The network outlives
    /// the supervisor, so the link is always there to take it; the core's
    /// `HostAbsent` input, for a zone host not yet bound, has no producer.
    fn publish_route(&mut self, route: ManagedRunning) -> Input {
        let installed = self.network.publish_managed_running(route.socks());
        self.incarnation = Some(installed);
        // A facet decided before the route was in has no incarnation to
        // name until now.
        self.publish_inbound(self.core.status().inbound);
        Input::RouteInstalled
    }

    fn withdraw_route(&mut self, cause: DownCause) {
        if let Some(id) = self.incarnation.take() {
            let _fell = self.network.publish_tor_down(id, cause);
        }
    }

    /// The pre-spawn space check (`TOR_SUPERVISOR.md` §5, "Data directory
    /// unusable"). `fresh` is the spawn's own bit: a new directory needs
    /// Tor's write headroom plus the cache copy, and a kept one needs the
    /// headroom. A disk that fills after the spawn is not this check's.
    /// A probe that cannot read the disk lets the spawn go ahead: "I cannot
    /// tell" is not "full".
    /// The bootstrap's state as the core reads it. `Ready` and `Failed`
    /// arrive once: the incarnation's producer stops after either.
    fn bootstrap_input(&mut self, state: BootstrapState) -> Input {
        match state {
            BootstrapState::Ready => {
                if let Some(control) = self.control.as_mut() {
                    control.mark_bootstrapped();
                }
                Input::BootstrapComplete
            }
            BootstrapState::Failed => Input::ControlEnded,
            BootstrapState::Connecting { progress } => Input::BootstrapNoted { progress },
        }
    }

    /// The status in words, as every client says it: the supervisor's
    /// snapshot through the one renderer. The daemon's own log names its
    /// data directory.
    fn said(&self) -> String {
        let data_dir = self.data_dir.display().to_string();
        render(&self.core.view(self.now()), Some(&data_dir))
    }

    fn now(&self) -> u64 {
        self.clock.now().get()
    }
}

/// One incarnation's producer: its bootstrap transitions, then its death,
/// posted with its generation. It ends with the process. The bootstrap
/// watch leaves it after `Ready` or `Failed`, or when its sender closes:
/// nothing follows either, and a closed watch answers at once, every time.
async fn incarnation(
    generation: u64,
    death: impl std::future::Future<Output = TorDeath>,
    mut bootstrap: tokio::sync::watch::Receiver<BootstrapState>,
    poster: inbox::Poster,
) {
    let mut watching = true;
    tokio::pin!(death);
    loop {
        tokio::select! {
            biased;
            how = &mut death => {
                poster.post(Arrival::Death { generation, how });
                return;
            }
            moved = bootstrap.changed(), if watching => {
                if moved.is_err() {
                    watching = false;
                    continue;
                }
                let state = *bootstrap.borrow_and_update();
                watching = !matches!(state, BootstrapState::Ready | BootstrapState::Failed);
                poster.post(Arrival::Bootstrap { generation, state });
            }
        }
    }
}

/// A pass's first inputs: the sleep the wait observed, then the cells that
/// changed. What woke the loop is judged on windows that start at the
/// wake.
fn led(lead: Option<Input>, changed: Vec<Input>) -> Vec<Input> {
    lead.into_iter().chain(changed).collect()
}

/// How late a wait armed with `armed` at `entered` returned at `woke`, when
/// that is a sleep ([`resume_lateness`]). A deadline already past when the
/// wait began has no time left: a return more than `RESUMED_AFTER` later
/// is still a sleep. With no deadline armed nothing can be late.
fn slept(armed: Option<u64>, entered: u64, woke: u64) -> Option<Duration> {
    let due = armed?;
    let until_due = Duration::from_nanos(due.saturating_sub(entered));
    let waited = Duration::from_nanos(woke.saturating_sub(entered));
    match resume_lateness(until_due, waited) {
        Resume::Slept { late_by } => Some(late_by),
        Resume::Awake => None,
    }
}

/// A death the phase treats as the process ending. A stop is not one:
/// the driver asked for it.
fn observed_death(death: TorDeath) -> Option<Input> {
    match death {
        TorDeath::Stopped => None,
        TorDeath::Exited { code } => Some(Input::ProcessEnded { exit_code: code }),
    }
}

/// The data directory's free space against what a launch needs, read after
/// any replacement (§5, "Data directory unusable"). `new_directory` counts
/// the cache a created directory is seeded from; a reused one already holds
/// it. An unreadable figure starts Tor anyway.
fn space_short(data_dir: &Path, new_directory: bool) -> Option<Input> {
    let needed = space_needed(data_dir, new_directory);
    match shekyl_node::free_bytes(data_dir) {
        Ok(available) if available < needed => Some(Input::DirectoryUnusable {
            space: Some(Space { available, needed }),
        }),
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(
                target: "global",
                path = %data_dir.display(),
                %error,
                "the free space for Tor's data directory could not be read; starting Tor anyway"
            );
            None
        }
    }
}

fn input_of_ask(_error: &DaemonTorStartError) -> Input {
    // The core holds the reply bound, so an ask that ends without an answer
    // is the control connection ending: a control error or a dead actor.
    Input::ControlEnded
}

/// A consensus ask beside the wall time it is compared with. `Ok(None)` is
/// Tor with no `valid-after` yet, or no wall time to compare. An ask that
/// failed is the process fault [`input_of_ask`] names.
fn consensus_sample(
    asked: Result<Option<u64>, &DaemonTorStartError>,
    wall: Option<u64>,
) -> Result<Option<Input>, Input> {
    let valid_after = asked.map_err(input_of_ask)?;
    Ok(valid_after
        .zip(wall)
        .map(|(valid_after, wall)| Input::ConsensusClock { valid_after, wall }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logged;
    use shekyl_tor_status::TorCause;

    /// A bootstrap sample does not ask Tor about its network. A Running
    /// sample does (§4.2): "no circuit" during bootstrap is not a statement.
    #[test]
    fn a_bootstrap_sample_does_not_ask_tor_about_its_network() {
        let bootstrap = sample_keys(false);
        assert!(!bootstrap.iter().any(|key| key == NETWORK_LIVENESS));
        assert!(!bootstrap.iter().any(|key| key == CIRCUIT_ESTABLISHED));
        let running = sample_keys(true);
        assert!(running.iter().any(|key| key == NETWORK_LIVENESS));
        assert!(running.iter().any(|key| key == CIRCUIT_ESTABLISHED));
        assert!(running.starts_with(&bootstrap));
    }

    /// A consensus ask that fails is a process fault: the control ended
    /// (the core holds the reply bound, so no ask here times out). Tor having
    /// no `valid-after` yet, or no wall time to compare, is no clock input.
    /// Fails if `consensus_sample` turns a failed ask into `Ok(None)`: the
    /// supervisor would keep a dead control connection and never name the
    /// clock.
    #[test]
    fn a_failed_consensus_ask_is_a_process_fault_and_a_missing_consensus_is_not() {
        let closed = DaemonTorStartError::Control(
            shekyl_tor_control_client::control::ControlError::ConnectionClosed,
        );
        let gone = DaemonTorStartError::Died(None);
        assert_eq!(
            consensus_sample(Err(&closed), Some(1)),
            Err(Input::ControlEnded)
        );
        assert_eq!(
            consensus_sample(Err(&gone), Some(1)),
            Err(Input::ControlEnded)
        );
        assert_eq!(consensus_sample(Ok(None), Some(1)), Ok(None));
        assert_eq!(consensus_sample(Ok(Some(10)), None), Ok(None));
        assert_eq!(
            consensus_sample(Ok(Some(10)), Some(20)),
            Ok(Some(Input::ConsensusClock {
                valid_after: 10,
                wall: 20,
            }))
        );
    }

    /// The managed Tor answers inside the Tor dial deadline: a blocked link
    /// is Tor's `0x06`, never a race with the deadline (case A, 2026-10-25:
    /// both were 120 s and the outcomes alternated). Launching with Tor's
    /// default, or setting it from another deadline, fails this.
    #[test]
    fn the_managed_tor_answers_inside_the_dial_deadline() {
        let timeout: u64 = SOCKS_TIMEOUT
            .as_arg()
            .expect("the daemon sets it")
            .parse()
            .expect("whole seconds");
        let deadline = shekyl_p2p::TOR_DIAL_WITHIN.as_secs();
        assert!(timeout < deadline, "{timeout} s inside {deadline} s");
        assert!(timeout >= deadline / 2, "not far inside it");
        // The dialer reads the same window the Tor is launched with: an
        // attempt failing at or after it is final within its test.
        assert_eq!(
            TOR_SOCKS_TIMEOUT.window(),
            Some(Duration::from_secs(timeout)),
            "one window"
        );
        assert_eq!(timeout, 105, "120 s less the 15 s margin");
        assert_eq!(
            TOR_SOCKS_TIMEOUT.earliest_expiry(),
            Some(Duration::from_secs(104)),
            "Tor counts a stream's age in whole seconds"
        );
    }

    fn secs(seconds: u64) -> u64 {
        seconds * 1_000_000_000
    }

    fn duration_ns_of(duration: Duration) -> u64 {
        u64::try_from(duration.as_nanos()).expect("fits")
    }

    /// At a wake the dialer's timers fire too, so a dial result can be in
    /// its cell when the late wait returns. The pass folds the sleep before
    /// it, so it is judged on windows that start at the wake (§5, "Resumed
    /// from suspend"). Folding the cells ahead of the lead fails this; so
    /// does judging the sleep only when a deadline woke the loop.
    #[test]
    fn a_wake_with_a_dial_result_waiting_folds_the_resume_first() {
        use shekyl_tor_control_client::control::RESUMED_AFTER;
        let due = secs(30);
        let woke = due + duration_ns_of(RESUMED_AFTER) + secs(1);
        let lead = slept(Some(due), 0, woke).map(|late_by| Input::Resumed { late_by });
        let tally = tally_input(LinkTally::default());
        let batch = led(lead, vec![tally]);
        assert!(
            matches!(
                batch.as_slice(),
                [Input::Resumed { .. }, Input::DialEvidence(_)]
            ),
            "the resume is folded first: {batch:?}"
        );
        let on_time = due + duration_ns_of(RESUMED_AFTER);
        let lead = slept(Some(due), 0, on_time).map(|late_by| Input::Resumed { late_by });
        assert_eq!(lead, None, "a wake on time is not a sleep");
    }

    /// A deadline already past when the wait began has no time left; a
    /// return more than `RESUMED_AFTER` later is still a sleep. With no
    /// deadline armed nothing is late.
    #[test]
    fn a_wait_is_late_against_the_deadline_it_was_armed_with() {
        use shekyl_tor_control_client::control::RESUMED_AFTER;
        let after = duration_ns_of(RESUMED_AFTER);
        assert_eq!(slept(Some(secs(5)), secs(10), secs(10) + after), None);
        assert_eq!(
            slept(Some(secs(5)), secs(10), secs(11) + after),
            Some(Duration::from_nanos(secs(1) + after))
        );
        assert_eq!(slept(None, 0, secs(3600)), None);
    }

    /// An exit reaches the phase with its code. A stop does not. Swapping
    /// the arms fails this.
    #[test]
    fn an_exit_reaches_the_phase_and_a_stop_does_not() {
        assert_eq!(
            observed_death(TorDeath::Exited { code: Some(9) }),
            Some(Input::ProcessEnded { exit_code: Some(9) })
        );
        assert_eq!(
            observed_death(TorDeath::Exited { code: None }),
            Some(Input::ProcessEnded { exit_code: None })
        );
        assert_eq!(observed_death(TorDeath::Stopped), None);
    }

    /// One class for the core and the posture. A missed discovery names the
    /// paths it searched; the clearnet sentence is the connector's, not a
    /// hedge. The words are the posture's, so a second sentence table fails
    /// this.
    #[test]
    fn a_refused_pin_is_one_class_and_speaks_the_posture() {
        let searched = PathBuf::from("/srv/missing/tor");
        let missing = TorBinaryError::NotFound {
            searched: vec![searched.clone()],
        };
        let class = classify_pin(&missing);
        assert_eq!(class.input, Input::BundleMissing);
        assert_eq!(class.cause, Cause::BundleMissing);
        let line = pin_warning_line(&missing, false);
        let sentence = install_sentence(&TorCause::Missing).expect("an install cause");
        assert!(line.contains(sentence));
        assert!(line.contains(searched.to_str().unwrap()));
        assert!(line.contains(&held_at_start_sentence(false)));
        assert!(!line.contains(&held_at_start_sentence(true)));

        let unavailable = TorBinaryError::Unavailable {
            reason: "no bundle for this target",
        };
        let class = classify_pin(&unavailable);
        assert_eq!(class.input, Input::Unavailable);
        assert_eq!(class.cause, Cause::Unavailable);
        let line = pin_warning_line(&unavailable, true);
        let sentence = install_sentence(&TorCause::Unavailable).expect("an install cause");
        assert!(line.contains(sentence));
        assert!(line.contains("no bundle for this target"));
        assert!(line.contains(&held_at_start_sentence(true)));

        let refused = TorBinaryError::NotAFile(PathBuf::from("/srv/tor-dir"));
        let class = classify_pin(&refused);
        assert_eq!(class.input, Input::PinRefused);
        assert_eq!(class.cause, Cause::PinRefused);
        assert_eq!(wire_cause(&class.cause), Some(TorCause::InstallDefect));
        let line = pin_warning_line(&refused, false);
        let sentence = install_sentence(&TorCause::InstallDefect).expect("an install cause");
        assert!(line.contains(sentence));
        assert!(line.contains("was not started"));
        assert!(line.contains("/srv/tor-dir"));
        assert!(line.contains(&held_at_start_sentence(false)));
    }

    /// **A running re-check's refusal names the file and the reason** (Rick,
    /// 2026-11-12): the status carries no path, so the log does. The first
    /// pin's refusal is the start's announcement and is not said twice.
    /// Fails if the re-check's error is thrown away, or the first is said
    /// again.
    #[test]
    fn a_re_checks_refusal_names_the_file_and_the_reason() {
        let refused = TorBinaryError::NotExecutable(PathBuf::from("/srv/tor/tor"));
        let first = logged(|| PinCheck::Start.say_refusal(&refused));
        assert!(first.is_empty(), "{first}");
        let again = logged(|| PinCheck::Recheck.say_refusal(&refused));
        assert_eq!(again.lines().count(), 1, "{again}");
        assert!(again.contains("WARN"), "{again}");
        assert!(again.contains("/srv/tor/tor"), "{again}");
        assert!(again.contains("not executable"), "{again}");
        assert!(again.contains("failed its check"), "{again}");
    }

    /// Tor's log lines reach the daemon's log under `tor`, each at Tor's own
    /// severity (§4.10). Red edit: log every line at `info`, and the warning
    /// and the error read as notices.
    #[test]
    fn tors_log_lines_reach_the_daemons_log_at_tors_severity() {
        let line = |severity, message: &str| LogEvent {
            severity,
            message: message.to_owned(),
        };
        let out = logged(|| {
            say_tor_log(&line(LogSeverity::Notice, "Bootstrapped 100% (done): Done"));
            say_tor_log(&line(LogSeverity::Warn, "Problem bootstrapping."));
            say_tor_log(&line(LogSeverity::Err, "Couldn't open file for 'Log'"));
        });
        let lines: Vec<&str> = out.lines().map(str::trim).collect();
        assert_eq!(
            lines,
            vec![
                "INFO tor: Tor: Bootstrapped 100% (done): Done",
                "WARN tor: Tor: Problem bootstrapping.",
                "ERROR tor: Tor: Couldn't open file for 'Log'",
            ]
        );
    }

    /// A control character in Tor's text, which can carry what a relay sent,
    /// does not reach the log as itself. Red edit: log the text as Tor sent
    /// it, and the escape sequence is in the log.
    #[test]
    fn a_control_character_in_tors_text_is_replaced() {
        let out = logged(|| {
            say_tor_log(&LogEvent {
                severity: LogSeverity::Notice,
                message: "relay \u{1b}[31mred\u{7} said hi".to_owned(),
            });
        });
        assert!(!out.chars().any(|c| c.is_control() && c != '\n'), "{out:?}");
        assert!(
            out.contains("relay \u{fffd}[31mred\u{fffd} said hi"),
            "{out:?}"
        );
    }
}
