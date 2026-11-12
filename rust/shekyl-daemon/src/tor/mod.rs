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
//! [`inbox`]: one queue of what happened, in order, and one doorbell for
//! the cells that hold state. Each pass folds the sleep the wait observed,
//! then every cell that changed, then the one arrival that woke it.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use shekyl_daemon_config::sections::Tor;
use shekyl_node::Network;
use shekyl_p2p::{
    dial_profile, ConnectorId, DownCause, OriginVerdict, PerConnector, SupervisorFeeds, TorCensus,
    TorLinkTally, TOR_SOCKS_TIMEOUT,
};
use shekyl_timing_engine::{Clock, MonotonicClock, OwnerClass};
use shekyl_tor_control_client::binary::{
    discover_and_verify, discover_and_verify_at, TorBinaryError, VerifiedTorBinary,
};
use shekyl_tor_control_client::control::{
    parse_event, resume_lateness, BootstrapState, ControlReply, EventSink, LogEvent, LogSeverity,
    Resume, ServiceId, SocksTimeout, TorEvent, UploadRounds,
};
use shekyl_tor_control_client::onion_identity::OnionIdentity;
use shekyl_tor_control_client::supervisor::{
    clock_evidence_of, directory_content_input_of, input_of, wire_cause, Action, Cause, Connectors,
    Core, DialTally, Input, ManagedRunning, NetworkView, OriginVerdict as FoldedOrigin, Policy,
    Sessions, Space, Status, Step, TorCensus as QuietCensus, TorSetting,
};
use shekyl_tor_control_daemon::{
    space_needed, sweep_stale_data_dirs, CacheSave, DaemonTorControl, DaemonTorStartError,
    IsolationPair, KeptDataDir, KeptLog, Retirement, TombstoneEnd, TorDeath,
};
use shekyl_tor_status::{held_at_start_sentence, install_sentence, render};
use tokio::sync::watch;
use tokio::task::JoinHandle;

mod inbox;
#[cfg(all(test, unix))]
mod loop_tests;
mod probe;
mod requests;

use self::inbox::{inbox, Arrival, Changed, Inbox, Owner, Timer, Wanted, Woken};

/// The managed Tor answers a SOCKS request it cannot attach just inside the
/// Tor dial deadline, so the dial's class is Tor's reply, never a race with
/// that deadline (`TOR_SUPERVISOR.md` §4.2).
const SOCKS_TIMEOUT: SocksTimeout = TOR_SOCKS_TIMEOUT;
/// The supervisor's waits. Its quiet span is the managed Tor's
/// `SocksTimeout` plus the Tor connector's judging bracket δ
/// (`DIALER_OUTAGE_EVIDENCE.md` §6), both the Tor connector's own
/// declarations: a dial started at the judge's last sign of life has then
/// used Tor's retries, and its bracket has closed empty.
fn policy() -> Policy {
    let window = SOCKS_TIMEOUT
        .window()
        .expect("the daemon sets the managed Tor's SocksTimeout");
    let bracket = Duration::from_nanos(dial_profile(ConnectorId::Tor).judging.bracket_nanos);
    Policy::provisional(window + bracket)
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

/// The managed Tor's inbox, made before the node opens: the network's
/// producers publish into it from their first value (`TOR_SUPERVISOR.md`
/// §5). [`begin`] starts the supervisor on it.
pub struct Prepared {
    owner: Owner,
    inbox: Inbox,
}

/// The inbox for a managed Tor, and the feeds the network publishes into.
/// Any other posture has no supervisor and returns `None`.
#[must_use]
pub fn prepare(tor: &Tor) -> Option<(Prepared, SupervisorFeeds)> {
    let Tor::Managed { .. } = tor else {
        return None;
    };
    let (owner, inbox, feeds) = inbox();
    Some((Prepared { owner, inbox }, feeds))
}

/// The running supervisor. Dropping it stops the loop, as
/// [`Self::shutdown`] does, without waiting for Tor's directory to be torn
/// down.
pub struct Supervisor {
    owner: Owner,
    task: JoinHandle<()>,
}

impl Supervisor {
    /// The zone host's forward listener, once step 8 has bound it.
    pub fn note_forward(&self, forward: SocketAddr) {
        self.owner.forward(forward);
    }

    /// The supervisor's status now. The loop answers it in its next pass,
    /// from the one place that holds the state: it never waits on Tor, so
    /// a Tor that does not answer does not hold this (Rick, 2026-11-10).
    /// `None` once the loop has stopped.
    pub async fn status(&self) -> Option<Status> {
        self.owner.ask_status()?.await.ok()
    }

    /// Stop Tor and wait for the directory to be torn down.
    pub async fn shutdown(self) {
        let Self { mut owner, task } = self;
        owner.stop();
        let _joined = task.await;
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
        TorBinaryError::NotAFile(path)
        | TorBinaryError::NotExecutable(path)
        | TorBinaryError::NotTheExecutable(path)
        | TorBinaryError::UnsafeLoaderPath(path)
        | TorBinaryError::Io { path, .. }
        | TorBinaryError::HashMismatch { path, .. } => refused(path.clone()),
        TorBinaryError::UnexpectedEntry { dir, name } => refused(dir.join(name)),
        TorBinaryError::MissingFile { dir, name } => refused(dir.join(name)),
    }
}

/// The pin refused `path`: the file it rejected, or the entry a staged
/// directory carried or lacked (IG-F26).
fn refused(path: PathBuf) -> PinClass {
    PinClass {
        input: Input::PinRefused { path: path.clone() },
        cause: Cause::PinRefused { path },
    }
}

/// The warning text for a pin error. `error`'s display is the detail: a
/// `NotFound` lists `searched`, and the posture cause does not carry those
/// paths.
fn pin_warning_line(error: &TorBinaryError, clearnet_on: bool) -> String {
    let class = classify_pin(error);
    let sentence = wire_cause(&class.cause)
        .as_ref()
        .and_then(install_sentence)
        .expect("a pin class is an install cause");
    let consequence = held_at_start_sentence(clearnet_on);
    format!("warning: managed Tor: {sentence} ({error}) {consequence}")
}

/// Start the supervisor on its inbox when Tor is managed. Any other
/// posture returns `None`. `network` is where the route, the onion and the
/// inbound facet are published, and whose timing engine the supervisor's
/// waits are owned by.
#[must_use]
pub fn begin(
    prepared: Prepared,
    tor: &Tor,
    clearnet_on: bool,
    virtual_port: u16,
    data_dir: &Path,
    handle: &tokio::runtime::Handle,
    network: Network,
) -> Option<Supervisor> {
    let Tor::Managed { binary } = tor else {
        return None;
    };
    let Prepared { owner, inbox } = prepared;
    let binary = binary.clone();
    let data_dir = data_dir.to_path_buf();
    let task = handle.spawn(async move {
        drive(
            PinSource::Discover(binary),
            policy(),
            clearnet_on,
            virtual_port,
            data_dir,
            inbox,
            network,
        )
        .await;
    });
    Some(Supervisor { owner, task })
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

fn dial_tally(tally: TorLinkTally) -> DialTally {
    DialTally {
        opened: tally.opened,
        unopened: tally.unopened,
        last_sign_of_life: tally.last_sign_of_life.map(|at| at.tick().get()),
        failed_attempt_began: tally.failed_attempt_began.map(|at| at.tick().get()),
        census: match tally.census {
            TorCensus::Pending => QuietCensus::Pending,
            TorCensus::Empty => QuietCensus::Empty,
            TorCensus::Held { seats, since } => QuietCensus::Held {
                seats,
                since: since.tick().get(),
            },
        },
    }
}

/// The dialer's tally as the core's input (§4.2). Counts only, and display
/// only (`TSR-Q14`).
fn tally_input(tally: TorLinkTally) -> Input {
    Input::DialEvidence(dial_tally(tally))
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

/// Where the binary a launch runs comes from.
enum PinSource {
    /// Discovered and checked against the pin: at the configured path, or
    /// the bundle's.
    Discover(Option<PathBuf>),
    /// A binary a test names, not checked (`unpinned-tor-for-tests`).
    #[cfg(all(test, unix))]
    Unchecked(VerifiedTorBinary),
}

async fn drive(
    binary: PinSource,
    policy: Policy,
    clearnet_on: bool,
    virtual_port: u16,
    data_dir: PathBuf,
    inbox: Inbox,
    network: Network,
) {
    if let Some(drive) = Drive::start(
        binary,
        policy,
        clearnet_on,
        virtual_port,
        data_dir,
        inbox,
        network,
    ) {
        drive.run().await;
    }
}

impl Drive {
    /// The driver, its core started and the network's state at start
    /// folded; `None`, said, when the boot's secrets or a scheduler are
    /// not to be had.
    fn start(
        binary: PinSource,
        policy: Policy,
        clearnet_on: bool,
        virtual_port: u16,
        data_dir: PathBuf,
        inbox: Inbox,
        network: Network,
    ) -> Option<Self> {
        let engine = network.engine();
        let owner = match engine.register(OwnerClass::Housekeeping) {
            Ok(owner) => owner,
            Err(error) => {
                tracing::error!(target: "global", "the Tor supervisor has no scheduler: {error:?}");
                return None;
            }
        };
        let onion = match DaemonTorControl::mint_identity() {
            Ok(onion) => onion,
            Err(error) => {
                tracing::error!(target: "global", "the Tor supervisor has no onion key: {error}");
                return None;
            }
        };
        // The probe's isolation pair, minted beside the onion and held with it
        // for the boot (§4.5): the probe's circuits are its own.
        let probe_pair = match IsolationPair::mint() {
            Ok(pair) => pair,
            Err(error) => {
                tracing::error!(target: "global", "the Tor supervisor has no probe isolation: {error}");
                return None;
            }
        };
        let connectors = Connectors {
            tor: TorSetting::Managed,
            clearnet_on,
        };
        let clock = owner.clock().clone();
        let poster = inbox.poster();
        let timer = Timer::start(owner, poster.clone());
        let started = clock.now().get();
        let (core, step) = Core::start(policy, connectors, started);
        let mut drive = Drive {
            core,
            step,
            clock,
            binary,
            data_dir,
            events: poster.events(),
            poster,
            inbox,
            timer,
            forward: None,
            onion: Arc::new(onion),
            probe_pair,
            virtual_port,
            network,
            service: None,
            rounds: None,
            dropped_seen: 0,
            probe: None,
            network_view: NetworkView::default(),
            control: None,
            kept: None,
            pinned: None,
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
        Some(drive)
    }
}

/// The process, the directory, and the route. The phase lives in [`Core`].
struct Drive {
    core: Core,
    step: Step,
    /// The process clock: the network's, which the dialer's stamps are on.
    clock: MonotonicClock,
    binary: PinSource,
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
    /// The boot's onion identity: the keypair Tor is handed on every
    /// publish, held until the daemon stops. Shared with the publish's task,
    /// never copied.
    onion: Arc<OnionIdentity>,
    /// The probe's isolation pair, held beside the onion for the boot.
    probe_pair: IsolationPair,
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
    pinned: Option<VerifiedTorBinary>,
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

impl Drive {
    async fn run(mut self) {
        loop {
            if self.perform() {
                break;
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
        }
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
            if let CacheSave::Failed(error) = teardown.cache {
                tracing::warn!(
                    target: "global",
                    "Tor's directory cache was not saved ({error}); the next start fetches the network directory again"
                );
            }
            if let Some(retirement) = teardown.retirement {
                say_retirement(&retirement);
            }
        }
        // Tor was down at the stop: the directory held for its respawn ends
        // here, the same way.
        if let Some(kept) = self.kept.take() {
            say_retirement(&kept.retire().await);
        }
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
    /// anything already queued. `true` means the daemon is stopping.
    fn perform(&mut self) -> bool {
        let mut queue: VecDeque<Action> = self.step.actions.drain(..).collect();
        let mut halt = false;
        while let Some(action) = queue.pop_front() {
            let inputs = self.act(&action, &mut halt);
            let mut produced = Vec::new();
            for input in inputs {
                self.fold(input);
                produced.append(&mut self.step.actions);
            }
            for action in produced.into_iter().rev() {
                queue.push_front(action);
            }
            if halt {
                break;
            }
        }
        halt
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

    fn act(&mut self, action: &Action, halt: &mut bool) -> Vec<Input> {
        if let Some(instead) = self.withheld(action) {
            return instead;
        }
        match action {
            Action::Announce => {
                let text = self.said();
                if self.core.status().health {
                    tracing::info!(target: "global", "{text}");
                } else {
                    tracing::warn!(target: "global", "{text}");
                }
                Vec::new()
            }
            // The progress line is news. The core only asks for it when no
            // cause is set, so this arm does not re-read the posture.
            Action::SayProgress => {
                let text = self.said();
                tracing::info!(target: "global", "{text}");
                Vec::new()
            }
            Action::CheckPin => vec![self.pin()],
            // A request: sent off the loop, answered as an arrival.
            Action::Reap
            | Action::Spawn { .. }
            | Action::SubscribeEvents
            | Action::Sample
            | Action::SetConfAvoidDiskWrites
            | Action::RepublishOnion
            | Action::AddOnion
            | Action::RefetchDescriptor
            | Action::CheckDirectories
            | Action::FetchFromDirectory { .. } => self.send(action),
            Action::WatchState => self.watch_state().into_iter().collect(),
            Action::Publish(route) => vec![self.publish_route(*route)],
            Action::Probe => vec![self.probe()],
            Action::CancelProbe => {
                self.cancel_probe();
                Vec::new()
            }
            Action::RoundStuck => self.round_stuck(),
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
                Vec::new()
            }
            Action::ProbeAfterJump => vec![probe::jump_probe(&self.network)],
            Action::DirectoriesUnmatched => {
                tracing::info!(
                    target: "tor",
                    "no directory the last upload round reached holds the descriptor Tor's client asks for; the probe alone decided"
                );
                Vec::new()
            }
            Action::DescriptorOverdue => {
                tracing::info!(
                    target: "tor",
                    "no descriptor upload began within the descriptor's lifetime"
                );
                Vec::new()
            }
            Action::PublishInbound(inbound) => {
                self.publish_inbound(*inbound);
                Vec::new()
            }
            Action::TakeDown => {
                self.withdraw_route(DownCause::ProcessExited);
                Vec::new()
            }
            Action::StopRoute => {
                self.withdraw_route(DownCause::ProcessStopped);
                Vec::new()
            }
            Action::StopChild => {
                *halt = true;
                Vec::new()
            }
        }
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
            Arrival::Reply { number, answer } => inputs.extend(self.answered(number, *answer)),
            Arrival::Status(reply) => {
                // Answered from the one place that holds the state, at once:
                // nothing on this loop waits on Tor.
                drop(reply.send(self.core.status()));
            }
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

    fn pin(&mut self) -> Input {
        let verified = match &self.binary {
            PinSource::Discover(Some(path)) => discover_and_verify_at(path),
            PinSource::Discover(None) => discover_and_verify(),
            #[cfg(all(test, unix))]
            PinSource::Unchecked(binary) => Ok(binary.clone()),
        };
        match verified {
            Ok(binary) => {
                self.pinned = Some(binary);
                Input::PinAccepted
            }
            Err(error) => classify_pin(&error).input,
        }
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
/// any replacement (§5, "Data directory unusable"). An unreadable figure
/// starts Tor anyway.
fn space_short(data_dir: &Path, fresh: bool) -> Option<Input> {
    let needed = space_needed(data_dir, fresh);
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

    /// The posture line's `quiet_after` is Tor's window plus the Tor
    /// connector's bracket (`DIALER_OUTAGE_EVIDENCE.md` §6), read from
    /// their declarations, so it moves when either does: 105 s + 15 s. A
    /// span of its own, or one read from elsewhere, fails this.
    #[test]
    fn the_posture_lines_quiet_span_is_tors_window_and_the_bracket() {
        let bracket = dial_profile(ConnectorId::Tor).judging.bracket_nanos;
        assert_eq!(
            policy().quiet_after,
            SOCKS_TIMEOUT.window().expect("set") + Duration::from_nanos(bracket)
        );
        assert_eq!(policy().quiet_after, Duration::from_secs(120));
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
        let tally = tally_input(TorLinkTally {
            unopened: 1,
            ..TorLinkTally::default()
        });
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
        let dir = PathBuf::from("/srv/tor-dir");
        assert_eq!(class.input, Input::PinRefused { path: dir.clone() });
        assert_eq!(class.cause, Cause::PinRefused { path: dir });
        assert_eq!(
            wire_cause(&class.cause),
            Some(TorCause::InstallDefect("/srv/tor-dir".to_owned()))
        );
        let line = pin_warning_line(&refused, false);
        let sentence =
            install_sentence(&TorCause::InstallDefect(String::new())).expect("an install cause");
        assert!(line.contains(sentence));
        assert!(line.contains("was not started"));
        assert!(line.contains("/srv/tor-dir"));
        assert!(line.contains(&held_at_start_sentence(false)));
    }

    /// What `f` writes to the log, one line per event, without times.
    fn logged(f: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Captured {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("capture").extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
            type Writer = Self;
            fn make_writer(&'a self) -> Self {
                self.clone()
            }
        }
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::TRACE)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = captured.0.lock().expect("capture").clone();
        String::from_utf8(bytes).expect("utf-8")
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
