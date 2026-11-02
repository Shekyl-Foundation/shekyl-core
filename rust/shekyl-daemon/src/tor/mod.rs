// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The managed Tor supervisor (`TOR_SUPERVISOR.md` §4, increment 3).
//!
//! [`Drive`] is the manager's hands. The [`Core`] decides. This driver
//! performs each [`Action`] and reports what happened, including a publish
//! the endpoint was not ready for. It keeps no second schedule.
//!
//! The Tor connector is not this driver. It reads the route a publish
//! installs and dials. Questions to Tor stay on the owning control
//! connection (`TSR-Q9`).
//!
//! A sleep is a wait this driver was in that returned more than
//! `control::RESUMED_AFTER` past the deadline it was armed with: the loop's
//! wait, whatever woke it, or a control ask. The core does not infer one
//! from a deadline that merely looks late. The wait itself lives in
//! [`wake`]: the timer stands ahead of control events, and events already
//! queued when it wins are folded before that deadline.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use shekyl_daemon_config::sections::Tor;
use shekyl_ffi::dialer_ffi::ConnectorId;
use shekyl_ffi::origin_verdict::OriginVerdict;
use shekyl_ffi::tor_link::{ProbeArrival, TorLinkTally};
use shekyl_ffi::zone_ffi::DownCause;
use shekyl_timing_engine::{Clock, MonotonicClock, OwnerClass, OwnerHandle, Tick};
use shekyl_tor_control_client::binary::{
    discover_and_verify, discover_and_verify_at, TorBinaryError, VerifiedTorBinary,
};
use shekyl_tor_control_client::control::{
    parse_bootstrap_progress, parse_event, parse_network_view, parse_socks_listeners,
    parse_traffic_read, BootstrapState, Command, ControlError, ControlReply, EventReceiver,
    EventSink, Resume, ServiceId, SocksTimeout, TorEvent, UploadRounds,
};
use shekyl_tor_control_client::supervisor::{
    clock_evidence_of, directory_input_of, held_sentence, input_of, install_sentence, render,
    Action, Cause, Connectors, Core, DialTally, Input, ManagedRunning, NetworkView,
    OriginVerdict as FoldedOrigin, Policy, Space, Step, Syncing, TorSetting,
};
use shekyl_tor_control_daemon::{
    space_needed, sweep_stale_data_dirs, CacheSave, DaemonTorConfig, DaemonTorControl,
    DaemonTorStartError, IsolationPair, KeptDataDir, OnionPow, OnionSeed, SpawnError, TorDeath,
};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

mod probe;
mod wake;

use self::wake::{led, plain_inputs, take_queued, wait, Sources, Wake, Woken};

/// A control reply this far past due is a process fault. Not a bootstrap limit.
const REPLY_BOUND: Duration = Duration::from_secs(30);

/// The managed Tor answers a SOCKS request it cannot attach just inside the
/// Tor dial deadline, so the dial's class is Tor's reply, never a race with
/// that deadline (`TOR_SUPERVISOR.md` §4.2).
const SOCKS_TIMEOUT: SocksTimeout = shekyl_ffi::tor_link::TOR_SOCKS_TIMEOUT;
/// The supervisor's waits. Its quiet stretch is the Tor connector's span S
/// from its dial profile (the dial profile brief, item 6): the posture line
/// and the dialer's quiet guard read one number, though the guard also
/// counts attempts and the line restarts its clock when a Tor reaches
/// Running.
const fn policy() -> Policy {
    Policy::provisional(Duration::from_nanos(
        shekyl_ffi::dialer_ffi::dial_profile(ConnectorId::Tor)
            .quiet()
            .span_nanos,
    ))
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

/// The running supervisor. Dropping it does not stop Tor; [`Self::shutdown`] does.
pub struct Supervisor {
    stop: watch::Sender<bool>,
    forward: watch::Sender<Option<SocketAddr>>,
    task: JoinHandle<()>,
}

impl Supervisor {
    /// The zone host's forward listener, once step 8 has bound it.
    pub fn note_forward(&self, forward: SocketAddr) {
        let _sent = self.forward.send(Some(forward));
    }

    /// Stop Tor and wait for the directory to be torn down.
    pub async fn shutdown(self) {
        let _sent = self.stop.send(true);
        let _joined = self.task.await;
    }
}

/// The pin half of a managed Tor's start, read for the configuration check
/// (`INPUT_GRAMMAR.md` IG-Q59): the binary is discovered and verified, and
/// not started.
///
/// `None` when the pin is accepted. Otherwise one warning. The cause is the
/// class the supervisor's pin takes, spoken with [`install_sentence`]; the
/// parenthetical is the pin error, which for a missed discovery names every
/// path it searched. The last sentence is [`held_sentence`] for a link that
/// is not up: nothing syncs over Tor, and clearnet is the connector. Under
/// TB-2 a pin that fails is announced and the daemon starts all the same.
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

/// The sync a pin warning speaks. The link is not up, so nothing syncs
/// over Tor. `clearnet` is the connector.
fn pin_sync(clearnet_on: bool) -> Syncing {
    Syncing {
        tor: false,
        clearnet: clearnet_on,
    }
}

/// The warning text for a pin error. `error`'s display is the detail: a
/// `NotFound` lists `searched`, and the posture cause does not carry those
/// paths.
fn pin_warning_line(error: &TorBinaryError, clearnet_on: bool) -> String {
    let class = classify_pin(error);
    let sentence = install_sentence(&class.cause).expect("a pin class is an install cause");
    let consequence = held_sentence(pin_sync(clearnet_on));
    format!("warning: managed Tor: {sentence} ({error}) {consequence}")
}

/// Start the supervisor when Tor is managed. Any other posture returns `None`.
#[must_use]
pub fn begin(
    tor: &Tor,
    clearnet_on: bool,
    virtual_port: u16,
    data_dir: &Path,
    handle: &tokio::runtime::Handle,
) -> Option<Supervisor> {
    let Tor::Managed { binary } = tor else {
        return None;
    };
    let binary = binary.clone();
    let data_dir = data_dir.to_path_buf();
    let (stop, stop_rx) = watch::channel(false);
    let (forward, forward_rx) = watch::channel(None);
    let task = handle.spawn(async move {
        drive(
            binary,
            clearnet_on,
            virtual_port,
            data_dir,
            stop_rx,
            forward_rx,
        )
        .await;
    });
    Some(Supervisor {
        stop,
        forward,
        task,
    })
}

fn dial_tally(tally: TorLinkTally) -> DialTally {
    DialTally {
        opened: tally.opened,
        unopened: tally.unopened,
        held: tally.held,
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

async fn drive(
    binary: Option<PathBuf>,
    clearnet_on: bool,
    virtual_port: u16,
    data_dir: PathBuf,
    stop: watch::Receiver<bool>,
    forward: watch::Receiver<Option<SocketAddr>>,
) {
    let engine = shekyl_ffi::zone_ffi::process_engine();
    let owner = match engine.register(OwnerClass::Housekeeping) {
        Ok(owner) => owner,
        Err(error) => {
            tracing::error!(target: "global", "the Tor supervisor has no scheduler: {error:?}");
            return;
        }
    };
    let seed = match DaemonTorControl::mint_seed() {
        Ok(seed) => seed,
        Err(error) => {
            tracing::error!(target: "global", "the Tor supervisor has no onion seed: {error}");
            return;
        }
    };
    // The probe's isolation pair, minted beside the seed and held with it
    // for the boot (§4.5): the probe's circuits are its own.
    let probe_pair = match IsolationPair::mint() {
        Ok(pair) => pair,
        Err(error) => {
            tracing::error!(target: "global", "the Tor supervisor has no probe isolation: {error}");
            return;
        }
    };
    let (events, incoming) = EventSink::bounded();
    let connectors = Connectors {
        tor: TorSetting::Managed,
        clearnet_on,
    };
    let origin = shekyl_ffi::origin_verdict::watch();
    let mut tor_link = shekyl_ffi::tor_link::watch();
    let mut probe_arrivals = shekyl_ffi::tor_link::probe_arrivals();
    // An arrival from an earlier supervisor in this process is not this one's.
    probe_arrivals.borrow_and_update();
    let started = now(&owner);
    let (mut core, mut step) = Core::start(policy(), connectors, started);
    // A receiver marks the current value seen, so a verdict published before
    // the supervisor started is folded once, here. The pin check stays the
    // first action: replacing the startup step would never spawn.
    let folded = core.on(verdict_input(*origin.borrow()), started);
    step.actions.extend(folded.actions);
    step.deadline = folded.deadline;
    // The current tally is already seen. Seed it as the baseline: history
    // is not an open, and folding it as evidence would move the stretch
    // clock. `borrow_and_update` also marks a value published since
    // subscribe, so the loop does not fold that one again.
    let seen = *tor_link.borrow_and_update();
    let baseline = core.on(Input::DialBaseline(dial_tally(seen)), started);
    step.actions.extend(baseline.actions);
    step.deadline = baseline.deadline;
    let (death_tx, death_rx) = mpsc::channel(4);
    Drive {
        core,
        step,
        owner,
        binary,
        data_dir,
        events,
        incoming,
        seed,
        probe_pair,
        virtual_port,
        stop,
        forward,
        origin,
        tor_link,
        probe_arrivals,
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
        death_tx,
        death_rx,
        bootstrap: None,
    }
    .run()
    .await;
}

/// The process, the directory, and the route. The phase lives in [`Core`].
struct Drive {
    core: Core,
    step: Step,
    owner: OwnerHandle<MonotonicClock>,
    binary: Option<PathBuf>,
    data_dir: PathBuf,
    events: EventSink,
    incoming: EventReceiver,
    seed: OnionSeed,
    /// The probe's isolation pair, held beside the seed for the boot.
    probe_pair: IsolationPair,
    virtual_port: u16,
    stop: watch::Receiver<bool>,
    forward: watch::Receiver<Option<SocketAddr>>,
    /// The relay's hop-0 verdict for a local origin (`GS-Q3`). Health and
    /// `OwnTx` project it.
    origin: watch::Receiver<OriginVerdict>,
    /// What this node's own Tor dials show (§4.2), for the posture line
    /// only (`TSR-Q14`). The value in the cell at start is the baseline.
    /// The loop folds a later change as evidence.
    tor_link: watch::Receiver<TorLinkTally>,
    /// Each probe whose nonce came back through the onion (§4.5): the mint
    /// that names it, and the process time the handshake took it. The core
    /// accepts the take when it names the probe in flight and landed before
    /// that probe's bound.
    probe_arrivals: watch::Receiver<Option<ProbeArrival>>,
    /// The onion as last published.
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
    generation: u64,
    death_tx: mpsc::Sender<(u64, TorDeath)>,
    death_rx: mpsc::Receiver<(u64, TorDeath)>,
    bootstrap: Option<watch::Receiver<BootstrapState>>,
}

impl Drive {
    async fn run(mut self) {
        loop {
            if self.perform().await {
                break;
            }
            // Captured before the arm. The wait's lateness is this interval,
            // not how late a deadline stored during `perform` looks afterwards.
            let armed = self.step.deadline;
            let entered = self.now();
            arm(&self.owner, armed);
            let sources = Sources {
                stop: &mut self.stop,
                forward: &mut self.forward,
                origin: &mut self.origin,
                tor_link: &mut self.tor_link,
                probe_arrivals: &mut self.probe_arrivals,
                incoming: &mut self.incoming,
                death: &mut self.death_rx,
                bootstrap: &mut self.bootstrap,
            };
            let wake = wait(sources, &self.owner, armed, entered).await;
            if !self.handle(wake).await {
                break;
            }
        }
        self.cancel_probe();
        if let Some(control) = self.control.take() {
            let teardown = control.shutdown().await;
            if let CacheSave::Failed(error) = teardown.cache {
                tracing::warn!(
                    target: "global",
                    "Tor's directory cache was not saved ({error}); the next start fetches the network directory again"
                );
            }
        }
    }

    /// Perform every action the last fold produced. Inputs from one action
    /// are folded in order and their actions run in that order, ahead of
    /// anything already queued. `true` means the daemon is stopping.
    async fn perform(&mut self) -> bool {
        let mut queue: VecDeque<Action> = self.step.actions.drain(..).collect();
        let mut halt = false;
        while let Some(action) = queue.pop_front() {
            let inputs = self.act(action, &mut halt).await;
            let mut produced = Vec::new();
            for input in inputs {
                self.fold(input).await;
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
    async fn fold(&mut self, input: Input) {
        self.fold_many(vec![input]).await;
    }

    /// Fold `inputs` at the driver's clock. See [`Self::fold_at`].
    async fn fold_many(&mut self, inputs: Vec<Input>) {
        self.fold_at(inputs, self.now()).await;
    }

    /// Fold `inputs` as one step at `at`. Each transition's actions are kept,
    /// in order, and the deadline is the last transition's. An empty list
    /// leaves the step alone, so a batch that carried nothing does not
    /// disarm a wait that is already armed.
    ///
    /// A process that ended is reaped here when that transition does not
    /// withdraw a route: there is nothing to take down, and the directory
    /// is still kept. A [`Action::TakeDown`] reaps after it withdraws, so
    /// the route is gone before the child is. A [`Action::StopRoute`] only
    /// withdraws: the shutdown wipe still owns the child.
    async fn fold_at(&mut self, inputs: Vec<Input>, at: u64) {
        if inputs.is_empty() {
            return;
        }
        let mut actions = Vec::new();
        let mut deadline = None;
        for input in inputs {
            let ended = ends_incarnation(&input);
            let step = self.core.on(input, at);
            let take_down = step
                .actions
                .iter()
                .any(|action| matches!(action, Action::TakeDown));
            actions.extend(step.actions);
            deadline = step.deadline;
            if ended && !take_down {
                self.reap().await;
            }
        }
        self.step = Step { actions, deadline };
    }

    async fn act(&mut self, action: Action, halt: &mut bool) -> Vec<Input> {
        match action {
            Action::Announce => {
                let status = self.core.status();
                let text = render(&status);
                if status.health {
                    tracing::info!(target: "global", "{text}");
                } else {
                    tracing::warn!(target: "global", "{text}");
                }
                Vec::new()
            }
            // The progress line is news. The core only asks for it when no
            // cause is set, so this arm does not re-read the posture.
            Action::SayProgress => {
                let text = render(&self.core.status());
                tracing::info!(target: "global", "{text}");
                Vec::new()
            }
            Action::CheckPin => vec![self.pin()],
            Action::Spawn { fresh_directory } => {
                let spawned = self.spawn(fresh_directory).await;
                self.resume_before(vec![spawned])
            }
            Action::Sample => {
                let mut stop = self.stop.clone();
                match race_stop(&mut stop, self.sample()).await {
                    Ok(inputs) => self.resume_before(inputs),
                    Err(shutdown) => vec![shutdown],
                }
            }
            Action::WatchState => self.watch_state().into_iter().collect(),
            Action::SetConfAvoidDiskWrites => {
                let mut stop = self.stop.clone();
                let Some(control) = self.control.as_ref() else {
                    return Vec::new();
                };
                match race_stop(&mut stop, control.defer_disk_writes()).await {
                    Err(shutdown) => vec![shutdown],
                    Ok(Ok(())) => self.resume_before(Vec::new()),
                    Ok(Err(error)) => {
                        tracing::warn!(
                            target: "global",
                            "leaving Tor writing its state ({error})"
                        );
                        self.resume_before(Vec::new())
                    }
                }
            }
            Action::Publish(route) => vec![self.publish_route(route)],
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
            Action::RefetchDescriptor => {
                let mut stop = self.stop.clone();
                match race_stop(&mut stop, self.refetch()).await {
                    Ok(input) => self.resume_before(vec![input]),
                    Err(shutdown) => vec![shutdown],
                }
            }
            Action::ProbeAfterJump => vec![probe::jump_probe()],
            Action::CheckDirectories => vec![self.directories_drawn()],
            Action::FetchFromDirectory { hsdir } => {
                let mut stop = self.stop.clone();
                match race_stop(&mut stop, self.fetch_from(hsdir)).await {
                    Ok(input) => self.resume_before(input.into_iter().collect()),
                    Err(shutdown) => vec![shutdown],
                }
            }
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
                    "no descriptor upload began within the descriptor's lifetime; publishing this node's onion again"
                );
                Vec::new()
            }
            Action::PublishInbound(inbound) => {
                self.publish_inbound(inbound);
                Vec::new()
            }
            Action::RepublishOnion => {
                let mut stop = self.stop.clone();
                match race_stop(&mut stop, self.republish()).await {
                    Ok(input) => self.resume_before(vec![input]),
                    Err(shutdown) => vec![shutdown],
                }
            }
            Action::TakeDown => {
                self.withdraw_route(DownCause::ProcessExited);
                self.reap().await;
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

    /// Fold what ended a wait (see [`wait`]). A sleep the wait observed is
    /// folded first, whichever branch returned, so what woke the loop is
    /// judged on windows that start at the wake. `false` means the timer
    /// closed and the loop ends.
    async fn handle(&mut self, wake: Wake) -> bool {
        let lead = wake.lead();
        let inputs = match wake.what {
            Woken::Timer { closed: true } => return false,
            Woken::Timer { closed: false } => {
                self.after_timer(lead, wake.woke).await;
                return true;
            }
            Woken::Event(reply) => reply
                .map(|reply| self.event_inputs(&reply))
                .unwrap_or_default(),
            Woken::Death(death) => death
                .filter(|(generation, _)| *generation == self.generation)
                .and_then(|(_, how)| observed_death(how))
                .into_iter()
                .collect(),
            Woken::Bootstrap => self.bootstrap_input().into_iter().collect(),
            plain => plain_inputs(&plain),
        };
        self.fold_many(led(lead, inputs)).await;
        true
    }

    /// The timer ended the wait at `woke`. Events already queued are folded
    /// first, at the wake, and then the deadline. The timer won this wait,
    /// so an event that arrives later cannot hold the deadline off.
    async fn after_timer(&mut self, lead: Option<Input>, woke: u64) {
        let queued = take_queued(&mut self.incoming);
        let mut inputs = lead.into_iter().collect::<Vec<_>>();
        for reply in &queued {
            inputs.extend(self.event_inputs(reply));
        }
        self.fold_at(inputs, woke).await;
        let due = self.core.on_deadline(woke);
        self.step.actions.extend(due.actions);
        self.step.deadline = due.deadline;
    }

    /// One event batch from Tor: the round resync, the clock evidence, the
    /// statement, and the round marks, in that order, folded as one step.
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
                    // A fetch of this onion: the directory check's evidence.
                    inputs.extend(directory_input_of(desc));
                }
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
            for input in self.round_marks(&parsed) {
                probe::say_round(&input);
                inputs.push(input);
            }
        }
        inputs
    }

    /// A control ask returned. A sleep it observed is the first input, so
    /// the reply is judged on windows that start at the wake. A stop that
    /// drops the ask does not come here: that ask wrote nothing.
    fn resume_before(&mut self, mut inputs: Vec<Input>) -> Vec<Input> {
        let Some(control) = self.control.as_ref() else {
            return inputs;
        };
        if let Resume::Slept { late_by } = control.take_resume() {
            inputs.insert(0, Input::Resumed { late_by });
        }
        inputs
    }

    fn pin(&mut self) -> Input {
        let verified = match &self.binary {
            Some(path) => discover_and_verify_at(path),
            None => discover_and_verify(),
        };
        match verified {
            Ok(binary) => {
                self.pinned = Some(binary);
                Input::PinAccepted
            }
            Err(error) => classify_pin(&error).input,
        }
    }

    async fn spawn(&mut self, fresh_directory: bool) -> Input {
        // A fault reaps before the next pin. A child still held here is kept,
        // not dropped: dropping the control wipes the directory.
        if self.control.is_some() {
            self.reap().await;
        }
        // Known before the drop. A kept directory wears the leftover name,
        // so the sweep runs only after that drop.
        let fresh = fresh_directory || self.kept.is_none();
        if fresh_directory {
            self.kept.take();
        }
        let Some(binary) = self.pinned.clone() else {
            return Input::PinRefused;
        };
        if fresh {
            sweep_stale_data_dirs(&self.data_dir);
        }
        if let Some(short) = self.space_short(fresh) {
            return short;
        }
        let spawned = if let Some(directory) = self.kept.take() {
            DaemonTorControl::spawn_into(
                directory,
                binary,
                self.events.clone(),
                REPLY_BOUND,
                SOCKS_TIMEOUT,
            )
            .await
            .map_err(|failure| (failure.error, Some(failure.directory)))
        } else {
            match DaemonTorControl::spawn_keeping(DaemonTorConfig {
                tor_binary: binary,
                data_dir_parent: self.data_dir.clone(),
                events: self.events.clone(),
                reply_deadline: REPLY_BOUND,
                socks_timeout: SOCKS_TIMEOUT,
            })
            .await
            {
                Ok(up) => Ok(up),
                Err(SpawnError::DataDir(error)) => Err((DaemonTorStartError::DataDir(error), None)),
                Err(SpawnError::Launch(failure)) => Err((failure.error, Some(failure.directory))),
            }
        };
        match spawned {
            Ok(up) => {
                self.generation = self.generation.wrapping_add(1);
                let gen = self.generation;
                let death = up.death();
                let tx = self.death_tx.clone();
                tokio::spawn(async move {
                    let _sent = tx.send((gen, death.await)).await;
                });
                self.bootstrap = Some(up.watch_bootstrap());
                // The child is up. The subscription is a control ask, so a
                // stop drops it. The fork itself has already returned; the
                // control is stored so shutdown still owns the child.
                self.control = Some(up);
                let mut stop = self.stop.clone();
                // Stored on the line above. The subscription borrows that
                // child; a missing one is a broken launch, not a quiet skip.
                let control = self
                    .control
                    .as_ref()
                    .expect("the child is stored before its event subscription");
                let subscribed =
                    race_stop(&mut stop, control.ask(Command::supervisor_events())).await;
                match subscribed {
                    Err(shutdown) => shutdown,
                    Ok(Err(error)) => {
                        tracing::warn!(
                            target: "global",
                            "Tor events were not subscribed ({error})"
                        );
                        Input::Spawned
                    }
                    Ok(Ok(_)) => Input::Spawned,
                }
            }
            Err((error, directory)) => {
                if let Some(directory) = directory {
                    self.kept = Some(directory);
                }
                match error {
                    DaemonTorStartError::DataDir(_) => Input::DirectoryUnusable {
                        path: self.data_dir.clone(),
                        space: None,
                    },
                    _ => Input::SpawnFailed,
                }
            }
        }
    }

    async fn sample(&mut self) -> Vec<Input> {
        // Read before borrowing the control: the keys and the view that is
        // folded are the same decision.
        let reads_network = self.core.reads_network();
        let Some(control) = self.control.as_mut() else {
            return vec![Input::ControlEnded];
        };
        let reply = match control
            .ask(Command::GetInfo(sample_keys(reads_network)))
            .await
        {
            Ok(reply) => reply,
            Err(error) => return vec![input_of_ask(&error)],
        };
        let socks = parse_socks_listeners(&reply);
        if let Some(socks) = socks {
            control.set_socks(socks);
        }
        let mut inputs = vec![Input::DirectorySample {
            progress: parse_bootstrap_progress(&reply),
            socks,
            read: parse_traffic_read(&reply),
        }];
        if reads_network {
            let view = parse_network_view(&reply);
            // Tor's view is what the next blocked-link run records (`TSR-Q14`):
            // said when it changes, not with every sample.
            if view != self.network_view {
                tracing::info!(
                    target: "tor",
                    network_liveness = ?view.liveness,
                    circuit_established = ?view.circuits,
                    "Tor's view of its network"
                );
                self.network_view = view;
            }
            inputs.push(Input::NetworkView(view));
        }
        inputs
    }

    fn watch_state(&self) -> Option<Input> {
        let path = self.control.as_ref()?.data_path()?;
        path.join("state")
            .is_file()
            .then_some(Input::StateFileAppeared)
    }

    fn publish_route(&mut self, route: ManagedRunning) -> Input {
        match shekyl_ffi::zone_ffi::publish_managed_running(&route) {
            Some(installed) => {
                self.incarnation = Some(installed);
                // A facet decided before the route was in has no incarnation
                // to name until now.
                self.publish_inbound(self.core.status().inbound);
                Input::RouteInstalled
            }
            None => Input::HostAbsent,
        }
    }

    async fn republish(&mut self) -> Input {
        let Some(control) = self.control.as_ref() else {
            return Input::ControlEnded;
        };
        let Some(forward) = *self.forward.borrow() else {
            return Input::ForwardAbsent;
        };
        match control
            .republish(
                &self.seed,
                self.virtual_port,
                forward,
                MAX_STREAMS,
                OnionPow::Enabled,
            )
            .await
        {
            Ok(service) => {
                shekyl_ffi::dialer_ffi::note_own_onion(service.as_str(), self.virtual_port);
                // A publish starts the onion's rounds afresh: a round left
                // open by the deleted service is not this one's.
                self.rounds = Some(UploadRounds::new(service.clone()));
                self.service = Some(service.clone());
                tracing::info!(
                    target: "global",
                    "Tor is up: overlay inbound is published at {}.onion:{}, forwarded from {forward}",
                    service.as_str(),
                    self.virtual_port,
                );
                Input::OnionPublished
            }
            Err(error) => {
                tracing::warn!(target: "global", "the onion was not published ({error})");
                Input::OnionRejected
            }
        }
    }

    fn withdraw_route(&mut self, cause: DownCause) {
        if let Some(id) = self.incarnation.take() {
            let _fell = shekyl_ffi::zone_ffi::publish_tor_down(id, cause);
        }
    }

    /// The pre-spawn space check (`TOR_SUPERVISOR.md` §5, "Data directory
    /// unusable"). `fresh` is the spawn's own bit: a new directory needs
    /// Tor's write headroom plus the cache copy, and a kept one needs the
    /// headroom. A disk that fills after the spawn is not this check's.
    /// A probe that cannot read the disk lets the spawn go ahead: "I cannot
    /// tell" is not "full".
    fn space_short(&self, fresh: bool) -> Option<Input> {
        let needed = space_needed(&self.data_dir, fresh);
        match shekyl_node::free_bytes(&self.data_dir) {
            Ok(available) if available < needed => Some(Input::DirectoryUnusable {
                path: self.data_dir.clone(),
                space: Some(Space { available, needed }),
            }),
            Ok(_) => None,
            Err(error) => {
                tracing::warn!(
                    target: "global",
                    path = %self.data_dir.display(),
                    %error,
                    "the free space for Tor's data directory could not be read; starting Tor anyway"
                );
                None
            }
        }
    }

    /// Stop the child and keep its directory. The generation moves so the
    /// stop's own death is not a second fault.
    async fn reap(&mut self) {
        self.bootstrap = None;
        self.cancel_probe();
        let Some(control) = self.control.take() else {
            return;
        };
        self.generation = self.generation.wrapping_add(1);
        self.kept = Some(control.stop_for_respawn().await);
    }

    fn bootstrap_input(&mut self) -> Option<Input> {
        let state = *self.bootstrap.as_ref()?.borrow();
        match state {
            BootstrapState::Ready => {
                if let Some(control) = self.control.as_mut() {
                    control.mark_bootstrapped();
                }
                Some(Input::BootstrapComplete)
            }
            BootstrapState::Failed => Some(Input::ControlEnded),
            BootstrapState::Connecting { progress } => Some(Input::BootstrapNoted { progress }),
        }
    }

    fn now(&self) -> u64 {
        now(&self.owner)
    }
}

fn now<C: Clock>(owner: &OwnerHandle<C>) -> u64 {
    owner.clock().now().get()
}

fn arm<C: Clock>(owner: &OwnerHandle<C>, deadline: Option<u64>) {
    let _cleared = owner.clear();
    if let Some(deadline) = deadline {
        let _armed = owner.arm(Tick::new(deadline));
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

fn ends_incarnation(input: &Input) -> bool {
    matches!(
        input,
        Input::ProcessEnded { .. } | Input::ControlEnded | Input::ReplyLate
    )
}

/// Resolves once the daemon is stopping: the flag is set, or its sender is
/// gone. A stop already signalled resolves at once.
async fn stopped(stop: &mut watch::Receiver<bool>) {
    loop {
        if *stop.borrow_and_update() {
            return;
        }
        if stop.changed().await.is_err() {
            return;
        }
    }
}

/// Race a control ask against shutdown. A stop already signalled, or one
/// that arrives while the ask waits, wins: the ask is dropped and the
/// caller folds [`Input::Shutdown`]. The fork inside spawn is not an ask
/// and does not come through here.
async fn race_stop<T>(
    stop: &mut watch::Receiver<bool>,
    ask: impl std::future::Future<Output = T>,
) -> Result<T, Input> {
    tokio::select! {
        biased;
        () = stopped(stop) => Err(Input::Shutdown),
        value = ask => Ok(value),
    }
}

fn input_of_ask(error: &DaemonTorStartError) -> Input {
    match error {
        DaemonTorStartError::Control(ControlError::Timeout) => Input::ReplyLate,
        _ => Input::ControlEnded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    /// The posture line's `quiet_after` is the Tor connector's span S, read
    /// from its dial profile (the dial profile brief, test 5): one number
    /// for the line and the dialer's quiet guard. The value is the profile's
    /// derivation in §97, so this pins the equality and not the value. The
    /// two clocks differ: the line's stretch also restarts when a Tor
    /// reaches Running, and the guard also counts attempts.
    #[test]
    fn the_posture_lines_quiet_stretch_is_the_dialers() {
        assert_eq!(
            u64::try_from(policy().quiet_after.as_nanos()).expect("small"),
            shekyl_ffi::dialer_ffi::dial_profile(ConnectorId::Tor)
                .quiet()
                .span_nanos
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
        let deadline = shekyl_ffi::tor_link::TOR_DIAL_WITHIN.as_secs();
        assert!(timeout < deadline, "{timeout} s inside {deadline} s");
        assert!(timeout >= deadline / 2, "not far inside it");
        // The dialer reads the same window the Tor is launched with: an
        // attempt failing at or after it is final within its test.
        assert_eq!(
            shekyl_ffi::tor_link::TOR_SOCKS_TIMEOUT.window(),
            Some(Duration::from_secs(timeout)),
            "one window"
        );
        assert_eq!(timeout, 105, "120 s less the 15 s margin");
        assert_eq!(
            shekyl_ffi::tor_link::TOR_SOCKS_TIMEOUT.earliest_expiry(),
            Some(Duration::from_secs(104)),
            "Tor counts a stream's age in whole seconds"
        );
    }

    /// A control ask that never answers, the wedged-Tor case, does not hold
    /// a stop: the stop resolves the race and the driver folds `Shutdown`.
    /// Dropping the `stopped` arm from [`race_stop`] makes this time out.
    /// The production asks call that function.
    #[tokio::test(start_paused = true)]
    async fn a_stop_interrupts_an_ask_a_wedged_tor_never_answers() {
        let (tx, rx) = watch::channel(false);
        let mut stop = rx.clone();
        let raced =
            tokio::spawn(
                async move { race_stop(&mut stop, std::future::pending::<Input>()).await },
            );
        tokio::time::sleep(Duration::from_secs(1)).await;
        tx.send(true).expect("the driver still holds the receiver");
        let outcome = tokio::time::timeout(Duration::from_secs(1), raced)
            .await
            .expect("the stop ended the ask within a second, not the 30 s bound")
            .expect("the race task ran");
        assert_eq!(outcome, Err(Input::Shutdown));
    }

    /// An ask that answers is unaffected, and a stop signalled before the
    /// ask began still wins (the daemon is already stopping).
    #[tokio::test]
    async fn an_answer_passes_through_and_an_earlier_stop_wins() {
        let (_tx, rx) = watch::channel(false);
        let mut stop = rx.clone();
        let answered = race_stop(&mut stop, async { Input::ReplyLate }).await;
        assert_eq!(answered, Ok(Input::ReplyLate));

        let (tx, rx) = watch::channel(false);
        tx.send(true).expect("receiver alive");
        let mut stop = rx.clone();
        let raced = race_stop(&mut stop, std::future::pending::<Input>()).await;
        assert_eq!(raced, Err(Input::Shutdown));
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
        let sentence = install_sentence(&Cause::BundleMissing).expect("an install cause");
        assert!(line.contains(sentence));
        assert!(line.contains(searched.to_str().unwrap()));
        assert!(line.contains(&held_sentence(pin_sync(false))));
        assert!(!line.contains(&held_sentence(pin_sync(true))));

        let unavailable = TorBinaryError::Unavailable {
            reason: "no bundle for this target",
        };
        let class = classify_pin(&unavailable);
        assert_eq!(class.input, Input::Unavailable);
        assert_eq!(class.cause, Cause::Unavailable);
        let line = pin_warning_line(&unavailable, true);
        let sentence = install_sentence(&Cause::Unavailable).expect("an install cause");
        assert!(line.contains(sentence));
        assert!(line.contains("no bundle for this target"));
        assert!(line.contains(&held_sentence(pin_sync(true))));

        let refused = TorBinaryError::NotAFile(PathBuf::from("/srv/tor-dir"));
        let class = classify_pin(&refused);
        assert_eq!(class.input, Input::PinRefused);
        assert_eq!(class.cause, Cause::PinRefused);
        let line = pin_warning_line(&refused, false);
        let sentence = install_sentence(&Cause::PinRefused).expect("an install cause");
        assert!(line.contains(sentence));
        assert!(line.contains("was not started"));
        assert!(line.contains("/srv/tor-dir"));
        assert!(line.contains(&held_sentence(pin_sync(false))));
    }
}
