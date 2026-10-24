// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The managed Tor supervisor (`TOR_SUPERVISOR.md` §4, increment 3).
//!
//! [`Drive`] is the manager's hands. The [`Core`] decides. This driver
//! performs each [`Action`] and reports what happened, including a publish
//! the endpoint was not ready for. It keeps no second schedule.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use shekyl_daemon_config::sections::Tor;
use shekyl_ffi::zone_ffi::DownCause;
use shekyl_timing_engine::{Clock, MonotonicClock, OwnerClass, OwnerHandle, Tick};
use shekyl_tor_control_client::binary::{
    discover_and_verify, discover_and_verify_at, VerifiedTorBinary,
};
use shekyl_tor_control_client::control::{
    parse_bootstrap_progress, parse_event, parse_socks_listeners, parse_traffic_read,
    BootstrapState, Command, ControlError, EventReceiver, EventSink,
};
use shekyl_tor_control_client::supervisor::{
    input_of, render, Action, Cause, Connectors, Core, Input, ManagedRunning, Policy, Shown, Space,
    Step, TorSetting,
};
use shekyl_tor_control_daemon::{
    space_needed, CacheSave, DaemonTorConfig, DaemonTorControl, DaemonTorStartError, KeptDataDir,
    OnionPow, OnionSeed, SpawnError, TorDeath,
};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// A control reply this far past due is a process fault. Not a bootstrap limit.
const REPLY_BOUND: Duration = Duration::from_secs(30);
/// The onion's stream cap.
const MAX_STREAMS: u16 = 8;
/// `GETINFO` key for the bootstrap phase. One sample asks this and the listener.
const BOOTSTRAP_PHASE: &str = "status/bootstrap-phase";
/// `GETINFO` key for the bytes Tor has read: with the bootstrap phase, it
/// tells a slow directory mirror from one that is not answering (§5).
const TRAFFIC_READ: &str = "traffic/read";
/// `GETINFO` key for the SOCKS listeners.
const SOCKS_LISTENERS: &str = "net/listeners/socks";

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
    let (events, incoming) = EventSink::bounded();
    let connectors = Connectors {
        tor: TorSetting::Managed,
        clearnet_on,
    };
    let (core, step) = Core::start(Policy::provisional(), connectors, now(&owner));
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
        virtual_port,
        stop,
        forward,
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
    virtual_port: u16,
    stop: watch::Receiver<bool>,
    forward: watch::Receiver<Option<SocketAddr>>,
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
            arm(&self.owner, self.step.deadline);
            tokio::select! {
                biased;
                changed = self.stop.changed() => {
                    if changed.is_err() || *self.stop.borrow() {
                        self.fold(Input::Shutdown).await;
                    }
                }
                changed = self.forward.changed() => {
                    // The first wait also sees a forward bound before the loop:
                    // the receiver has not marked the current value seen.
                    if changed.is_ok() && self.forward.borrow().is_some() {
                        self.fold(Input::EndpointReady).await;
                    }
                }
                wake = self.owner.wait_wake_async() => {
                    if wake.is_err() {
                        break;
                    }
                    self.step = self.core.on_deadline(self.now());
                }
                event = self.incoming.recv() => {
                    if let Some(reply) = event {
                        if let Some(parsed) = parse_event(&reply) {
                            if let Some(input) = input_of(&parsed) {
                                self.fold(input).await;
                            }
                        }
                    }
                }
                death = self.death_rx.recv() => {
                    if let Some((gen, how)) = death {
                        if gen == self.generation {
                            if let Some(input) = observed_death(how) {
                                self.fold(input).await;
                            }
                        }
                    }
                }
                () = wait_bootstrap(&mut self.bootstrap) => {
                    if let Some(input) = self.bootstrap_input() {
                        self.fold(input).await;
                    }
                }
            }
        }
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

    /// Perform every action the last fold produced. `true` means the daemon
    /// is stopping and the child is shut down by the caller.
    async fn perform(&mut self) -> bool {
        let mut queue: VecDeque<Action> = self.step.actions.drain(..).collect();
        let mut halt = false;
        while let Some(action) = queue.pop_front() {
            if let Some(input) = self.act(action, &mut halt).await {
                self.fold(input).await;
                for action in self.step.actions.drain(..).rev() {
                    queue.push_front(action);
                }
            }
            if halt {
                break;
            }
        }
        halt
    }

    /// Fold one observation. A process that ended is reaped here when the
    /// phase does not withdraw a route: there is nothing to take down, and
    /// the directory is still kept. A [`Action::TakeDown`] reaps after it
    /// withdraws, so the route is gone before the child is. A
    /// [`Action::StopRoute`] only withdraws: the shutdown wipe still owns
    /// the child.
    async fn fold(&mut self, input: Input) {
        let ended = ends_incarnation(&input);
        self.step = self.core.on(input, self.now());
        let take_down = self
            .step
            .actions
            .iter()
            .any(|action| matches!(action, Action::TakeDown));
        if ended && !take_down {
            self.reap().await;
        }
    }

    async fn act(&mut self, action: Action, halt: &mut bool) -> Option<Input> {
        match action {
            Action::Announce => {
                let status = self.core.status();
                let text = render(&status);
                // A bootstrap's progress line is news, not a fault.
                let progress = status.shown == Shown::Bootstrapping && status.cause == Cause::None;
                if status.health || progress {
                    tracing::info!(target: "global", "{text}");
                } else {
                    tracing::warn!(target: "global", "{text}");
                }
                None
            }
            Action::CheckPin => Some(self.pin()),
            Action::Spawn { fresh_directory } => Some(self.spawn(fresh_directory).await),
            // A control ask waits on Tor for up to the reply bound. A stop
            // that arrives meanwhile drops the ask and stops at once: a
            // wedged Tor must not hold the daemon's shutdown for the bound,
            // nor run fault recovery first.
            Action::Sample => {
                let mut stop = self.stop.clone();
                tokio::select! {
                    biased;
                    () = stopped(&mut stop) => Some(Input::Shutdown),
                    input = self.sample() => Some(input),
                }
            }
            Action::WatchState => self.watch_state(),
            Action::SetConfAvoidDiskWrites => {
                let mut stop = self.stop.clone();
                let control = self.control.as_ref()?;
                tokio::select! {
                    biased;
                    () = stopped(&mut stop) => Some(Input::Shutdown),
                    result = control.defer_disk_writes() => {
                        if let Err(error) = result {
                            tracing::warn!(
                                target: "global",
                                "leaving Tor writing its state ({error})"
                            );
                        }
                        None
                    }
                }
            }
            Action::Publish(route) => Some(self.publish_route(route)),
            Action::RepublishOnion => {
                let mut stop = self.stop.clone();
                tokio::select! {
                    biased;
                    () = stopped(&mut stop) => Some(Input::Shutdown),
                    input = self.republish() => Some(input),
                }
            }
            Action::TakeDown => {
                self.withdraw_route(DownCause::ProcessExited);
                self.reap().await;
                None
            }
            Action::StopRoute => {
                self.withdraw_route(DownCause::ProcessStopped);
                None
            }
            Action::StopChild => {
                *halt = true;
                None
            }
        }
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
            Err(error) => match error {
                shekyl_tor_control_daemon::TorBinaryError::NotFound { .. } => Input::BundleMissing,
                shekyl_tor_control_daemon::TorBinaryError::Unavailable { .. } => Input::Unavailable,
                _ => Input::PinRefused,
            },
        }
    }

    async fn spawn(&mut self, fresh_directory: bool) -> Input {
        // A fault reaps before the next pin. A child still held here is kept,
        // not dropped: dropping the control wipes the directory.
        if self.control.is_some() {
            self.reap().await;
        }
        if fresh_directory {
            self.kept.take();
        }
        let Some(binary) = self.pinned.clone() else {
            return Input::PinRefused;
        };
        if let Some(short) = self.space_short() {
            return short;
        }
        let spawned = if let Some(directory) = self.kept.take() {
            DaemonTorControl::spawn_into(directory, binary, self.events.clone(), REPLY_BOUND)
                .await
                .map_err(|failure| (failure.error, Some(failure.directory)))
        } else {
            match DaemonTorControl::spawn_keeping(DaemonTorConfig {
                tor_binary: binary,
                data_dir_parent: self.data_dir.clone(),
                events: self.events.clone(),
                reply_deadline: REPLY_BOUND,
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
                if let Err(error) = up.ask(Command::supervisor_events()).await {
                    tracing::warn!(target: "global", "Tor events were not subscribed ({error})");
                }
                self.control = Some(up);
                Input::Spawned
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

    async fn sample(&mut self) -> Input {
        let Some(control) = self.control.as_mut() else {
            return Input::ControlEnded;
        };
        let reply = control
            .ask(Command::GetInfo(vec![
                BOOTSTRAP_PHASE.to_owned(),
                SOCKS_LISTENERS.to_owned(),
                TRAFFIC_READ.to_owned(),
            ]))
            .await;
        let reply = match reply {
            Ok(reply) => reply,
            Err(error) => return input_of_ask(&error),
        };
        let socks = parse_socks_listeners(&reply);
        if let Some(socks) = socks {
            control.set_socks(socks);
        }
        Input::DirectorySample {
            progress: parse_bootstrap_progress(&reply),
            socks,
            read: parse_traffic_read(&reply),
        }
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
                Input::RouteInstalled
            }
            None => Input::HostAbsent,
        }
    }

    async fn republish(&self) -> Input {
        let Some(control) = self.control.as_ref() else {
            return Input::ControlEnded;
        };
        let Some(forward) = *self.forward.borrow() else {
            return Input::ForwardAbsent;
        };
        match control
            .publish(
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

    /// Stop the child and keep its directory. The generation moves so the
    /// stop's own death is not a second fault.
    /// The pre-spawn space check (`TOR_SUPERVISOR.md` §5, "Data directory
    /// unusable"): a spawn needs Tor's write headroom free, plus the cache's
    /// size when it takes a fresh directory. A disk that fills after the spawn
    /// is not this check's: Tor runs on, and a respawn checks again. A probe
    /// that cannot read the disk lets the spawn go ahead: "I cannot tell" is
    /// not "full".
    fn space_short(&self) -> Option<Input> {
        let needed = space_needed(&self.data_dir, self.kept.is_none());
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

    async fn reap(&mut self) {
        self.bootstrap = None;
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
            BootstrapState::Connecting { progress } => Some(Input::DirectorySample {
                progress: Some(progress),
                socks: None,
                read: None,
            }),
        }
    }

    fn now(&self) -> u64 {
        now(&self.owner)
    }
}

fn now(owner: &OwnerHandle<MonotonicClock>) -> u64 {
    owner.clock().now().get()
}

fn arm(owner: &OwnerHandle<MonotonicClock>, deadline: Option<u64>) {
    let _cleared = owner.clear();
    if let Some(deadline) = deadline {
        let _armed = owner.arm(Tick::new(deadline));
    }
}

async fn wait_bootstrap(bootstrap: &mut Option<watch::Receiver<BootstrapState>>) {
    if let Some(bootstrap) = bootstrap {
        let _changed = bootstrap.changed().await;
    } else {
        std::future::pending::<()>().await;
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

fn input_of_ask(error: &DaemonTorStartError) -> Input {
    match error {
        DaemonTorStartError::Control(ControlError::Timeout) => Input::ReplyLate,
        _ => Input::ControlEnded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A control ask that never answers, the wedged-Tor case, does not hold
    /// a stop: the stop resolves the race and the driver folds `Shutdown`.
    /// Dropping the `stopped` arm from the select makes this time out.
    #[tokio::test(start_paused = true)]
    async fn a_stop_interrupts_an_ask_a_wedged_tor_never_answers() {
        let (tx, rx) = watch::channel(false);
        let mut stop = rx.clone();
        let wedged = std::future::pending::<Input>();
        let raced = tokio::spawn(async move {
            tokio::select! {
                biased;
                () = stopped(&mut stop) => Some(Input::Shutdown),
                input = wedged => Some(input),
            }
        });
        tokio::time::sleep(Duration::from_secs(1)).await;
        tx.send(true).expect("the driver still holds the receiver");
        let outcome = tokio::time::timeout(Duration::from_secs(1), raced)
            .await
            .expect("the stop ended the ask within a second, not the 30 s bound")
            .expect("the race task ran");
        assert_eq!(outcome, Some(Input::Shutdown));
    }

    /// An ask that answers is unaffected, and a stop signalled before the
    /// ask began still wins (the daemon is already stopping).
    #[tokio::test]
    async fn an_answer_passes_through_and_an_earlier_stop_wins() {
        let (_tx, rx) = watch::channel(false);
        let mut stop = rx.clone();
        let answered = tokio::select! {
            biased;
            () = stopped(&mut stop) => Some(Input::Shutdown),
            input = async { Input::ReplyLate } => Some(input),
        };
        assert_eq!(answered, Some(Input::ReplyLate));

        let (tx, rx) = watch::channel(false);
        tx.send(true).expect("receiver alive");
        let mut stop = rx.clone();
        let raced = tokio::select! {
            biased;
            () = stopped(&mut stop) => Some(Input::Shutdown),
            input = std::future::pending::<Input>() => Some(input),
        };
        assert_eq!(raced, Some(Input::Shutdown));
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
}
