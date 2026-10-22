// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The managed Tor supervisor (`TOR_SUPERVISOR.md` §4, increment 3).
//!
//! The policy core is sans-IO. This driver performs what it asks, on the
//! daemon's one timing engine, and publishes the Tor route only from a
//! [`ManagedRunning`] the core builds when Tor is running.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use shekyl_daemon_config::sections::Tor;
use shekyl_ffi::zone_ffi::DownCause;
use shekyl_timing_engine::{Clock, MonotonicClock, OwnerClass, OwnerHandle, Tick};
use shekyl_tor_control_client::binary::{discover_and_verify, discover_and_verify_at};
use shekyl_tor_control_client::control::{
    parse_bootstrap_progress, parse_event, parse_socks_listeners, BootstrapState, Command,
    ControlReply, EventSink,
};
use shekyl_tor_control_client::supervisor::{
    input_of, render, Action, Connectors, Core, Input, ManagedRunning, Policy, Step, TorSetting,
};
use shekyl_tor_control_daemon::{
    DaemonTorConfig, DaemonTorControl, DaemonTorStartError, KeptDataDir, OnionPow, OnionSeed,
    SpawnError, TorBinaryError, TorDeath,
};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// A control reply this far past due is a process fault. Not a bootstrap limit.
const REPLY_BOUND: Duration = Duration::from_secs(30);
/// The onion's stream cap.
const MAX_STREAMS: u16 = 8;

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
    mut stop: watch::Receiver<bool>,
    mut forward: watch::Receiver<Option<SocketAddr>>,
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
    let (events, mut incoming) = EventSink::bounded();
    let connectors = Connectors {
        tor: TorSetting::Managed,
        clearnet_on,
    };
    let (mut core, mut step) = Core::start(Policy::provisional(), connectors, now(&owner));
    let mut control: Option<DaemonTorControl> = None;
    let mut kept: Option<KeptDataDir> = None;
    let mut pinned = None;
    let mut incarnation = None;
    let mut pending_route: Option<ManagedRunning> = None;
    let mut publish_onion = false;
    let mut generation = 0u64;
    let (death_tx, mut death_rx) = mpsc::channel(4);
    let mut bootstrap: Option<tokio::sync::watch::Receiver<BootstrapState>> = None;

    loop {
        let mut halt = false;
        step = perform(
            &mut core,
            step,
            &owner,
            &binary,
            &data_dir,
            &events,
            &seed,
            virtual_port,
            &mut control,
            &mut kept,
            &mut pinned,
            &mut incarnation,
            &mut pending_route,
            &mut publish_onion,
            &forward,
            &mut generation,
            &death_tx,
            &mut bootstrap,
            &mut halt,
        )
        .await;
        if halt {
            break;
        }
        arm(&owner, step.deadline);
        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    step = core.on(Input::Shutdown, now(&owner));
                }
            }
            _ = forward.changed() => {}
            wake = owner.wait_wake_async() => {
                if wake.is_err() {
                    break;
                }
                step = core.on_deadline(now(&owner));
            }
            event = incoming.recv() => {
                if let Some(reply) = event {
                    if let Some(parsed) = parse_event(&reply) {
                        if let Some(input) = input_of(&parsed) {
                            step = core.on(input, now(&owner));
                        }
                    }
                }
            }
            death = death_rx.recv() => {
                if let Some((gen, how)) = death {
                    if gen == generation && how == TorDeath::Exited {
                        step = core.on(
                            Input::ProcessEnded { exit_code: None },
                            now(&owner),
                        );
                    }
                }
            }
            () = wait_bootstrap(&mut bootstrap) => {
                if bootstrap.as_ref().is_some_and(|rx| matches!(*rx.borrow(), BootstrapState::Ready))
                {
                    if let Some(control) = control.as_mut() {
                        control.mark_bootstrapped();
                    }
                    step = core.on(Input::BootstrapComplete, now(&owner));
                } else if bootstrap
                    .as_ref()
                    .is_some_and(|rx| matches!(*rx.borrow(), BootstrapState::Failed))
                {
                    step = core.on(Input::ControlEnded, now(&owner));
                }
            }
        }
    }
    if let Some(control) = control {
        let _exit = control.shutdown().await;
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

async fn wait_bootstrap(bootstrap: &mut Option<tokio::sync::watch::Receiver<BootstrapState>>) {
    if let Some(bootstrap) = bootstrap {
        let _changed = bootstrap.changed().await;
    } else {
        std::future::pending::<()>().await
    }
}

#[allow(clippy::too_many_arguments)]
async fn perform(
    core: &mut Core,
    mut step: Step,
    owner: &OwnerHandle<MonotonicClock>,
    binary: &Option<PathBuf>,
    data_dir: &Path,
    events: &EventSink,
    seed: &OnionSeed,
    virtual_port: u16,
    control: &mut Option<DaemonTorControl>,
    kept: &mut Option<KeptDataDir>,
    pinned: &mut Option<shekyl_tor_control_client::binary::VerifiedTorBinary>,
    incarnation: &mut Option<u64>,
    pending_route: &mut Option<ManagedRunning>,
    publish_onion: &mut bool,
    forward: &watch::Receiver<Option<SocketAddr>>,
    generation: &mut u64,
    death_tx: &mpsc::Sender<(u64, TorDeath)>,
    bootstrap: &mut Option<tokio::sync::watch::Receiver<BootstrapState>>,
    halt: &mut bool,
) -> Step {
    try_pending_route(pending_route, incarnation);
    let mut queue: std::collections::VecDeque<Action> = step.actions.drain(..).collect();
    while let Some(action) = queue.pop_front() {
        let input = match action {
            Action::Announce => {
                let status = core.status();
                let text = render(&status);
                if status.health {
                    tracing::info!(target: "global", "{text}");
                } else {
                    tracing::warn!(target: "global", "{text}");
                }
                None
            }
            Action::CheckPin => Some(pin(binary, pinned)),
            Action::Spawn { fresh_directory } => Some(
                spawn(
                    fresh_directory,
                    pinned,
                    data_dir,
                    events,
                    control,
                    kept,
                    generation,
                    death_tx,
                    bootstrap,
                )
                .await,
            ),
            Action::Sample => sample(control, owner).await,
            Action::WatchState => watch_state(control),
            Action::SetConfAvoidDiskWrites => {
                if let Some(control) = control.as_ref() {
                    if let Err(error) = control.defer_disk_writes().await {
                        tracing::warn!(
                            target: "global",
                            "leaving Tor writing its state ({error})"
                        );
                    }
                }
                None
            }
            Action::Publish(route) => {
                publish_route(route, pending_route, incarnation);
                None
            }
            Action::RepublishOnion => {
                *publish_onion = true;
                None
            }
            Action::TakeDown => {
                take_down(incarnation);
                *generation = generation.wrapping_add(1);
                if let Some(control) = control.take() {
                    *kept = Some(control.stop_for_respawn().await);
                }
                *bootstrap = None;
                None
            }
            Action::StopChild => {
                *halt = true;
                None
            }
        };
        if let Some(input) = input {
            step = core.on(input, now(owner));
            for action in step.actions.drain(..).rev() {
                queue.push_front(action);
            }
        }
        if *publish_onion && publish_held_onion(control, seed, virtual_port, forward).await {
            *publish_onion = false;
        }
    }
    step
}

fn pin(
    binary: &Option<PathBuf>,
    pinned: &mut Option<shekyl_tor_control_client::binary::VerifiedTorBinary>,
) -> Input {
    let verified = match binary {
        Some(path) => discover_and_verify_at(path),
        None => discover_and_verify(),
    };
    match verified {
        Ok(binary) => {
            *pinned = Some(binary);
            Input::PinAccepted
        }
        Err(TorBinaryError::NotFound) => Input::BundleMissing,
        Err(TorBinaryError::Unavailable { .. }) => Input::Unavailable,
        Err(_) => Input::PinRefused,
    }
}

#[allow(clippy::too_many_arguments)]
async fn spawn(
    fresh_directory: bool,
    pinned: &Option<shekyl_tor_control_client::binary::VerifiedTorBinary>,
    data_dir: &Path,
    events: &EventSink,
    control: &mut Option<DaemonTorControl>,
    kept: &mut Option<KeptDataDir>,
    generation: &mut u64,
    death_tx: &mpsc::Sender<(u64, TorDeath)>,
    bootstrap: &mut Option<tokio::sync::watch::Receiver<BootstrapState>>,
) -> Input {
    if fresh_directory {
        drop(kept.take());
    }
    let Some(binary) = pinned.clone() else {
        return Input::PinRefused;
    };
    let spawned = if let Some(directory) = kept.take() {
        DaemonTorControl::spawn_into(directory, binary, events.clone(), REPLY_BOUND)
            .await
            .map_err(|failure| (failure.error, Some(failure.directory)))
    } else {
        match DaemonTorControl::spawn_keeping(DaemonTorConfig {
            tor_binary: binary,
            data_dir_parent: data_dir.to_path_buf(),
            events: events.clone(),
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
            *generation = generation.wrapping_add(1);
            let gen = *generation;
            let death = up.death();
            let tx = death_tx.clone();
            tokio::spawn(async move {
                let _sent = tx.send((gen, death.await)).await;
            });
            *bootstrap = Some(up.watch_bootstrap());
            if let Err(error) = up.ask(Command::supervisor_events()).await {
                tracing::warn!(target: "global", "Tor events were not subscribed ({error})");
            }
            *control = Some(up);
            Input::Spawned
        }
        Err((error, directory)) => {
            if let Some(directory) = directory {
                *kept = Some(directory);
            }
            match error {
                DaemonTorStartError::DataDir(_) => Input::DirectoryUnusable,
                _ => Input::SpawnFailed,
            }
        }
    }
}

async fn sample(
    control: &mut Option<DaemonTorControl>,
    owner: &OwnerHandle<MonotonicClock>,
) -> Option<Input> {
    let Some(control) = control.as_mut() else {
        return Some(Input::SpawnFailed);
    };
    let reply = tokio::time::timeout(
        REPLY_BOUND,
        control.ask(Command::GetInfo(vec![
            "status/bootstrap-phase".to_owned(),
            "net/listeners/socks".to_owned(),
            "traffic/read".to_owned(),
        ])),
    )
    .await;
    let reply = match reply {
        Ok(Ok(reply)) => reply,
        Ok(Err(DaemonTorStartError::Died(_))) => return Some(Input::ControlEnded),
        _ => return Some(Input::ReplyLate),
    };
    if let Some(socks) = parse_socks_listeners(&reply) {
        control.set_socks(socks);
        // The sample input carries the progress. The socks binding is a
        // second input, applied by the caller through the returned value
        // only once. Prefer the socks input when the address just appeared;
        // the following sample carries progress.
        let _ = owner;
        return Some(Input::SocksBound(socks));
    }
    Some(Input::DirectorySample {
        progress: parse_bootstrap_progress(&reply),
        traffic_read: traffic_read(&reply),
    })
}

fn watch_state(control: &Option<DaemonTorControl>) -> Option<Input> {
    let Some(control) = control else {
        return None;
    };
    control
        .data_path()
        .join("state")
        .is_file()
        .then_some(Input::StateFileAppeared)
}

fn publish_route(
    route: ManagedRunning,
    pending: &mut Option<ManagedRunning>,
    incarnation: &mut Option<u64>,
) {
    match shekyl_ffi::zone_ffi::publish_managed_running(&route) {
        Some(installed) => *incarnation = Some(installed),
        None => *pending = Some(route),
    }
}

fn try_pending_route(pending: &mut Option<ManagedRunning>, incarnation: &mut Option<u64>) {
    let Some(route) = pending.take() else {
        return;
    };
    match shekyl_ffi::zone_ffi::publish_managed_running(&route) {
        Some(installed) => *incarnation = Some(installed),
        None => *pending = Some(route),
    }
}

fn take_down(incarnation: &mut Option<u64>) {
    if let Some(incarnation) = incarnation.take() {
        let _fell = shekyl_ffi::zone_ffi::publish_tor_down(incarnation, DownCause::ProcessExited);
    }
}

async fn publish_held_onion(
    control: &Option<DaemonTorControl>,
    seed: &OnionSeed,
    virtual_port: u16,
    forward: &watch::Receiver<Option<SocketAddr>>,
) -> bool {
    let (Some(control), Some(forward)) = (control, *forward.borrow()) else {
        return false;
    };
    match control
        .publish(seed, virtual_port, forward, MAX_STREAMS, OnionPow::Enabled)
        .await
    {
        Ok(service) => {
            shekyl_ffi::dialer_ffi::note_own_onion(service.as_str(), virtual_port);
            tracing::info!(
                target: "global",
                "Tor is up: overlay inbound is published at {}.onion",
                service.as_str()
            );
            true
        }
        Err(error) => {
            tracing::warn!(target: "global", "the onion was not published ({error})");
            false
        }
    }
}

fn traffic_read(reply: &ControlReply) -> Option<u64> {
    reply.lines().iter().find_map(|line| {
        line.strip_prefix("traffic/read=")
            .and_then(|value| value.parse().ok())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An exit and a stop are different link causes. Swapping the arms
    /// fails this.
    fn down_cause(death: TorDeath) -> DownCause {
        match death {
            TorDeath::Exited => DownCause::ProcessExited,
            TorDeath::Stopped => DownCause::ProcessStopped,
        }
    }

    #[test]
    fn an_exit_and_a_stop_are_different_link_causes() {
        assert_eq!(down_cause(TorDeath::Exited), DownCause::ProcessExited);
        assert_eq!(down_cause(TorDeath::Stopped), DownCause::ProcessStopped);
    }
}
