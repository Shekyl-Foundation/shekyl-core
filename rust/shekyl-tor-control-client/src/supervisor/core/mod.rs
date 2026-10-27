// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The managed Tor's phase machine.
//!
//! One [`Input`] moves the [`Phase`]. The [`Action`]s that come back are
//! the whole instruction to the driver. A publish the driver could not
//! perform comes back as an input, and the phase keeps the duty.

use std::net::SocketAddr;
use std::time::Duration;

use super::posture::{
    fixes, own_tx, BootstrapLine, Cause, Connectors, OriginVerdict, ProgressWindow, Shown, Space,
    Status, Syncing,
};

mod announce;
mod backoff;
mod dials;
mod network_view;
mod running;

use crate::control::NetworkView;
use announce::{Announcements, Cadence};
use backoff::Backoff;
pub use dials::DialTally;
use dials::Dials;

/// How long a respawn waits, and how often a failure is said again.
///
/// `TSR-M2` measured the repair and did not move these waits. A test passes
/// the policy it means to pin.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// The first process-fault wait.
    pub base: Duration,
    /// The longest wait, and the gap between repeated announcements.
    pub cap: Duration,
    /// How often a bootstrap is sampled while Tor is answering.
    pub sample_every: Duration,
    /// How often a live Tor is checked, and the width of the bootstrap
    /// window. While Running the check is [`Action::Sample`]: one `GETINFO`,
    /// so a Tor that sends nothing still meets the driver's reply bound.
    /// While bootstrapping the check is [`Action::SayProgress`]: the log says
    /// the line once per this interval. The line itself stays current at
    /// every directory sample. Its byte window opens on the newest sample at
    /// least this old, and runs to the moment it is read.
    pub alive_every: Duration,
    /// Consecutive failed launches before the next one takes a fresh
    /// data directory. `TSR-M2` had no launch failure, so this stays 3.
    pub fresh_directory_after: u32,
    /// How long no Tor connection is open and none opens, with Tor saying
    /// nothing about its network, before the posture line says so (§4.2):
    /// a neutral fact, never a cause. Provisional until the floor-device
    /// soak.
    pub quiet_after: Duration,
}

impl Policy {
    /// The waits the driver uses.
    #[must_use]
    pub const fn provisional() -> Self {
        Self {
            base: Duration::from_secs(1),
            cap: Duration::from_secs(60),
            sample_every: Duration::from_secs(5),
            // With the driver's 30 s reply bound, a wedge is a fault within
            // about a minute: the same order as `TSR-M2`'s 60 s bound.
            alive_every: Duration::from_secs(30),
            fresh_directory_after: 3,
            // Wall time since the last opened stream, or since this Tor
            // reached Running, with at least one unopened dial and nothing
            // held. Five minutes, provisional until the floor-device soak.
            // Not a count of dials.
            quiet_after: Duration::from_secs(300),
        }
    }
}

/// What the driver does next.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Discover and pin. No spawn until this accepts.
    CheckPin,
    /// Spawn. `fresh_directory` drops the kept data directory first.
    Spawn {
        /// Take a new data directory.
        fresh_directory: bool,
    },
    /// One `GETINFO` of bootstrap progress, the SOCKS listeners, and
    /// `traffic/read`. While Running the same reply also carries Tor's
    /// network view ([`Input::NetworkView`]); during a bootstrap those keys
    /// are not asked. While Running this is the liveness question: a Tor
    /// that sends nothing still has a reply to be late with.
    /// A reply inside the driver's bound is [`Input::DirectorySample`],
    /// then [`Input::NetworkView`] while Running.
    /// A reply past it is [`Input::ReplyLate`].
    Sample,
    /// Look for the first `state` file.
    WatchState,
    /// `SETCONF AvoidDiskWrites=1` on the owning connection.
    SetConfAvoidDiskWrites,
    /// Publish the managed route. Only the transition into `Running` builds it.
    Publish(ManagedRunning),
    /// The installed route is down because the process ended. The driver
    /// reaps and keeps the directory.
    TakeDown,
    /// The installed route is down because this node is stopping. The
    /// driver leaves the child up; [`Self::StopChild`] wipes it.
    StopRoute,
    /// `ADD_ONION` with the boot's seed.
    RepublishOnion,
    /// Say the posture. At most once per cap interval, except a recovery.
    /// The driver logs a healthy posture at info and any other at warn.
    Announce,
    /// Say the bootstrap progress line. News, logged at info. Not
    /// [`Self::Announce`]: a named cause and an origin-hold keep that path.
    SayProgress,
    /// The daemon is stopping. Tear the child down and wipe.
    StopChild,
}

/// The managed Tor's SOCKS route. Built only on the transition into `Running`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedRunning {
    socks: SocketAddr,
}

impl ManagedRunning {
    /// The SOCKS address the link publishes.
    #[must_use]
    pub fn socks(self) -> SocketAddr {
        self.socks
    }
}

/// What the driver observed.
#[derive(Debug, PartialEq, Eq)]
pub enum Input {
    /// The pin accepted the binary.
    PinAccepted,
    /// The pin refused it.
    PinRefused,
    /// No bundle was found.
    BundleMissing,
    /// This platform manages no Tor.
    Unavailable,
    /// The data directory cannot be used, or has too little free space for
    /// the spawn (the pre-spawn check).
    DirectoryUnusable {
        /// The daemon's data directory.
        path: std::path::PathBuf,
        /// The shortfall, when that was the reason.
        space: Option<Space>,
    },
    /// The process is up and the control connection answered.
    Spawned,
    /// The process did not stay up through the launch.
    SpawnFailed,
    /// Bootstrap reached the ready gate.
    BootstrapComplete,
    /// A directory sample answered inside the reply bound.
    ///
    /// This is the `GETINFO` reply, not the actor's bootstrap poll. The poll
    /// is [`Self::BootstrapNoted`]: it carries no byte count and does not
    /// move the sample deadline.
    ///
    /// `socks` is `Some` when this reply named a listener. `None` leaves
    /// a listener the core already recorded.
    DirectorySample {
        /// `PROGRESS=`, when the reply carried one.
        progress: Option<u8>,
        /// The SOCKS listener, when the reply named one.
        socks: Option<SocketAddr>,
        /// `traffic/read`, the bytes Tor has read since it started, when the
        /// reply carried a count. `None` is unknown, never zero.
        read: Option<u64>,
    },
    /// The actor's bootstrap poll moved the percent. Not a sample.
    BootstrapNoted {
        /// `PROGRESS=`.
        progress: u8,
    },
    /// A control reply missed the bound.
    ReplyLate,
    /// The process ended.
    ProcessEnded {
        /// The exit code, when the reap reported one.
        exit_code: Option<i32>,
    },
    /// The control connection ended.
    ControlEnded,
    /// The zone host was not up, so the route was not installed.
    HostAbsent,
    /// The route is installed.
    RouteInstalled,
    /// The forward listener was not bound, so the onion was not published.
    ForwardAbsent,
    /// `ADD_ONION` succeeded.
    OnionPublished,
    /// `ADD_ONION` failed. The process stays up.
    OnionRejected,
    /// The zone host is up and the forward listener is bound.
    EndpointReady,
    /// Outbound to the Tor network is blocked.
    ExternalBlocked,
    /// No directory is reachable.
    DirectoryUnreachable,
    /// A reported clock difference.
    ClockSkew {
        /// Seconds.
        seconds: i64,
    },
    /// Tor resumed and closed its circuits.
    ClockJumped,
    /// The open-file limit. The process stays up.
    TooManyFiles {
        /// Sockets Tor reported open.
        open: u64,
    },
    /// An upload of our descriptor failed.
    DescriptorFailed,
    /// An upload of our descriptor reached a directory.
    DescriptorUploaded,
    /// The consensus does not recommend this Tor.
    DangerousVersion,
    /// `state` exists in the data directory.
    StateFileAppeared,
    /// The daemon is stopping.
    Shutdown,
    /// The relay's hop-0 verdict for a local origin moved (`GS-Q3`).
    AddressHidingOrigin(OriginVerdict),
    /// The tally already in the cell when this supervisor started watching.
    /// It is the baseline, not an open: the stretch clock does not move.
    DialBaseline(DialTally),
    /// The dialer's tally of this node's Tor dials changed (§4.2). Display
    /// only, never a cause (`TSR-Q14`).
    DialEvidence(DialTally),
    /// Tor's sampled view of its network. Ignored unless Running.
    NetworkView(NetworkView),
    /// Tor says it reaches its network: `NETWORK_LIVENESS UP` or
    /// `CIRCUIT_ESTABLISHED`.
    ExternalCleared,
}

/// Actions and the next absolute deadline, in the caller's clock units.
/// `None` waits until the next input.
#[derive(Debug, PartialEq, Eq)]
pub struct Step {
    /// What to perform, in order.
    pub actions: Vec<Action>,
    /// When to call [`Core::on_deadline`], if anything is waiting.
    pub deadline: Option<u64>,
}

/// Why there is no process, and what the next deadline may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AbsentDuty {
    /// A process fault. The pin is checked when the backoff elapses.
    Retry,
    /// A spawn precondition failed. The pin is checked when the cap elapses.
    Held,
    /// This build has no managed Tor. Nothing is spawned.
    Fixed,
}

/// A publish the running Tor still owes the driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Duty {
    /// Ask the driver.
    Owed,
    /// Asked, and the endpoint was not there. Asked again on [`Input::EndpointReady`].
    Waiting,
    /// The driver reported it done.
    Done,
}

/// `AvoidDiskWrites` relative to Tor's first `state` file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disk {
    /// Look for the first `state` file.
    Watching,
    /// `AvoidDiskWrites=1` has been asked.
    Deferred,
}

/// The outbound facet while Tor is running, apart from [`Cause`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Link {
    /// The cause says whether the facet is up.
    Open,
    /// `CLOCK_JUMPED`. Shown as bootstrapping until the next sample.
    Resumed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Absent {
        duty: AbsentDuty,
    },
    Launching,
    Bootstrapping {
        socks: Option<SocketAddr>,
        ready: bool,
    },
    Running {
        socks: SocketAddr,
        route: Duty,
        onion: Duty,
        disk: Disk,
        link: Link,
    },
    Stopping,
}

/// The sans-IO supervisor.
#[derive(Debug)]
pub struct Core {
    policy: Policy,
    connectors: Connectors,
    /// The relay's hop-0 verdict, as last folded (`GS-Q3`).
    origin: OriginVerdict,
    phase: Phase,
    cause: Cause,
    /// The [`Shown`] value [`Self::since`] names. `since` moves when the
    /// projection changes, which is not the same event as a new cause.
    posted: Shown,
    since: u64,
    announcements: Announcements,
    respawn_count: u32,
    launch_failures: u32,
    backoff: Backoff,
    /// The bootstrap percent and the byte mark the progress line measures.
    progress: ProgressWindow,
    /// What this node's own Tor dials show (§4.2). Display only.
    dials: Dials,
    /// When the next pin check is due. Only while [`Phase::Absent`] is
    /// [`AbsentDuty::Retry`] or [`AbsentDuty::Held`].
    pin_at: Option<u64>,
    /// When the next sample or `state` watch is due.
    sample_at: Option<u64>,
    /// When the live check is next due: [`Action::Sample`] while Running,
    /// [`Action::SayProgress`] while bootstrapping. Only in those phases.
    alive_at: Option<u64>,
}

impl Core {
    /// Start. The first action is the pin check.
    #[must_use]
    pub fn start(policy: Policy, connectors: Connectors, now: u64) -> (Self, Step) {
        let mut core = Self {
            policy,
            connectors,
            origin: OriginVerdict::Absent,
            phase: Phase::Absent {
                duty: AbsentDuty::Retry,
            },
            cause: Cause::None,
            posted: Shown::Restarting,
            since: now,
            announcements: Announcements::new(),
            respawn_count: 0,
            launch_failures: 0,
            backoff: Backoff::new(),
            progress: ProgressWindow::start(now, policy.alive_every),
            dials: Dials::new(now),
            pin_at: None,
            sample_at: None,
            alive_at: None,
        };
        let step = core.step(now, vec![Action::CheckPin]);
        (core, step)
    }

    /// Fold one observation in.
    ///
    /// CLIPPY: an observation is consumed by the transition. The driver does
    /// not keep it, and a reference would only clone the fields out.
    #[allow(clippy::needless_pass_by_value)]
    pub fn on(&mut self, input: Input, now: u64) -> Step {
        let actions = match input {
            Input::PinAccepted => self.pin_accepted(),
            Input::PinRefused => self.hold(now, Cause::PinRefused, AbsentDuty::Held),
            Input::BundleMissing => self.hold(now, Cause::BundleMissing, AbsentDuty::Held),
            Input::Unavailable => self.hold(now, Cause::Unavailable, AbsentDuty::Fixed),
            Input::DirectoryUnusable { path, space } => self.hold(
                now,
                Cause::DirectoryUnusable { path, space },
                AbsentDuty::Held,
            ),
            Input::Spawned => self.spawned(now),
            Input::SpawnFailed => self.launch_failed(now),
            Input::BootstrapComplete => self.bootstrap_complete(now),
            Input::DirectorySample {
                progress,
                socks,
                read,
            } => self.note_sample(now, progress, socks, read),
            Input::BootstrapNoted { progress } => self.note_bootstrap(now, progress),
            Input::ReplyLate => self.process_fault(now, Cause::ReplyLate, false),
            Input::ProcessEnded { exit_code } => {
                self.process_fault(now, Cause::Died { exit_code }, false)
            }
            Input::ControlEnded => self.process_fault(now, Cause::Died { exit_code: None }, false),
            Input::HostAbsent => self.host_absent(),
            Input::RouteInstalled => self.route_installed(now),
            Input::ForwardAbsent => self.forward_absent(),
            Input::OnionPublished | Input::DescriptorUploaded => self.onion_published(),
            Input::OnionRejected => self.onion_rejected(now),
            Input::EndpointReady => self.endpoint_ready(),
            Input::ExternalBlocked => self.external(now, Cause::ExternalBlocked),
            Input::DirectoryUnreachable => self.external(now, Cause::DirectoryUnreachable),
            Input::ClockSkew { seconds } => self.external(now, Cause::ClockSkew { seconds }),
            Input::ClockJumped => self.clock_jumped(),
            Input::TooManyFiles { open } => self.too_many_files(now, open),
            Input::DescriptorFailed => self.descriptor_failed(),
            Input::DangerousVersion => {
                self.set_cause(Cause::DangerousVersion);
                self.say(now, Cadence::Due)
            }
            Input::StateFileAppeared => self.state_file(),
            Input::Shutdown => self.shutdown(),
            Input::AddressHidingOrigin(verdict) => self.origin_verdict(verdict, now),
            Input::DialBaseline(tally) => self.dial_baseline(tally),
            Input::DialEvidence(tally) => self.dial_evidence(tally, now),
            Input::NetworkView(view) => self.network_view(now, view),
            Input::ExternalCleared => self.external_cleared(now),
        };
        self.step(now, actions)
    }

    /// The deadline fired. Each armed time is its own kind of work: a pin
    /// check, a sample, or another announcement.
    pub fn on_deadline(&mut self, now: u64) -> Step {
        if self.phase == Phase::Stopping {
            self.pin_at = None;
            self.sample_at = None;
            self.announcements.disarm();
            self.alive_at = None;
            return self.step(now, Vec::new());
        }
        if self.deadline().is_none_or(|due| now < due) {
            return self.step(now, Vec::new());
        }
        let mut actions = Vec::new();
        let pin_due = self.pin_at.is_some_and(|at| now >= at);
        if self.announcements.on_deadline(
            now,
            self.say_key(),
            self.cap(),
            self.repeats_announcement(),
            pin_due,
        ) {
            actions.push(Action::Announce);
        }
        if pin_due {
            self.pin_at = None;
            if matches!(
                self.phase,
                Phase::Absent {
                    duty: AbsentDuty::Retry | AbsentDuty::Held
                }
            ) {
                actions.push(Action::CheckPin);
            }
        }
        if self.sample_at.is_some_and(|at| now >= at) {
            self.sample_at = None;
            actions.extend(self.on_sample_deadline(now));
        }
        if self.alive_at.is_some_and(|at| now >= at) {
            self.alive_at = None;
            match self.phase {
                Phase::Running { .. } => {
                    actions.push(Action::Sample);
                    actions.extend(self.quiet_line(now));
                    self.arm_alive(now);
                }
                Phase::Bootstrapping { .. } => {
                    self.progress.speak(now);
                    // A named cause is said by its own events, at most once
                    // per cap. The progress line is a different action, so
                    // it cannot say the cause again.
                    if self.cause == Cause::None {
                        actions.push(Action::SayProgress);
                    }
                    self.arm_alive(now);
                }
                // Cleared above. A phase that is no longer live does not
                // re-arm: fault, hold, and shutdown already dropped it.
                _ => {}
            }
        }
        self.step(now, actions)
    }

    /// The typed read.
    #[must_use]
    pub fn status(&self) -> Status {
        let shown = self.shown();
        // Health is the verdict's class part, not the link: after a boot the
        // link is usable before any address-hiding peer has handshaken.
        let bootstrap = match self.phase {
            Phase::Bootstrapping { .. } => self.progress.line(),
            _ => None,
        };
        Status {
            health: self.origin.hides_address(),
            shown,
            cause: self.cause.clone(),
            since: self.since,
            respawn_count: self.respawn_count,
            sync: Syncing {
                clearnet: self.connectors.clearnet_on,
                tor: shown == Shown::Usable,
            },
            own_tx: own_tx(self.origin, self.connectors),
            fixes: fixes(&self.cause, self.connectors),
            progress: self.progress.percent(),
            bootstrap,
            pace: bootstrap.and_then(BootstrapLine::pace),
            tor_quiet: match (&self.phase, &self.cause) {
                (Phase::Running { .. }, Cause::None) => self.dials.line(),
                _ => None,
            },
        }
    }

    /// The next time [`Self::on_deadline`] has work, in the caller's clock.
    #[must_use]
    fn deadline(&self) -> Option<u64> {
        [
            self.pin_at,
            self.sample_at,
            self.announcements.due(),
            self.alive_at,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn pin_accepted(&mut self) -> Vec<Action> {
        self.phase = Phase::Launching;
        let fresh =
            self.launch_failures >= self.policy.fresh_directory_after && self.launch_failures > 0;
        vec![Action::Spawn {
            fresh_directory: fresh,
        }]
    }

    fn spawned(&mut self, now: u64) -> Vec<Action> {
        self.phase = Phase::Bootstrapping {
            socks: None,
            ready: false,
        };
        self.launch_failures = 0;
        self.progress = ProgressWindow::start(now, self.policy.alive_every);
        self.set_cause(Cause::None);
        self.arm_sample(now);
        self.arm_alive(now);
        vec![Action::Sample]
    }

    fn bootstrap_complete(&mut self, now: u64) -> Vec<Action> {
        let bound = match &mut self.phase {
            Phase::Bootstrapping { ready, socks } => {
                *ready = true;
                *socks
            }
            _ => return Vec::new(),
        };
        if let Some(socks) = bound {
            self.enter_running(now, socks)
        } else {
            // One ask for the listener. A reply that still omits it waits
            // out the sample interval instead of asking again.
            vec![Action::Sample]
        }
    }

    fn note_sample(
        &mut self,
        now: u64,
        progress: Option<u8>,
        socks: Option<SocketAddr>,
        read: Option<u64>,
    ) -> Vec<Action> {
        if let Some(progress) = progress {
            self.progress.note_percent(progress, now);
        }
        self.progress.note_read(read, now);
        if let Phase::Running { link, .. } = &mut self.phase {
            *link = Link::Open;
            return Vec::new();
        }
        let enter = match &mut self.phase {
            Phase::Bootstrapping {
                socks: have, ready, ..
            } => {
                if let Some(addr) = socks {
                    *have = Some(addr);
                }
                match (*ready, *have) {
                    (true, Some(addr)) => Some(addr),
                    // Not ready yet, or ready and still no listener. The
                    // deadline asks again. An immediate sample here loops.
                    _ => None,
                }
            }
            _ => return Vec::new(),
        };
        if let Some(addr) = enter {
            self.enter_running(now, addr)
        } else {
            self.arm_sample(now);
            Vec::new()
        }
    }

    fn route_installed(&mut self, now: u64) -> Vec<Action> {
        let Phase::Running { route, .. } = &mut self.phase else {
            return Vec::new();
        };
        let first = *route != Duty::Done;
        *route = Duty::Done;
        if first && self.shown() == Shown::Usable {
            self.say(now, Cadence::Now)
        } else {
            Vec::new()
        }
    }

    fn host_absent(&mut self) -> Vec<Action> {
        if let Phase::Running { route, .. } = &mut self.phase {
            if *route != Duty::Done {
                *route = Duty::Waiting;
            }
        }
        Vec::new()
    }

    fn forward_absent(&mut self) -> Vec<Action> {
        if let Phase::Running { onion, .. } = &mut self.phase {
            if *onion != Duty::Done {
                *onion = Duty::Waiting;
            }
        }
        Vec::new()
    }

    fn onion_published(&mut self) -> Vec<Action> {
        if let Phase::Running { onion, .. } = &mut self.phase {
            *onion = Duty::Done;
        }
        Vec::new()
    }

    fn onion_rejected(&mut self, now: u64) -> Vec<Action> {
        if let Phase::Running { onion, .. } = &mut self.phase {
            *onion = Duty::Owed;
        }
        self.ensure_sample(now);
        Vec::new()
    }

    fn endpoint_ready(&mut self) -> Vec<Action> {
        if let Phase::Running { route, onion, .. } = &mut self.phase {
            if *route == Duty::Waiting {
                *route = Duty::Owed;
            }
            if *onion == Duty::Waiting {
                *onion = Duty::Owed;
            }
        }
        self.owed_actions()
    }

    fn clock_jumped(&mut self) -> Vec<Action> {
        match &mut self.phase {
            Phase::Running { link, .. } => *link = Link::Resumed,
            Phase::Bootstrapping { .. } => {}
            _ => return Vec::new(),
        }
        vec![Action::Sample]
    }

    fn too_many_files(&mut self, now: u64, open: u64) -> Vec<Action> {
        // The process is still up. Stay in the phase: no pin, no takedown.
        if !self.live() {
            return Vec::new();
        }
        self.set_cause(Cause::TooManyFiles { open });
        self.say(now, Cadence::Due)
    }

    fn descriptor_failed(&mut self) -> Vec<Action> {
        let Phase::Running { onion, .. } = &mut self.phase else {
            return Vec::new();
        };
        if *onion != Duty::Done {
            return Vec::new();
        }
        *onion = Duty::Owed;
        vec![Action::RepublishOnion]
    }

    fn state_file(&mut self) -> Vec<Action> {
        let Phase::Running { disk, .. } = &mut self.phase else {
            return Vec::new();
        };
        if *disk == Disk::Deferred {
            return Vec::new();
        }
        *disk = Disk::Deferred;
        if !self.keeps_sampling() {
            self.sample_at = None;
        }
        vec![Action::SetConfAvoidDiskWrites]
    }

    fn launch_failed(&mut self, now: u64) -> Vec<Action> {
        self.process_fault(now, Cause::FailedStart, true)
    }

    fn shutdown(&mut self) -> Vec<Action> {
        let installed = self.route_done();
        self.phase = Phase::Stopping;
        self.pin_at = None;
        self.sample_at = None;
        self.announcements.disarm();
        self.alive_at = None;
        let mut actions = Vec::new();
        if installed {
            actions.push(Action::StopRoute);
        }
        actions.push(Action::StopChild);
        actions
    }

    fn process_fault(&mut self, now: u64, cause: Cause, launch_failed: bool) -> Vec<Action> {
        let installed = self.route_done();
        self.phase = Phase::Absent {
            duty: AbsentDuty::Retry,
        };
        self.sample_at = None;
        self.alive_at = None;
        // Close the usable interval before the wait is chosen, so a cap
        // already served restarts this fault. A degradation earlier records
        // the same cap and this fault consumes it.
        self.settle_shown(now);
        if launch_failed {
            self.launch_failures = self.launch_failures.saturating_add(1);
        } else {
            self.launch_failures = 0;
        }
        let wait = self.backoff.on_fault(self.base(), self.cap());
        self.respawn_count = self.respawn_count.saturating_add(1);
        self.set_cause(cause);
        self.pin_at = Some(now.saturating_add(wait));
        let mut actions = Vec::new();
        if installed {
            actions.push(Action::TakeDown);
        }
        actions.extend(self.say(now, Cadence::Due));
        actions
    }

    fn hold(&mut self, now: u64, cause: Cause, duty: AbsentDuty) -> Vec<Action> {
        let installed = self.route_done();
        self.phase = Phase::Absent { duty };
        self.sample_at = None;
        self.alive_at = None;
        self.pin_at = match duty {
            AbsentDuty::Fixed => None,
            AbsentDuty::Held | AbsentDuty::Retry => Some(now.saturating_add(self.cap())),
        };
        self.set_cause(cause);
        let mut actions = Vec::new();
        if installed {
            actions.push(Action::TakeDown);
        }
        actions.extend(self.say(now, Cadence::Due));
        actions
    }

    fn on_sample_deadline(&mut self, now: u64) -> Vec<Action> {
        let mut actions = Vec::new();
        match self.phase {
            Phase::Bootstrapping { .. } => actions.push(Action::Sample),
            Phase::Running {
                disk: Disk::Watching,
                ..
            } => actions.push(Action::WatchState),
            _ => {}
        }
        actions.extend(self.owed_actions());
        if self.keeps_sampling() {
            self.arm_sample(now);
        }
        actions
    }

    fn owed_actions(&self) -> Vec<Action> {
        let Phase::Running {
            socks,
            route,
            onion,
            ..
        } = &self.phase
        else {
            return Vec::new();
        };
        let mut actions = Vec::new();
        if *route == Duty::Owed {
            actions.push(Action::Publish(ManagedRunning { socks: *socks }));
        }
        if *onion == Duty::Owed {
            actions.push(Action::RepublishOnion);
        }
        actions
    }

    fn keeps_sampling(&self) -> bool {
        matches!(
            self.phase,
            Phase::Bootstrapping { .. }
                | Phase::Running {
                    disk: Disk::Watching,
                    ..
                }
                | Phase::Running {
                    route: Duty::Owed,
                    ..
                }
                | Phase::Running {
                    onion: Duty::Owed,
                    ..
                }
        )
    }

    fn say(&mut self, now: u64, cadence: Cadence) -> Vec<Action> {
        if self.announcements.say(
            now,
            cadence,
            self.say_key(),
            self.cap(),
            self.repeats_announcement(),
        ) {
            vec![Action::Announce]
        } else {
            Vec::new()
        }
    }

    fn say_key(&self) -> announce::SayKey {
        announce::SayKey::new(self.shown(), &self.cause)
    }

    /// The relay's verdict moved. The posture sentence follows whether a
    /// local origin leaves, so only that change is said: a recovery at once,
    /// a loss once under the cap. The class moving on its own says nothing.
    /// The same routable state again is not a change. Health still follows
    /// the stored verdict.
    fn origin_verdict(&mut self, verdict: OriginVerdict, now: u64) -> Vec<Action> {
        let was_leaving = self.origin.origin_leaves();
        let leaves = verdict.origin_leaves();
        self.origin = verdict;
        if was_leaving == leaves {
            return Vec::new();
        }
        self.say(now, if leaves { Cadence::Now } else { Cadence::Once })
    }

    fn repeats_announcement(&self) -> bool {
        matches!(self.phase, Phase::Absent { .. })
            || matches!(self.cause, Cause::TooManyFiles { .. })
    }

    fn arm_sample(&mut self, now: u64) {
        self.sample_at = Some(now.saturating_add(self.sample_ns()));
    }

    /// A bootstrap poll moved the percent. The sample deadline stays where
    /// the directory sample armed it: a notice is not a sample, and moving
    /// the deadline would starve `traffic/read`.
    fn note_bootstrap(&mut self, now: u64, progress: u8) -> Vec<Action> {
        if !matches!(self.phase, Phase::Bootstrapping { .. }) {
            return Vec::new();
        }
        self.progress.note_percent(progress, now);
        Vec::new()
    }

    fn arm_alive(&mut self, now: u64) {
        self.alive_at = Some(now.saturating_add(duration_ns(self.policy.alive_every)));
    }

    fn ensure_sample(&mut self, now: u64) {
        let at = now.saturating_add(self.sample_ns());
        self.sample_at = Some(self.sample_at.map(|have| have.min(at)).unwrap_or(at));
    }

    fn set_cause(&mut self, cause: Cause) {
        self.cause = cause;
    }

    fn shown(&self) -> Shown {
        if self.degraded() && self.live() {
            return Shown::Degraded;
        }
        match self.phase {
            Phase::Running {
                route: Duty::Done,
                link: Link::Open,
                ..
            } => Shown::Usable,
            Phase::Bootstrapping { .. } | Phase::Running { .. } => Shown::Bootstrapping,
            Phase::Absent {
                duty: AbsentDuty::Held | AbsentDuty::Fixed,
            } => Shown::RestartingHeld,
            Phase::Absent { .. } | Phase::Launching | Phase::Stopping => Shown::Restarting,
        }
    }

    fn route_done(&self) -> bool {
        matches!(
            self.phase,
            Phase::Running {
                route: Duty::Done,
                ..
            }
        )
    }

    fn live(&self) -> bool {
        matches!(
            self.phase,
            Phase::Bootstrapping { .. } | Phase::Running { .. }
        )
    }

    fn degraded(&self) -> bool {
        matches!(
            self.cause,
            Cause::ExternalBlocked
                | Cause::DirectoryUnreachable
                | Cause::ClockSkew { .. }
                | Cause::TooManyFiles { .. }
        )
    }

    /// Move [`Self::posted`] onto the projection. Closing a usable interval
    /// that lasted a cap records the backoff restart.
    fn settle_shown(&mut self, now: u64) {
        let shown = self.shown();
        if self.posted == Shown::Usable
            && shown != Shown::Usable
            && now.saturating_sub(self.since) >= self.cap()
        {
            self.backoff.note_usable_cap();
        }
        if shown != self.posted {
            self.since = now;
            self.posted = shown;
        }
    }

    fn step(&mut self, now: u64, actions: Vec<Action>) -> Step {
        self.settle_shown(now);
        Step {
            actions,
            deadline: self.deadline(),
        }
    }

    fn base(&self) -> u64 {
        duration_ns(self.policy.base)
    }

    fn cap(&self) -> u64 {
        duration_ns(self.policy.cap)
    }

    fn sample_ns(&self) -> u64 {
        duration_ns(self.policy.sample_every)
    }
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests;
