// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The managed Tor's policy (`TOR_SUPERVISOR.md` §4).
//!
//! Events in, actions and the next deadline out. No process, no socket, no
//! clock of its own: the driver performs the actions and reports what
//! happened, and the daemon's one timing engine waits for the deadline.
//! [`ManagedRunning`] is built only on the transition into `Running`, so a
//! route for a Tor that is not running cannot be constructed.

use std::net::SocketAddr;
use std::time::Duration;

use crate::control::{
    Bootstrap, ClientStatus, GeneralStatus, HsDescAction, Liveness, Recommendation, TorEvent,
};

/// How long a respawn waits, and how often a failure is said again.
///
/// `TSR-M2` (the floor device, 2026-10-22) measured the repair itself:
/// outbound usable in at most 2.93 s, and inbound reachable within 26.44 s
/// in 9 of 10 runs. The tenth was a SOCKS CONNECT with no reply at the 60 s
/// probe bound; the nonce was not sent. The base stays the 1 s pause before
/// the next spawn, and the cap stays the 60 s crash-loop ceiling. The run had
/// no launch failure,
/// so it does not size `fresh_directory_after`. A test passes the policy it
/// means to pin.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// The first process-fault wait.
    pub base: Duration,
    /// The longest wait, and the gap between repeated announcements.
    pub cap: Duration,
    /// How often a bootstrap is sampled while Tor is answering.
    pub sample_every: Duration,
    /// Consecutive failed launches before the next one takes a fresh
    /// data directory. `TSR-M2`'s 2026-10-22 run had no launch failure, so
    /// this stays 3.
    pub fresh_directory_after: u32,
}

impl Policy {
    /// The waits the driver uses. `TSR-M2` did not move them; see the type doc.
    #[must_use]
    pub const fn provisional() -> Self {
        Self {
            base: Duration::from_secs(1),
            cap: Duration::from_secs(60),
            sample_every: Duration::from_secs(5),
            fresh_directory_after: 3,
        }
    }
}

/// The connector settings the posture is read from. Not a config key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TorSetting {
    /// `Tor::Off`.
    Off,
    /// `Tor::Managed`.
    Managed,
    /// `Tor::Operator`.
    Operator,
}

/// What the node was configured to connect with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connectors {
    /// The Tor setting.
    pub tor: TorSetting,
    /// Whether clearnet is on.
    pub clearnet_on: bool,
}

/// What the node does with its own transactions (`TSR-Q11`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnTx {
    /// Health is true: originated traffic goes out over Tor.
    AddressHiding,
    /// Health is false and Tor is managed or an operator's Tor. The
    /// transaction stays off clearnet.
    Held,
    /// The operator set Tor off and clearnet on.
    ClearnetOnly,
    /// Tor off and clearnet off.
    Offline,
}

/// A fix the posture offers. The wire carries the variant. The words are
/// [`render`]'s.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedTorFix {
    /// Stay managed and restore a bundle that passes the pin.
    RestoreManaged,
    /// Use a Tor the operator runs.
    Operator,
    /// Turn clearnet on. Tor stays managed.
    ClearnetOn,
    /// Turn Tor off and send over clearnet.
    ClearnetOnly,
}

/// The phase the posture line shows (§4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shown {
    /// Starting again after a process fault.
    Restarting,
    /// The spawn is waiting out the cap. A pin, a missing bundle, or the
    /// data directory. Not [`OwnTx::Held`].
    RestartingHeld,
    /// Tor is up and has not reached the network yet.
    Bootstrapping,
    /// The outbound link is usable.
    Usable,
    /// Tor is up and a facet is down.
    Degraded,
}

/// Why the phase is what it is. The detail is the variant (`TSR-Q12`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cause {
    /// Nothing is wrong.
    None,
    /// Discovery found no bundle.
    BundleMissing,
    /// The pin refused the binary. It was not executed.
    PinRefused,
    /// This build has no managed Tor.
    Unavailable,
    /// A spawn that passed the pin did not come up.
    FailedStart,
    /// The process ended. `exit_code` is present once the reap reported one.
    Died {
        /// The process exit code, when the reap reported one.
        exit_code: Option<i32>,
    },
    /// The data directory could not be used.
    DirectoryUnusable,
    /// This machine cannot reach the Tor network.
    ExternalBlocked,
    /// No directory Tor knows answered.
    DirectoryUnreachable,
    /// A source reported the clock this far off, in seconds.
    ClockSkew {
        /// The reported difference, in seconds.
        seconds: i64,
    },
    /// Tor hit the open-file limit.
    TooManyFiles {
        /// How many sockets Tor reported open.
        open: u64,
    },
    /// A control reply missed its bound.
    ReplyLate,
    /// The consensus does not recommend this Tor.
    DangerousVersion,
}

/// Whether the node is syncing, and over what (`TSR-Q12`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Syncing {
    /// Syncing over clearnet.
    pub clearnet: bool,
    /// Syncing over Tor.
    pub tor: bool,
}

/// One typed read of the supervisor (`TSR-Q12`). No message text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// True when the Tor link's outbound facet is usable.
    pub health: bool,
    /// The §4.3 projection.
    pub shown: Shown,
    /// The typed cause.
    pub cause: Cause,
    /// When `shown` last changed, in the caller's clock units.
    pub since: u64,
    /// Process-fault respawns this boot.
    pub respawn_count: u32,
    /// What the node is syncing over.
    pub sync: Syncing,
    /// What happens to the node's own transactions.
    pub own_tx: OwnTx,
    /// Fixes offered while a managed Tor is down. Empty otherwise.
    pub fixes: Vec<ManagedTorFix>,
    /// The last bootstrap percent. Telemetry for the posture line.
    pub progress: u8,
}

/// What the driver does next.
#[derive(Debug)]
pub enum Action {
    /// Discover and pin. No spawn until this accepts.
    CheckPin,
    /// Spawn. `fresh_directory` drops the kept data directory first.
    Spawn {
        /// Take a new data directory.
        fresh_directory: bool,
    },
    /// A cheap `GETINFO`. A reply inside the driver's bound is
    /// [`Input::DirectorySample`]. A reply past it is [`Input::ReplyLate`].
    Sample,
    /// Look for the first `state` file.
    WatchState,
    /// `SETCONF AvoidDiskWrites=1` on the owning connection.
    SetConfAvoidDiskWrites,
    /// Publish the managed route. Only a `Running` transition builds it.
    Publish(ManagedRunning),
    /// The current incarnation's route is down.
    TakeDown,
    /// `ADD_ONION` again, with the boot's seed.
    RepublishOnion,
    /// Say the posture. At most once per cap interval, except a recovery.
    Announce,
    /// The daemon is stopping. Tear the child down and wipe.
    StopChild,
}

/// The managed Tor's SOCKS route. Constructed only when the phase becomes
/// `Running`.
#[derive(Debug)]
pub struct ManagedRunning {
    socks: SocketAddr,
}

impl ManagedRunning {
    /// The SOCKS address the link publishes.
    #[must_use]
    pub fn socks(&self) -> SocketAddr {
        self.socks
    }
}

/// What the driver observed.
#[derive(Debug)]
pub enum Input {
    /// The pin accepted the binary.
    PinAccepted,
    /// The pin refused it.
    PinRefused,
    /// No bundle was found.
    BundleMissing,
    /// This platform manages no Tor.
    Unavailable,
    /// The data directory cannot be used.
    DirectoryUnusable,
    /// The process is up and the control connection answered.
    Spawned,
    /// The process did not stay up through the launch.
    SpawnFailed,
    /// The SOCKS listener is bound.
    SocksBound(SocketAddr),
    /// Bootstrap reached the ready gate.
    BootstrapComplete,
    /// A bootstrap sample answered inside the reply bound.
    DirectorySample {
        /// `PROGRESS=`, when the reply carried one.
        progress: Option<u8>,
        /// `traffic/read`, when the reply carried one.
        traffic_read: Option<u64>,
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
    /// The open-file limit.
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
}

/// Actions and the next absolute deadline, in the caller's clock units.
/// `None` waits until the next input.
#[derive(Debug)]
pub struct Step {
    /// What to perform, in order.
    pub actions: Vec<Action>,
    /// When to call [`Core::on_deadline`], if anything is waiting.
    pub deadline: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Absent,
    Launching,
    Bootstrapping,
    Running,
    Stopping,
}

/// The sans-IO supervisor.
#[derive(Debug)]
pub struct Core {
    policy: Policy,
    connectors: Connectors,
    phase: Phase,
    held: bool,
    cause: Cause,
    since: u64,
    last_announce: Option<u64>,
    respawn_count: u32,
    launch_failures: u32,
    backoff_failures: u32,
    socks: Option<SocketAddr>,
    progress: u8,
    traffic: u64,
    bootstrap_done: bool,
    published: bool,
    avoid_attempted: bool,
    republish_outstanding: bool,
    retry_at: Option<u64>,
    deadline: Option<u64>,
}

impl Core {
    /// Start. The first action is the pin check.
    #[must_use]
    pub fn start(policy: Policy, connectors: Connectors, now: u64) -> (Self, Step) {
        let core = Self {
            policy,
            connectors,
            phase: Phase::Absent,
            held: false,
            cause: Cause::None,
            since: now,
            last_announce: None,
            respawn_count: 0,
            launch_failures: 0,
            backoff_failures: 0,
            socks: None,
            progress: 0,
            traffic: 0,
            bootstrap_done: false,
            published: false,
            avoid_attempted: false,
            republish_outstanding: false,
            retry_at: None,
            deadline: None,
        };
        let step = core.step(vec![Action::CheckPin]);
        (core, step)
    }

    /// Fold one observation in.
    #[allow(clippy::needless_pass_by_value)]
    pub fn on(&mut self, input: Input, now: u64) -> Step {
        let actions = match input {
            Input::PinAccepted => self.pin_accepted(),
            Input::PinRefused => self.hold(now, Cause::PinRefused),
            Input::BundleMissing => self.hold(now, Cause::BundleMissing),
            Input::Unavailable => self.hold(now, Cause::Unavailable),
            Input::DirectoryUnusable => self.hold(now, Cause::DirectoryUnusable),
            Input::Spawned => self.spawned(now),
            Input::SpawnFailed => self.launch_failed(now),
            Input::SocksBound(addr) => {
                self.socks = Some(addr);
                if self.phase == Phase::Bootstrapping {
                    self.arm_until(now, now.saturating_add(self.sample_ns()));
                }
                self.maybe_run(now)
            }
            Input::BootstrapComplete => {
                self.bootstrap_done = true;
                self.maybe_run(now)
            }
            Input::DirectorySample {
                progress,
                traffic_read,
            } => self.sample(now, progress, traffic_read),
            Input::ReplyLate => self.process_fault(now, Cause::ReplyLate, false),
            Input::ProcessEnded { exit_code } => {
                self.process_fault(now, Cause::Died { exit_code }, false)
            }
            Input::ControlEnded => self.process_fault(now, Cause::Died { exit_code: None }, false),
            Input::ExternalBlocked => self.external(now, Cause::ExternalBlocked),
            Input::DirectoryUnreachable => self.external(now, Cause::DirectoryUnreachable),
            Input::ClockSkew { seconds } => self.external(now, Cause::ClockSkew { seconds }),
            Input::ClockJumped => Vec::new(),
            Input::TooManyFiles { open } => self.hold(now, Cause::TooManyFiles { open }),
            Input::DescriptorFailed => self.descriptor_failed(),
            Input::DescriptorUploaded => {
                self.republish_outstanding = false;
                Vec::new()
            }
            Input::DangerousVersion => {
                self.set_cause(now, Cause::DangerousVersion);
                self.say(now, false)
            }
            Input::StateFileAppeared => self.state_file(),
            Input::Shutdown => {
                self.phase = Phase::Stopping;
                self.deadline = None;
                self.retry_at = None;
                vec![Action::StopChild]
            }
        };
        self.step(actions)
    }

    /// The deadline fired.
    pub fn on_deadline(&mut self, now: u64) -> Step {
        let Some(due) = self.deadline else {
            return self.step(Vec::new());
        };
        if now < due {
            return self.step(Vec::new());
        }
        if self.phase == Phase::Stopping {
            self.deadline = None;
            return self.step(Vec::new());
        }
        if let Some(retry) = self.retry_at {
            if now < retry {
                let actions = self.say(now, false);
                self.arm_until(now, retry);
                return self.step(actions);
            }
        }
        self.deadline = None;
        let actions = match self.phase {
            Phase::Absent if self.cause == Cause::Unavailable => {
                let actions = self.say(now, false);
                self.arm_until(now, now.saturating_add(self.cap()));
                actions
            }
            Phase::Absent => vec![Action::CheckPin],
            Phase::Bootstrapping => vec![Action::Sample],
            Phase::Running if !self.avoid_attempted => {
                self.arm_until(now, now.saturating_add(self.sample_ns()));
                vec![Action::WatchState]
            }
            Phase::Launching | Phase::Running | Phase::Stopping => Vec::new(),
        };
        self.step(actions)
    }

    /// The typed read.
    #[must_use]
    pub fn status(&self) -> Status {
        let shown = self.shown();
        let health = shown == Shown::Usable;
        Status {
            health,
            shown,
            cause: self.cause.clone(),
            since: self.since,
            respawn_count: self.respawn_count,
            sync: Syncing {
                clearnet: self.connectors.clearnet_on,
                tor: health,
            },
            own_tx: own_tx(health, self.connectors),
            fixes: fixes(health, self.connectors),
            progress: self.progress,
        }
    }

    fn pin_accepted(&mut self) -> Vec<Action> {
        self.held = false;
        self.phase = Phase::Launching;
        self.bootstrap_done = false;
        self.socks = None;
        self.published = false;
        let fresh =
            self.launch_failures >= self.policy.fresh_directory_after && self.launch_failures > 0;
        vec![Action::Spawn {
            fresh_directory: fresh,
        }]
    }

    fn spawned(&mut self, now: u64) -> Vec<Action> {
        self.phase = Phase::Bootstrapping;
        self.held = false;
        self.launch_failures = 0;
        self.avoid_attempted = false;
        self.set_cause(now, Cause::None);
        self.arm_until(now, now.saturating_add(self.sample_ns()));
        vec![Action::Sample]
    }

    fn sample(&mut self, now: u64, progress: Option<u8>, traffic_read: Option<u64>) -> Vec<Action> {
        if let Some(progress) = progress {
            self.progress = progress;
        }
        if let Some(traffic) = traffic_read {
            self.traffic = traffic;
        }
        if self.phase == Phase::Bootstrapping {
            self.arm_until(now, now.saturating_add(self.sample_ns()));
        }
        let mut actions = Vec::new();
        if self.bootstrap_done && self.socks.is_none() {
            actions.push(Action::Sample);
        }
        actions
    }

    fn maybe_run(&mut self, now: u64) -> Vec<Action> {
        let Some(socks) = self.socks else {
            return vec![Action::Sample];
        };
        if !self.bootstrap_done || self.phase == Phase::Running {
            return Vec::new();
        }
        self.phase = Phase::Running;
        self.held = false;
        self.published = true;
        self.set_cause(now, Cause::None);
        self.arm_until(now, now.saturating_add(self.sample_ns()));
        let mut actions = vec![
            Action::Publish(ManagedRunning { socks }),
            Action::RepublishOnion,
        ];
        actions.extend(self.say(now, true));
        actions
    }

    fn launch_failed(&mut self, now: u64) -> Vec<Action> {
        self.process_fault(now, Cause::FailedStart, true)
    }

    fn process_fault(&mut self, now: u64, cause: Cause, launch_failed: bool) -> Vec<Action> {
        let was_published = self.published;
        self.published = false;
        self.phase = Phase::Absent;
        self.held = false;
        self.bootstrap_done = false;
        self.socks = None;
        if launch_failed {
            self.launch_failures = self.launch_failures.saturating_add(1);
        } else {
            self.launch_failures = 0;
        }
        self.backoff_failures = self.backoff_failures.saturating_add(1);
        self.respawn_count = self.respawn_count.saturating_add(1);
        self.set_cause(now, cause);
        let retry = now.saturating_add(self.backoff_delay());
        self.retry_at = Some(retry);
        self.arm_until(now, retry);
        let mut actions = Vec::new();
        if was_published {
            actions.push(Action::TakeDown);
        }
        actions.extend(self.say(now, false));
        actions
    }

    fn hold(&mut self, now: u64, cause: Cause) -> Vec<Action> {
        self.phase = Phase::Absent;
        self.held = true;
        self.published = false;
        self.bootstrap_done = false;
        self.set_cause(now, cause);
        let retry = now.saturating_add(self.cap());
        self.arm_until(now, retry);
        self.say(now, false)
    }

    fn external(&mut self, now: u64, cause: Cause) -> Vec<Action> {
        self.set_cause(now, cause);
        self.say(now, false)
    }

    fn descriptor_failed(&mut self) -> Vec<Action> {
        if self.phase != Phase::Running || self.republish_outstanding {
            return Vec::new();
        }
        self.republish_outstanding = true;
        vec![Action::RepublishOnion]
    }

    fn state_file(&mut self) -> Vec<Action> {
        if self.avoid_attempted {
            return Vec::new();
        }
        if !matches!(self.phase, Phase::Bootstrapping | Phase::Running) {
            return Vec::new();
        }
        self.avoid_attempted = true;
        vec![Action::SetConfAvoidDiskWrites]
    }

    fn say(&mut self, now: u64, recovery: bool) -> Vec<Action> {
        let due = self
            .last_announce
            .map(|then| now.saturating_sub(then) >= self.cap())
            .unwrap_or(true);
        if recovery || due {
            self.last_announce = Some(now);
            vec![Action::Announce]
        } else {
            Vec::new()
        }
    }

    fn arm_until(&mut self, now: u64, retry_at: u64) {
        self.retry_at = Some(retry_at);
        let at = match self.next_announcement(now) {
            Some(announce) if announce < retry_at => announce,
            _ => retry_at,
        };
        self.deadline = Some(at);
    }

    fn next_announcement(&self, now: u64) -> Option<u64> {
        if !matches!(self.phase, Phase::Absent) {
            return None;
        }
        let last = self.last_announce?;
        let at = last.saturating_add(self.cap());
        (at > now).then_some(at)
    }

    fn backoff_delay(&self) -> u64 {
        let exp = self.backoff_failures.saturating_sub(1).min(16);
        let factor = 1u64 << exp;
        self.base().saturating_mul(factor).min(self.cap())
    }

    fn set_cause(&mut self, now: u64, cause: Cause) {
        if self.cause != cause {
            self.since = now;
        }
        self.cause = cause;
    }

    fn shown(&self) -> Shown {
        match self.phase {
            Phase::Bootstrapping => Shown::Bootstrapping,
            Phase::Running if self.degraded() => Shown::Degraded,
            Phase::Running => Shown::Usable,
            Phase::Absent if self.held => Shown::RestartingHeld,
            Phase::Absent | Phase::Launching | Phase::Stopping => Shown::Restarting,
        }
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

    fn step(&self, actions: Vec<Action>) -> Step {
        Step {
            actions,
            deadline: self.deadline,
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

/// `OwnTx` from health and the connector settings.
#[must_use]
pub fn own_tx(health: bool, connectors: Connectors) -> OwnTx {
    if health {
        return OwnTx::AddressHiding;
    }
    match (connectors.tor, connectors.clearnet_on) {
        (TorSetting::Off, true) => OwnTx::ClearnetOnly,
        (TorSetting::Off, false) => OwnTx::Offline,
        (TorSetting::Managed | TorSetting::Operator, _) => OwnTx::Held,
    }
}

/// Fixes while a managed Tor is down. Empty when it is up, and empty when
/// the operator already chose to run without a managed Tor.
#[must_use]
pub fn fixes(health: bool, connectors: Connectors) -> Vec<ManagedTorFix> {
    if health || connectors.tor != TorSetting::Managed {
        return Vec::new();
    }
    let mut offered = vec![ManagedTorFix::RestoreManaged, ManagedTorFix::Operator];
    if !connectors.clearnet_on {
        offered.push(ManagedTorFix::ClearnetOn);
    }
    offered.push(ManagedTorFix::ClearnetOnly);
    offered
}

/// The one renderer (`TSR-Q13`). Behaviour, then the cause, then the fixes
/// in the posture table's order.
#[must_use]
pub fn render(status: &Status) -> String {
    let mut text = String::new();
    match status.own_tx {
        OwnTx::AddressHiding => text.push_str("Tor is carrying this node's traffic."),
        OwnTx::Held if status.sync.clearnet => text.push_str(
            "This node is syncing over clearnet and holding its own transactions.",
        ),
        OwnTx::Held => text.push_str(
            "This node is waiting for Tor and holding its own transactions. It is not syncing.",
        ),
        OwnTx::ClearnetOnly => text.push_str(
            "This node is syncing and sending over the open network. Until the encrypted link is in place, that network is unencrypted.",
        ),
        OwnTx::Offline => text.push_str("This node is offline."),
    }
    if let Some(cause) = cause_sentence(status) {
        text.push(' ');
        text.push_str(&cause);
    }
    if !status.fixes.is_empty() {
        text.push(' ');
        text.push_str(&fixes_sentence(&status.fixes));
    }
    text
}

fn cause_sentence(status: &Status) -> Option<String> {
    let sentence = match &status.cause {
        Cause::None if status.shown == Shown::Bootstrapping => Some(format!(
            "Tor is fetching the network directory ({progress}%).",
            progress = status.progress
        )),
        Cause::None => None,
        Cause::BundleMissing => Some("No Tor was found beside the daemon.".to_owned()),
        Cause::PinRefused => {
            Some("The Tor that was found failed its check, so it was not started.".to_owned())
        }
        Cause::Unavailable => Some("This release has no Tor for this platform yet.".to_owned()),
        Cause::FailedStart => Some("Tor did not start.".to_owned()),
        Cause::Died { exit_code } => Some(died_sentence(status.respawn_count, *exit_code)),
        Cause::DirectoryUnusable => Some("Tor's data directory could not be used.".to_owned()),
        Cause::ExternalBlocked | Cause::DirectoryUnreachable => Some(
            "This machine cannot reach the Tor network. Check the firewall or the network."
                .to_owned(),
        ),
        Cause::ClockSkew { seconds } => Some(format!(
            "The clock is off by {seconds} seconds. Check time sync."
        )),
        Cause::TooManyFiles { open } => Some(format!(
            "Tor reached the open-file limit ({open} open). Raise the limit."
        )),
        Cause::ReplyLate => Some("Tor stopped answering and is being started again.".to_owned()),
        Cause::DangerousVersion => {
            Some("Upgrade Shekyl when a release updates the bundled Tor.".to_owned())
        }
    };
    sentence
}

fn died_sentence(count: u32, exit_code: Option<i32>) -> String {
    if count <= 1 {
        return "Tor stopped and is being started again.".to_owned();
    }
    match exit_code {
        Some(code) => format!(
            "Tor has stopped {count} times. The last exit code was {code}. It is being started again."
        ),
        None => format!("Tor has stopped {count} times and is being started again."),
    }
}

fn fixes_sentence(fixes: &[ManagedTorFix]) -> String {
    let mut parts = Vec::new();
    for fix in fixes {
        parts.push(match fix {
            ManagedTorFix::RestoreManaged => {
                "Restore the bundled Tor, or name one that passes its check."
            }
            ManagedTorFix::Operator => "Or use a Tor you run yourself.",
            ManagedTorFix::ClearnetOn => "Or turn clearnet on and keep Tor managed.",
            ManagedTorFix::ClearnetOnly => {
                "Or turn Tor off and send over the open network. Until the encrypted link is in place, that network is unencrypted."
            }
        });
    }
    parts.join(" ")
}

/// Events the core acts on (`TOR_SUPERVISOR.md` §4.2). Anything else is `None`.
///
/// | Event | Input |
/// | --- | --- |
/// | `BOOTSTRAP` with `WARNING` or `REASON`, and `RECOMMENDATION=warn` | [`Input::ExternalBlocked`] |
/// | `NETWORK_LIVENESS DOWN` | [`Input::ExternalBlocked`] |
/// | `DIR_ALL_UNREACHABLE` | [`Input::DirectoryUnreachable`] |
/// | `CLOCK_SKEW` | [`Input::ClockSkew`] |
/// | `CLOCK_JUMPED` | [`Input::ClockJumped`] |
/// | `TOO_MANY_CONNECTIONS` | [`Input::TooManyFiles`] |
/// | `DANGEROUS_VERSION` | [`Input::DangerousVersion`] |
/// | `HS_DESC FAILED` for an upload | [`Input::DescriptorFailed`] |
/// | `HS_DESC UPLOADED` | [`Input::DescriptorUploaded`] |
///
/// A bootstrap problem Tor has not yet marked `warn` is not outbound-blocked.
/// Tor sends `warn` from the tenth problem at a phase (§4.2).
#[must_use]
pub fn input_of(event: &TorEvent) -> Option<Input> {
    match event {
        TorEvent::NetworkLiveness(Liveness::Down) => Some(Input::ExternalBlocked),
        TorEvent::General { status, .. } => match status {
            GeneralStatus::DirAllUnreachable => Some(Input::DirectoryUnreachable),
            GeneralStatus::ClockSkew { skew, .. } => skew.as_ref().map(|skew| Input::ClockSkew {
                seconds: match skew {
                    crate::control::ClockSkew::Measured(seconds)
                    | crate::control::ClockSkew::AtLeast(seconds) => *seconds,
                },
            }),
            GeneralStatus::ClockJumped { .. } => Some(Input::ClockJumped),
            GeneralStatus::TooManyConnections { current } => Some(Input::TooManyFiles {
                open: current.unwrap_or(0),
            }),
            GeneralStatus::DangerousVersion { .. } => Some(Input::DangerousVersion),
            GeneralStatus::Other => None,
        },
        TorEvent::Client { status, .. } => match status {
            ClientStatus::Bootstrap(Bootstrap {
                problem: Some(problem),
                ..
            }) if outbound_blocked(problem) => Some(Input::ExternalBlocked),
            _ => None,
        },
        TorEvent::HsDesc(event) => match event.action {
            HsDescAction::Failed if event.descriptor_id.is_none() => Some(Input::DescriptorFailed),
            HsDescAction::Uploaded => Some(Input::DescriptorUploaded),
            _ => None,
        },
        TorEvent::Log(_) | TorEvent::Unsubscribed | TorEvent::NetworkLiveness(_) => None,
    }
}

/// §4.2's named external cause: a bootstrap problem Tor has marked `warn`,
/// carrying `WARNING` or `REASON`.
fn outbound_blocked(problem: &crate::control::BootstrapProblem) -> bool {
    problem.recommendation == Recommendation::Warn
        && (problem.warning.is_some() || problem.reason.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_timing_engine::{Clock, ManualClock, Tick};

    fn policy() -> Policy {
        Policy {
            base: Duration::from_secs(1),
            cap: Duration::from_secs(8),
            sample_every: Duration::from_secs(1),
            fresh_directory_after: 3,
        }
    }

    fn managed(clearnet_on: bool) -> Connectors {
        Connectors {
            tor: TorSetting::Managed,
            clearnet_on,
        }
    }

    fn clock() -> ManualClock {
        ManualClock::new(Tick::new(0))
    }

    fn ns(clock: &ManualClock) -> u64 {
        clock.now().get()
    }

    fn announces(step: &Step) -> usize {
        step.actions
            .iter()
            .filter(|action| matches!(action, Action::Announce))
            .count()
    }

    fn spawns(step: &Step) -> bool {
        step.actions
            .iter()
            .any(|action| matches!(action, Action::Spawn { .. }))
    }

    /// Backoff doubles until the cap, and the failure is said at the first
    /// fault and then once per cap — deleting the announcement cap makes a
    /// second `Announce` land inside the interval.
    #[test]
    fn a_respawn_backs_off_and_announces_once_per_cap() {
        let clock = clock();
        let (mut core, step) = Core::start(policy(), managed(true), ns(&clock));
        assert!(matches!(step.actions[0], Action::CheckPin));
        let mut step = core.on(Input::PinAccepted, ns(&clock));
        assert!(matches!(
            step.actions[0],
            Action::Spawn {
                fresh_directory: false
            }
        ));
        step = core.on(Input::SpawnFailed, ns(&clock));
        assert_eq!(announces(&step), 1);
        let mut said = 1usize;
        let mut pin_at = Vec::new();
        let mut fresh = Vec::new();
        while pin_at.len() < 4 {
            let due = step.deadline.expect("a retry is armed");
            clock.set(Tick::new(due));
            step = core.on_deadline(ns(&clock));
            said += announces(&step);
            if step
                .actions
                .iter()
                .any(|action| matches!(action, Action::CheckPin))
            {
                pin_at.push(due);
                step = core.on(Input::PinAccepted, ns(&clock));
                fresh.push(fresh_directory(&step));
                step = core.on(Input::SpawnFailed, ns(&clock));
                said += announces(&step);
            }
        }
        assert_eq!(
            pin_at,
            vec![1_000_000_000, 3_000_000_000, 7_000_000_000, 15_000_000_000,],
            "the wait doubles, then the cap, and an announcement does not spawn"
        );
        assert_eq!(fresh, vec![false, false, true, true]);
        assert_eq!(
            said, 2,
            "the first fault and one more at the cap, not each retry"
        );
        let text = render(&core.status());
        assert!(
            text.contains("syncing over clearnet and holding its own transactions"),
            "{text}"
        );
        assert!(!text.contains("clearnet-only"), "{text}");
    }

    /// A bootstrap that makes no progress, and answers `GETINFO` inside the
    /// bound, never respawns — at a second or at a day. A reply past the
    /// bound does. Treating elapsed time as a fault fails the first half.
    #[test]
    fn a_stalled_bootstrap_never_respawns_and_a_late_reply_does() {
        let (mut core, _) = Core::start(policy(), managed(true), 0);
        core.on(Input::PinAccepted, 0);
        core.on(Input::Spawned, 0);
        let socks: SocketAddr = "127.0.0.1:9050".parse().expect("socks");
        core.on(Input::SocksBound(socks), 0);
        for step in [1_u64, 60, 3_600, 86_400] {
            let now = step * 1_000_000_000;
            let step = core.on(
                Input::DirectorySample {
                    progress: Some(10),
                    traffic_read: Some(now),
                },
                now,
            );
            assert!(
                !spawns(&step),
                "progress standing still is not a fault at {now}"
            );
            assert!(
                !step
                    .actions
                    .iter()
                    .any(|action| matches!(action, Action::TakeDown)),
                "a timely reply is not a death at {now}"
            );
            assert_eq!(core.status().shown, Shown::Bootstrapping);
        }
        let step = core.on(Input::ReplyLate, 90_000 * 1_000_000_000);
        assert!(
            step.actions
                .iter()
                .any(|action| matches!(action, Action::TakeDown))
                || core.status().shown == Shown::Restarting,
            "a reply past the bound is a process fault"
        );
        assert_ne!(core.status().shown, Shown::Bootstrapping);
    }

    /// A pin failure at the respawn does not spawn, shows Restarting
    /// (held), and waits out the cap. Spawning on `PinRefused` fails this.
    #[test]
    fn a_pin_failure_does_not_spawn_and_retries_at_the_cap() {
        let (mut core, _) = Core::start(policy(), managed(true), 0);
        reach_running(&mut core);
        let step = core.on(Input::ProcessEnded { exit_code: Some(9) }, 5_000_000_000);
        assert!(step
            .actions
            .iter()
            .any(|action| matches!(action, Action::TakeDown)));
        let due = step.deadline.expect("backoff");
        let step = core.on_deadline(due);
        assert!(matches!(step.actions.first(), Some(Action::CheckPin)));
        let step = core.on(Input::PinRefused, due);
        assert!(!spawns(&step), "a refused pin is not executed");
        let status = core.status();
        assert_eq!(status.shown, Shown::RestartingHeld);
        assert_eq!(status.cause, Cause::PinRefused);
        let mut step = step;
        let mut retried = false;
        for _ in 0..4 {
            let next = step.deadline.expect("the hold stays armed");
            step = core.on_deadline(next);
            assert!(!spawns(&step), "the hold never executes the binary");
            if step
                .actions
                .iter()
                .any(|action| matches!(action, Action::CheckPin))
            {
                assert_eq!(next, due + duration_ns(policy().cap));
                retried = true;
                break;
            }
            assert_eq!(announces(&step), 1, "the hold is said once per cap");
        }
        assert!(retried, "the pin is retried when the cap elapses");
        let text = render(&status);
        assert!(text.contains("failed its check"), "{text}");
        assert!(text.contains("holding its own transactions"), "{text}");
        assert!(!text.contains("clearnet-only"), "{text}");
        assert_eq!(
            status.fixes,
            vec![
                ManagedTorFix::RestoreManaged,
                ManagedTorFix::Operator,
                ManagedTorFix::ClearnetOnly,
            ]
        );
    }

    /// Unavailable is a fixed condition. It is said once per cap and it
    /// never starts a spawn loop. A backoff that calls `CheckPin` again
    /// fails this.
    #[test]
    fn an_unavailable_platform_is_fixed_and_announced_once_per_cap() {
        let (mut core, _) = Core::start(policy(), managed(false), 0);
        let step = core.on(Input::Unavailable, 0);
        assert!(!spawns(&step));
        assert_eq!(announces(&step), 1);
        let text = render(&core.status());
        assert!(
            text.contains("This release has no Tor for this platform yet"),
            "{text}"
        );
        assert!(text.contains("waiting for Tor"), "{text}");
        assert!(!text.contains("clearnet-only"), "{text}");
        let mut said = 1usize;
        let mut now = 0u64;
        for _ in 0..3 {
            let due = core.deadline.expect("the cap is armed");
            let early = core.on_deadline(due - 1);
            assert_eq!(announces(&early), 0, "inside the cap says nothing");
            let step = core.on_deadline(core.deadline.expect("still armed"));
            said += announces(&step);
            assert!(!spawns(&step));
            assert!(
                !step
                    .actions
                    .iter()
                    .any(|action| matches!(action, Action::CheckPin)),
                "nothing at runtime changes an unavailable platform"
            );
            now = due;
        }
        assert_eq!(said, 4, "the first announcement plus one per cap");
        assert_eq!(core.status().own_tx, OwnTx::Held);
        assert_eq!(now, 3 * duration_ns(policy().cap));
        assert!(core.status().fixes.contains(&ManagedTorFix::ClearnetOn));
    }

    fn fresh_directory(step: &Step) -> bool {
        step.actions
            .iter()
            .find_map(|action| match action {
                Action::Spawn { fresh_directory } => Some(*fresh_directory),
                _ => None,
            })
            .expect("a passed pin spawns")
    }

    fn reach_running(core: &mut Core) {
        let socks: SocketAddr = "127.0.0.1:9150".parse().expect("socks");
        core.on(Input::PinAccepted, 0);
        core.on(Input::Spawned, 0);
        core.on(Input::SocksBound(socks), 0);
        let step = core.on(Input::BootstrapComplete, 0);
        assert!(
            step.actions
                .iter()
                .any(|action| matches!(action, Action::Publish(_))),
            "running publishes"
        );
        assert!(core.status().health);
        assert_eq!(core.status().own_tx, OwnTx::AddressHiding);
    }

    /// §4.2: a bootstrap problem Tor has marked `warn`, with `WARNING` or
    /// `REASON`, is outbound blocked. A problem it still says to ignore is
    /// not. Treating every `REASON` as blocked fails the second half.
    #[test]
    fn a_warned_bootstrap_problem_is_outbound_blocked() {
        use crate::control::{
            Bootstrap, BootstrapProblem, ClientStatus, Recommendation, Severity, TorEvent,
        };
        let warned = TorEvent::Client {
            severity: Severity::Warn,
            status: ClientStatus::Bootstrap(Bootstrap {
                progress: Some(25),
                tag: Some("conn".to_owned()),
                problem: Some(BootstrapProblem {
                    warning: Some("connection refused".to_owned()),
                    reason: Some("CONNECTREFUSED".to_owned()),
                    count: Some(10),
                    recommendation: Recommendation::Warn,
                }),
            }),
        };
        assert!(matches!(input_of(&warned), Some(Input::ExternalBlocked)));
        let TorEvent::Client {
            status: ClientStatus::Bootstrap(Bootstrap { problem, .. }),
            ..
        } = &warned
        else {
            panic!("the fixture is a bootstrap event");
        };
        let mut ignored = problem.clone().expect("a problem");
        ignored.recommendation = Recommendation::Ignore;
        let early = TorEvent::Client {
            severity: Severity::Notice,
            status: ClientStatus::Bootstrap(Bootstrap {
                progress: Some(25),
                tag: Some("conn".to_owned()),
                problem: Some(ignored),
            }),
        };
        assert!(input_of(&early).is_none());
    }
}
