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
    fixes, own_tx, BootstrapLine, Carriage, Cause, Connectors, Inbound, OriginVerdict,
    ProgressWindow, ReportedSkew, Sessions, Shown, Space, Status,
};

mod announce;
mod backoff;
mod clock;
mod clock_evidence;
mod clock_jump;
mod dials;
mod directories;
mod network_view;
mod probe;
mod requests;
mod resume;
mod running;

use crate::binary::VerifiedTorBinary;
use crate::control::{NetworkView, RelayFingerprint, ServiceDescriptor};
use announce::{Announcements, Cadence};
use backoff::Backoff;
use dials::Dials;
pub use dials::{DialTally, TorCensus};
pub use directories::{DirectoryAnswer, DirectoryFetch};
use probe::Probe;

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
    /// How long nothing comes through Tor, with a Tor dial failed since and
    /// Tor saying nothing about its network, before the posture line says
    /// so (§4.2): a neutral fact, never a cause. The daemon passes Tor's
    /// `SocksTimeout` plus the Tor connector's judging bracket δ
    /// (`DIALER_OUTAGE_EVIDENCE.md` §6): by then a dial started at the last
    /// sign of life has used Tor's own retries and its bracket has closed
    /// empty, so the judge has excused it as the link's.
    pub quiet_after: Duration,
    /// The probe's delay after a round's first upload is drawn uniformly
    /// from this to [`Self::probe_after_max`] (§4.5, §10): long enough for
    /// the descriptor to reach the directories, and spread so a directory
    /// does not see an upload followed at once by a fetch of it.
    pub probe_after_min: Duration,
    /// The top of the probe's delay range.
    pub probe_after_max: Duration,
    /// How long a probe has to arrive (`TSR-M2`: 60 s).
    pub probe_within: Duration,
    /// How long after a round's first upload the probe stops waiting for the
    /// round to end (Rick, 2026-10-29): five times the longest round measured
    /// to end (12 s, §10), so most directories have the descriptor, and a
    /// round whose last uploads hang does not hold the probe until the next.
    pub round_wait: Duration,
    /// How long a round may stay open before it is counted as stuck, said
    /// once at debug, and ended in the coalescer so the next round is seen.
    pub round_stuck_after: Duration,
    /// How long, after Tor reported a clock jump during a bootstrap, the
    /// percent and `traffic/read` may both stand still before the bootstrap
    /// counts as stranded and Tor is started again (Rick, 2026-10-30). The
    /// soak refines it.
    pub jump_stall_after: Duration,
    /// The window in which certificate lines and closed handshakes must
    /// both reach their count before the clock is named (§4.2; Rick,
    /// 2026-10-30).
    pub clock_evidence_within: Duration,
    /// How long an onion-service descriptor lives at a directory. With no
    /// upload round begun this long after the last round's first upload, or
    /// the last probe arrival, the directories may have dropped it, and a
    /// probe asks (§4.5, "Overdue"; Rick, 2026-10-31). Tor's
    /// `HS_DESC_DEFAULT_LIFETIME`, re-checked at every re-pin.
    pub descriptor_lifetime: Duration,
    /// How far this computer's clock may sit behind the consensus's
    /// `valid-after` before the clock is named (§4.2, §10 `TSR-M13`; Rick,
    /// 2026-11-01). A correct clock can hold a consensus up to the
    /// authorities' distribution delay before its `valid-after`, and Tor's
    /// own early-consensus notice allows that plus 60 s.
    pub clock_behind_after: Duration,
    /// The first wait between republishes once one has been judged and
    /// failed (§4.5, "Republish backoff", §10 `TSR-M14`): one probe check's
    /// worst case. It doubles at each failed republish, up to
    /// [`Self::descriptor_lifetime`], and resets on a confirmed Reachable.
    pub republish_after: Duration,
    /// How long a request to Tor may go unanswered before it is a process
    /// fault ([`Cause::ReplyLate`]): one bound after the send, in this
    /// core's clock, restarted at a wake. The driver never waits on it; the
    /// request runs off the loop (Rick, 2026-11-10).
    pub reply_bound: Duration,
}

impl Policy {
    /// The waits the driver uses, with the caller's quiet stretch.
    #[must_use]
    pub const fn provisional(quiet_after: Duration) -> Self {
        Self {
            base: Duration::from_secs(1),
            cap: Duration::from_secs(60),
            sample_every: Duration::from_secs(5),
            // With the driver's 30 s reply bound, a wedge is a fault within
            // about a minute: the same order as `TSR-M2`'s 60 s bound.
            alive_every: Duration::from_secs(30),
            fresh_directory_after: 3,
            // Time since the judge's last sign of life on Tor, or since this
            // Tor reached Running, with a Tor dial failed since. Not a count
            // of dials.
            quiet_after,
            // Upload p50 4.6 s (`TSR-M7`); the descriptor then has to reach
            // the directories the probe's own fetch asks (§10).
            probe_after_min: Duration::from_secs(15),
            probe_after_max: PROBE_AFTER_MAX,
            // Nine of ten probes arrived within 26.44 s and the x86 cluster
            // reached 46 s (`TSR-M2`, `TSR-M3`).
            probe_within: PROBE_WITHIN,
            // Five times the longest round that ended (7 to 12 s, §10).
            round_wait: ROUND_WAIT,
            // The live tests' wait for a round, where the stuck rounds were
            // found (§10).
            round_stuck_after: Duration::from_secs(300),
            // Rick, 2026-10-30: 5 minutes; the soak refines it.
            jump_stall_after: Duration::from_secs(300),
            // The clock-ahead run's five certificate lines and its first
            // ten handshake problems fell within 10 s (§7); Tor retries its
            // handshakes every few seconds while it bootstraps. A minute
            // holds such a pass several times over, and keeps a line from
            // one stretch from pairing with relays from another.
            clock_evidence_within: Duration::from_secs(60),
            // `HS_DESC_DEFAULT_LIFETIME` (3 h) in tor 0.4.9.14:
            // `src/feature/hs/hs_descriptor.h:30`, set as the descriptor's
            // lifetime at `src/feature/hs/hs_service.c:1942`.
            descriptor_lifetime: DESCRIPTOR_LIFETIME,
            clock_behind_after: CLOCK_BEHIND_AFTER,
            // One judgment's worst case (`TSR-M14`). Named with the waits it
            // is made of, so a later probe bound moves this with them.
            republish_after: REPUBLISH_AFTER,
            // `TSR-M2`: a healthy Tor answered every ask well inside a
            // second; 30 s keeps a wedge a fault within about a minute with
            // `alive_every`.
            reply_bound: REPLY_BOUND,
        }
    }
}

/// How long the probe waits for a round to end after its first upload
/// (`TSR-M3`): five times the longest round measured to end.
pub const ROUND_WAIT: Duration = Duration::from_secs(60);

/// The probe's longest delay (`TSR-M2`).
pub const PROBE_AFTER_MAX: Duration = Duration::from_secs(60);

/// The probe's bound, and one directory fetch's answer window (`TSR-M2`).
pub const PROBE_WITHIN: Duration = Duration::from_secs(60);

/// [`Policy::republish_after`] (`TSR-M14`): the round's wait, then a probe
/// and the refetch's probe, each at its longest delay and its bound. A wait
/// shorter than one judgment republishes inside the previous check.
/// The reply bound the daemon uses ([`Policy::reply_bound`]).
pub const REPLY_BOUND: Duration = Duration::from_secs(30);

pub const REPUBLISH_AFTER: Duration = {
    let one_probe = PROBE_AFTER_MAX.saturating_add(PROBE_WITHIN);
    ROUND_WAIT
        .saturating_add(one_probe)
        .saturating_add(one_probe)
};

/// The directory authorities' distribution delay, `V3AuthDistDelay`'s
/// default in tor 0.4.9.14 (`src/app/config/config.c:713`, 5 minutes):
/// how long before its `valid-after` a consensus can already be fetched.
pub const CONSENSUS_DIST_DELAY: Duration = Duration::from_secs(5 * 60);

/// Tor's own allowance on top of that before it says a consensus came
/// early (`EARLY_CONSENSUS_NOTICE_SKEW`, `networkstatus.c:1891`).
pub const EARLY_CONSENSUS_SKEW: Duration = Duration::from_secs(60);

/// [`Policy::clock_behind_after`]: the line Tor draws for its own
/// early-consensus notice (`networkstatus.c:1899`), 6 minutes. NTP's
/// slop is far inside it.
pub const CLOCK_BEHIND_AFTER: Duration =
    Duration::from_secs(CONSENSUS_DIST_DELAY.as_secs() + EARLY_CONSENSUS_SKEW.as_secs());

/// Tor's `HS_DESC_DEFAULT_LIFETIME` at the pinned tor 0.4.9.14
/// (`src/feature/hs/hs_descriptor.h:30`): 3 hours.
pub const DESCRIPTOR_LIFETIME: Duration = Duration::from_secs(3 * 60 * 60);

/// The data directory a launch takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchDirectory {
    /// The directory the last incarnation kept, or a new one when none is
    /// kept.
    Kept,
    /// A new directory; a kept one is retired first. Taken once
    /// [`Policy::fresh_directory_after`] launches in a row have failed.
    Fresh,
}

/// One launch of Tor: the binary its own pin check accepted (`TSR-F5`) and
/// the data directory it takes. A launch exists only with a binary, so the
/// driver holds none of its own and cannot be asked to launch without one
/// (Rick, 2026-11-12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Launch {
    /// What the pin verified.
    pub binary: VerifiedTorBinary,
    /// Where it runs.
    pub directory: LaunchDirectory,
}

/// What the driver does next.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Discover and pin. No spawn until this accepts.
    CheckPin,
    /// Stop and reap the incarnation that ended, keeping its data
    /// directory for the next launch: the owning connection closes, Tor is
    /// given its grace to exit, and is killed past it. A request: the
    /// reply is [`Input::Replied`] alone, and the next launch waits behind it.
    Reap,
    /// Spawn Tor: the binary its pin accepted, in the directory it takes.
    Spawn(Launch),
    /// One `GETINFO` of bootstrap progress, the SOCKS listeners, and
    /// `traffic/read`. While Running the same reply also carries Tor's
    /// network view ([`Input::NetworkView`]); during a bootstrap those keys
    /// are not asked. While Running this is the liveness question: a Tor
    /// that sends nothing still has a reply to be late with.
    /// The reply is [`Input::DirectorySample`], then [`Input::NetworkView`]
    /// while Running, then the consensus clock. A reply past
    /// [`Policy::reply_bound`] is [`Cause::ReplyLate`].
    Sample,
    /// Subscribe the owning connection to the supervisor's events. Sent
    /// after a launch and before its first sample.
    SubscribeEvents,
    /// Look for the first `state` file.
    WatchState,
    /// `SETCONF AvoidDiskWrites=1` on the owning connection.
    SetConfAvoidDiskWrites,
    /// Publish the managed route. Only the transition into `Running` builds it.
    Publish(ManagedRunning),
    /// The installed route is down because the process ended. The driver
    /// withdraws it; [`Self::Reap`] follows.
    TakeDown,
    /// The installed route is down because this node is stopping. The
    /// driver leaves the child up; [`Self::StopChild`] wipes it.
    StopRoute,
    /// Publish the onion from the boot's seed, first half: `DEL_ONION`, so
    /// a Tor that still holds the service takes it again. A delete Tor
    /// refuses is [`Input::OnionRejected`], and no [`Self::AddOnion`] is sent.
    RepublishOnion,
    /// The second half: `ADD_ONION`. The reply is [`Input::OnionPublished`]
    /// or [`Input::OnionRejected`].
    AddOnion,
    /// Dial this node's own onion with a fresh probe nonce (§4.5). The
    /// driver answers [`Input::ProbeDialed`], or [`Input::ProbeNotDialed`]
    /// when it cannot. The core holds the bound.
    Probe,
    /// Drop the probe's dial: it missed its bound, or the phase it ran in
    /// ended. Its nonce leaves the set with it.
    CancelProbe,
    /// `HSFETCH` this node's own onion: a first probe missed, and Tor's own
    /// client view of the address is refreshed before the second probe
    /// (`TSR-Q14`: Tor does Tor; no other stream is touched). The driver
    /// answers [`Input::DescriptorRefetched`].
    RefetchDescriptor,
    /// Tor reported a clock jump while Running: draw the delay of one probe
    /// (§4.5, "Overdue"). The driver says so at info and answers
    /// [`Input::JumpProbeDrawn`].
    ProbeAfterJump,
    /// No upload round began within the descriptor's lifetime of the last
    /// round's first upload (§4.5, "Overdue"): Tor broke its own lifetime.
    /// Said at info. The [`Self::RepublishOnion`] that follows forces a
    /// fresh upload.
    DescriptorOverdue,
    /// A probe's check began: give the directories the latest round's
    /// uploads reached, each with a CSPRNG draw for its own fetch delay
    /// (§4.5, the directory check). The driver answers
    /// [`Input::DirectoriesDrawn`].
    CheckDirectories,
    /// `HSFETCH` this node's onion from `hsdir` alone (`SERVER=`). Tor
    /// accepting the command is [`Input::DirectoryFetchAccepted`], and the
    /// answer arrives later as [`Input::DirectoryAnswered`]. A command Tor
    /// refuses is answered at once as [`DirectoryAnswer::Unusable`].
    FetchFromDirectory {
        /// The directory to ask.
        hsdir: RelayFingerprint,
    },
    /// The check counted no directory: none the round reached holds the
    /// descriptor Tor's client asks for, or none answered about it. The
    /// probe alone decided. Said once at info: a node whose uploads land
    /// under a key no fetch asks for is the clock's signature (§4.5).
    DirectoriesUnmatched,
    /// Publish the inbound facet on the managed route's link (§4.1).
    PublishInbound(Inbound),
    /// A descriptor round has been open for `Policy::round_stuck_after`:
    /// say it once at debug, and end the coalescer's open round so the next
    /// round's uploads start a round of their own. Counted in Status.
    RoundStuck,
    /// A timer the driver was waiting on fired `late_by` late: the machine
    /// slept, and every window started again from the wake. Said once at info.
    Resumed {
        /// How far past its deadline the waited timer fired.
        late_by: Duration,
    },
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
    /// The pin accepted the binary: the witness the next launch spawns.
    PinAccepted {
        /// What the pin verified.
        binary: VerifiedTorBinary,
    },
    /// The pin refused it.
    PinRefused,
    /// No bundle was found.
    BundleMissing,
    /// This platform manages no Tor.
    Unavailable,
    /// The data directory cannot be used, or has too little free space for
    /// the spawn (the pre-spawn check).
    DirectoryUnusable {
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
    /// The last input of a request's reply: the actions the driver runs off
    /// its loop (the launch, the subscription, the sample, `SETCONF`, the
    /// republish's two halves, the refetch, the directory check and its
    /// fetches). `number` is [`Core::in_flight`] as the request was sent. A
    /// reply for any other number is not folded.
    Replied {
        /// The request this reply answers.
        number: u64,
    },
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
    /// Tor reported the clock off.
    ClockSkew {
        /// Tor's figure: `SKEW` or `MIN_SKEW`.
        skew: ReportedSkew,
    },
    /// Tor resumed and closed its circuits.
    ClockJumped,
    /// The driver was waiting on a timer and found it more than
    /// `control::RESUMED_AFTER` late ([`crate::control::resume_lateness`]).
    /// The machine slept. Folded before the reply that wait produced, so
    /// the reply is judged on windows that start at the wake.
    Resumed {
        /// How far past its deadline the waited timer fired.
        late_by: Duration,
    },
    /// Tor logged a relay's certificate as expired or not yet valid (§4.2).
    /// The line names no relay.
    CertificateOutOfDate,
    /// A bootstrap problem with `REASON=DONE`: the TLS handshake with this
    /// relay completed and Tor closed the connection.
    HandshakeClosed {
        /// The problem's `HOSTID`.
        relay: crate::control::RelayFingerprint,
    },
    /// The open-file limit. The process stays up.
    TooManyFiles {
        /// Sockets Tor reported open.
        open: u64,
    },
    /// A descriptor round began: its first `HS_DESC UPLOAD`.
    UploadRoundStarted,
    /// A round's first upload reached a directory. The probe follows the
    /// round's end, or `Policy::round_wait` after this, whichever comes
    /// first; `draw` sets the delay if the wait runs out first.
    FirstUploaded {
        /// Uniform over `u64`.
        draw: u64,
    },
    /// A descriptor round ended (`HS_DESC`, coalesced by round, `TSR-Q5`).
    /// A round with an upload that succeeded schedules the round's one probe
    /// (Rick, 2026-10-29: after the round, not its first upload, so the
    /// directory the probe's fetch asks has the descriptor). `draw` is a
    /// uniform random number from the daemon's CSPRNG; the core maps it onto
    /// the probe's delay range.
    UploadRoundEnded {
        /// How many reached a directory, how many of those that began were
        /// refused, and how many began.
        tally: RoundTally,
        /// Uniform over `u64`.
        draw: u64,
    },
    /// The consensus's `valid-after` and this machine's wall time, both in
    /// Unix seconds, read at a liveness sample (§4.2). The core compares
    /// them; it never reads a clock itself.
    ConsensusClock {
        /// `GETINFO consensus/valid-after`.
        valid_after: u64,
        /// This machine's wall time when it was read.
        wall: u64,
    },
    /// The descriptor refetch after a first miss (`HSFETCH`) was asked;
    /// `draw` sets the second probe's delay, as a round's does.
    DescriptorRefetched {
        /// Uniform over `u64`.
        draw: u64,
    },
    /// The delay of the probe [`Action::ProbeAfterJump`] asked for. `draw` is
    /// from the daemon's CSPRNG, as a round's is.
    JumpProbeDrawn {
        /// Uniform over `u64`.
        draw: u64,
    },
    /// The directories for the check [`Action::CheckDirectories`] asked for.
    DirectoriesDrawn {
        /// One per directory, each with its own draw. Empty when the round
        /// reached none: the probe alone decides. A list that was never
        /// folded is not this: the verdict waits.
        fetches: Vec<DirectoryFetch>,
        /// This service's `desc_current` (`GETINFO
        /// hs/service/desc/id/<onion>`): its blinded key and counter. A copy
        /// of that descriptor counts only at that counter; a copy of another
        /// counts by being there. `None` when Tor gave none: the check
        /// counts nothing and the probe alone decides.
        ours: Option<ServiceDescriptor>,
    },
    /// Tor accepted `HSFETCH` for `hsdir` (`250`). That fetch's answer
    /// window starts at this fold.
    DirectoryFetchAccepted {
        /// The directory.
        hsdir: RelayFingerprint,
    },
    /// A fetch this check sent named this descriptor (`HS_DESC REQUESTED`
    /// for `hsdir`): the one Tor's client asks for. A `REQUESTED` for a
    /// directory this check has not sent is ignored.
    DirectoryAsked {
        /// The directory the fetch named.
        hsdir: RelayFingerprint,
        /// The blinded key.
        descriptor_id: String,
    },
    /// A directory answered a fetch of this node's onion (`HS_DESC RECEIVED`
    /// or `FAILED`), or the driver could not ask it.
    DirectoryAnswered {
        /// The directory.
        hsdir: RelayFingerprint,
        /// The descriptor the answer is about; `None` when the driver could
        /// not ask.
        descriptor_id: Option<String>,
        /// What it said.
        answer: DirectoryAnswer,
    },
    /// The probe's nonce is minted, at `minted_at`, and its dial launched.
    ProbeDialed {
        /// The mint tick, which names the probe.
        minted_at: u64,
    },
    /// The probe could not be dialed: no route, no tip, or no onion.
    ProbeNotDialed,
    /// A probe nonce came back through this node's onion.
    ProbeArrived {
        /// The mint tick of the probe that arrived.
        minted_at: u64,
        /// Process time when the handshake took the nonce, on this core's
        /// clock. Evidence only when it is before the probe's bound.
        arrived_at: u64,
    },
    /// The consensus does not recommend this Tor.
    DangerousVersion,
    /// `state` exists in the data directory.
    StateFileAppeared,
    /// The daemon is stopping.
    Shutdown,
    /// The relay's hop-0 verdict for a local origin moved (`GS-Q3`).
    AddressHidingOrigin(OriginVerdict),
    /// The dialer's tally of this node's Tor dials changed (§4.2). Display
    /// only, never a cause (`TSR-Q14`).
    DialEvidence(DialTally),
    /// The sessions each connector holds changed (`TSR-Q12`): what the
    /// node syncs over. Display only.
    Sessions(Sessions),
    /// Tor's sampled view of its network. Ignored unless Running.
    NetworkView(NetworkView),
    /// Tor says it reaches its network: `NETWORK_LIVENESS UP` or
    /// `CIRCUIT_ESTABLISHED`.
    ExternalCleared,
}

/// How one upload round ended (§4.5). The three counts are one fact: how
/// many reached a directory, how many of the uploads that began were
/// refused, and how many began. A refused majority is read from `begun`,
/// not from the successes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundTally {
    /// Uploads that reached a directory (`UPLOADED`).
    pub uploaded: u32,
    /// Of [`Self::begun`], the uploads a directory refused.
    pub refused: u32,
    /// Uploads that began, including those that never reported an end.
    pub begun: u32,
}

impl RoundTally {
    /// More than half of the uploads that began were refused. Exactly half
    /// is not a majority. A round that began nothing is not one.
    #[must_use]
    pub fn majority_refused(self) -> bool {
        self.begun > 0 && u64::from(self.refused) * 2 > u64::from(self.begun)
    }
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
    /// The sessions each connector holds, as last folded.
    sessions: Sessions,
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
    /// Whether peers can reach this node's onion (§4.1).
    inbound: Inbound,
    /// The inbound facet as last asked of the driver.
    published_inbound: Inbound,
    /// When the outbound facet last became usable, while it is. A usable
    /// stretch of a cap restarts the backoff (§4.4).
    outbound_since: Option<u64>,
    /// The round's probe (§4.5).
    probe: Probe,
    /// The directory half of the probe's check. `None` when no check is
    /// open. [`directories::DirectoryHalf::AwaitingDraw`] until the driver
    /// folds the list.
    directories: Option<directories::DirectoryHalf>,
    /// The descriptor round open now, while one is.
    round: Option<probe::RoundTrack>,
    /// Rounds that stayed open past `Policy::round_stuck_after`, this boot.
    stuck_rounds: u32,
    /// Where the descriptor's lifetime is counted from (§4.5, "Overdue"):
    /// the last round's first upload, or the moment a republish was handed
    /// to the driver. A probe's arrival does not move it. None before the
    /// first of those and after the probe is dropped. Standing down because
    /// a republish cannot help does not move it, and a hand-over the driver
    /// then withholds puts back the anchor it moved.
    lifetime_from: Option<u64>,
    /// The anchor and hold to restore if the remedial send in
    /// [`clock::QueuedSend`] is withheld before it is published.
    queued_send: Option<clock::QueuedSend>,
    /// The probe in hand was scheduled from a republish's own upload round,
    /// so its Reachable confirms that republish. A clock-jump probe and a
    /// probe scheduled before the republish do not.
    probe_confirms: bool,
    /// More than half of the latest round's directories refused its upload.
    uploads_refused: bool,
    /// Whether Tor's standing skew report owns a bootstrap block.
    skew_hold: clock::SkewHold,
    /// The republish backoff (§4.5).
    republish: clock::RepublishHold,
    /// A clock jump during this bootstrap, and `traffic/read`'s movement.
    jump: clock_jump::JumpWatch,
    /// This bootstrap's certificate lines and closed handshakes (§4.2).
    clock_evidence: clock_evidence::ClockEvidence,
    /// The owed republish is a Service remedy: a refusal escalates.
    service_republish: bool,
    /// The requests to Tor, and the one in flight.
    requests: requests::Requests,
}

impl Core {
    /// Start. The first action is the pin check.
    #[must_use]
    pub fn start(policy: Policy, connectors: Connectors, now: u64) -> (Self, Step) {
        let mut core = Self {
            policy,
            connectors,
            origin: OriginVerdict::Absent,
            sessions: Sessions::default(),
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
            inbound: Inbound::NotOffered,
            published_inbound: Inbound::NotOffered,
            outbound_since: None,
            probe: Probe::Idle,
            directories: None,
            round: None,
            stuck_rounds: 0,
            lifetime_from: None,
            queued_send: None,
            probe_confirms: false,
            uploads_refused: false,
            skew_hold: clock::SkewHold::Holding,
            republish: clock::RepublishHold::new(duration_ns(policy.republish_after)),
            jump: clock_jump::JumpWatch::new(now),
            clock_evidence: clock_evidence::ClockEvidence::default(),
            service_republish: false,
            requests: requests::Requests::default(),
        };
        let step = core.step(now, vec![Action::CheckPin]);
        (core, step)
    }

    /// Fold one observation in.
    ///
    pub fn on(&mut self, input: Input, now: u64) -> Step {
        let actions = match input {
            Input::PinAccepted { binary } => self.pin_accepted(binary),
            Input::PinRefused => self.hold(now, Cause::PinRefused, AbsentDuty::Held),
            Input::BundleMissing => self.hold(now, Cause::BundleMissing, AbsentDuty::Held),
            Input::Unavailable => self.hold(now, Cause::Unavailable, AbsentDuty::Fixed),
            Input::DirectoryUnusable { space } => {
                self.hold(now, Cause::DirectoryUnusable { space }, AbsentDuty::Held)
            }
            Input::Spawned => self.spawned(now),
            Input::SpawnFailed => self.launch_failed(now),
            Input::BootstrapComplete => self.bootstrap_complete(now),
            Input::DirectorySample {
                progress,
                socks,
                read,
            } => self.note_sample(now, progress, socks, read),
            Input::BootstrapNoted { progress } => self.note_bootstrap(now, progress),
            Input::Replied { number } => self.replied(number),
            Input::ProcessEnded { exit_code } => {
                self.process_fault(now, Cause::Died { exit_code }, false)
            }
            Input::ControlEnded => self.process_fault(now, Cause::Died { exit_code: None }, false),
            Input::HostAbsent => self.host_absent(),
            Input::RouteInstalled => self.route_installed(now),
            Input::ForwardAbsent => self.forward_absent(),
            Input::OnionPublished => self.onion_published(now),
            Input::UploadRoundStarted => self.round_started(now),
            Input::FirstUploaded { draw } => self.first_uploaded(now, draw),
            Input::UploadRoundEnded { tally, draw } => self.round_ended(now, tally, draw),
            Input::ConsensusClock { valid_after, wall } => {
                self.consensus_clock(now, valid_after, wall)
            }
            Input::DescriptorRefetched { draw } => self.refetched(now, draw),
            Input::JumpProbeDrawn { draw } => self.jump_probe_drawn(now, draw),
            Input::DirectoriesDrawn { fetches, ours } => self.directories_drawn(now, fetches, ours),
            Input::DirectoryFetchAccepted { hsdir } => self.directory_fetch_accepted(now, hsdir),
            Input::DirectoryAsked {
                hsdir,
                descriptor_id,
            } => self.directory_asked(now, hsdir, &descriptor_id),
            Input::DirectoryAnswered {
                hsdir,
                descriptor_id,
                answer,
            } => self.directory_answered(now, hsdir, descriptor_id.as_deref(), answer),
            Input::ProbeDialed { minted_at } => self.probe_dialed(minted_at),
            Input::ProbeNotDialed => self.probe_not_dialed(),
            Input::ProbeArrived {
                minted_at,
                arrived_at,
            } => self.probe_arrived(now, minted_at, arrived_at),
            Input::OnionRejected => self.onion_refused(now),
            Input::EndpointReady => self.endpoint_ready(),
            Input::ExternalBlocked => self.blocked(now),
            Input::DirectoryUnreachable => self.unreachable_directories(now),
            Input::ClockSkew { skew } => self.clock_skew(now, skew),
            Input::ClockJumped => self.clock_jumped(now),
            Input::Resumed { late_by } => self.resumed(now, late_by),
            Input::CertificateOutOfDate => self.line_logged(now),
            Input::HandshakeClosed { relay } => self.handshake_closed(relay, now),
            Input::TooManyFiles { open } => self.too_many_files(now, open),
            Input::DangerousVersion => {
                self.set_cause(Cause::DangerousVersion);
                self.say(now, Cadence::Due)
            }
            Input::StateFileAppeared => self.state_file(),
            Input::Shutdown => self.shutdown(),
            Input::AddressHidingOrigin(verdict) => self.origin_verdict(verdict, now),
            Input::DialEvidence(tally) => self.dial_evidence(tally, now),
            Input::Sessions(sessions) => {
                self.sessions = sessions;
                Vec::new()
            }
            Input::NetworkView(view) => self.network_view(now, view),
            Input::ExternalCleared => self.external_cleared(now),
        };
        self.step(now, actions)
    }

    /// Whether `action` still names work this core is waiting on.
    ///
    /// A deadline can queue a republish, a probe, or a directory fetch and
    /// also a liveness sample. The driver folds the sample first. Once that
    /// sample has named a cause a republish cannot get past, the later
    /// actions no longer stand: sending them would replace introduction
    /// points the directories still advertise, or judge a copy a republish
    /// cannot replace (§4.5). A Tor's first publish still stands. The clock
    /// names this machine, and the first descriptor has to be uploaded
    /// before a directory can refuse it.
    #[must_use]
    pub fn action_stands(&self, action: &Action) -> bool {
        match action {
            Action::RepublishOnion => !self.service_republish || !self.republish_cannot_help(),
            Action::Probe => matches!(self.probe, probe::Probe::InFlight { .. }),
            Action::CheckDirectories => {
                matches!(
                    self.directories,
                    Some(directories::DirectoryHalf::AwaitingDraw)
                )
            }
            Action::FetchFromDirectory { hsdir } => {
                matches!(
                    &self.directories,
                    Some(directories::DirectoryHalf::Open(check)) if check.queued(*hsdir)
                ) && !self.republish_cannot_help()
            }
            Action::RefetchDescriptor => matches!(self.probe, probe::Probe::Refetching),
            _ => true,
        }
    }

    /// The connector settings this core runs under.
    pub(in crate::supervisor) fn connectors(&self) -> Connectors {
        self.connectors
    }

    /// The deadline fired. Each armed time is its own kind of work: a pin
    /// check, a sample, or another announcement.
    pub fn on_deadline(&mut self, now: u64) -> Step {
        // A request past its bound is a process fault, whatever else is due.
        if self.phase != Phase::Stopping && self.reply_late(now) {
            let actions = self.process_fault(now, Cause::ReplyLate, false);
            return self.step(now, actions);
        }
        if self.phase == Phase::Stopping {
            self.pin_at = None;
            self.sample_at = None;
            self.announcements.disarm();
            self.alive_at = None;
            let dropped = self.drop_probe();
            return self.step(now, dropped.into_iter().collect());
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
        // The liveness sample is first. The driver folds it before the
        // republish, probe, and directory actions this same deadline queues,
        // and a clock that sample names stands those down (§4.5).
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
                    // it cannot say the cause again; nor the clock, which
                    // the consensus check names beside no cause.
                    if self.cause == Cause::None && !self.clock_is_behind() {
                        actions.push(Action::SayProgress);
                    }
                    self.arm_alive(now);
                }
                // Cleared above. A phase that is no longer live does not
                // re-arm: fault, hold, and shutdown already dropped it.
                _ => {}
            }
        }
        if self.sample_at.is_some_and(|at| now >= at) {
            self.sample_at = None;
            actions.extend(self.on_sample_deadline(now));
        }
        if self.round_due().is_some_and(|at| now >= at) {
            actions.extend(self.on_round_deadline(now));
        }
        if self.overdue_due().is_some_and(|at| now >= at) {
            actions.extend(self.on_overdue_deadline(now));
        }
        if self.probe.due().is_some_and(|at| now >= at) {
            actions.extend(self.on_probe_deadline(now));
        }
        if self.directories_due().is_some_and(|at| now >= at) {
            actions.extend(self.on_directories_deadline(now));
        }
        if self.republish_due().is_some_and(|at| now >= at) {
            actions.extend(self.on_republish_deadline(now));
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
            carriage: self.carriage(),
            cause: self.cause.clone(),
            since: self.since,
            respawn_count: self.respawn_count,
            // What the node syncs over is the sessions it holds, not the
            // configuration or the link (alpha.11 finding 9).
            sync: self.sessions.syncing(),
            own_tx: own_tx(self.origin, self.connectors),
            fixes: fixes(&self.cause, self.connectors),
            progress: self.progress.percent(),
            bootstrap,
            pace: bootstrap.and_then(BootstrapLine::pace),
            tor_quiet: match (&self.phase, &self.cause) {
                (Phase::Running { .. }, Cause::None) => self.dials.line(),
                _ => None,
            },
            inbound: self.inbound,
            stuck_upload_rounds: self.stuck_rounds,
            clock_behind: self.clock_lag(),
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
            self.probe.due(),
            self.round_due(),
            self.overdue_due(),
            self.directories_due(),
            self.republish_due(),
            self.requests.due(duration_ns(self.policy.reply_bound)),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// The pin accepted `binary`: the launch carries it, so every spawn is
    /// of the binary its own pin check accepted (`TSR-F5`).
    fn pin_accepted(&mut self, binary: VerifiedTorBinary) -> Vec<Action> {
        self.phase = Phase::Launching;
        let directory = if self.launch_failures > 0
            && self.launch_failures >= self.policy.fresh_directory_after
        {
            LaunchDirectory::Fresh
        } else {
            LaunchDirectory::Kept
        };
        vec![Action::Spawn(Launch { binary, directory })]
    }

    fn spawned(&mut self, now: u64) -> Vec<Action> {
        self.phase = Phase::Bootstrapping {
            socks: None,
            ready: false,
        };
        self.launch_failures = 0;
        self.progress = ProgressWindow::start(now, self.policy.alive_every);
        self.jump = clock_jump::JumpWatch::new(now);
        self.clock_evidence = clock_evidence::ClockEvidence::default();
        self.skew_hold = clock::SkewHold::Holding;
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
        self.jump.note_read(read, now);
        if let Some(fault) = self.stranded_after_jump(now) {
            return fault;
        }
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

    /// The onion is published: `ADD_ONION`'s reply, or a round's first
    /// upload. An onion offered for the first time is publishing. One that
    /// was unreachable stays so until a probe arrives.
    fn onion_published(&mut self, now: u64) -> Vec<Action> {
        if let Phase::Running { onion, .. } = &mut self.phase {
            *onion = Duty::Done;
            self.service_republish = false;
            // The send happened. The anchor it moved stays; a later withhold
            // has nothing to put back.
            self.queued_send = None;
            if self.inbound == Inbound::NotOffered {
                self.inbound = Inbound::Publishing { since: now };
            }
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

    /// Tor reported a clock jump. Re-evaluate now with one sample. While
    /// Running, also one probe (§4.5, "Overdue"): Tor's next upload may be
    /// scheduled on the clock that jumped, and the probe shows whether the
    /// onion is still reachable meanwhile.
    fn clock_jumped(&mut self, now: u64) -> Vec<Action> {
        self.jump.jumped(now);
        self.note_clock_jumped(now);
        let running = match &mut self.phase {
            Phase::Running { link, .. } => {
                *link = Link::Resumed;
                true
            }
            Phase::Bootstrapping { .. } => false,
            _ => return Vec::new(),
        };
        let mut actions = vec![Action::Sample];
        if running {
            actions.extend(self.jump_probe());
        }
        actions
    }

    fn too_many_files(&mut self, now: u64, open: u64) -> Vec<Action> {
        // The process is still up. Stay in the phase: no pin, no takedown.
        if !self.live() {
            return Vec::new();
        }
        self.set_cause(Cause::TooManyFiles { open });
        self.say(now, Cadence::Due)
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
        self.requests.clear();
        let installed = self.route_done();
        self.phase = Phase::Stopping;
        self.pin_at = None;
        self.sample_at = None;
        self.announcements.disarm();
        self.alive_at = None;
        let mut actions: Vec<Action> = self.drop_probe().into_iter().collect();
        if installed {
            actions.push(Action::StopRoute);
        }
        actions.push(Action::StopChild);
        actions
    }

    fn process_fault(&mut self, now: u64, cause: Cause, launch_failed: bool) -> Vec<Action> {
        // The incarnation ended: nothing queued for it is sent, and a reply
        // still on its way is not folded. A Tor that was launched is reaped,
        // off the loop, before the next launch.
        self.requests.clear();
        let launched = matches!(
            self.phase,
            Phase::Bootstrapping { .. } | Phase::Running { .. }
        );
        let installed = self.route_done();
        let dropped = self.drop_probe();
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
        let mut actions: Vec<Action> = dropped.into_iter().collect();
        if installed {
            actions.push(Action::TakeDown);
        }
        if launched {
            actions.push(Action::Reap);
        }
        actions.extend(self.say(now, Cadence::Due));
        actions
    }

    fn hold(&mut self, now: u64, cause: Cause, duty: AbsentDuty) -> Vec<Action> {
        self.requests.clear();
        // A hold comes from the pin check or the launch, before a Tor runs.
        // One that comes while a Tor runs ends it like a fault: reaped, off
        // the loop.
        let launched = matches!(
            self.phase,
            Phase::Bootstrapping { .. } | Phase::Running { .. }
        );
        let installed = self.route_done();
        let dropped = self.drop_probe();
        self.phase = Phase::Absent { duty };
        self.sample_at = None;
        self.alive_at = None;
        self.pin_at = match duty {
            AbsentDuty::Fixed => None,
            AbsentDuty::Held | AbsentDuty::Retry => Some(now.saturating_add(self.cap())),
        };
        self.set_cause(cause);
        let mut actions: Vec<Action> = dropped.into_iter().collect();
        if installed {
            actions.push(Action::TakeDown);
        }
        if launched {
            actions.push(Action::Reap);
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

    /// The line changed and was already said. Record the key it has now,
    /// without speaking and without moving the cap.
    fn note_key(&mut self) {
        let key = self.say_key();
        self.announcements.note_key(key);
    }

    fn say_key(&self) -> announce::SayKey {
        announce::SayKey::new(self.shown(), &self.cause, self.inbound)
    }

    /// The relay's verdict moved. Only a change in whether a local origin
    /// leaves is said. A loss is one announcement under the cap. A recovery
    /// is said at once, unless it retires a loss that has not been said: that
    /// once is forgiven and nothing is said, so churn inside the cap is
    /// silent. The first recovery, and a recovery after a loss that was said,
    /// have no armed once, so they are said. The class moving on its own says
    /// nothing. The same routable state again is not a change. Health still
    /// follows the stored verdict.
    fn origin_verdict(&mut self, verdict: OriginVerdict, now: u64) -> Vec<Action> {
        let was_leaving = self.origin.origin_leaves();
        let leaves = verdict.origin_leaves();
        self.origin = verdict;
        if was_leaving == leaves {
            return Vec::new();
        }
        if !leaves {
            return self.say(now, Cadence::Once);
        }
        if self.announcements.forgive_once(self.repeats_announcement()) {
            return Vec::new();
        }
        self.say(now, Cadence::Now)
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
        // The inbound facet down degrades a running Tor (§4.3). Publishing
        // does not: Usable is the outbound link, and an onion not yet proven
        // is not one found unreachable.
        if matches!(self.phase, Phase::Running { .. })
            && matches!(self.inbound, Inbound::Unreachable { .. })
        {
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

    /// What the link carries: the outbound facet, and whether the Tor that
    /// holds the connections still runs with its route installed. Not the
    /// projection, which shows an unreachable onion or any cause as
    /// degraded (Copilot, #1283: a version warning beside a usable link).
    fn carriage(&self) -> Carriage {
        if self.outbound_usable() {
            Carriage::Carries
        } else if matches!(
            self.phase,
            Phase::Running {
                route: Duty::Done,
                link: Link::Open,
                ..
            }
        ) {
            Carriage::OpenOnly
        } else {
            Carriage::Gone
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
                | Cause::CertificatesOutOfDate
                | Cause::TooManyFiles { .. }
        )
    }

    /// The outbound facet is usable: Running, the route installed, no
    /// resume pending, and no outbound cause. The inbound facet does not
    /// enter (§4.1): an onion peers cannot reach still dials out.
    fn outbound_usable(&self) -> bool {
        matches!(
            self.phase,
            Phase::Running {
                route: Duty::Done,
                link: Link::Open,
                ..
            }
        ) && !self.degraded()
    }

    /// Move [`Self::posted`] onto the projection. Closing an interval in
    /// which the outbound facet was usable for a cap records the backoff
    /// restart (§4.4): the facet, not the projection, so an unreachable
    /// onion does not end it.
    fn settle_shown(&mut self, now: u64) {
        let outbound = self.outbound_usable();
        match (self.outbound_since, outbound) {
            (None, true) => self.outbound_since = Some(now),
            (Some(since), false) => {
                if now.saturating_sub(since) >= self.cap() {
                    self.backoff.note_usable_cap();
                }
                self.outbound_since = None;
            }
            _ => {}
        }
        let shown = self.shown();
        if shown != self.posted {
            self.since = now;
            self.posted = shown;
        }
    }

    fn step(&mut self, now: u64, actions: Vec<Action>) -> Step {
        let mut actions = self.route_requests(now, actions);
        self.settle_shown(now);
        if self.inbound != self.published_inbound {
            self.published_inbound = self.inbound;
            actions.push(Action::PublishInbound(self.inbound));
        }
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
