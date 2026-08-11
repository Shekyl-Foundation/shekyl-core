// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `TorService` supervisor — DQ-T0.6, design §3c: keep the wallet's tor
//! **alive, verified, and honest about its state** across crashes.
//!
//! The economic driver is the transport plan's §5 slash model: the slash is
//! sliding-window `m`-of-`n`, *sustained*-failure-gated, and challenge cadence is
//! epoch-scale while a tor restart is seconds — so the slashing risk this module
//! retires is **not the crash, it is the silent unrecovered crash**. Three
//! commitments, in order:
//!
//! - **Never silent** — one long-lived [`watch`]`<`[`TorPosture`]`>` always
//!   reflects reality; sustained failure goes loudly [`TorPosture::Degraded`]
//!   (the operator-alarm hook, rule 82) while retries continue.
//! - **Never unverified** — **every** spawn re-runs the SP-T0c hash-pin gate.
//!   The [`VerifiedTorBinary`] witness is
//!   point-in-time; a respawn hours later (after a package update replaced
//!   `tor`) through a retained witness would be exactly the TOCTOU-respawn gap
//!   the SP-T0c review named. The supervisor holds discovery *inputs*
//!   ([`TorBinarySource`]), never a cached witness.
//! - **Always retrying** — there is **no give-up state**. After
//!   [`SupervisorPolicy::degrade_after`] consecutive failures the posture turns
//!   `Degraded` but retries continue at the backoff cap: an unattended node that
//!   stopped trying is a *guaranteed* `m`-of-`n` slash; one that keeps trying may
//!   self-heal. (Trust failures never fast-retry — see [`FailureClass`].)
//!
//! **Detection vs policy, one level up (§3b's discipline):** the per-incarnation
//! [`TorControl`] actor *detects* and fails fast — it already stops on desync /
//! EOF / spawn failure and never reconnects into a desync. This supervisor owns
//! *policy*: classification, backoff, posture. Nothing inside the actor grows
//! retry logic.
//!
//! **The SOCKS endpoint is data on the posture channel.** Production uses
//! `SocksPort auto` and each incarnation's bound address is discovered via
//! `GETINFO net/listeners/socks`, published in [`TorPosture::Ready`]. Because a
//! silent restart rebinds a fresh port, consumers must read the endpoint at
//! use-time, not cache it — the [`TorService::current_socks`] accessor is the safe
//! path (it returns the address only while the *live* posture is `Ready`), so a
//! caller that uses it cannot hold a stale endpoint. (`TorPosture::Ready` still
//! carries the address for watch-driven consumers; the discipline is theirs.)
//!
//! `DataDirectory` is reused across incarnations, so the entry-guard set
//! survives supervision — restarting must not decide DQ-T0.7's guard-rotation
//! posture by accident.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use kameo::actor::Spawn;
use kameo::error::SendError;
use tokio::sync::{oneshot, watch};

use crate::binary::{self, TorBinaryError, VerifiedTorBinary};
use crate::control::framing::ControlReply;
use crate::control::onion::{
    parse_service_id, AddOnion, OnionFlags, OnionPort, OnionPow, ServiceId,
};
use crate::control::{
    BootstrapReadiness, BootstrapState, Command, ControlError, EventSink, ManagedTor, SocksPort,
    TorControl, TorControlConfig, TorExit, TorLaunch,
};
use crate::onion_identity::OnionIdentity;

/// The service-level posture — what the rest of the wallet sees. One long-lived
/// watch, owned by the supervisor, outliving every incarnation (the §3b
/// per-incarnation `BootstrapState` watch is supervisor-internal).
///
/// The watch **sender dropping** (all receivers see the channel closed) is the
/// "service stopped" signal — a clean caller-initiated shutdown has no posture
/// state, deliberately: a state would invite consumers to poll for it instead of
/// observing the close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TorPosture {
    /// An incarnation is being launched (binary gate + spawn in progress).
    Starting,
    /// Tor is bootstrapping (§3b telemetry passed through).
    Connecting {
        /// Tor's reported bootstrap percent (0–99), for the "Connecting…" UX.
        progress: u8,
    },
    /// Usable **now**. The SOCKS endpoint is **data on this channel** — read it
    /// here at use-time, never cache it (it changes across restarts by design).
    ///
    /// `Ready` is *always* published when the transport is usable, even during a
    /// degraded episode — hiding a working transport from SP-T1 would turn a
    /// partial outage into a total one (missed challenge windows), the exact harm
    /// this supervisor exists to prevent. The episode is carried alongside
    /// instead: see `recovering`.
    Ready {
        /// The bound `SocksPort auto` address of the *current* incarnation.
        socks_addr: SocketAddr,
        /// `true` while the degraded episode has **not yet cleared**: the tor is
        /// usable now, but has not held `Ready` for `stable_reset` since the
        /// alarm fired. An operator-alarm layer should render
        /// `Degraded ∪ Ready{recovering: true}` as **one continuous incident**
        /// (no flapping); the supervisor republishes
        /// `Ready { recovering: false }` the moment the sustained-recovery
        /// threshold is met, which is the alarm-clear edge.
        recovering: bool,
    },
    /// The incarnation died; the supervisor will retry. Normal-operations
    /// transient — not the alarm state.
    Restarting {
        /// Consecutive failures since the last stable `Ready` period.
        attempt: u32,
        /// How long until the next attempt.
        retry_in: Duration,
    },
    /// The restart limit tripped (or a trust failure occurred) — **retries
    /// continue** at the backoff cap; this is the loud operator-alarm hook
    /// (rule 82), not a terminal state. Sticky, as an *episode*: intermediate
    /// `Starting` / `Connecting` of retry attempts are not published while
    /// degraded, and a brief recovery publishes `Ready { recovering: true }`
    /// (usable, but the incident is still open). The episode ends — and the
    /// alarm clears — only when an incarnation holds `Ready` for `stable_reset`
    /// (`Ready { recovering: false }` is republished at that moment); a
    /// genuinely flapping tor never reaches it and keeps alarming.
    Degraded {
        /// The most recent failure (updated on each failed retry).
        last: ServiceFailure,
    },
}

/// Why an incarnation failed — the classification input, carried in
/// [`TorPosture::Degraded`] for diagnosability. Same failure-surface posture as
/// its constituents: these are operator-facing setup/liveness diagnostics, not
/// persona-linked forensic data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceFailure {
    /// The SP-T0c gate refused the binary (or discovery found none).
    Binary(TorBinaryError),
    /// The control channel failed with a specific cause (the underlying
    /// [`ControlError`] is preserved, not collapsed into `Exited`).
    Control(ControlError),
    /// Bootstrap reached 100% but `GETINFO net/listeners/socks` reported **no TCP
    /// SOCKS listener** — a usable-looking tor with nothing for SP-T1 to dial (a
    /// misconfiguration, distinct from a malformed command).
    NoSocksListener,
    /// Tor did not reach bootstrap 100% within
    /// [`SupervisorPolicy::bootstrap_deadline`].
    BootstrapTimeout,
    /// The incarnation (actor/child) died. Carries the reaped [`TorExit`] when the
    /// death was observed through teardown (`Killed` = tor wedged and was
    /// `SIGKILL`-ed — the unclean signal an operator wants), or `None` when the
    /// exit was not observed (e.g. the readiness channel closed first).
    Exited(Option<TorExit>),
    /// A supervisor-internal fault, not a tor failure — the gate's
    /// `spawn_blocking` task panicked or was cancelled (a `JoinError`). Carries
    /// its rendered message (the type is neither `Clone` nor `Eq`, so it is kept
    /// as text) rather than masquerading as a tor `Exited`.
    Internal(String),
    /// `ADD_ONION` for the configured onion service failed — the incarnation
    /// bootstrapped and has a SOCKS listener, but the persona's serving
    /// endpoint could not be published, so `Ready` (which means the FULL
    /// serving posture is up) is never reached on this incarnation.
    OnionPublish(OnionPublishError),
}

/// Why publishing the configured onion service failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnionPublishError {
    /// The control channel failed (or the reply timed out) during
    /// `ADD_ONION`.
    Control(ControlError),
    /// Tor answered with a non-250 status.
    Rejected {
        /// The status tor returned.
        status: u16,
    },
    /// A 250 reply with no parseable `ServiceID=` line.
    NoServiceId,
    /// Tor published a **different address** than the one derived from the
    /// configured seed — the spike's fail-stop, kept: serving at an address
    /// the persona does not advertise is an unreachable service that looks
    /// healthy from the inside. (Both ids render redacted.)
    ServiceIdMismatch {
        /// The address derived from the configured seed.
        expected: ServiceId,
        /// The address tor reported.
        published: ServiceId,
    },
}

/// The two retry cadences (§3c restart classification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Crash / socket drop / desync teardown / bootstrap timeout / spawn I/O —
    /// the path a staker's liveness rides: capped exponential backoff.
    Transient,
    /// The SP-T0c gate refused. **No fast retry into an untrusted binary**:
    /// immediately `Degraded` + a slow re-discovery cadence — safe to retry
    /// forever because discovery never launches what it cannot verify, and an
    /// operator who reinstalls the pinned bundle gets auto-recovery.
    Trust,
}

/// Classify a failure into its retry cadence.
pub fn classify(failure: &ServiceFailure) -> FailureClass {
    match failure {
        ServiceFailure::Binary(_) => FailureClass::Trust,
        ServiceFailure::Control(_)
        | ServiceFailure::NoSocksListener
        | ServiceFailure::BootstrapTimeout
        | ServiceFailure::Exited(_)
        | ServiceFailure::Internal(_)
        | ServiceFailure::OnionPublish(_) => FailureClass::Transient,
    }
}

/// §3c retry policy. Defaults are production values; tests shrink them.
#[derive(Debug, Clone)]
pub struct SupervisorPolicy {
    /// First transient retry delay (doubles per consecutive failure).
    pub backoff_base: Duration,
    /// Transient backoff ceiling — also the forever-retry cadence once capped.
    pub backoff_cap: Duration,
    /// Consecutive transient failures before the posture turns `Degraded`
    /// (retries continue regardless — this is the alarm threshold, not a stop).
    pub degrade_after: u32,
    /// A `Ready` period at least this long resets the consecutive-failure
    /// counter (the "n within a window" restart limit, in its simplest form:
    /// stability resets, instability accumulates).
    pub stable_reset: Duration,
    /// Retry cadence for trust failures (slow — see [`FailureClass::Trust`]).
    pub trust_retry: Duration,
    /// How long an incarnation gets to reach bootstrap 100% before it is torn
    /// down as [`ServiceFailure::BootstrapTimeout`].
    pub bootstrap_deadline: Duration,
    /// Bound on the post-bootstrap `GETINFO net/listeners/socks` reply — an alive
    /// tor answers instantly, so a stall here means a wedged control port; this
    /// keeps SOCKS discovery from hanging the supervisor (and thus `shutdown()`).
    /// Policy-driven (like the other timeouts) so tests can shrink it.
    pub socks_discovery_deadline: Duration,
    /// Bound on the `ADD_ONION` reply for the configured onion service.
    /// `ADD_ONION` loads the key and answers immediately — descriptor
    /// publication is asynchronous and NOT awaited here — so, like SOCKS
    /// discovery, a stall means a wedged control port, not a slow network.
    pub onion_publish_deadline: Duration,
}

impl Default for SupervisorPolicy {
    fn default() -> Self {
        Self {
            backoff_base: Duration::from_secs(1),
            backoff_cap: Duration::from_secs(60),
            degrade_after: 5,
            stable_reset: Duration::from_secs(600),
            trust_retry: Duration::from_secs(300),
            bootstrap_deadline: Duration::from_secs(300),
            socks_discovery_deadline: Duration::from_secs(30),
            onion_publish_deadline: Duration::from_secs(30),
        }
    }
}

/// The delay before retry `attempt` (1-based consecutive-failure count) — the
/// pure §3c cadence: transient = `base * 2^(attempt-1)` capped; trust = the slow
/// re-discovery cadence, flat.
pub fn retry_delay(policy: &SupervisorPolicy, class: FailureClass, attempt: u32) -> Duration {
    match class {
        FailureClass::Trust => policy.trust_retry,
        FailureClass::Transient => {
            // Clamp the exponent so the shift can't overflow; the cap dominates
            // long before 2^20 anyway.
            let factor = 1u32 << attempt.saturating_sub(1).min(20);
            policy
                .backoff_base
                .saturating_mul(factor)
                .min(policy.backoff_cap)
        }
    }
}

/// Is the posture `Degraded` at this failure? Trust failures alarm immediately
/// (the binary the firewall rests on is refusing verification); transients alarm
/// once the consecutive count reaches the threshold.
pub fn is_degraded(policy: &SupervisorPolicy, class: FailureClass, attempt: u32) -> bool {
    match class {
        FailureClass::Trust => true,
        FailureClass::Transient => attempt >= policy.degrade_after,
    }
}

/// Extract the first TCP listener from a `GETINFO net/listeners/socks` reply —
/// the `SocksPort auto` discovery. Tor normally returns a space-separated list of
/// **quoted** listener specs (`"127.0.0.1:9050"`, possibly `"unix:/…"`), but each
/// entry is escaped independently and the `getsockname()`-fallback path (exactly
/// the auto-port case discovery relies on) emits an **unquoted** `addr:port` — so
/// a *mixed* list is possible. One uniform pass handles every shape: whitespace
/// tokens, surrounding quotes stripped per token, first token that parses as a
/// socket address wins (unix and other non-TCP entries never parse and are
/// skipped; a quoted unix path containing spaces splits into tokens that also
/// never parse — harmless). `None` = no TCP SOCKS listener at all (a tor with
/// nothing for SP-T1 to dial — [`ServiceFailure::NoSocksListener`], not `Ready`).
pub fn parse_socks_listeners(reply: &ControlReply) -> Option<SocketAddr> {
    let line = reply
        .lines()
        .iter()
        .find_map(|l| l.strip_prefix("net/listeners/socks="))?;
    line.split_ascii_whitespace()
        .map(|tok| tok.trim_matches('"'))
        .find_map(|tok| tok.parse::<SocketAddr>().ok())
}

/// Where the supervisor gets each incarnation's binary — discovery *inputs*, so
/// the SP-T0c gate re-runs per spawn (never a cached witness).
#[derive(Debug, Clone)]
pub enum TorBinarySource {
    /// The ambient production path: `binary::discover_and_verify()` (env
    /// override → beside the wallet → `PATH`), hash-gated.
    Discover,
    /// A caller-supplied path (the wallet's settings file):
    /// `binary::discover_and_verify_at`, hash-gated.
    At(PathBuf),
    /// **Test-only bypass** of the gate (lifecycle tests injecting an arbitrary
    /// tor). Loud and greppable, like `VerifiedTorBinary::unchecked_for_test`.
    #[cfg(test)]
    UncheckedForTest(PathBuf),
}

impl TorBinarySource {
    /// Run the gate for one incarnation. Blocking file I/O (the ~3.6 MB hash)
    /// rides `spawn_blocking`.
    async fn resolve(&self) -> Result<VerifiedTorBinary, ServiceFailure> {
        let outcome = match self {
            Self::Discover => tokio::task::spawn_blocking(binary::discover_and_verify).await,
            Self::At(path) => {
                let path = path.clone();
                tokio::task::spawn_blocking(move || binary::discover_and_verify_at(&path)).await
            }
            #[cfg(test)]
            Self::UncheckedForTest(path) => {
                return Ok(VerifiedTorBinary::unchecked_for_test(path.clone()));
            }
        };
        match outcome {
            Ok(Ok(verified)) => Ok(verified),
            Ok(Err(e)) => Err(ServiceFailure::Binary(e)),
            // The blocking task itself died (panic/cancel) — a supervisor-internal
            // fault, not a tor exit; surface it as such rather than mislabeling.
            Err(join) => Err(ServiceFailure::Internal(join.to_string())),
        }
    }
}

/// The persona's onion service, as supervisor configuration: everything the
/// supervisor needs to (re-)publish the service on **every** incarnation.
///
/// `Detach` is unrepresentable in the `ADD_ONION` surface, so a published
/// onion dies with its incarnation; the supervisor mints a fresh one-shot
/// key from the held [`OnionIdentity`] and republishes at the *same* address
/// on each `Ready` transition.
///
/// **The boundary is an [`OnionIdentity`], never a seed** — the least-
/// privilege credential (the expanded onion key authorizes exactly one
/// thing, publishing this onion), derived once in the wallet context. A
/// serving config that cannot hold a seed cannot hold `master_seed`, so the
/// cold/hot bond-authority separation (§7.2(iii)) is structural here rather
/// than a wiring convention. See [`crate::onion_identity::OnionIdentity`].
///
/// **One `Option`, not a `Vec`, deliberately:** one persona on the wire per
/// wallet is the Model D co-activation rule, and the SP-T3 spike priced
/// multi-persona co-serving as a forbidden layout. A service instance that
/// can hold at most one onion makes that layout unrepresentable here; a
/// second persona is a second wallet process with its own `TorService`
/// (and its own guard identity).
pub struct OnionServiceSpec {
    /// The wallet-derived serving identity (expanded key + address); the
    /// supervisor mints a one-shot `OnionKey` from it per incarnation.
    identity: OnionIdentity,
    /// The virtual-port → loopback-target mapping (loopback enforced at
    /// construction by [`OnionPort::loopback`]).
    port: OnionPort,
    /// Per-rendezvous-circuit stream cap (`MaxStreams`, with
    /// `MaxStreamsCloseCircuit` always on — the wire assembly pins that).
    ///
    /// **Carried placeholder (SPIKE-PIN-1), not a derivation.** A witness
    /// drawn for several of one `P`'s shards in the same block opens
    /// concurrent streams on *one* rendezvous circuit, so this interacts
    /// with the λ=3 per-pair concurrency finding; the W₂ rig derives the
    /// real value. Parameterized (not hardcoded) so the rig chooses it.
    max_streams: u16,
    /// PoW defense posture; defaults to [`OnionPow::Enabled`].
    pow: OnionPow,
}

impl OnionServiceSpec {
    /// A spec publishing `virtual_port` onto the loopback `target`, keyed by
    /// the wallet-derived `identity`. Returns `None` when `target` is not
    /// loopback (hard invariant 4, enforced where the mapping is created).
    ///
    /// Takes an [`OnionIdentity`] — the expanded credential, never a seed
    /// (see the type doc's custody boundary). `HiddenServicePoW` defaults
    /// **on** ([`OnionPow::Enabled`]) — the TJ-H ruling pins PoW for serving
    /// personas as part of the guard-discovery mitigation set;
    /// [`Self::with_pow`] exists for measurement arms that price the other
    /// postures, not as a production opt-out.
    #[must_use]
    pub fn new(
        identity: OnionIdentity,
        virtual_port: u16,
        target: SocketAddr,
        max_streams: u16,
    ) -> Option<Self> {
        let port = OnionPort::loopback(virtual_port, target)?;
        Some(Self {
            identity,
            port,
            max_streams,
            pow: OnionPow::Enabled,
        })
    }

    /// Override the PoW posture (measurement arms; production keeps the
    /// default).
    #[must_use]
    pub fn with_pow(mut self, pow: OnionPow) -> Self {
        self.pow = pow;
        self
    }

    /// The `.onion` address this spec publishes at — so the caller can
    /// advertise it (and dial it) without waiting for a `Ready` posture. The
    /// supervisor fail-stops any incarnation where tor reports a different
    /// id.
    #[must_use]
    pub fn service_id(&self) -> ServiceId {
        self.identity.service_id().clone()
    }
}

// The identity is the persona's serving key; redact wholesale.
impl std::fmt::Debug for OnionServiceSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionServiceSpec").finish_non_exhaustive()
    }
}

/// Supervisor configuration.
pub struct TorServiceConfig {
    /// Per-incarnation binary source (the gate re-runs every spawn).
    pub binary: TorBinarySource,
    /// The wallet-private `DataDirectory`, reused across incarnations **and
    /// across wallet sessions** (DQ-T0.7, decided: persistent — the dir carries
    /// the entry-guard identity, and stability is the privacy-preserving
    /// posture). The caller supplies a wallet-adjacent, wallet-controlled,
    /// non-world-writable path and hands the *same* path every session; see
    /// `ManagedTor::data_dir` for the full contract.
    pub data_dir: PathBuf,
    /// The long-lived async-event sink, cloned into each incarnation.
    pub events: EventSink,
    /// Retry/backoff policy.
    pub policy: SupervisorPolicy,
    /// Spawn incarnations with `--DisableNetwork 1` — offline-test posture only
    /// (an offline tor never bootstraps, so `Ready` never publishes);
    /// **production always leaves it `false`**. Same typed-knob rationale as
    /// `ManagedTor::disable_network`.
    pub disable_network: bool,
    /// The persona's onion service, republished on every incarnation's
    /// `Ready` transition (onions are per-incarnation: `Detach` is
    /// unrepresentable). When set, `Ready` means the **full** serving
    /// posture is up — SOCKS discovered *and* the onion published at the
    /// derived address; a publish failure tears the incarnation down
    /// through the normal retry/degrade policy instead of publishing a
    /// half-up `Ready`.
    pub onion: Option<OnionServiceSpec>,
}

/// Handle to a running supervisor: the posture watch + shutdown.
pub struct TorService {
    posture: watch::Receiver<TorPosture>,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl TorService {
    /// Start the supervisor (needs a tokio runtime). The returned handle owns
    /// shutdown; posture receivers can be cloned freely.
    #[must_use]
    pub fn spawn(config: TorServiceConfig) -> Self {
        let (posture_tx, posture) = watch::channel(TorPosture::Starting);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(supervise(config, posture_tx, shutdown_rx));
        Self {
            posture,
            shutdown: Some(shutdown_tx),
            task,
        }
    }

    /// A posture receiver (late subscribers see the current state immediately —
    /// the same `watch` rationale as §3b).
    #[must_use]
    pub fn posture(&self) -> watch::Receiver<TorPosture> {
        self.posture.clone()
    }

    /// The current incarnation's SOCKS endpoint, or `None` when the service is not
    /// `Ready`. **This is the safe way to reach the endpoint** — it reads the live
    /// posture at call time, so a caller cannot cache an address that a silent
    /// restart has invalidated (`SocksPort::Auto` rebinds a fresh port per
    /// incarnation). Prefer this over destructuring `TorPosture::Ready` and
    /// stashing the `SocketAddr`.
    #[must_use]
    pub fn current_socks(&self) -> Option<SocketAddr> {
        match &*self.posture.borrow() {
            TorPosture::Ready { socks_addr, .. } => Some(*socks_addr),
            _ => None,
        }
    }

    /// Clean stop: shut the current incarnation down and **await its child being
    /// reaped** (SIGTERM → bounded wait → SIGKILL, via the actor's `on_stop`,
    /// observed through the exit channel) before returning, so no tor lingers
    /// after `shutdown()` resolves. Consumers observe the posture channel closing.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            tx.send(()).ok();
        }
        self.task.await.ok();
    }
}

/// One incarnation's outcome, as seen by the supervisor loop.
enum IncarnationEnd {
    /// The incarnation died (before or after `Ready`) with this cause. For an
    /// `Exited(None)` the supervisor fills in the reaped [`TorExit`] during
    /// teardown; other causes ignore it.
    Failed(ServiceFailure),
    /// The caller asked the service to stop.
    Shutdown,
}

/// Bound on the **whole** teardown (the graceful-stop signal *and* the child's
/// reap wait) — the actor's own `SHUTDOWN_GRACE` is 5s, so this sits comfortably
/// above it. Not a `SupervisorPolicy` field on purpose: it is coupled to the
/// actor's grace window (it must exceed it), so exposing it as a free knob would
/// invite a `reap < grace` misconfiguration that gives up on a reap that was
/// about to succeed. On a genuine miss the loop proceeds; `kill_on_drop` and
/// `TAKEOWNERSHIP` remain reap backstops.
const REAP_TIMEOUT: Duration = Duration::from_secs(15);

/// The supervisor loop (§3c). Owns policy only; the incarnation actor owns
/// detection and fails fast.
async fn supervise(
    config: TorServiceConfig,
    posture: watch::Sender<TorPosture>,
    mut shutdown: oneshot::Receiver<()>,
) {
    // Consecutive-failure count since the last sustained `Ready` (see the §3c
    // while-alive reset in `drive_incarnation`).
    let mut attempt: u32 = 0;
    // Sticky alarm (§3c): set on threshold/trust; cleared only when an
    // incarnation holds `Ready` for `stable_reset` (in `drive_incarnation`).
    let mut degraded = false;

    loop {
        if !degraded {
            posture.send(TorPosture::Starting).ok();
        }

        // 1. The SP-T0c gate, re-run for THIS incarnation (a `VerifiedTorBinary`
        //    is point-in-time). Shutdown-responsive so a stop during the hash is
        //    observed promptly (E2).
        let resolved = tokio::select! {
            _ = &mut shutdown => return,
            r = config.binary.resolve() => r,
        };
        let verified = match resolved {
            Ok(v) => v,
            Err(failure) => {
                let delay = after_failure(
                    failure,
                    &config.policy,
                    &mut attempt,
                    &mut degraded,
                    &posture,
                );
                if wait_or_shutdown(delay, &mut shutdown).await {
                    return;
                }
                continue;
            }
        };

        // 2. Spawn the incarnation with a wired exit observer — teardown awaits
        //    it, both to reap the child before the next spawn reuses the
        //    DataDirectory and to surface the `TorExit` telemetry. Per-incarnation
        //    readiness watch (internal); the long-lived events sink is cloned in.
        let (exit_tx, exit_rx) = oneshot::channel();
        let (readiness, ready_rx) = BootstrapReadiness::new();
        let actor = TorControl::spawn(TorControlConfig {
            launch: TorLaunch::Managed(ManagedTor {
                tor_binary: verified,
                data_dir: config.data_dir.clone(),
                socks_port: SocksPort::Auto,
                disable_network: config.disable_network,
                exit_observer: Some(exit_tx),
            }),
            events: config.events.clone(),
            readiness,
        });

        // 3. Drive it: bootstrap → SOCKS discovery → onion publish → Ready →
        //    hold until death.
        let end = drive_incarnation(
            &actor,
            ready_rx,
            &config.policy,
            config.onion.as_ref(),
            &mut attempt,
            &mut degraded,
            &posture,
            &mut shutdown,
        )
        .await;

        // 4. Teardown: stop the actor and AWAIT the child's reap (via the exit
        //    channel) before the loop can respawn into the same DataDirectory —
        //    otherwise the still-exiting tor holds the lockfile and the next
        //    incarnation self-conflicts.
        let exit = stop_and_reap(&actor, exit_rx).await;

        match end {
            IncarnationEnd::Shutdown => return,
            IncarnationEnd::Failed(mut failure) => {
                // Attach the reaped exit to an unqualified death (`Killed` vs
                // `Reaped` is the operator signal); other causes keep their own.
                if let ServiceFailure::Exited(slot) = &mut failure {
                    *slot = exit;
                }
                let delay = after_failure(
                    failure,
                    &config.policy,
                    &mut attempt,
                    &mut degraded,
                    &posture,
                );
                if wait_or_shutdown(delay, &mut shutdown).await {
                    return;
                }
            }
        }
    }
}

/// Stop the incarnation and **await its child being reaped**, returning the exit
/// telemetry. The exit channel fires from `on_stop` *after* `TorChild::shutdown`
/// completes the SIGTERM→wait→SIGKILL→reap, so awaiting it guarantees no tor
/// lingers to lock the reused `DataDirectory` (and yields `Killed`/`Reaped`).
///
/// The **whole** sequence is bounded by [`REAP_TIMEOUT`], not just the reap wait:
/// `stop_gracefully` sends `Signal::Stop` on the actor's bounded (cap-64) mailbox,
/// and a wedged actor with a full mailbox would block that send — so bounding only
/// the reap could still hang `shutdown()`. On timeout, `kill()` aborts the actor
/// so it cannot linger (its `on_stop`/`kill_on_drop` still reap the child), and we
/// proceed best-effort.
async fn stop_and_reap(
    actor: &kameo::actor::ActorRef<TorControl>,
    exit_rx: oneshot::Receiver<TorExit>,
) -> Option<TorExit> {
    let teardown = async {
        actor.stop_gracefully().await.ok();
        exit_rx.await.ok()
    };
    match tokio::time::timeout(REAP_TIMEOUT, teardown).await {
        Ok(exit) => exit,
        Err(_timeout) => {
            // Teardown wedged past the grace budget — force the actor down so it
            // cannot linger; the child reap is backstopped by `kill_on_drop` /
            // `TAKEOWNERSHIP`.
            actor.kill();
            None
        }
    }
}

/// Apply §3c policy to a failure: bump the counter, classify, set the sticky
/// alarm, publish `Restarting`/`Degraded`, and return the retry delay. The
/// stability *reset* is not here — it happens live in `drive_incarnation` when an
/// incarnation holds `Ready` long enough.
fn after_failure(
    failure: ServiceFailure,
    policy: &SupervisorPolicy,
    attempt: &mut u32,
    degraded: &mut bool,
    posture: &watch::Sender<TorPosture>,
) -> Duration {
    *attempt += 1;
    let class = classify(&failure);
    *degraded = *degraded || is_degraded(policy, class, *attempt);
    let delay = retry_delay(policy, class, *attempt);
    let state = if *degraded {
        TorPosture::Degraded { last: failure }
    } else {
        TorPosture::Restarting {
            attempt: *attempt,
            retry_in: delay,
        }
    };
    posture.send(state).ok();
    delay
}

/// Sleep `delay`, returning `true` if the shutdown signal arrived instead.
async fn wait_or_shutdown(delay: Duration, shutdown: &mut oneshot::Receiver<()>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        _ = &mut *shutdown => true,
    }
}

/// Drive one incarnation from spawn to death: forward bootstrap telemetry,
/// discover the SOCKS endpoint, publish the configured onion (if any), then
/// hold until the actor dies, the bootstrap deadline fires, or the caller
/// shuts down. Clears the sticky alarm in place once this incarnation has
/// held `Ready` for `stable_reset`.
#[allow(clippy::too_many_arguments)]
async fn drive_incarnation(
    actor: &kameo::actor::ActorRef<TorControl>,
    mut ready_rx: watch::Receiver<BootstrapState>,
    policy: &SupervisorPolicy,
    onion: Option<&OnionServiceSpec>,
    attempt: &mut u32,
    degraded: &mut bool,
    posture: &watch::Sender<TorPosture>,
    shutdown: &mut oneshot::Receiver<()>,
) -> IncarnationEnd {
    let deadline = tokio::time::Instant::now() + policy.bootstrap_deadline;
    // Phase 1: to Ready (or death/deadline/shutdown).
    loop {
        tokio::select! {
            _ = &mut *shutdown => return IncarnationEnd::Shutdown,
            () = actor.wait_for_shutdown() => return IncarnationEnd::Failed(ServiceFailure::Exited(None)),
            () = tokio::time::sleep_until(deadline) => {
                return IncarnationEnd::Failed(ServiceFailure::BootstrapTimeout);
            }
            changed = ready_rx.changed() => {
                if changed.is_err() {
                    // Readiness sender gone with no terminal state — the actor is
                    // going down; the wait_for_shutdown arm will normally win, but
                    // don't spin on a closed channel.
                    return IncarnationEnd::Failed(ServiceFailure::Exited(None));
                }
                match ready_rx.borrow_and_update().clone() {
                    BootstrapState::Connecting { progress } => {
                        // Suppressed while degraded so a retry's bootstrap does not
                        // flap the alarm; the suppression lifts when a sustained
                        // Ready clears `degraded` below (§3c).
                        if !*degraded {
                            posture.send(TorPosture::Connecting { progress }).ok();
                        }
                    }
                    BootstrapState::Failed => {
                        return IncarnationEnd::Failed(ServiceFailure::Exited(None));
                    }
                    BootstrapState::Ready => break,
                }
            }
        }
    }

    // Phase 2: bootstrap done — discover the SocksPort-auto endpoint. Bounded and
    // shutdown-responsive: a wedged-but-alive control port here must not hang the
    // supervisor (and thus `shutdown()`) forever. A tor with no TCP SOCKS listener
    // is not usable whatever bootstrap says — a distinct diagnostic, and the
    // control error is preserved rather than collapsed into a generic exit.
    let reply = tokio::select! {
        _ = &mut *shutdown => return IncarnationEnd::Shutdown,
        () = tokio::time::sleep(policy.socks_discovery_deadline) => {
            return IncarnationEnd::Failed(ServiceFailure::Control(ControlError::Timeout));
        }
        r = actor.ask(Command::GetInfo(vec!["net/listeners/socks".to_owned()])) => r,
    };
    let socks_addr = match reply {
        Ok(reply) => match parse_socks_listeners(&reply) {
            Some(addr) => addr,
            None => return IncarnationEnd::Failed(ServiceFailure::NoSocksListener),
        },
        // Preserve the control-level cause when the command itself errored; an
        // actor-stopped/not-running send error is a death, not a control fault.
        Err(SendError::HandlerError(e)) => {
            return IncarnationEnd::Failed(ServiceFailure::Control(e))
        }
        Err(_) => return IncarnationEnd::Failed(ServiceFailure::Exited(None)),
    };
    // Phase 2b: publish the persona's onion service, if configured — on
    // EVERY incarnation, because a published onion dies with its control
    // connection (`Detach` is unrepresentable). Runs before the `Ready`
    // posture so `Ready` means the FULL serving posture is up: a persona
    // whose SOCKS works but whose onion did not publish is unreachable for
    // challenges, and publishing `Ready` for it would hide exactly the
    // failure the supervisor exists to surface.
    if let Some(spec) = onion {
        if let Err(end) = publish_onion(actor, spec, policy, shutdown).await {
            return end;
        }
    }

    // Usable now — published unconditionally (never hide a working transport
    // from SP-T1). While the degraded episode is still open, `recovering: true`
    // keeps the operator incident continuous instead of flapping it closed.
    posture
        .send(TorPosture::Ready {
            socks_addr,
            recovering: *degraded,
        })
        .ok();

    // Phase 3: hold until death or shutdown. Once this incarnation has held
    // `Ready` for `stable_reset`, forgive prior instability in place (§3c): clear
    // the sticky alarm and the counter so a later isolated failure restarts fresh
    // rather than re-firing `Degraded`, and republish `recovering: false` — the
    // alarm-clear edge. A tor that never reaches a sustained Ready (a genuine
    // flapper) never forgives — it keeps alarming.
    let reset_deadline = tokio::time::Instant::now() + policy.stable_reset;
    let mut forgiven = false;
    loop {
        tokio::select! {
            _ = &mut *shutdown => return IncarnationEnd::Shutdown,
            () = actor.wait_for_shutdown() => return IncarnationEnd::Failed(ServiceFailure::Exited(None)),
            () = tokio::time::sleep_until(reset_deadline), if !forgiven => {
                let was_degraded = *degraded;
                *attempt = 0;
                *degraded = false;
                forgiven = true;
                if was_degraded {
                    posture
                        .send(TorPosture::Ready {
                            socks_addr,
                            recovering: false,
                        })
                        .ok();
                }
            }
        }
    }
}

/// Publish `spec`'s onion service on the current incarnation: derive the
/// identity fresh from the seed, `ADD_ONION`, and **fail-stop unless tor
/// reports exactly the derived address** (the spike's published-vs-derived
/// cross-check, kept — a mismatch means the persona would serve at an
/// address it does not advertise). Teardown needs no pairing: the actor's
/// `on_stop` already `DEL_ONION`s everything it published.
async fn publish_onion(
    actor: &kameo::actor::ActorRef<TorControl>,
    spec: &OnionServiceSpec,
    policy: &SupervisorPolicy,
    shutdown: &mut oneshot::Receiver<()>,
) -> Result<(), IncarnationEnd> {
    let expected = spec.identity.service_id().clone();
    // `discard_pk` always: the key is re-mintable from the held identity on
    // demand, so tor has no reason to keep a copy it could be asked to hand
    // back.
    let request = AddOnion::new(spec.identity.mint_onion_key(), spec.port, spec.max_streams)
        .with_flags(OnionFlags { discard_pk: true })
        .with_pow(spec.pow);

    let onion_failed =
        |e: OnionPublishError| IncarnationEnd::Failed(ServiceFailure::OnionPublish(e));

    // Bounded and shutdown-responsive, exactly like SOCKS discovery:
    // ADD_ONION answers immediately (descriptor publication is async and
    // not awaited), so a stall is a wedged control port.
    let reply = tokio::select! {
        _ = &mut *shutdown => return Err(IncarnationEnd::Shutdown),
        () = tokio::time::sleep(policy.onion_publish_deadline) => {
            return Err(onion_failed(OnionPublishError::Control(ControlError::Timeout)));
        }
        r = actor.ask(Command::AddOnion(request)) => r,
    };
    let reply = match reply {
        Ok(reply) => reply,
        // Preserve the control-level cause; an actor-stopped send error is a
        // death, not a publish fault.
        Err(SendError::HandlerError(e)) => {
            return Err(onion_failed(OnionPublishError::Control(e)));
        }
        Err(_) => return Err(IncarnationEnd::Failed(ServiceFailure::Exited(None))),
    };
    evaluate_add_onion_reply(&reply, &expected).map_err(onion_failed)
}

/// Decide whether an `ADD_ONION` reply published the expected service — the
/// pure core of [`publish_onion`], so the non-250 / no-id / mismatch
/// fail-stops are unit-testable without a tor.
///
/// The mismatch check is the load-bearing one: tor returning 250 with a
/// *different* `ServiceID` than the address derived from the persona's key
/// means the service exists but not at the address the persona advertises —
/// unreachable to every witness, and invisible from the serving side. It
/// must fail the incarnation, not pass it.
fn evaluate_add_onion_reply(
    reply: &ControlReply,
    expected: &ServiceId,
) -> Result<(), OnionPublishError> {
    if reply.status() != 250 {
        return Err(OnionPublishError::Rejected {
            status: reply.status(),
        });
    }
    match parse_service_id(reply.lines()) {
        Some(published) if &published == expected => Ok(()),
        Some(published) => Err(OnionPublishError::ServiceIdMismatch {
            expected: expected.clone(),
            published,
        }),
        None => Err(OnionPublishError::NoServiceId),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_policy() -> SupervisorPolicy {
        SupervisorPolicy {
            backoff_base: Duration::from_millis(10),
            backoff_cap: Duration::from_millis(80),
            degrade_after: 3,
            stable_reset: Duration::from_millis(200),
            trust_retry: Duration::from_millis(20),
            bootstrap_deadline: Duration::from_secs(5),
            socks_discovery_deadline: Duration::from_secs(2),
            onion_publish_deadline: Duration::from_secs(2),
        }
    }

    // --- pure-core KATs ---

    #[test]
    fn transient_backoff_doubles_and_caps() {
        let p = tiny_policy();
        assert_eq!(
            retry_delay(&p, FailureClass::Transient, 1),
            Duration::from_millis(10)
        );
        assert_eq!(
            retry_delay(&p, FailureClass::Transient, 2),
            Duration::from_millis(20)
        );
        assert_eq!(
            retry_delay(&p, FailureClass::Transient, 3),
            Duration::from_millis(40)
        );
        // Capped from attempt 4 on — and stays capped arbitrarily far out
        // (the shift exponent is clamped, no overflow).
        assert_eq!(
            retry_delay(&p, FailureClass::Transient, 4),
            Duration::from_millis(80)
        );
        assert_eq!(
            retry_delay(&p, FailureClass::Transient, 1_000),
            Duration::from_millis(80)
        );
    }

    #[test]
    fn trust_failures_use_the_flat_slow_cadence() {
        let p = tiny_policy();
        for attempt in [1, 2, 100] {
            assert_eq!(retry_delay(&p, FailureClass::Trust, attempt), p.trust_retry);
        }
    }

    #[test]
    fn degraded_immediately_on_trust_at_threshold_on_transient() {
        let p = tiny_policy();
        assert!(is_degraded(&p, FailureClass::Trust, 1));
        assert!(!is_degraded(&p, FailureClass::Transient, 1));
        assert!(!is_degraded(&p, FailureClass::Transient, 2));
        assert!(is_degraded(&p, FailureClass::Transient, 3));
        assert!(is_degraded(&p, FailureClass::Transient, 4));
    }

    #[test]
    fn classify_maps_binary_to_trust_everything_else_transient() {
        assert_eq!(
            classify(&ServiceFailure::Binary(TorBinaryError::Unpinned)),
            FailureClass::Trust
        );
        assert_eq!(
            classify(&ServiceFailure::Control(ControlError::Io)),
            FailureClass::Transient
        );
        assert_eq!(
            classify(&ServiceFailure::BootstrapTimeout),
            FailureClass::Transient
        );
        assert_eq!(
            classify(&ServiceFailure::Exited(None)),
            FailureClass::Transient
        );
        assert_eq!(
            classify(&ServiceFailure::NoSocksListener),
            FailureClass::Transient
        );
        assert_eq!(
            classify(&ServiceFailure::Internal("gate task panicked".to_owned())),
            FailureClass::Transient
        );
        // A publish failure is transient: the persona should keep retrying to
        // get its onion up (a not-yet-published service is a coming slash),
        // never sit in a give-up state.
        assert_eq!(
            classify(&ServiceFailure::OnionPublish(
                OnionPublishError::NoServiceId
            )),
            FailureClass::Transient
        );
    }

    // --- onion publish decision (pure core; the live publish is on the
    // SHEKYL_TEST_TOR_BINARY lane, like the other tor-touching tests) ---

    /// A derived identity plus a reply that published it — the seed is
    /// arbitrary; what matters is that `expected` is the address the reply
    /// carries.
    fn identity_and_id() -> (crate::onion_identity::OnionIdentity, ServiceId) {
        let identity = crate::onion_identity::OnionIdentity::from_hs_id_seed(&[0x24u8; 32]);
        let id = identity.service_id().clone();
        (identity, id)
    }

    #[test]
    fn add_onion_reply_accepts_the_derived_address() {
        let (_identity, id) = identity_and_id();
        let reply = reply_from(&format!("ServiceID={}", id.as_str()));
        assert_eq!(evaluate_add_onion_reply(&reply, &id), Ok(()));
    }

    #[test]
    fn add_onion_reply_fail_stops_on_a_different_address() {
        // The load-bearing check: tor published *a* service, but not the
        // persona's. Publishing Ready here would advertise an address no
        // witness can reach.
        let (_identity, expected) = identity_and_id();
        let other = crate::onion_identity::OnionIdentity::from_hs_id_seed(&[0x99u8; 32])
            .service_id()
            .clone();
        let reply = reply_from(&format!("ServiceID={}", other.as_str()));
        assert_eq!(
            evaluate_add_onion_reply(&reply, &expected),
            Err(OnionPublishError::ServiceIdMismatch {
                expected,
                published: other,
            })
        );
    }

    #[test]
    fn add_onion_reply_without_a_service_id_is_a_publish_failure() {
        let (_identity, expected) = identity_and_id();
        // 250 OK but no ServiceID= line — a malformed success.
        let reply = reply_from("version=0.4.9.11");
        assert_eq!(
            evaluate_add_onion_reply(&reply, &expected),
            Err(OnionPublishError::NoServiceId)
        );
    }

    #[test]
    fn add_onion_non_250_carries_the_status() {
        // Build a 550 reply directly through the framer.
        let mut framer = crate::control::ReplyFramer::new();
        framer.push_bytes(b"550 Onion address collision\r\n");
        let reply = framer
            .next_reply()
            .expect("well-formed")
            .expect("one reply");
        let (_identity, expected) = identity_and_id();
        assert_eq!(
            evaluate_add_onion_reply(&reply, &expected),
            Err(OnionPublishError::Rejected { status: 550 })
        );
    }

    #[test]
    fn onion_spec_refuses_a_non_loopback_target() {
        let (identity, _id) = identity_and_id();
        // A routable target would make the endpoint reachable off the onion.
        assert!(OnionServiceSpec::new(identity, 80, "8.8.8.8:1234".parse().unwrap(), 8).is_none());
    }

    #[test]
    fn onion_spec_advertises_the_derived_address_and_defaults_pow_on() {
        let (identity, id) = identity_and_id();
        let spec = OnionServiceSpec::new(identity, 80, "127.0.0.1:9000".parse().unwrap(), 8)
            .expect("loopback target");
        assert_eq!(spec.service_id(), id, "advertised == derived, pre-Ready");
        assert_eq!(
            spec.pow,
            OnionPow::Enabled,
            "HiddenServicePoW on by default"
        );
    }

    // --- SOCKS-listener parse KATs (drive a reply through the real framer so
    // the KAT covers the actual ingress shape, mirroring the bootstrap KATs) ---

    fn reply_from(payload: &str) -> ControlReply {
        let mut framer = crate::control::ReplyFramer::new();
        framer.push_bytes(format!("250-{payload}\r\n250 OK\r\n").as_bytes());
        framer
            .next_reply()
            .expect("well-formed")
            .expect("one reply")
    }

    #[test]
    fn socks_listener_single_quoted_addr_parses() {
        let reply = reply_from(r#"net/listeners/socks="127.0.0.1:38581""#);
        assert_eq!(
            parse_socks_listeners(&reply),
            Some("127.0.0.1:38581".parse().unwrap())
        );
    }

    #[test]
    fn socks_listener_skips_unix_and_takes_first_tcp() {
        let reply = reply_from(
            r#"net/listeners/socks="unix:/run/tor/socks" "127.0.0.1:9050" "127.0.0.1:9051""#,
        );
        assert_eq!(
            parse_socks_listeners(&reply),
            Some("127.0.0.1:9050".parse().unwrap())
        );
    }

    /// Tor's getsockname()-fallback (exactly the auto-port path) can emit a
    /// single UNQUOTED address; discovery must still parse it rather than tear
    /// down a healthy tor.
    #[test]
    fn socks_listener_unquoted_addr_parses() {
        let reply = reply_from("net/listeners/socks=127.0.0.1:9050");
        assert_eq!(
            parse_socks_listeners(&reply),
            Some("127.0.0.1:9050".parse().unwrap())
        );
    }

    /// Each listener entry is escaped independently, so a MIXED list (a quoted
    /// unix entry + an unquoted TCP fallback entry) is possible — the uniform
    /// token pass must still find the TCP listener.
    #[test]
    fn socks_listener_mixed_quoted_and_unquoted_parses() {
        let reply = reply_from(r#"net/listeners/socks="unix:/run/tor/socks" 127.0.0.1:9050"#);
        assert_eq!(
            parse_socks_listeners(&reply),
            Some("127.0.0.1:9050".parse().unwrap())
        );
        // Quoted-unix-only genuinely has no TCP listener — still None.
        let none = reply_from(r#"net/listeners/socks="unix:/run/tor/socks""#);
        assert_eq!(parse_socks_listeners(&none), None);
    }

    #[test]
    fn socks_listener_empty_or_absent_is_none() {
        assert_eq!(
            parse_socks_listeners(&reply_from(r#"net/listeners/socks="#)),
            None
        );
        assert_eq!(parse_socks_listeners(&reply_from("version=0.4.9.11")), None);
    }

    // --- supervisor behavior, deterministic (no tor binary involved) ---

    /// A trust failure (the SP-T0c gate refusing) goes Degraded immediately and
    /// KEEPS RETRYING — the §3c no-give-up property, observed end-to-end
    /// through the real supervisor loop with the real gate.
    #[tokio::test]
    async fn trust_failure_degrades_loudly_and_retries_forever() {
        let dir = tempfile::tempdir().unwrap();
        // A real file that can never match CURRENT_PIN: the gate itself
        // produces the HashMismatch (no mocks).
        let bogus = dir.path().join("not-tor");
        std::fs::write(&bogus, b"definitely not the pinned tor").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bogus, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let service = TorService::spawn(TorServiceConfig {
            binary: TorBinarySource::At(bogus),
            data_dir: dir.path().join("data"),
            events: EventSink::new(tx),
            policy: tiny_policy(),
            disable_network: true,
            onion: None,
        });
        let mut posture = service.posture();

        // First failure: Degraded immediately (trust class), carrying the
        // gate's verdict.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut degraded_seen = 0u32;
        while degraded_seen < 3 {
            tokio::select! {
                changed = posture.changed() => {
                    changed.expect("supervisor alive");
                    let state = posture.borrow_and_update().clone();
                    if let TorPosture::Degraded { last } = state {
                        assert!(
                            matches!(
                                last,
                                ServiceFailure::Binary(
                                    TorBinaryError::HashMismatch { .. } | TorBinaryError::Unpinned
                                )
                            ),
                            "degraded must carry the gate's verdict, got {last:?}"
                        );
                        degraded_seen += 1;
                    }
                }
                () = tokio::time::sleep_until(deadline) => {
                    panic!("saw only {degraded_seen} Degraded updates before the deadline");
                }
            }
        }
        // 3 successive Degraded publications = it retried after alarming (and
        // never gave up); trust cadence, not fast-spin, is covered by the
        // pure-core KATs.
        service.shutdown().await;
    }

    /// Clean shutdown ends supervision promptly and closes the posture channel
    /// (the "stopped" signal is the close, not a state).
    #[tokio::test]
    async fn shutdown_closes_the_posture_channel() {
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("not-tor");
        std::fs::write(&bogus, b"x").unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let service = TorService::spawn(TorServiceConfig {
            binary: TorBinarySource::At(bogus),
            data_dir: dir.path().join("data"),
            events: EventSink::new(tx),
            policy: tiny_policy(),
            disable_network: true,
            onion: None,
        });
        let mut posture = service.posture();
        service.shutdown().await;
        // Drain any buffered states; the channel must then report closed.
        while posture.changed().await.is_ok() {}
    }
}

/// Live supervision tests — a real tor, real bootstrap, a real `SIGKILL`.
/// `#[ignore]`-gated off the unit lane; hard-fail (never skip) when run.
#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::test_support::tor_binary;

    /// Await a posture state matching `pred`, panicking after `secs`. The value
    /// is cloned from the SAME borrow the predicate checked — a second borrow
    /// could observe a newer state that no longer matches.
    async fn await_posture<F: Fn(&TorPosture) -> bool>(
        rx: &mut watch::Receiver<TorPosture>,
        secs: u64,
        what: &str,
        pred: F,
    ) -> TorPosture {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let current = rx.borrow_and_update().clone();
            if pred(&current) {
                return current;
            }
            tokio::select! {
                changed = rx.changed() => { changed.unwrap_or_else(|_| panic!("supervisor died awaiting {what}")); }
                () = tokio::time::sleep_until(deadline) => panic!("timed out awaiting {what}"),
            }
        }
    }

    /// The §3c core property end-to-end: a managed tor bootstraps to
    /// `Ready{socks_addr}`, is murdered with SIGKILL (the crash the supervisor
    /// exists for), and the service — without any caller action — republishes
    /// `Restarting` and then a fresh `Ready`, after which a clean shutdown
    /// leaves no orphan. The SOCKS endpoint is read from the posture channel
    /// both times (the consumers-never-cache contract exercised for real).
    // Unix-only: the crash is delivered with `pkill -9` (deliberately an
    // *external* SIGKILL with no handle — the shape of a real crash; exposing
    // the child pid just for the test would soften the scenario). The
    // integration lane is Linux; off Unix the test does not exist, so the crate
    // stays cross-platform-buildable by construction.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY (bootstraps twice, network)"]
    async fn crash_is_survived_respawn_reaches_ready_again() {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().join("data");
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let service = TorService::spawn(TorServiceConfig {
            binary: TorBinarySource::UncheckedForTest(tor_binary()),
            data_dir: data_dir.clone(),
            events: EventSink::new(tx),
            policy: SupervisorPolicy {
                // Fast retries for the test; production defaults elsewhere.
                backoff_base: Duration::from_millis(100),
                backoff_cap: Duration::from_secs(2),
                ..SupervisorPolicy::default()
            },
            disable_network: false,
            onion: None,
        });
        let mut posture = service.posture();

        // First life: bootstrap → Ready with a discovered SocksPort-auto addr.
        let first = await_posture(&mut posture, 120, "first Ready", |p| {
            matches!(p, TorPosture::Ready { .. })
        })
        .await;
        let TorPosture::Ready {
            socks_addr: first_addr,
            recovering,
        } = first
        else {
            unreachable!()
        };
        assert!(
            first_addr.ip().is_loopback(),
            "SocksPort auto must bind loopback"
        );
        // A clean first launch is not a degraded-episode recovery.
        assert!(!recovering, "first Ready must not be flagged recovering");
        // The safe accessor returns the same live endpoint while Ready.
        assert_eq!(service.current_socks(), Some(first_addr));

        // Murder the incarnation the way a real crash would: SIGKILL, no
        // SIGTERM, no control-connection close. The unique DataDirectory arg
        // identifies exactly our child.
        let killed = std::process::Command::new("pkill")
            .arg("-9")
            .arg("-f")
            .arg(data_dir.to_str().expect("utf8 tmpdir"))
            .status()
            .expect("pkill runs");
        assert!(killed.success(), "pkill must find the managed tor");

        // The supervisor must notice and retry on its own...
        await_posture(&mut posture, 30, "Restarting after SIGKILL", |p| {
            matches!(p, TorPosture::Restarting { .. } | TorPosture::Starting)
        })
        .await;
        // ...and reach Ready again (a fresh incarnation, fresh endpoint).
        let second = await_posture(&mut posture, 120, "second Ready", |p| {
            matches!(p, TorPosture::Ready { .. })
        })
        .await;
        let TorPosture::Ready {
            socks_addr: second_addr,
            ..
        } = second
        else {
            unreachable!()
        };
        assert!(second_addr.ip().is_loopback());

        // Clean shutdown; the posture channel closes and nothing is orphaned
        // (asserted by the lane's zero-orphan check after the run).
        service.shutdown().await;
        while posture.changed().await.is_ok() {}
    }

    /// The onion is republished on **every** incarnation, not just the first —
    /// the reviewer's concern made a test: a persona that publishes once and
    /// then serves until its first Tor restart, after which it silently stops,
    /// is a slow slash. With an onion configured, `Ready` *means the onion is
    /// published at the derived address* (the publish runs before `Ready` and
    /// fail-stops on any other outcome), so reaching `Ready` again after a
    /// SIGKILL is exactly the proof that the second incarnation republished.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY (bootstraps twice, network)"]
    async fn onion_is_republished_on_every_incarnation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().join("data");
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        // A loopback target for the onion's virtual port — it need not be
        // listening for ADD_ONION to succeed; the publish is what we test.
        let target = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind loopback target")
            .local_addr()
            .expect("local addr");
        let identity = crate::onion_identity::OnionIdentity::from_hs_id_seed(&[0x5cu8; 32]);
        // The address the persona advertises is known before spawn (the caller
        // holds it from the spec), so witnesses can be told where to connect
        // without waiting on any posture.
        let spec = OnionServiceSpec::new(identity, 80, target, 8).expect("loopback spec");
        let _advertised = spec.service_id();

        let service = TorService::spawn(TorServiceConfig {
            binary: TorBinarySource::UncheckedForTest(tor_binary()),
            data_dir: data_dir.clone(),
            events: EventSink::new(tx),
            policy: SupervisorPolicy {
                backoff_base: Duration::from_millis(100),
                backoff_cap: Duration::from_secs(2),
                ..SupervisorPolicy::default()
            },
            disable_network: false,
            onion: Some(spec),
        });
        let mut posture = service.posture();

        // First life: Ready is only published after the onion published at
        // `expected` (a mismatch or rejection would fail the incarnation).
        await_posture(&mut posture, 120, "first Ready (onion published)", |p| {
            matches!(p, TorPosture::Ready { .. })
        })
        .await;

        // Crash it; the republish must happen again on the fresh incarnation.
        let killed = std::process::Command::new("pkill")
            .arg("-9")
            .arg("-f")
            .arg(data_dir.to_str().expect("utf8 tmpdir"))
            .status()
            .expect("pkill runs");
        assert!(killed.success(), "pkill must find the managed tor");

        await_posture(&mut posture, 30, "Restarting after SIGKILL", |p| {
            matches!(p, TorPosture::Restarting { .. } | TorPosture::Starting)
        })
        .await;
        // Second Ready ⇒ the onion republished on the second incarnation.
        await_posture(&mut posture, 120, "second Ready (onion republished)", |p| {
            matches!(p, TorPosture::Ready { .. })
        })
        .await;

        service.shutdown().await;
        while posture.changed().await.is_ok() {}
    }

    /// The degraded-episode continuity (§3c, review round 3): a crash trips the
    /// sticky alarm, the *next* incarnation is usable-but-still-in-episode
    /// (`Ready { recovering: true }`), and once it holds `Ready` for `stable_reset`
    /// the alarm clears in place (`Ready { recovering: false }`). This is the one
    /// path the pure-core KATs can't reach — it needs a real incarnation to reach
    /// `Ready`, fail, then recover.
    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY (bootstraps twice, network)"]
    async fn degraded_episode_clears_only_after_sustained_ready() {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().join("data");
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let service = TorService::spawn(TorServiceConfig {
            binary: TorBinarySource::UncheckedForTest(tor_binary()),
            data_dir: data_dir.clone(),
            events: EventSink::new(tx),
            policy: SupervisorPolicy {
                // One failure trips the alarm; a 5s sustained Ready clears it.
                degrade_after: 1,
                stable_reset: Duration::from_secs(5),
                backoff_base: Duration::from_millis(200),
                backoff_cap: Duration::from_secs(2),
                ..SupervisorPolicy::default()
            },
            disable_network: false,
            onion: None,
        });
        let mut posture = service.posture();

        // First Ready: a clean launch is not a recovery.
        let first = await_posture(&mut posture, 120, "first Ready", |p| {
            matches!(p, TorPosture::Ready { .. })
        })
        .await;
        assert!(
            matches!(
                first,
                TorPosture::Ready {
                    recovering: false,
                    ..
                }
            ),
            "first Ready must not be recovering, got {first:?}"
        );

        // Crash it → one failure → degrade_after=1 trips the sticky alarm.
        let killed = std::process::Command::new("pkill")
            .arg("-9")
            .arg("-f")
            .arg(data_dir.to_str().expect("utf8 tmpdir"))
            .status()
            .expect("pkill runs");
        assert!(killed.success(), "pkill must find the managed tor");

        // The crash must actually trip the alarm (degrade_after=1) — assert the
        // `Degraded` edge before the recovery, so the test can't pass on a
        // `recovering` flag set without the episode ever opening.
        await_posture(&mut posture, 30, "Degraded after crash", |p| {
            matches!(p, TorPosture::Degraded { .. })
        })
        .await;

        // The next incarnation is usable, but the episode is still open.
        await_posture(&mut posture, 120, "Ready{recovering:true}", |p| {
            matches!(
                p,
                TorPosture::Ready {
                    recovering: true,
                    ..
                }
            )
        })
        .await;

        // Holding Ready for `stable_reset` clears the alarm in place.
        await_posture(&mut posture, 30, "Ready{recovering:false}", |p| {
            matches!(
                p,
                TorPosture::Ready {
                    recovering: false,
                    ..
                }
            )
        })
        .await;

        service.shutdown().await;
        while posture.changed().await.is_ok() {}
    }

    /// The reap-race guard: a bootstrap-timeout restart reuses the same
    /// DataDirectory while the previous (still-alive, network-disabled) tor is
    /// being torn down. If teardown did not AWAIT the child's reap, the respawn
    /// would hit the still-held DataDirectory lock and fail to start — never
    /// reaching `Connecting` on the second incarnation. So: drive at least two
    /// incarnations through a short bootstrap deadline with `DisableNetwork` (tor
    /// opens its control port and reports progress but never bootstraps), and
    /// require both to reach `Connecting` — proof each respawn got a clean,
    /// unlocked DataDirectory.
    #[tokio::test]
    #[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY (spawns tor repeatedly)"]
    async fn bootstrap_timeout_restart_does_not_self_lock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let service = TorService::spawn(TorServiceConfig {
            binary: TorBinarySource::UncheckedForTest(tor_binary()),
            data_dir: dir.path().join("data"),
            events: EventSink::new(tx),
            policy: SupervisorPolicy {
                // Short deadline so a network-disabled tor times out fast; short
                // backoff so a respawn would collide with the exiting child if the
                // reap were not awaited (SHUTDOWN_GRACE is 5s).
                bootstrap_deadline: Duration::from_secs(4),
                backoff_base: Duration::from_millis(200),
                backoff_cap: Duration::from_secs(1),
                ..SupervisorPolicy::default()
            },
            // Never bootstraps → every incarnation hits the bootstrap deadline →
            // teardown + respawn into the same DataDirectory.
            disable_network: true,
            onion: None,
        });
        let mut posture = service.posture();

        // Two separate incarnations must each reach Connecting — i.e. tor
        // actually started (control port up), which a self-inflicted lock
        // conflict would have prevented (that surfaces as an Exited/Spawn
        // failure with no Connecting).
        for nth in ["first", "second"] {
            await_posture(&mut posture, 60, &format!("{nth} Connecting"), |p| {
                matches!(p, TorPosture::Connecting { .. })
            })
            .await;
            // Then leave Connecting (deadline fires → Restarting), so the next
            // iteration observes a fresh Connecting rather than the same one.
            await_posture(&mut posture, 60, &format!("{nth} Restarting"), |p| {
                matches!(p, TorPosture::Restarting { .. } | TorPosture::Starting)
            })
            .await;
        }

        service.shutdown().await;
        while posture.changed().await.is_ok() {}
    }
}
