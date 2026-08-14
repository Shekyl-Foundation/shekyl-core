// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SH-2b-2 — the persona serving host's **lifecycle**: what starts it, when,
//! what keeps its serve-set following the chain, and what takes it down.
//!
//! `shekyl-p-host` composes the loopback listener, the onion, and the pin
//! witness into one object with one lifetime (`ARCHIVAL_CHALLENGE_MECHANISM.md`
//! §9.7). It has no opinion about *when* that lifetime begins, and nothing
//! constructed one until this module. What is here is the three things the host
//! deliberately does not decide.
//!
//! # 1. The launch is scheduled independently of wallet open (gate-6 §10.9)
//!
//! §10.9's restore-flow bullet: *"On wallet restore, `StakeEngine` **must not
//! auto-launch `P`'s HS in lockstep with `LedgerEngine`'s principal sync**."*
//! Co-timing principal-sync with `.onion` reanimation is a correlation that
//! `p_slot` rotation does not foreclose — it changes the address, not the
//! timing. So the host does not start inside the open path beside the P-scan;
//! the task waits a drawn standoff first
//! ([`draw_serving_launch_delay`](super::super::stake_timing::draw_serving_launch_delay)).
//!
//! **What that buys is the interval, not the sequence** — a host cannot start
//! before there is a serve-set to pin, so `principal-sync → HS-up` is forced by
//! data dependency and is not concealed. See the window constant for the full
//! statement, including why the window is sized against *open frequency*.
//!
//! # 2. Refresh runs on its own cadence, and arms its own tripwire
//!
//! The plan of record said "P-scan-driven refresh", and this drives refresh on
//! an independent timer at the same cadence instead. The reason is the
//! **arming predicate**, not convenience. `StalenessBound` is armed only once
//! the wallet is caught up — during catch-up the wallet ingests far faster than
//! the steady-state rate the bound is sized for, so an armed check fires on
//! every healthy catch-up. Deciding that needs both the chain height and the
//! wallet's ingest height, and **both are already on the witness**:
//! `ServeSet::as_of_height` is the chain height the bond record was read at, and
//! `ServingReader::sync_tip_height` is what this wallet has ingested. Threading
//! a host handle into the sweep would buy a tip the witness already carries, at
//! the cost of shared mutable state for a host that does not exist during the
//! launch standoff. Recorded as a divergence rather than taken silently.
//!
//! (SH-2a's warning against subtracting those two heights is about the
//! *staleness clock*, which must be one clock read twice. This is a different
//! question — "is the wallet caught up" — and comparing the wallet's ingest to
//! the chain is exactly what that means.)
//!
//! # 3. Every condition reports through OA-1, and one of them is terminal
//!
//! [`Staleness`] and the pin report are projected onto the operator alarm board.
//! Four of the five conditions are recoverable and land as
//! `AlarmLifetime::Episode`. The fifth — leaf bytes already pruned — is
//! irreversible, and it is the reason the board needed a latch. It does **not**
//! need durable acknowledgment, because it re-derives at every start more
//! loudly than an alarm: `PinnedServeSet::acquire` refuses outright, so the
//! host does not start at all.

use std::sync::Arc;
use std::time::Duration;

use shekyl_operator_alarm::serve_set::{apply as report, ServeSetObservation};
use shekyl_operator_alarm::OperatorAlarms;
use shekyl_p_host::{
    HostError, PersonaServing, PersonaServingHost, PinError, PinnedServeSet, ServeSetPinner,
    StalenessBound,
};
use shekyl_tor::service::TorServiceConfig;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::super::stake_timing::{
    draw_serving_launch_delay, OsRngGapAdapter, DEFAULT_SERVING_LAUNCH_WINDOW,
};

/// How many refresh cadences of ingest may pass before the serve-set is stale.
///
/// The bound is `k × cadence` worth of ingest, armed only in steady state (see
/// the module docs). `k = 10` leaves nine missed refreshes of slack before the
/// tripwire fires: a bound of one would alarm on any single slow tick, and a
/// false alarm is how a tripwire gets ignored.
pub(crate) const STALENESS_BOUND_REFRESHES: u64 = 10;

/// How far the wallet's ingest may trail the chain and still count as caught up.
///
/// Not zero: the wallet is always a little behind a live chain, and requiring
/// exact equality would leave the tripwire disarmed forever. One archival reorg
/// depth is the natural unit — below it the wallet is inside the window the
/// chain itself treats as unsettled.
pub(crate) const CAUGHT_UP_SLACK_BLOCKS: u64 = 64;

/// Virtual port the persona's onion publishes — the port a witness dials.
///
/// 80 because it is the onion-service convention and carries no information: a
/// non-default port is a per-operator distinguisher on an address whose whole
/// purpose is to be indistinguishable. Not a setting, for that reason.
pub(crate) const SERVING_VIRTUAL_PORT: u16 = 80;

/// Per-rendezvous-circuit stream cap. **Carried placeholder (SPIKE-PIN-1), not
/// a derivation** — the W₂ rig chooses it, and the value here is the one the
/// composition tests already use. Named rather than inlined so the rig's answer
/// lands in one place.
pub(crate) const SERVING_MAX_STREAMS: u16 = 8;

/// Timeout for the claim-source round trip the serve-set is derived from.
/// Matches the loopback claim transport the regtest composition builds.
pub(crate) const CLAIM_SOURCE_TIMEOUT: Duration = Duration::from_secs(10);

/// Serving lifecycle settings. Parameterized rather than hardcoded so tests can
/// collapse the standoff and the cadence; production takes
/// [`ServingConfig::production`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct ServingConfig {
    /// Upper bound of the §10.9 launch standoff draw.
    pub(crate) launch_window: Duration,
    /// How often the serve-set is re-pinned against the bond record.
    pub(crate) refresh_cadence: Duration,
    /// How many blocks of local ingest may pass before the set reads stale.
    pub(crate) staleness_bound: StalenessBound,
}

impl ServingConfig {
    /// Production settings: the §10.9 standoff window, refreshing at the P-scan
    /// sweep cadence so the serve-set follows the chain at the rate the wallet
    /// learns about it.
    ///
    /// The staleness bound is **derived, not picked**: it is
    /// [`STALENESS_BOUND_REFRESHES`] refresh cadences expressed in blocks, which
    /// needs the chain's block target. That is taken as an argument rather than
    /// read from a constant here, the same shape
    /// [`WatchdogConfig::from_block_target`](super::super::submit_watchdog) uses
    /// for the same reason — a wallet-side horizon in blocks is a function of a
    /// consensus parameter, and burying that parameter in this module would
    /// fork it.
    ///
    /// # Panics
    ///
    /// If `block_target_seconds` is zero — a zero block target makes
    /// "blocks per cadence" undefined, and silently substituting a default
    /// would hide a mis-wired constant behind a plausible-looking bound.
    pub(crate) fn production(sweep_cadence: Duration, block_target_seconds: u64) -> Self {
        assert!(block_target_seconds > 0, "block target must be positive");
        // Round up: a cadence shorter than one block still advances the wallet
        // past at least one block boundary sometimes, and a floor of zero would
        // make the bound zero — alarming on every tick.
        let blocks_per_cadence = sweep_cadence
            .as_secs()
            .div_ceil(block_target_seconds)
            .max(1);
        Self {
            launch_window: DEFAULT_SERVING_LAUNCH_WINDOW,
            refresh_cadence: sweep_cadence,
            staleness_bound: StalenessBound::blocks(
                STALENESS_BOUND_REFRESHES.saturating_mul(blocks_per_cadence),
            ),
        }
    }
}

/// A running serving lifecycle: the cancel token plus the task's join handle.
///
/// Deliberately the same shape as `PScanHandle` — the embedder parks it for the
/// wallet's open lifetime and shuts it down on close. The token fires on both
/// [`cancel`](Self::cancel) and `Drop`, so a dropped handle winds the host down
/// (stopping tor before the listener) rather than leaking a published onion
/// pointing at a dead port.
pub struct ServingHandle {
    cancel_token: CancellationToken,
    join: Option<JoinHandle<()>>,
}

impl ServingHandle {
    /// Fire the cancel token. Idempotent. The task observes it at its next
    /// await point — including *during* the launch standoff, so a wallet closed
    /// inside the standoff window never publishes at all.
    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }

    /// Cancel and await the task's exit, including the host's ordered teardown.
    ///
    /// Awaiting matters here more than it does for the P-scan: shutdown stops
    /// tor *before* the listener (§9.7 item 4), and returning before that
    /// completes would leave a published descriptor naming a port that is
    /// already gone.
    pub async fn shutdown(mut self) {
        self.cancel_token.cancel();
        if let Some(join) = self.join.take() {
            let _outcome = join.await;
        }
    }
}

impl Drop for ServingHandle {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

/// Spawn the serving lifecycle. Returns immediately; the host itself starts
/// after the §10.9 standoff.
pub(crate) fn spawn_serving_task<P>(
    tor: TorServiceConfig,
    serving: PersonaServing,
    pinner: P,
    alarms: Arc<OperatorAlarms>,
    config: ServingConfig,
) -> ServingHandle
where
    P: ServeSetPinner + Send + Sync + 'static,
{
    let cancel_token = CancellationToken::new();
    let join = tokio::spawn(run_serving_task(
        tor,
        serving,
        pinner,
        alarms,
        config,
        cancel_token.clone(),
    ));
    ServingHandle {
        cancel_token,
        join: Some(join),
    }
}

async fn run_serving_task<P>(
    tor: TorServiceConfig,
    serving: PersonaServing,
    pinner: P,
    alarms: Arc<OperatorAlarms>,
    config: ServingConfig,
    cancel: CancellationToken,
) where
    P: ServeSetPinner + Send + Sync + 'static,
{
    // The serve-set condition is watched from the moment the task exists, so a
    // wallet sitting in the launch standoff reads "not serving yet" rather than
    // reading nothing at all.
    report(&alarms, ServeSetObservation::NotServing);

    let delay = draw_serving_launch_delay(config.launch_window, &mut OsRngGapAdapter);
    tokio::select! {
        biased;
        () = cancel.cancelled() => return,
        () = tokio::time::sleep(delay) => {}
    }

    // `start_host` has already reported why it failed, and every reason it
    // gives up on is one this task cannot retry (its inputs are consumed).
    let Some(host) = start_host(tor, serving, pinner, &alarms).await else {
        return;
    };

    // OA-1's tor producer attaches to *this* host's supervisor, so the transport
    // conditions are on the board for as long as the host is.
    let posture = shekyl_operator_alarm::tor_posture::spawn_tor_posture_translator(
        host.posture(),
        Arc::clone(&alarms),
    );

    let bound = config.staleness_bound;
    let mut ticker = tokio::time::interval(config.refresh_cadence);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick completes immediately; the host was just started and its
    // pins are fresh, so skip straight to the cadence.
    ticker.tick().await;

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            _ = ticker.tick() => {}
        }

        report(&alarms, observe(&host, bound).await);
    }

    // Ordered teardown: tor first, then the listener (§9.7 item 4).
    host.shutdown().await;
    posture.abort();
    // Nothing is watched once the host is gone. Disarm rather than clear: a
    // closed wallet is not a healthy serve-set, and a live pruned-bytes report
    // stays live because nothing observed it fixed.
    report(&alarms, ServeSetObservation::NotServing);
}

/// Run one refresh and read the tripwire, producing the observation the alarm
/// board consumes. Every arm is a reading, never a decision — the mapping from
/// readings to alarms is `shekyl-operator-alarm`'s, so this function cannot
/// disagree with the tor producer about what an alarm means.
async fn observe<P>(host: &PersonaServingHost<P>, bound: StalenessBound) -> ServeSetObservation
where
    P: ServeSetPinner,
{
    if let Err(e) = host.refresh().await {
        return ServeSetObservation::RefreshFailed {
            already_pruned: match e {
                PinError::MembersAlreadyPruned { shard_ids } => Some(count(shard_ids.len())),
                _ => None,
            },
        };
    }

    let pinned = host.pinned_serve_set();
    match caught_up(&pinned) {
        Some(false) => return ServeSetObservation::CatchingUp,
        // The store could not be read at all. That is a refresh-side fault, not
        // a reason to report health.
        None => {
            return ServeSetObservation::RefreshFailed {
                already_pruned: None,
            }
        }
        Some(true) => {}
    }

    match host.staleness(bound) {
        Ok(staleness) => ServeSetObservation::Refreshed {
            staleness,
            already_pruned: count(pinned.already_pruned().len()),
        },
        Err(_) => ServeSetObservation::RefreshFailed {
            already_pruned: None,
        },
    }
}

/// Saturating member count — the board's vocabulary is `u32`, and a serve-set
/// with more than `u32::MAX` terminally-pruned members is a store that has
/// bigger problems than the width of this counter.
fn count(members: usize) -> u32 {
    u32::try_from(members).unwrap_or(u32::MAX)
}

/// Start the host, reporting whichever condition prevented it.
///
/// **One attempt, deliberately.** `PersonaServingHost::start` consumes its
/// inputs by value — the `TorServiceConfig` carries an `EventSink` and the
/// wallet-private data-dir path — so a retry would have to rebuild them, and
/// this task is not the thing that knows how. A failed start therefore ends the
/// serving lifecycle for this session with the reason on the board, and the
/// remedy is a wallet reopen. Stated rather than hidden behind a loop that
/// could not work: the alternative is a retry that silently rebuilds a
/// *different* config from the one the wallet was opened with.
async fn start_host<P>(
    tor: TorServiceConfig,
    serving: PersonaServing,
    pinner: P,
    alarms: &OperatorAlarms,
) -> Option<PersonaServingHost<P>>
where
    P: ServeSetPinner + Send + Sync + 'static,
{
    match PersonaServingHost::start(tor, serving, pinner).await {
        Ok(host) => Some(host),
        Err(HostError::Pin(PinError::MembersAlreadyPruned { shard_ids })) => {
            // Terminal by the store's own contract: chain replay, not retry.
            // Latched, so it outlives the task that reported it.
            report(
                alarms,
                ServeSetObservation::RefreshFailed {
                    already_pruned: Some(count(shard_ids.len())),
                },
            );
            None
        }
        Err(_) => {
            // A dead curve-tree actor, an unreachable daemon, a refused
            // loopback bind. Nothing serves until the operator acts, and the
            // board is where they find out.
            report(
                alarms,
                ServeSetObservation::RefreshFailed {
                    already_pruned: None,
                },
            );
            None
        }
    }
}

/// Whether the wallet has ingested close enough to the chain for the staleness
/// bound to mean anything. `None` when the store could not be read.
///
/// Both operands come off the witness: `as_of_height` is the chain height the
/// bond record was read at, `sync_tip_height` is what this wallet has ingested.
fn caught_up(pinned: &PinnedServeSet) -> Option<bool> {
    let chain = pinned.serve_set().as_of_height().0;
    let ingested = pinned.reader().sync_tip_height().ok()?.0;
    Some(chain.saturating_sub(ingested) <= CAUGHT_UP_SLACK_BLOCKS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bound is derived from the cadence and the chain's block target, not
    /// picked — so a change to either moves it, and a mis-wired zero target is
    /// a loud panic rather than a plausible-looking number.
    #[test]
    fn the_staleness_bound_is_derived_from_cadence_and_block_target() {
        // Ten refreshes at a cadence of two blocks' worth of wall clock.
        let cfg = ServingConfig::production(Duration::from_secs(240), 120);
        assert_eq!(
            cfg.staleness_bound.get(),
            STALENESS_BOUND_REFRESHES * 2,
            "k refreshes x blocks-per-cadence",
        );

        // A cadence shorter than one block still bounds at one block per
        // refresh: a floor of zero would alarm on every tick.
        let fast = ServingConfig::production(Duration::from_secs(5), 120);
        assert_eq!(fast.staleness_bound.get(), STALENESS_BOUND_REFRESHES);
    }

    #[test]
    #[should_panic(expected = "block target must be positive")]
    fn a_zero_block_target_is_refused_rather_than_defaulted() {
        let _ = ServingConfig::production(Duration::from_secs(60), 0);
    }

    #[test]
    fn production_carries_the_gate6_launch_window() {
        let cfg = ServingConfig::production(Duration::from_secs(60), 120);
        assert_eq!(
            cfg.launch_window, DEFAULT_SERVING_LAUNCH_WINDOW,
            "the §10.9 standoff is not something a caller opts into",
        );
        assert!(
            cfg.launch_window > Duration::ZERO,
            "a zero standoff would co-time the onion with principal sync",
        );
    }
}

// ---------------------------------------------------------------------------
// Assembling `TorServiceConfig` — the rulings, and why most fields are not
// settings
// ---------------------------------------------------------------------------

/// Why a staker could not be given a Tor configuration.
///
/// **Fail-closed, mirroring `wrap_and_start_pscan`.** A staker whose serving
/// path cannot be configured must not open, for the same reason a staker whose
/// P-scan state will not load must not open: holdings that are not served
/// accrue misses and end in a slash, and the operator cannot see it happening.
/// Opening with serving dark is opening into an accruing loss.
#[derive(Debug)]
pub enum TorConfigError {
    /// The derived `<P>.tor/` directory could not be created.
    DataDirUnusable {
        /// The path that could not be established.
        path: std::path::PathBuf,
        /// The underlying I/O failure.
        source: std::io::Error,
    },
    /// The directory exists but is group- or world-writable, so another user on
    /// this machine can tamper with the entry-guard state. DQ-T0.7 requires a
    /// wallet-controlled, non-world-writable placement; a directory that fails
    /// that is refused rather than tightened silently, because the wallet did
    /// not create it and does not know what else is relying on its mode.
    #[cfg(unix)]
    DataDirTooPermissive {
        /// The offending directory.
        path: std::path::PathBuf,
        /// Its current mode.
        mode: u32,
    },
}

impl std::fmt::Display for TorConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DataDirUnusable { path, source } => write!(
                f,
                "the wallet's Tor data directory {} could not be created: {source}",
                path.display()
            ),
            #[cfg(unix)]
            Self::DataDirTooPermissive { path, mode } => write!(
                f,
                "the wallet's Tor data directory {} is mode {mode:o}: it must not be \
                 group- or world-writable, because it holds this wallet's entry-guard \
                 identity",
                path.display()
            ),
        }
    }
}

impl std::error::Error for TorConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DataDirUnusable { source, .. } => Some(source),
            #[cfg(unix)]
            Self::DataDirTooPermissive { .. } => None,
        }
    }
}

/// Assemble this wallet's [`TorServiceConfig`].
///
/// # Four rulings, recorded here because this is where they are visible
///
/// `TorServiceConfig` has public fields, which makes it look like a settings
/// struct. It is not, and the organizing principle is that **every knob is a
/// fingerprint** — DQ-T0.7's argument about data-directory rotation (deviation
/// from defaults is itself a signature) generalizes to the whole surface. So the
/// default answer is derive-or-inherit, and exposure is justified only where the
/// operator holds information the wallet cannot.
///
/// 1. **`data_dir` is derived, never configured** —
///    [`tor_data_dir_from`](shekyl_engine_file::paths::tor_data_dir_from)
///    gives DQ-T0.7's three placement requirements by construction, and
///    forecloses the cross-wallet guard linkage a shared directory would create.
/// 2. **`binary` is discovery by default**, with one override
///    ([`DevicePrefs::tor_binary_path`]) — the single item where the operator
///    knows something the wallet cannot derive. The hash gate runs either way.
/// 3. **`policy` gets no surface at all.** Backoff curve, `degrade_after`,
///    `bootstrap_deadline` and `trust_retry` are all observable in retry
///    timing, so an operator-tuned supervisor is a *distinguishable client*.
///    The defaults are taken and pinned. This is the field most likely to
///    acquire a knob by accident, precisely because it is a struct of public
///    `Duration`s sitting right there.
/// 4. **`posture` is not a choice.** `PersonaServingHost::start` is the sole
///    author of it (it overwrites whatever is passed), and vanguards are
///    already ruled `Managed` for a serving persona and enforced by the sealed
///    witness. `disable_network` is an offline-test knob and stays `false`.
///
/// # The non-item, stated so nobody adds it
///
/// **There is no serve-or-not toggle.** A staker with holdings that does not
/// serve accrues misses and eventually slashes, so serving is not a preference —
/// *the bond is the decision*. A configuration surface is exactly where someone
/// would add an "enable serving" checkbox, and it must not exist.
///
/// # Operator-facing residual: two staking wallets on one machine
///
/// Each derives its own directory, its own guards and its own tor process,
/// which is correct for isolation — but they are then two personas active from
/// one IP simultaneously. That is §10.9's co-activation at the *machine* level,
/// and no per-wallet mechanism can observe it, let alone prevent it. It is not
/// forced against here. **The recommended posture is one staking wallet per
/// machine (or per VM);** operators who want to serve several `P`s should serve
/// them from separate machines. Written down so it is a stated recommendation
/// rather than a discovered surprise.
///
/// # Errors
///
/// [`TorConfigError`] when the derived directory cannot be created, or exists
/// with group/world-write permission. Both are fail-closed at open.
pub(crate) fn tor_service_config(
    wallet_state_path: &std::path::Path,
    device: &shekyl_engine_prefs::DevicePrefs,
) -> Result<TorServiceConfig, TorConfigError> {
    let data_dir = shekyl_engine_file::paths::tor_data_dir_from(wallet_state_path);
    establish_data_dir(&data_dir)?;

    Ok(TorServiceConfig {
        binary: binary_source(&device.tor_binary_path),
        data_dir,
        // Nothing subscribes to tor's async events in production: no call site
        // issues `SETEVENTS`, so the sink receives nothing at all. Named rather
        // than left as an anonymous dropped receiver.
        events: shekyl_tor::control::EventSink::unsubscribed(),
        // Ruling 3: taken, not exposed.
        policy: shekyl_tor::service::SupervisorPolicy::default(),
        disable_network: false,
        // Ruling 4: overwritten by `PersonaServingHost::start`, which is the
        // sole author. Passing `Client` asserts we are not the one choosing.
        posture: shekyl_tor::service::ServingPosture::Client,
    })
}

/// Resolve the binary source from the device override.
///
/// An override that does not resolve to an existing file falls back to
/// discovery **and says so once**, rather than failing. The reason is the
/// travel residual on [`DevicePrefs::tor_binary_path`]: `<P>.prefs.toml` sits
/// beside the wallet file, so a cluster copied to another machine carries a
/// path that machine may not have. Treating that as fatal would make moving a
/// wallet break it; treating it silently would hide a genuine operator typo.
/// Warn-once-and-fall-back is the same shape the FAKECHAIN settlement-epoch
/// lever uses for an ignored setting.
fn binary_source(override_path: &str) -> shekyl_tor::service::TorBinarySource {
    use shekyl_tor::service::TorBinarySource;
    if override_path.is_empty() {
        return TorBinarySource::Discover;
    }
    let path = std::path::PathBuf::from(override_path);
    if path.is_file() {
        return TorBinarySource::At(path);
    }
    tracing::warn!(
        configured = %path.display(),
        "device.tor_binary_path does not name a file on this machine; falling back to \
         discovery (a wallet cluster copied from another machine carries its prefs, and \
         the override is machine-scoped). Clear or correct the setting to silence this."
    );
    TorBinarySource::Discover
}

/// Create the derived directory **private**, or refuse a too-permissive
/// pre-existing one.
///
/// The two halves are deliberately different, and the distinction is ownership.
/// A directory this wallet creates is created at `0o700`: `create_dir_all`
/// honours the process umask, which on a typical box yields `0o775` — group
/// writable — so *not* setting the mode would leave every fresh wallet's
/// entry-guard state writable by the operator's group. A directory that was
/// already there is **refused rather than tightened**: the wallet did not create
/// it, and does not know what else is relying on its mode.
fn establish_data_dir(path: &std::path::Path) -> Result<(), TorConfigError> {
    let pre_existing = path.is_dir();
    std::fs::create_dir_all(path).map_err(|source| TorConfigError::DataDirUnusable {
        path: path.to_path_buf(),
        source,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if !pre_existing {
            // Ours, and freshly made: make it private rather than umask-shaped.
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
                |source| TorConfigError::DataDirUnusable {
                    path: path.to_path_buf(),
                    source,
                },
            )?;
        }
        let mode = std::fs::metadata(path)
            .map_err(|source| TorConfigError::DataDirUnusable {
                path: path.to_path_buf(),
                source,
            })?
            .permissions()
            .mode();
        // Group- or world-writable means another account on this machine can
        // tamper with the entry-guard state. Read access is a separate (and
        // disclosed) at-rest residual — tor's state file is plaintext by
        // DQ-T0.7 — so this checks the write bits, which are the ones that let
        // someone else *change* the guard set.
        if mode & 0o022 != 0 {
            return Err(TorConfigError::DataDirTooPermissive {
                path: path.to_path_buf(),
                mode: mode & 0o777,
            });
        }
    }
    #[cfg(not(unix))]
    let _ = pre_existing;
    Ok(())
}

#[cfg(test)]
mod tor_config_tests {
    use super::*;
    use shekyl_engine_prefs::DevicePrefs;
    use shekyl_tor::service::TorBinarySource;

    fn device(tor_binary_path: &str) -> DevicePrefs {
        DevicePrefs {
            tor_binary_path: tor_binary_path.to_owned(),
            ..DevicePrefs::default()
        }
    }

    #[test]
    fn the_data_dir_is_derived_from_the_wallet_path_and_created() {
        let tmp = tempfile::tempdir().expect("tmp");
        let wallet = tmp.path().join("alice.wallet");
        let cfg = tor_service_config(&wallet, &device("")).expect("config");
        assert_eq!(cfg.data_dir, tmp.path().join("alice.wallet.tor"));
        assert!(
            cfg.data_dir.is_dir(),
            "the directory is established at open"
        );
    }

    /// The linkage property, asserted rather than assumed: a shared directory
    /// would be a shared entry-guard set across two wallets.
    #[test]
    fn two_wallets_never_share_a_tor_directory() {
        let tmp = tempfile::tempdir().expect("tmp");
        let a = tor_service_config(&tmp.path().join("one.wallet"), &device("")).expect("a");
        let b = tor_service_config(&tmp.path().join("two.wallet"), &device("")).expect("b");
        assert_ne!(a.data_dir, b.data_dir);
    }

    #[test]
    fn no_override_means_discovery() {
        assert!(matches!(binary_source(""), TorBinarySource::Discover));
    }

    #[test]
    fn an_override_naming_a_real_file_is_taken() {
        let tmp = tempfile::tempdir().expect("tmp");
        let bin = tmp.path().join("tor");
        std::fs::write(&bin, b"not really tor, but it is a file").expect("write");
        // The hash gate runs on this later; the override selects *which*
        // candidate is gated, never whether it is.
        match binary_source(bin.to_str().expect("utf8")) {
            TorBinarySource::At(p) => assert_eq!(p, bin),
            other => panic!("expected the override to be taken, got {other:?}"),
        }
    }

    /// The travel residual: a cluster copied from another machine carries a
    /// path this machine does not have. That must not break the wallet.
    #[test]
    fn a_travelled_override_falls_back_to_discovery() {
        assert!(matches!(
            binary_source("/nonexistent/machine/specific/tor"),
            TorBinarySource::Discover,
        ));
    }

    #[test]
    fn the_supervisor_policy_is_taken_not_tuned() {
        let tmp = tempfile::tempdir().expect("tmp");
        let cfg = tor_service_config(&tmp.path().join("w.wallet"), &device("")).expect("config");
        // `SupervisorPolicy` is deliberately not `PartialEq` (it is a config,
        // not a value), so the assertion compares the fields whose *timing* is
        // observable — which is the property the ruling is about.
        let default = shekyl_tor::service::SupervisorPolicy::default();
        assert_eq!(cfg.policy.backoff_base, default.backoff_base);
        assert_eq!(cfg.policy.backoff_cap, default.backoff_cap);
        assert_eq!(cfg.policy.degrade_after, default.degrade_after);
        assert_eq!(cfg.policy.trust_retry, default.trust_retry);
        assert_eq!(cfg.policy.bootstrap_deadline, default.bootstrap_deadline);
        assert_eq!(cfg.policy.stable_reset, default.stable_reset);
        assert!(!cfg.disable_network, "offline-test knob, never production");
    }

    #[cfg(unix)]
    #[test]
    fn a_group_or_world_writable_directory_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("tmp");
        let wallet = tmp.path().join("loose.wallet");
        let dir = tmp.path().join("loose.wallet.tor");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).expect("chmod");

        // `TorServiceConfig` is not `Debug` (it holds an `EventSink`, a
        // forensic surface), so match rather than `expect_err`.
        match tor_service_config(&wallet, &device("")) {
            Err(TorConfigError::DataDirTooPermissive { mode, .. }) => {
                assert_eq!(
                    mode & 0o022,
                    0o022,
                    "the group/world write bits are what fail"
                );
            }
            Err(other) => panic!("wrong refusal: {other:?}"),
            Ok(_) => panic!(
                "entry-guard state another account can rewrite must be refused, not \
                 tightened silently"
            ),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_private_directory_is_accepted() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path().join("tight.wallet.tor");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        assert!(tor_service_config(&tmp.path().join("tight.wallet"), &device("")).is_ok());
    }
}

// ---------------------------------------------------------------------------
// The construction site
// ---------------------------------------------------------------------------

/// Why a staker's serving host could not be started.
#[derive(Debug)]
pub enum ServingStartError {
    /// No stake engine is resident.
    NoStakeEngine,
    /// `staking_enabled` with no resident actor — the mid-session bond-watch
    /// recovery state. Names the reopen remedy rather than reporting a generic
    /// "not a staker" over a wallet that just recovered its staking history
    /// (rule 82), mirroring `PScanStartError::RecoveredPendingReopen`.
    RecoveredPendingReopen,
    /// The wallet's Tor configuration could not be established.
    TorConfig(TorConfigError),
    /// The persona's serving identity could not be read from the stake engine.
    Identity(String),
    /// The daemon this wallet talks to is not on loopback, so there is no
    /// persona-isolated transport to derive the serve-set over.
    ///
    /// Serving currently requires an **own node** — which is the documented
    /// privacy default (SP-T2: "run-your-own-node is the privacy default"), and
    /// the ② remote posture that would lift this is the unbuilt 2c
    /// config-source slice. Refused loudly with the remedy named rather than
    /// silently serving a set derived over the principal's shared connection.
    DaemonNotLoopback {
        /// What the transport refused, for the operator-facing message.
        detail: String,
    },
}

impl std::fmt::Display for ServingStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoStakeEngine => write!(f, "this wallet is not staking"),
            Self::RecoveredPendingReopen => write!(
                f,
                "this wallet recovered staking history this session; reopen it to start serving"
            ),
            Self::TorConfig(e) => write!(f, "the wallet's Tor configuration is unusable: {e}"),
            Self::Identity(e) => write!(f, "the persona's serving identity is unavailable: {e}"),
            Self::DaemonNotLoopback { detail } => write!(
                f,
                "serving derives its shard set over a persona-isolated transport, which \
                 currently requires your own node on loopback; this wallet's daemon was \
                 refused: {detail}"
            ),
        }
    }
}

impl std::error::Error for ServingStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TorConfig(e) => Some(e),
            _ => None,
        }
    }
}

// Same Engine-trait privacy posture as `start_pscan_with`: the engine traits are
// `pub(crate)` and the entry point is re-exported for the embedder, exactly as
// `PScanHandle`'s is.
#[allow(private_bounds)]
impl<S, D, L, E, R, P> crate::engine::Engine<S, D, L, E, R, P, shekyl_engine_file::WalletFile>
where
    S: crate::engine::EngineSignerKind + Send + Sync + 'static,
    D: crate::engine::traits::DaemonEngine,
    L: crate::engine::traits::LedgerEngine,
    E: crate::engine::traits::EconomicsEngine,
    R: crate::engine::traits::RefreshEngine,
    P: crate::engine::traits::PendingTxEngine,
    Self: Send + Sync,
{
    /// Start the persona serving host **iff this wallet is a staker with an
    /// active persona** — the lifecycle auto-start, sibling to
    /// [`start_pscan_if_staker`](Self::start_pscan_if_staker).
    ///
    /// Returns `Ok(None)` for a non-staker, and for a staker with no *active*
    /// persona: there is nothing to serve until one is activated, and
    /// first-stake mid-session already collapses onto reopen under Model D, so
    /// the serving start follows the same rule rather than inventing a
    /// mid-session activation hook.
    ///
    /// The returned [`ServingHandle`] is **embedder-held** for the wallet's open
    /// lifetime, exactly as `PScanHandle` is, and shutting it down is what
    /// unpublishes the onion in the right order.
    ///
    /// # The daemon endpoint is the caller's
    ///
    /// The serve-set is derived over a persona-isolated transport, and the
    /// wallet's daemon address lives with the embedder rather than on the
    /// `Engine` — the same shape `submit_emission_claim` already uses for the
    /// claim path. The caller passes the address it already holds; this method
    /// builds the ① local-posture transport from it and refuses anything that
    /// is not loopback.
    ///
    /// # Errors
    ///
    /// [`ServingStartError`] — see its variants. Every arm is fail-closed at
    /// open: a staker that cannot serve accrues misses toward a slash, and the
    /// operator cannot see it happening.
    pub async fn start_serving_if_staker(
        self_arc: std::sync::Arc<tokio::sync::RwLock<Self>>,
        daemon_address: &str,
    ) -> Result<Option<ServingHandle>, ServingStartError> {
        // Brief read borrow: clone the spawn inputs, exactly as `spawn_pscan` does.
        let (stake, curve_tree, tor) = {
            let g = self_arc.read().await;
            let stake = match g.stake_handle() {
                Some(stake) => stake,
                None if g.ledger.staking_enabled() => {
                    return Err(ServingStartError::RecoveredPendingReopen)
                }
                None => return Ok(None),
            };
            let tor = tor_service_config(g.persistence().base_path(), &g.prefs().device)
                .map_err(ServingStartError::TorConfig)?;
            (stake, g.curve_tree.clone(), tor)
        };

        let Some(active) = stake
            .active_persona()
            .await
            .map_err(|e| ServingStartError::Identity(e.to_string()))?
        else {
            // A staker with no active persona has nothing to serve yet.
            return Ok(None);
        };

        let identity = stake
            .persona_onion_identity(active.p_slot)
            .await
            .map_err(|e| ServingStartError::Identity(e.to_string()))?;
        let p_id = shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey(
            &active
                .bond_id
                .to_canonical_bytes()
                .map_err(|e| ServingStartError::Identity(e.to_string()))?,
        );

        // ① local posture. `LocalNodeRpc` refuses a non-loopback URL by
        // construction, so the refusal below is the type's, not a check here.
        let claim_rpc =
            crate::engine::prpc::LocalNodeRpc::new(daemon_address.to_owned(), CLAIM_SOURCE_TIMEOUT)
                .await
                .map_err(|e| ServingStartError::DaemonNotLoopback {
                    detail: e.to_string(),
                })?;

        let pinner = super::serve_set_source::EngineServeSetPinner::new(
            curve_tree,
            claim_rpc,
            p_id.to_bytes(),
        );

        Ok(Some(spawn_serving_task(
            tor,
            PersonaServing {
                identity,
                virtual_port: SERVING_VIRTUAL_PORT,
                max_streams: SERVING_MAX_STREAMS,
            },
            pinner,
            std::sync::Arc::new(shekyl_operator_alarm::OperatorAlarms::new()),
            ServingConfig::production(
                crate::engine::pscan::start::DEFAULT_PSCAN_CADENCE,
                // Single-sourced from the same place the submit driver's
                // watchdog horizon comes from, rather than taken as an
                // embedder argument: the block target is a consensus
                // parameter, not a wallet setting.
                shekyl_economics::EconomicParams::default().daa_target_seconds,
            ),
        )))
    }
}
