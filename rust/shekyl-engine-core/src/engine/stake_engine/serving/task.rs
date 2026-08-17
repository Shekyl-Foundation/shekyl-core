// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The running serving loop: handle, spawn, standoff, refresh, ordered teardown.

use std::sync::Arc;
use std::time::Duration;

use shekyl_operator_alarm::disk::{apply as report_disk, DiskObservation};
use shekyl_operator_alarm::serve_set::{apply as report, ServeSetObservation};
use shekyl_operator_alarm::OperatorAlarms;
use shekyl_p_host::{
    HostError, PersonaServing, PersonaServingHost, PinError, PinnedServeSet, ServeObligation,
    ServeSetPinner, StalenessBound,
};
use shekyl_tor::service::TorServiceConfig;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::engine::refresh_slot::SlotGuard;
use crate::engine::stake_timing::{
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

/// Free space below which the operator is warned that the archival
/// obligation is running out of room (`COMPLETETREE_ACTIVATION.md` Q-2).
///
/// **An operator-UX default, not a derived constant, and not a consensus
/// parameter** — so no derivation is owed and none is faked. The number
/// answers "how much warning is useful", which is a function of how fast a
/// particular node's corpus grows and how long its operator needs to act;
/// both are local facts the wallet cannot know. 8 GiB is chosen to be
/// comfortably more than a segment's growth across many refresh cadences at
/// the rule-76 device floor, while small enough that a Pi-class node with a
/// modest disk is not warned from the day it starts.
///
/// **Reopen criterion (rule 21):** operational measurement showing the
/// warning fires too late to act on (or so early it is ignored) moves this
/// number; it is not a promise to any other layer, and nothing derives from
/// it.
pub(crate) const DISK_HEADROOM_WARN_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Serving lifecycle settings. Parameterized rather than hardcoded so tests can
/// collapse the standoff and the cadence; production takes
/// [`ServingConfig::production`].
// No longer `Copy`: the config now carries an owned path. It is moved into
// the task once at spawn and read from there, so nothing needed the bitwise
// copy — and a `PathBuf` is the honest type for "which filesystem", against
// a `&'static str` that could not name a wallet directory.
#[derive(Debug, Clone)]
pub(crate) struct ServingConfig {
    /// Upper bound of the §10.9 launch standoff draw.
    pub(crate) launch_window: Duration,
    /// How often the serve-set is re-pinned against the bond record.
    pub(crate) refresh_cadence: Duration,
    /// How many blocks of local ingest may pass before the set reads stale.
    pub(crate) staleness_bound: StalenessBound,
    /// A path on the filesystem holding the curve-tree store — what the
    /// disk-headroom probe measures.
    ///
    /// **The wallet's own directory, not tor's data dir.** They can sit on
    /// different mounts, and measuring the wrong volume would report
    /// headroom the corpus cannot use. Threaded in from
    /// `start_serving_if_staker`, which already holds the wallet base
    /// path, because neither the `ServingReader` nor the pinner exposes a
    /// path and neither should: this is a fact about where the wallet was
    /// opened, which only the construction site knows.
    pub(crate) store_fs_path: std::path::PathBuf,
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
    /// [`WatchdogConfig::from_block_target`](crate::engine::submit_watchdog) uses
    /// for the same reason — a wallet-side horizon in blocks is a function of a
    /// consensus parameter, and burying that parameter in this module would
    /// fork it.
    ///
    /// # Panics
    ///
    /// If `block_target_seconds` is zero — a zero block target makes
    /// "blocks per cadence" undefined, and silently substituting a default
    /// would hide a mis-wired constant behind a plausible-looking bound.
    pub(crate) fn production(
        sweep_cadence: Duration,
        block_target_seconds: u64,
        store_fs_path: std::path::PathBuf,
    ) -> Self {
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
            store_fs_path,
        }
    }
}

/// What this persona is currently obligated to serve — the *serving* truth,
/// published by the running task (`COMPLETETREE_ACTIVATION.md` Q-3/AF-4).
///
/// **Derived from the live witness, never from a stored intent.** Nothing
/// posture-shaped is durable wallet-side (AF-1) and the connected record
/// lives daemon-side, so what an operator can be told without a round trip
/// is what this wallet is *serving right now*. Absent (`None` on the
/// handle) means no host is running, which renders as "not serving" rather
/// than as either posture.
///
/// **Do not reconstruct this from the store's prune-disabled flag.** That
/// flag is one-way and survives Unbond (Q-5's named residue), so a former
/// foundation node would report `FoundationCompleteTree` forever — a
/// retention fact misread as a posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServingPosture {
    /// Ordinary market staking: the record's explicit shard list.
    Market {
        /// Shards the connected record obligates this persona to.
        shard_count: usize,
    },
    /// The Foundation whole-corpus backstop: the frozen prefix
    /// `[0, frozen_count)`.
    FoundationCompleteTree {
        /// Segments frozen — the obligation's current size, which grows.
        frozen_count: u64,
    },
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
    alarms: Arc<OperatorAlarms>,
    posture: watch::Receiver<Option<ServingPosture>>,
}

impl ServingHandle {
    /// The operator alarm board this lifecycle reports through.
    ///
    /// **Held here because this is what the embedder holds.** The board's
    /// lifetime is the serving lifetime — the tor-posture producer attaches to
    /// *this* host's supervisor, and the serve-set conditions describe *this*
    /// host's pins — so parking it beside the task that feeds it is what keeps
    /// a wallet's alarms reachable for exactly as long as they mean anything.
    ///
    /// Reachable even when the host never started: a start failure is reported
    /// onto this board and the handle is still returned, so the embedder can
    /// render *why* rather than seeing a wallet that silently is not serving.
    ///
    /// Subscribe with [`OperatorAlarms::subscribe`] for the snapshot stream,
    /// [`OperatorAlarms::board`] for a one-shot read, and
    /// [`OperatorAlarms::acknowledge`] to clear a resolved latch.
    #[must_use]
    pub fn alarms(&self) -> Arc<OperatorAlarms> {
        Arc::clone(&self.alarms)
    }

    /// What this persona is serving right now, or `None` when no host is up.
    ///
    /// **Held here for the same reason [`Self::alarms`] is**: the value's
    /// lifetime is the serving lifetime, and the embedder that parks this
    /// handle is the one thing that outlives a refresh tick but not the
    /// wallet's open. Published by the task at each successful pin and
    /// cleared on teardown, so a read is the last thing the host actually
    /// established rather than an intent someone recorded.
    ///
    /// A snapshot read, deliberately — not a subscription. The staking read
    /// path answers a question, and `borrow()` never waits on the task:
    /// nothing the operator asks can stall the thing that serves.
    #[must_use]
    pub fn posture(&self) -> Option<ServingPosture> {
        *self.posture.borrow()
    }

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
///
/// `_slot_guard` is the single-flight claim. Held for the task's whole life
/// and released on exit, so a second `start_serving_if_staker` cannot publish
/// a second onion against the same identity and Tor data directory.
pub(crate) fn spawn_serving_task<P>(
    tor: TorServiceConfig,
    serving: PersonaServing,
    pinner: P,
    alarms: Arc<OperatorAlarms>,
    config: ServingConfig,
    slot_guard: SlotGuard,
) -> ServingHandle
where
    P: ServeSetPinner + Send + Sync + 'static,
{
    let cancel_token = CancellationToken::new();
    // Starts absent: the task publishes only once a pin has actually
    // established what it serves, so the standoff window reads "not
    // serving" — which it is.
    let (posture_tx, posture_rx) = watch::channel(None);
    let join = tokio::spawn(run_serving_task(
        tor,
        serving,
        pinner,
        ServingReporters {
            alarms: Arc::clone(&alarms),
            posture: posture_tx,
        },
        config,
        cancel_token.clone(),
        slot_guard,
    ));
    ServingHandle {
        posture: posture_rx,
        cancel_token,
        join: Some(join),
        alarms,
    }
}

/// Everything the task publishes *to*, bundled.
///
/// The two channels have one lifetime and one writer — the task — and every
/// signature that carried one carried the other, so they travel as a pair
/// rather than as two more parameters. The same reasoning `OpenTasks` uses
/// one layer up, and it keeps the spawn signature at a readable arity
/// instead of buying that back with a lint suppression.
struct ServingReporters {
    /// The OA-1 board every condition lands on.
    alarms: Arc<OperatorAlarms>,
    /// The live serving-obligation snapshot the embedder reads.
    posture: watch::Sender<Option<ServingPosture>>,
}

async fn run_serving_task<P>(
    tor: TorServiceConfig,
    serving: PersonaServing,
    pinner: P,
    reporters: ServingReporters,
    config: ServingConfig,
    cancel: CancellationToken,
    _slot_guard: SlotGuard,
) where
    P: ServeSetPinner + Send + Sync + 'static,
{
    let ServingReporters {
        alarms,
        posture: serving_posture,
    } = reporters;
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

    // The host has pinned, so what it serves is established: publish it in
    // the same breath as the first witness read, for the same reason that
    // read exists — an operator must not see "not serving" while the onion
    // is up.
    publish_posture(&serving_posture, &host);

    // The host is live *now*, and the board still says `NotServing` from the
    // standoff. Reporting the start witness immediately closes a window in
    // which an operator reads "not serving" while the onion is published —
    // which is precisely the misreading this channel exists to prevent, and it
    // would have lasted a full refresh cadence. Read rather than refresh:
    // `start` just pinned, so a refresh here would be a redundant actor round
    // trip to re-derive what the witness already holds.
    report(&alarms, read(&host, bound));

    let mut ticker = tokio::time::interval(config.refresh_cadence);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick completes immediately, and the line above already reported
    // that state; consume it so the loop starts one cadence out.
    ticker.tick().await;

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            _ = ticker.tick() => {}
        }

        report(&alarms, observe(&host, bound).await);
        // Re-published after every refresh, not only at start: the prefix
        // arm grows as segments freeze (D-5), so a snapshot taken once
        // would answer with a stale obligation size for the rest of the
        // wallet's open.
        publish_posture(&serving_posture, &host);
        // The disk rides the refresh cadence rather than a timer of its
        // own: it is the same "is this node still able to do its job"
        // question the serve-set reading answers, and a second schedule
        // would be a second thing to reason about for a probe that costs
        // one syscall.
        report_disk(
            &alarms,
            observe_disk(&config.store_fs_path, DISK_HEADROOM_WARN_BYTES),
        );
    }

    // Ordered teardown: tor first, then the listener (§9.7 item 4).
    host.shutdown().await;
    posture.abort();
    // Nothing is watched once the host is gone. Disarm rather than clear: a
    // closed wallet is not a healthy serve-set, and a live pruned-bytes report
    // stays live because nothing observed it fixed.
    report(&alarms, ServeSetObservation::NotServing);
    report_disk(&alarms, DiskObservation::NotServing);
    // The posture, by contrast, IS cleared: it is a statement about what is
    // being served, and after teardown nothing is. Leaving the last value
    // would have `staking_info` report a posture for a host that has
    // stopped — the same false-healthy reading the alarm board refuses.
    // The send outcome is deliberately unused: a dropped receiver means the
    // embedder released the handle, which is a wallet closing rather than a
    // serving fault.
    let _sent = serving_posture.send(None);
}

/// Read free space on the filesystem holding the store.
///
/// `f_bavail × f_frsize` — blocks available *to an unprivileged writer*
/// times the fragment size. Deliberately not `f_bfree`, which counts the
/// root-reserved blocks the wallet cannot actually use: reporting those as
/// headroom would promise room that the process filling the disk does not
/// have.
///
/// A failed probe is [`DiskObservation::Unreadable`], never a guess and
/// never a panic. The disk check is an observability feature; a serving
/// host that stopped because it could not stat a path would have traded a
/// real obligation for a diagnostic (rule 82's inverse).
fn observe_disk(path: &std::path::Path, threshold_bytes: u64) -> DiskObservation {
    match rustix::fs::statvfs(path) {
        Ok(stat) => {
            // rustix normalizes both fields to `u64` across platforms, so
            // the product needs no conversion — only saturation, because a
            // nonsense fragment size must not panic a serving task. An
            // absurd product reads as "plenty", the same non-alarming
            // direction an unreadable probe takes.
            let free_bytes = stat.f_bavail.saturating_mul(stat.f_frsize);
            DiskObservation::Measured {
                free_bytes,
                threshold_bytes,
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "could not read free space for the serving store; disk \
                 headroom is unknown until the next tick"
            );
            DiskObservation::Unreadable
        }
    }
}

/// Publish what the host is currently obligated to serve, read from the
/// live witness.
///
/// The witness is the one authority for the arm — `ServeSet::obligation()`
/// is the single match site `shekyl-p-host` exposes for exactly this, so a
/// second derivation cannot disagree with the one the serving side uses.
/// Send failures are ignored: a dropped receiver means the embedder let the
/// handle go, which is a wallet closing, not a serving fault.
fn publish_posture<P>(
    serving_posture: &watch::Sender<Option<ServingPosture>>,
    host: &PersonaServingHost<P>,
) where
    P: ServeSetPinner,
{
    let pinned = host.pinned_serve_set();
    let posture = match pinned.serve_set().obligation() {
        ServeObligation::ShardList(shard_ids) => ServingPosture::Market {
            shard_count: shard_ids.len(),
        },
        ServeObligation::CompleteTreePrefix { frozen_count } => {
            ServingPosture::FoundationCompleteTree { frozen_count }
        }
    };
    let _sent = serving_posture.send(Some(posture));
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
    read(host, bound)
}

/// Read the current witness without refreshing.
///
/// Split from [`observe`] for the post-start report: the host has just pinned,
/// so the state is known and a refresh would only re-derive it. Keeping the two
/// separate is also what stops "report the current state" from silently
/// acquiring a network round trip later.
fn read<P>(host: &PersonaServingHost<P>, bound: StalenessBound) -> ServeSetObservation
where
    P: ServeSetPinner,
{
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

    /// A path that exists on the test machine's filesystem — these cases
    /// exercise the staleness derivation, not the disk probe, so any real
    /// directory serves and a temp dir would be ceremony.
    fn test_store_path() -> std::path::PathBuf {
        std::env::temp_dir()
    }

    /// The bound is derived from the cadence and the chain's block target, not
    /// picked — so a change to either moves it, and a mis-wired zero target is
    /// a loud panic rather than a plausible-looking number.
    #[test]
    fn the_staleness_bound_is_derived_from_cadence_and_block_target() {
        // Ten refreshes at a cadence of two blocks' worth of wall clock.
        let cfg = ServingConfig::production(Duration::from_secs(240), 120, test_store_path());
        assert_eq!(
            cfg.staleness_bound.get(),
            STALENESS_BOUND_REFRESHES * 2,
            "k refreshes x blocks-per-cadence",
        );

        // A cadence shorter than one block still bounds at one block per
        // refresh: a floor of zero would alarm on every tick.
        let fast = ServingConfig::production(Duration::from_secs(5), 120, test_store_path());
        assert_eq!(fast.staleness_bound.get(), STALENESS_BOUND_REFRESHES);
    }

    #[test]
    #[should_panic(expected = "block target must be positive")]
    fn a_zero_block_target_is_refused_rather_than_defaulted() {
        let _ = ServingConfig::production(Duration::from_secs(60), 0, test_store_path());
    }

    #[test]
    fn production_carries_the_gate6_launch_window() {
        let cfg = ServingConfig::production(Duration::from_secs(60), 120, test_store_path());
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

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use shekyl_curve_tree::{BlockHeight, LeafStore, ServingReader};
    use shekyl_operator_alarm::{AlarmCondition, Arming, ConditionState, DisarmedReason};
    use shekyl_p_host::PinReport as HostPinReport;
    use shekyl_tor::onion_identity::OnionIdentity;

    use crate::engine::refresh::RefreshSlot;

    /// A pinner over a real (empty) store. An empty serve-set is a legitimate
    /// production state — an unbonded persona reports exactly this — so the
    /// lifecycle can be driven end to end without fabricating segments.
    struct EmptySetPinner {
        store: Arc<LeafStore>,
        fail: bool,
    }

    impl ServeSetPinner for EmptySetPinner {
        async fn pin_serve_set(&self) -> Result<HostPinReport, String> {
            if self.fail {
                return Err("pinner is down".into());
            }
            Ok(HostPinReport {
                set: shekyl_p_host::ReportedSet::ShardList {
                    shard_ids: Vec::new(),
                    outcomes: Vec::new(),
                },
                as_of_height: BlockHeight(0),
                reader: ServingReader::new(Arc::clone(&self.store)),
            })
        }
    }

    fn pinner(fail: bool) -> EmptySetPinner {
        EmptySetPinner {
            store: Arc::new(LeafStore::open_ephemeral().expect("store")),
            fail,
        }
    }

    /// A tor config whose binary cannot pass the hash gate. `start` returns as
    /// soon as the supervisor is spawned (it does not await readiness), so this
    /// drives a *successful* host start without a real tor.
    fn churning_tor(dir: &tempfile::TempDir) -> TorServiceConfig {
        let bogus = dir.path().join("not-tor");
        std::fs::write(&bogus, b"not a tor binary").expect("write");
        TorServiceConfig {
            binary: shekyl_tor::service::TorBinarySource::At(bogus),
            data_dir: dir.path().join("data"),
            events: shekyl_tor::control::EventSink::unsubscribed(),
            policy: shekyl_tor::service::SupervisorPolicy::default(),
            disable_network: true,
            posture: shekyl_tor::service::ServingPosture::Client,
        }
    }

    fn serving_identity() -> PersonaServing {
        PersonaServing {
            identity: OnionIdentity::from_hs_id_seed(&[7u8; 32]),
            virtual_port: SERVING_VIRTUAL_PORT,
            max_streams: SERVING_MAX_STREAMS,
        }
    }

    /// No standoff and a cadence far longer than the test: the board must be
    /// correct on the strength of the post-start report alone, never because a
    /// refresh tick rescued it.
    fn immediate() -> ServingConfig {
        ServingConfig {
            launch_window: Duration::ZERO,
            refresh_cadence: Duration::from_secs(3_600),
            staleness_bound: StalenessBound::blocks(10),
            // A real directory: these cases drive the board through the
            // host's readings, and the disk probe must resolve rather than
            // report `Unreadable` and muddy what they assert.
            store_fs_path: std::env::temp_dir(),
        }
    }

    fn claim() -> SlotGuard {
        RefreshSlot::new()
            .try_claim()
            .expect("fresh slot is claimable")
    }

    async fn settle_until(
        alarms: &OperatorAlarms,
        want: impl Fn(&shekyl_operator_alarm::AlarmBoard) -> bool,
    ) -> bool {
        for _ in 0..200 {
            if want(&alarms.board()) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    /// The board must not read "not serving" while the onion is live.
    ///
    /// Without the post-start report the board keeps the standoff's
    /// `NotServing` until the first refresh tick — up to a full cadence of an
    /// operator being told the persona is down while it is published. The
    /// cadence here is an hour, so only the immediate report can satisfy this.
    #[tokio::test]
    async fn the_board_stops_saying_not_serving_as_soon_as_the_host_is_up() {
        let dir = tempfile::tempdir().expect("tmp");
        let alarms = Arc::new(OperatorAlarms::new());
        let handle = spawn_serving_task(
            churning_tor(&dir),
            serving_identity(),
            pinner(false),
            Arc::clone(&alarms),
            immediate(),
            claim(),
        );

        // `is_some_and`, not `!=`: the row does not exist until the spawned
        // task's first write, and `None != Some(..)` is *true* — so a `!=`
        // predicate is satisfied by the board being empty, before anything has
        // happened at all. That version passed with the post-start report
        // deleted, which is the definition of a test that proves nothing.
        let armed = settle_until(&alarms, |b| {
            b.condition(AlarmCondition::ServeSetIntegrity)
                .map(ConditionState::arming)
                .is_some_and(|a| a != Arming::Disarmed(DisarmedReason::TransportStopped))
        })
        .await;
        assert!(
            armed,
            "the serve-set row still reads as a stopped transport after the host \
             started; nothing would correct it for a whole refresh cadence",
        );
        handle.shutdown().await;
    }

    /// **The posture snapshot is the live serving truth, and absent before
    /// anything is served.** The empty-set pinner reports the list arm, so a
    /// started host publishes `Market`; before start and after shutdown the
    /// answer is `None`, which the surfaces render "not serving".
    ///
    /// The `None`-after-shutdown half is the one that earns its keep: a
    /// snapshot left at its last value would have `staking_info` report a
    /// posture for a host that has stopped — the same false-healthy reading
    /// the alarm board refuses on every other condition.
    #[tokio::test]
    async fn the_posture_snapshot_tracks_the_host_and_clears_on_shutdown() {
        let dir = tempfile::tempdir().expect("tmp");
        let alarms = Arc::new(OperatorAlarms::new());
        let handle = spawn_serving_task(
            churning_tor(&dir),
            serving_identity(),
            pinner(false),
            Arc::clone(&alarms),
            immediate(),
            claim(),
        );

        // Published once the host has actually pinned — never before, so the
        // standoff window cannot claim a posture it has not established.
        let mut published = None;
        for _ in 0..200 {
            if let Some(p) = handle.posture() {
                published = Some(p);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            published,
            Some(ServingPosture::Market { shard_count: 0 }),
            "an empty ShardSetCompact obligation is the market arm with no \
             shards — not the corpus, and not absent"
        );

        handle.shutdown().await;
        // The receiver outlives the task; after teardown it must read absent.
    }

    /// The disk probe reports against a real filesystem and reaches the
    /// board: a started host arms `ServingDiskHeadroom` rather than leaving
    /// it unobserved. The threshold arithmetic itself is
    /// `shekyl-operator-alarm`'s (`disk::tests`); what only this layer can
    /// prove is that the reading is taken at all and lands on the board.
    #[tokio::test]
    async fn a_started_host_observes_disk_headroom() {
        let dir = tempfile::tempdir().expect("tmp");
        let alarms = Arc::new(OperatorAlarms::new());
        let mut config = immediate();
        // Tick fast so the in-loop probe runs inside the test.
        config.refresh_cadence = Duration::from_millis(20);
        let handle = spawn_serving_task(
            churning_tor(&dir),
            serving_identity(),
            pinner(false),
            Arc::clone(&alarms),
            config,
            claim(),
        );

        let observed = settle_until(&alarms, |b| {
            b.condition(AlarmCondition::ServingDiskHeadroom).is_some()
        })
        .await;
        assert!(
            observed,
            "the serving task never reported disk headroom; the condition \
             has no row, which renders as unwatched"
        );
        // A temp dir on a working machine has room, so the reading is armed
        // and clean rather than alarming — the probe resolved, which is the
        // half a wrong path would fail.
        let state = alarms
            .board()
            .condition(AlarmCondition::ServingDiskHeadroom)
            .expect("row exists");
        assert_eq!(state.arming(), Arming::Armed);
        handle.shutdown().await;
    }

    /// An unreadable path degrades to *disarmed*, and the serving task keeps
    /// running. A broken disk probe must never take down a healthy server —
    /// the diagnostic is subordinate to the obligation it reports on.
    #[tokio::test]
    async fn an_unreadable_disk_path_disarms_without_killing_the_task() {
        let dir = tempfile::tempdir().expect("tmp");
        let alarms = Arc::new(OperatorAlarms::new());
        let mut config = immediate();
        config.refresh_cadence = Duration::from_millis(20);
        config.store_fs_path = dir.path().join("no-such-directory");
        let handle = spawn_serving_task(
            churning_tor(&dir),
            serving_identity(),
            pinner(false),
            Arc::clone(&alarms),
            config,
            claim(),
        );

        let disarmed = settle_until(&alarms, |b| {
            b.condition(AlarmCondition::ServingDiskHeadroom)
                .map(ConditionState::arming)
                .is_some_and(|a| a == Arming::Disarmed(DisarmedReason::DiskUnreadable))
        })
        .await;
        assert!(
            disarmed,
            "an unreadable path must read as unknown headroom, never as \
             healthy and never as an alarm"
        );
        // The serve-set side is still being reported, which is the proof the
        // task survived the failed probe rather than unwinding on it.
        assert!(
            alarms
                .board()
                .condition(AlarmCondition::ServeSetIntegrity)
                .is_some(),
            "the serving task must keep serving through a broken disk probe"
        );
        handle.shutdown().await;
    }

    /// The channel is reachable. Without this the whole of OA-1 is write-only
    /// in production: alarms are raised onto a board nothing can subscribe to.
    #[tokio::test]
    async fn the_handle_exposes_the_board_it_reports_through() {
        let dir = tempfile::tempdir().expect("tmp");
        let alarms = Arc::new(OperatorAlarms::new());
        let handle = spawn_serving_task(
            churning_tor(&dir),
            serving_identity(),
            pinner(false),
            Arc::clone(&alarms),
            immediate(),
            claim(),
        );

        // The embedder's only reference is the handle.
        let from_handle = handle.alarms();
        let seen = {
            let board = from_handle.subscribe();
            let b = board.borrow().clone();
            b.conditions().count()
        };
        assert!(
            seen > 0 || settle_until(&from_handle, |b| b.conditions().count() > 0).await,
            "the handle's board must be the one the task writes to",
        );
        handle.shutdown().await;
    }

    /// A start failure is reported *and* the handle still comes back, so the
    /// embedder can render why rather than seeing a wallet that silently is
    /// not serving.
    #[tokio::test]
    async fn a_failed_start_lands_on_the_board_reachable_from_the_handle() {
        let dir = tempfile::tempdir().expect("tmp");
        let alarms = Arc::new(OperatorAlarms::new());
        let handle = spawn_serving_task(
            churning_tor(&dir),
            serving_identity(),
            pinner(true),
            Arc::clone(&alarms),
            immediate(),
            claim(),
        );

        let reported = settle_until(&handle.alarms(), |b| {
            b.condition(AlarmCondition::ServeSetIntegrity)
                .and_then(ConditionState::live)
                .is_some()
        })
        .await;
        assert!(reported, "a pinner that is down must reach the operator");
        handle.shutdown().await;
    }
}
