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
//! # What is still missing, and why it is not guessed here
//!
//! [`PersonaServingHost::start`] needs a `TorServiceConfig`: a
//! `TorBinarySource`, a `DataDirectory` path, and a `SupervisorPolicy`. **The
//! wallet has no configuration surface for any of them** — nothing in
//! `shekyl-engine-core`, `shekyl-wallet-rpc` or `shekyl-engine-prefs` names one
//! — so this module builds the lifecycle and stops at the point where it would
//! have to invent that surface.
//!
//! That is a named blocker rather than a deferral (rule 22), and the reason it
//! is not a small gap: the data directory is constrained by **DQ-T0.7**, which
//! ruled it **persistent** (the dir carries the entry-guard identity, and
//! per-session rotation is itself a deviation-from-defaults signature) and
//! requires a "wallet-adjacent, wallet-controlled, non-world-writable
//! placement". The binary source is constrained by rule 17's reuse-don't-own
//! ruling — a hash-pinned Tor Expert Bundle, with a release-checklist
//! obligation attached. Both are operator-visible decisions with a threat-model
//! basis; picking a path here would be inventing an answer to a question this
//! slice was not asked.
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

// Inert until the wallet gains a Tor configuration surface — see the
// "What is still missing" section above. Everything here is exercised by this
// module's tests; what has no caller is the *production* construction, because
// `TorServiceConfig` has no wallet-side home yet.
#![allow(dead_code)]

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
