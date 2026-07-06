// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! WI-3 — the block-timed bond-post dispatch driver
//! (`ARCHIVAL_BOND_WI3_DISPATCH.md`).
//!
//! Makes the sealed pending post actually reach a wire at its planned block:
//! the due-check rides the pscan sweep's tip read (§3.1), at most one post
//! dispatches per tick with deterministic ordering (§3.2), the `Dispatched`
//! transition is sealed **before** any network send (§3.3), and every send —
//! first or resubmit — re-lifts the *stored* bytes through the
//! `submit_bound` choke path (pin P-2).
//!
//! ## The locked write path (§3.3 writer discipline, gate 11)
//!
//! The pending seal has two writers on two cadences: the WI-2 assemble path
//! (append) and this driver (transition/remove). Both go through one
//! [`PendingPostStore`] handle owning an async mutex around
//! load→modify→seal, so two writers can never race one read-modify-seal
//! cycle. The seal itself stays single-sourced in
//! `WalletFile::save_pending_posts` — the sole writer of `.wallet.pending`
//! and the sole `PayloadKind::PendingPostBlockPostcard` encode site — which
//! the production [`PendingSealStore`] impl delegates to. Crash-atomicity is
//! structural (R2-2): the whole block is one postcard blob under one AEAD
//! envelope committed by one atomic file write; the reservation is derived,
//! never stored, so no torn seal-vs-reservation state is representable.

use std::collections::BTreeSet;
use std::time::Duration;

use rand_core::RngCore as _;
use shekyl_archival_retention::ARCHIVAL_REORG_DEPTH_BLOCKS;
use shekyl_engine_state::{PendingBondPost, PendingPostBlock, PendingPostState};
use shekyl_standoff::draw::{bounded_uniform, GapRng};
use shekyl_types::{BlockHeight, PCanonicalId};
use tokio_util::sync::CancellationToken;

#[cfg(feature = "gf7-hooks")]
use shekyl_standoff::gf7::{BroadcastTimelineObserver, TimelineEvent};

use crate::engine::bond_assembly::PBoundBytes;
use crate::engine::transaction_submitter::{BroadcastSubmitError, SubmitSuccess, SubmitterError};

// ---------------------------------------------------------------------------
// The sealed-block store (trait + locked write path)
// ---------------------------------------------------------------------------

/// The durable sink for the pending-post block — the `.wallet.pending` seal,
/// behind a trait so the driver is testable with an in-memory store and the
/// engine layer supplies the `WalletFile`-backed impl (same seam shape as
/// [`PScanStore`](super::task::PScanStore)).
///
/// The production impl MUST delegate to `WalletFile::save_pending_posts` /
/// `open_pending_posts` — the single write path / single payload kind the
/// §5 gate-11 enforcement pins. No other implementation may write
/// `.wallet.pending`.
pub(crate) trait PendingSealStore: Send + Sync + 'static {
    /// The store's failure type (boxed into [`DispatchError::Store`]).
    type Error: std::error::Error + Send + Sync + 'static;

    /// Load the sealed block, or `None` for a wallet that has never
    /// assembled a bond post (the store then starts from
    /// [`PendingPostBlock::empty`]). A v1 seal under the v2 binary fails
    /// closed inside the impl's decode (`from_postcard_bytes` refuses the
    /// version) — pre-genesis, the operator re-assembles (rule 15).
    fn load(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<PendingPostBlock>, Self::Error>> + Send;

    /// Seal the whole block (one postcard blob → one AEAD envelope → one
    /// atomic write; the R2-2 structural crash-atomicity).
    fn save(
        &self,
        block: &PendingPostBlock,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;
}

/// The single shared write path over the pending seal (§3.3 writer
/// discipline): an async mutex around load→modify→seal. Both writers — the
/// WI-2 assemble path (append) and this driver (transition/remove) — go
/// through one instance of this handle; the lock is what makes their two
/// cadences safe against read-modify-seal races. (Same shape as
/// `PScanStore`, plus the lock, because unlike the pscan seal this one
/// legitimately has two writers.)
pub(crate) struct PendingPostStore<S> {
    seal: S,
    write_lock: tokio::sync::Mutex<()>,
}

impl<S: PendingSealStore> PendingPostStore<S> {
    /// Wrap the sealed-block store in the locked write path.
    pub(crate) fn new(seal: S) -> Self {
        Self {
            seal,
            write_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Read the current block under the lock (a serialized snapshot; no
    /// seal write). The WI-2 assemble path reads the derived reservation
    /// set ([`PendingPostBlock::reserved_gindexes`]) through this.
    // Transient — the consumer is the assemble-path rewire through this shared
    // handle (the gate-11 writer-discipline follow-through in this WI-3 PR).
    #[allow(dead_code)]
    pub(crate) async fn read<R>(
        &self,
        f: impl FnOnce(&PendingPostBlock) -> R,
    ) -> Result<R, S::Error> {
        let _guard = self.write_lock.lock().await;
        let block = self
            .seal
            .load()
            .await?
            .unwrap_or_else(PendingPostBlock::empty);
        Ok(f(&block))
    }

    /// One locked load→modify→seal cycle. The closure returns
    /// `(changed, R)`; the seal is rewritten only when `changed` is `true`
    /// (an unchanged tick must not burn an AEAD seal + fsync). The seal
    /// happens **inside** the closure's critical section — a caller that
    /// needs seal-before-send (§3.3) gets it by construction: `mutate`
    /// returns only after the transition is durable.
    pub(crate) async fn mutate<R>(
        &self,
        f: impl FnOnce(&mut PendingPostBlock) -> (bool, R),
    ) -> Result<R, S::Error> {
        let _guard = self.write_lock.lock().await;
        let mut block = self
            .seal
            .load()
            .await?
            .unwrap_or_else(PendingPostBlock::empty);
        let (changed, out) = f(&mut block);
        if changed {
            self.seal.save(&block).await?;
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// The broadcast seam
// ---------------------------------------------------------------------------

/// The driver's submit seam: `P`-bound bytes in, verdict out. The production
/// impl routes through `BroadcastSubmitter::submit_bound` (the single choke
/// path; posture → submitter binding per `for_posture`); tests script
/// verdicts. Per-dispatch construction is the impl's concern — under the ②
/// posture each persona gets its own circuit-bound submitter (D1
/// independent-submitter invariant), which is invisible at this seam.
pub(crate) trait BondBroadcast: Send + Sync + 'static {
    /// Submit the bound bytes; the pairing check and transport live behind
    /// the seam.
    fn submit_bound(
        &self,
        bound: PBoundBytes,
    ) -> impl std::future::Future<Output = Result<SubmitSuccess, BroadcastSubmitError>> + Send;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// The unconfirmed-dispatch alarm horizon, in blocks past the tip the
/// due-check first fired against (`Dispatched::at`). A dispatched post with
/// no pscan confirmation after this many blocks stops resubmitting and
/// raises the operator alarm (§3.4 resubmit bound: beyond it, resending is
/// pointless by construction — F31, the pool either has the bytes or is
/// censoring — and the escalation is the alarm, never a faster loop).
///
/// **Default rationale (rule 75), resolving `ARCHIVAL_BOND_WI3_DISPATCH.md`
/// §6(b).** §6(b) proposed reusing the submit-watchdog's escape horizon;
/// verification at source rejects that: the watchdog bound is
/// `DAEMON_RE_RELAY_CUTOFF_SECONDS / 2 / block_target` ≈ 540 blocks, but the
/// pscan cannot confirm a bond post until it is **reorg-deep** — at least
/// [`ARCHIVAL_REORG_DEPTH_BLOCKS`] (720) blocks behind tip — so the
/// watchdog's own lower-bound rule ("comfortably above the confirmation
/// floor") is violated by its own value in the `P` context: a normally-mined
/// post would trip a 540-block horizon before confirmation is *possible*, a
/// guaranteed false alarm. The bound here is derived instead, inheriting the
/// watchdog's two-constraint shape with `P`'s own constants:
///
/// - *Lower bound:* strictly above `ARCHIVAL_REORG_DEPTH_BLOCKS` (720, the
///   confirmation floor) plus ordinary mine latency and a sweep cadence of
///   slack — anything lower alarms on the normal path.
/// - *Upper bound:* below the daemon's re-relay cutoff in blocks
///   (`DAEMON_RE_RELAY_CUTOFF_SECONDS / block_target` ≈ 1080 at a 120 s
///   target) — past it an in-pool tx is held-but-no-longer-relayed, so a
///   later alarm inspects a tx the network has stopped seeing (the F35
///   shape).
///
/// The default is the confirmation floor plus a 25 % margin: 900 blocks
/// (~30 h at 120 s), sitting between both bounds with margin each way.
pub(crate) const DISPATCH_ALARM_HORIZON_BLOCKS: u64 =
    ARCHIVAL_REORG_DEPTH_BLOCKS + ARCHIVAL_REORG_DEPTH_BLOCKS / 4;

/// Tuning knobs for the dispatch driver.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DispatchConfig {
    /// Blocks past `Dispatched::at` after which an unconfirmed post alarms
    /// and stops resubmitting. Production is
    /// [`DISPATCH_ALARM_HORIZON_BLOCKS`]; see its rationale.
    pub alarm_horizon_blocks: u64,
    /// Upper bound (exclusive) of the send-time dispersal draw (§3.2
    /// part 3): each dispatch sleeps `U[0, bound)` before the submit call,
    /// decorrelating the send from the sweep's tick phase. Production is
    /// the sweep cadence; `Duration::ZERO` disables the sleep (tests).
    pub dispersal_bound: Duration,
}

impl DispatchConfig {
    /// The production config: the derived alarm horizon + a dispersal draw
    /// spanning the sweep cadence (the tick interval is exactly the phase
    /// window the draw must cover).
    pub(crate) fn production(tick_interval: Duration) -> Self {
        Self {
            alarm_horizon_blocks: DISPATCH_ALARM_HORIZON_BLOCKS,
            dispersal_bound: tick_interval,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a dispatch tick failed. Only the seal path is an error: submit
/// failures are *outcomes* (§3.4) handled inside the tick, and the sweep
/// treats a failed tick like any other transient sweep failure (log, retry
/// next tick).
#[derive(Debug, thiserror::Error)]
pub(crate) enum DispatchError {
    /// Loading or sealing the pending-post block failed. Boxed (not
    /// stringified) so the store's typed error stays walkable as a
    /// `source()` chain.
    #[error("sealing the pending-post block failed: {0}")]
    Store(#[source] Box<dyn std::error::Error + Send + Sync>),
}

// ---------------------------------------------------------------------------
// Selection (pure — gates 1 and 2)
// ---------------------------------------------------------------------------

/// The pure due-block arithmetic (§3.1): `due = anchor_t0 +
/// bond_post_offset_blocks`. Saturating: a plan whose offset overflows the
/// height space can only push the due block *later* (monotone noise), never
/// wrap to "due immediately".
fn due_height(post: &PendingBondPost) -> u64 {
    post.anchor_t0
        .to_raw()
        .saturating_add(post.bond_post_offset_blocks)
}

/// Select the single post to dispatch this tick, or `None` (§3.2 part 2).
///
/// Candidates are live posts whose due block has arrived at `tip` and that
/// still have a send to make:
///
/// - [`PendingPostState::Pending`] — the first dispatch;
/// - [`PendingPostState::Dispatched`] — the byte-identical resubmit probe,
///   unless the persona is **held** (a success-equivalent verdict was
///   observed this session; the record is awaiting pscan confirmation and
///   resending adds nothing — F31 early-returns, F40 re-claims), **alarmed**
///   (past the horizon; the escalation is the alarm, not a faster loop), or
///   past the alarm horizon (the alarm pass this tick will catch it).
///
/// Ordering: lowest due block; ties broken by lowest `anchor_t0`, then
/// persona id — pinned so a catch-up backlog replays deterministically. The
/// posts left behind wait for subsequent ticks (one-per-tick: co-launching a
/// backlog links the wallet's personas by simultaneity).
fn select_dispatch_candidate<'a>(
    posts: &'a [PendingBondPost],
    tip: BlockHeight,
    alarm_horizon_blocks: u64,
    held: &BTreeSet<PCanonicalId>,
    alarmed: &BTreeSet<PCanonicalId>,
) -> Option<&'a PendingBondPost> {
    posts
        .iter()
        .filter(|p| due_height(p) <= tip.to_raw())
        .filter(|p| !alarmed.contains(&p.persona))
        .filter(|p| match p.state {
            PendingPostState::Pending => true,
            PendingPostState::Dispatched { at, .. } => {
                !held.contains(&p.persona)
                    && tip.to_raw() < at.to_raw().saturating_add(alarm_horizon_blocks)
            }
        })
        .min_by_key(|p| (due_height(p), p.anchor_t0.to_raw(), p.persona))
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

/// The sweep-facing seam for the end-of-sweep dispatch tick: the driving
/// task (`run_pscan_task`) is generic over it, so the loop tests run with
/// the [`()`](impl@DispatchTick) no-op and never build a driver.
/// [`DispatchDriver`] is the production impl.
pub(crate) trait DispatchTick: Send + 'static {
    /// Run one dispatch tick at the end of a pscan sweep — see the
    /// [`DispatchDriver`] impl for the full per-tick contract.
    fn on_tick(
        &mut self,
        tip: BlockHeight,
        confirmed: &BTreeSet<PCanonicalId>,
        cancel: &CancellationToken,
    ) -> impl std::future::Future<Output = Result<(), DispatchError>> + Send;
}

/// The no-dispatch no-op — for pscan loop tests that exercise the scan and
/// never the dispatch path.
impl DispatchTick for () {
    async fn on_tick(
        &mut self,
        _tip: BlockHeight,
        _confirmed: &BTreeSet<PCanonicalId>,
        _cancel: &CancellationToken,
    ) -> Result<(), DispatchError> {
        Ok(())
    }
}

/// What one locked read-modify-seal pass decided (phase 1 of a tick).
struct TickPlan {
    /// Personas retired by confirmation this tick (records removed).
    retired: Vec<PCanonicalId>,
    /// Dispatched-but-unconfirmed posts newly past the alarm horizon:
    /// `(persona, first-dispatch tip, total attempts)`.
    alarms: Vec<(PCanonicalId, BlockHeight, u32)>,
    /// The post sealed as `Dispatched` this tick (a clone of the sealed
    /// record) and its post-transition attempt count.
    dispatched: Option<(PendingBondPost, u32)>,
}

/// Adapts [`rand_core::OsRng`] to [`GapRng`] for the dispersal draw — fresh
/// OS entropy per dispatch, per §3.2 part 3 (same zero-state adapter shape
/// as the stake engine's entry-gap `OsRngGapAdapter`).
struct OsRngDispersalAdapter;

impl GapRng for OsRngDispersalAdapter {
    fn next_u64(&mut self) -> u64 {
        rand_core::OsRng.next_u64()
    }
}

/// The block-timed dispatch driver. Owned by the pscan task; [`Self::on_tick`]
/// runs at the end of every sweep tick against the tip the sweep already
/// fetched (§3.1 — no new network read, no separate timer task).
pub(crate) struct DispatchDriver<S, T> {
    store: PendingPostStore<S>,
    broadcast: T,
    config: DispatchConfig,
    /// Personas whose last submit this session returned a success-equivalent
    /// verdict (`Accepted` / `AlreadyInPool` / `AlreadyInChain`): the bytes
    /// are network-exposed (or mined), so per-tick resubmits add nothing —
    /// the record waits for pscan confirmation (§3.5). In-memory only: a
    /// restart clears it, and the resume re-probes once with the same bytes
    /// (safe by P-2 idempotence), exactly the watchdog's probe discipline.
    held_this_session: BTreeSet<PCanonicalId>,
    /// Personas already alarmed this session (alarm once, not once per
    /// tick — alarm fatigue is itself an attack surface). In-memory only:
    /// the durable record stays held (funds-safety over liveness), so a
    /// restart re-raises the alarm, which is the desired resume behavior.
    alarmed_this_session: BTreeSet<PCanonicalId>,
    /// GF-7 timeline seam (hooks-spec §3/§4 discipline): production injects
    /// [`NoOpObserver`](shekyl_standoff::gf7::NoOpObserver); only the sim
    /// wires a recording observer.
    #[cfg(feature = "gf7-hooks")]
    observer: Box<dyn BroadcastTimelineObserver>,
}

impl<S: PendingSealStore, T: BondBroadcast> DispatchDriver<S, T> {
    /// Build the driver over the sealed-block store and the broadcast seam.
    pub(crate) fn new(seal: S, broadcast: T, config: DispatchConfig) -> Self {
        Self {
            store: PendingPostStore::new(seal),
            broadcast,
            config,
            held_this_session: BTreeSet::new(),
            alarmed_this_session: BTreeSet::new(),
            #[cfg(feature = "gf7-hooks")]
            observer: Box::new(shekyl_standoff::gf7::NoOpObserver),
        }
    }

    /// Replace the GF-7 observer (sim wiring only; hooks-spec §4).
    #[cfg(feature = "gf7-hooks")]
    pub(crate) fn set_observer(&mut self, observer: Box<dyn BroadcastTimelineObserver>) {
        self.observer = observer;
    }

    /// The locked write path, exposed so the WI-2 assemble path appends its
    /// sealed post through the **same** handle (§3.3 writer discipline —
    /// two writers, one lock, one seal path).
    // Transient — the consumer is the assemble-path rewire (gate-11 follow-
    // through in this WI-3 PR), same as `PendingPostStore::read` above.
    #[allow(dead_code)]
    pub(crate) fn store(&self) -> &PendingPostStore<S> {
        &self.store
    }
}

impl<S: PendingSealStore, T: BondBroadcast> DispatchTick for DispatchDriver<S, T> {
    /// Run one dispatch tick (§3.2–§3.6), at the end of a pscan sweep.
    ///
    /// `tip` is the sweep's own `tip_height()` read. Clock trust (R2-1):
    /// this is the daemon's **claimed** tip — sound under local-daemon
    /// posture; reopens under 2d-2 (§3.1 named invariant; the
    /// sweep-corroborated clamp is the pre-designed mitigation held in
    /// reserve for that reopen).
    ///
    /// `confirmed` is the set of personas whose bond post the pscan has
    /// **observed on-chain, reorg-deep** (JoinMarket `BondPostMatch`es from
    /// the sweep's own scan — never a daemon claim, §3.5).
    ///
    /// Per tick: retire confirmed records (one seal, releasing bytes +
    /// derived reservation together), raise past-horizon alarms, then
    /// dispatch at most one due post — seal the `Dispatched` transition
    /// first, sleep the dispersal draw, submit, and absorb the outcome
    /// (§3.4).
    async fn on_tick(
        &mut self,
        tip: BlockHeight,
        confirmed: &BTreeSet<PCanonicalId>,
        cancel: &CancellationToken,
    ) -> Result<(), DispatchError> {
        // -- Phase 1: one locked read-modify-seal pass ----------------------
        // Retire + alarm-scan + select + mark, sealed as ONE write (the
        // retire's byte-prune + reservation release and the dispatch
        // transition land in the same atomic seal — R2-2/R2-4 single-blob
        // discipline). Session sets are read inside, mutated after (the
        // closure is sync; the sets are this driver's own fields).
        let held = &self.held_this_session;
        let alarmed = &self.alarmed_this_session;
        let horizon = self.config.alarm_horizon_blocks;
        let plan = self
            .store
            .mutate(|block| {
                let mut changed = false;

                // Confirmation retire (§3.5): state-agnostic — observed
                // reality wins, whatever the record's state arm says (the
                // `Pending`-but-confirmed arm is the seal-before-send crash
                // case). Removal is the byte-prune and the reservation
                // release in one seal (R2-4).
                let mut retired = Vec::new();
                for persona in confirmed {
                    if block.remove_post(persona).is_some() {
                        changed = true;
                        retired.push(*persona);
                    }
                }

                // Alarm scan (§3.4 resubmit bound): dispatched, unconfirmed,
                // past the horizon, not yet alarmed this session.
                let mut alarms = Vec::new();
                for post in block.posts() {
                    if let PendingPostState::Dispatched { at, attempts } = post.state {
                        if tip.to_raw() >= at.to_raw().saturating_add(horizon)
                            && !alarmed.contains(&post.persona)
                        {
                            alarms.push((post.persona, at, attempts));
                        }
                    }
                }

                // Select + mark (§3.2 part 2 / §3.3 step 2): at most one,
                // deterministic order, sealed as `Dispatched` BEFORE any
                // send.
                let candidate =
                    select_dispatch_candidate(block.posts(), tip, horizon, held, alarmed)
                        .map(|p| p.persona);
                let dispatched = candidate.map(|persona| {
                    let attempts = block
                        .mark_dispatched(&persona, tip)
                        .expect("selected candidate is a live post by construction");
                    changed = true;
                    let post = block
                        .posts()
                        .iter()
                        .find(|p| p.persona == persona)
                        .expect("post just marked is present")
                        .clone();
                    (post, attempts)
                });

                (
                    changed,
                    TickPlan {
                        retired,
                        alarms,
                        dispatched,
                    },
                )
            })
            .await
            .map_err(|e| DispatchError::Store(Box::new(e)))?;

        // -- Phase 2: session bookkeeping -----------------------------------
        for persona in &plan.retired {
            self.held_this_session.remove(persona);
            self.alarmed_this_session.remove(persona);
        }
        if !plan.retired.is_empty() {
            tracing::info!(
                count = plan.retired.len(),
                "bond-post dispatch: pscan confirmation retired pending post(s) — bytes and \
                 funding reservation released in one seal"
            );
        }
        for (persona, at, attempts) in &plan.alarms {
            self.alarmed_this_session.insert(*persona);
            // Truncated `Debug` on `PCanonicalId` — enough for the operator
            // to correlate with their own records, never the full id in a log.
            tracing::error!(
                persona = ?persona,
                dispatched_at = at.to_raw(),
                tip = tip.to_raw(),
                attempts,
                horizon_blocks = self.config.alarm_horizon_blocks,
                "bond-post dispatch ALARM: dispatched post unconfirmed past the alarm horizon — \
                 resubmits stop (F31: the pool either holds the bytes or is censoring); the \
                 record and its funding reservation are HELD (funds-safety over liveness). \
                 Operator action: check daemon connectivity / chain health; a manual re-anchor \
                 is a fresh assemble (§3.6), never automatic"
            );
        }

        // -- Phase 3: the single dispatch (dispersal → emit → send) ---------
        let Some((post, attempts)) = plan.dispatched else {
            return Ok(());
        };

        // Send-time dispersal (§3.2 part 3): an independently drawn uniform
        // delay in [0, tick_interval), fresh OS entropy per dispatch, so the
        // send is not phase-locked to the wallet's sweep cadence. A cancel
        // during the sleep leaves the sealed `Dispatched` state as
        // maybe-sent — exactly the crash-resume case P-2 makes safe.
        let bound_ms = u64::try_from(self.config.dispersal_bound.as_millis()).unwrap_or(u64::MAX);
        if bound_ms > 0 {
            let delay_ms = bounded_uniform(&mut OsRngDispersalAdapter, bound_ms - 1);
            tokio::select! {
                biased;
                () = cancel.cancelled() => return Ok(()),
                () = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
            }
        }

        // GF-7 emission (§3.7): at the submit call site, after the dispersal
        // sleep. `at` is the logical block the due-check fired against;
        // `persona` is the opaque wallet-local slot ordinal (payload
        // discipline: no wall-clock, no txid, no identity).
        #[cfg(feature = "gf7-hooks")]
        self.observer.record(TimelineEvent::BondPostDispatched {
            persona: u64::from(post.p_slot),
            at: tip.to_raw(),
        });

        // The send: re-lift the SEALED bytes (pin P-2 — every attempt sends
        // the stored value) through the single choke path.
        let persona = post.persona;
        let outcome = self
            .broadcast
            .submit_bound(PBoundBytes::from_pending(&post))
            .await;

        // -- Phase 4: outcome handling (§3.4) --------------------------------
        match outcome {
            // Accepted / F31 in-pool: network-exposed, not settled. Hold
            // further resubmits; the pscan's own observation retires it.
            Ok(SubmitSuccess::Broadcast { .. }) => {
                self.held_this_session.insert(persona);
            }
            // F40 already-in-chain: mined per the daemon's CLAIM. Hold
            // resubmits, but NEVER release on the claim — release only on
            // the pscan's reorg-deep observation (§3.5; fund-safety first).
            Ok(SubmitSuccess::AlreadyInChain { height, .. }) => {
                self.held_this_session.insert(persona);
                tracing::debug!(
                    claimed_height = height,
                    attempts,
                    "bond-post dispatch: daemon claims already-in-chain; awaiting the pscan's \
                     own reorg-deep confirmation (the claim never releases the reservation)"
                );
            }
            // Terminal verify rejection: fail loud, stop resending. Remove
            // the record — the byte-prune and the reservation release are
            // the same seal (R2-4) — and surface the alarm. No automatic
            // re-assembly (§3.6: a rejection-driven re-assemble loop is a
            // probe amplifier for a malicious daemon).
            Err(BroadcastSubmitError::Submit(SubmitterError::RejectedTerminal { kind })) => {
                self.store
                    .mutate(|block| (block.remove_post(&persona).is_some(), ()))
                    .await
                    .map_err(|e| DispatchError::Store(Box::new(e)))?;
                self.held_this_session.remove(&persona);
                tracing::error!(
                    ?kind,
                    attempts,
                    "bond-post dispatch ALARM: terminal verify rejection — record removed, \
                     bytes pruned, funding reservation released (one seal). Re-anchor is a \
                     fresh assemble on the next natural bond-attempt trigger (§3.6), never \
                     automatic"
                );
            }
            // Retryable / ambiguous: unknown or transient outcome. The state
            // already says `Dispatched` (sealed before the send), so the
            // next due tick resubmits the same bytes; the alarm horizon
            // bounds the loop.
            Err(BroadcastSubmitError::Submit(SubmitterError::RejectedRetryable { cause })) => {
                tracing::warn!(
                    ?cause,
                    attempts,
                    "bond-post dispatch: retryable rejection; byte-identical resubmit next tick"
                );
            }
            Err(BroadcastSubmitError::Submit(SubmitterError::Ambiguous { kind })) => {
                tracing::warn!(
                    ?kind,
                    attempts,
                    "bond-post dispatch: ambiguous outcome (bytes may or may not have \
                     propagated); sealed state already says Dispatched — byte-identical \
                     resubmit next tick"
                );
            }
            // Persona mismatch: a build-path defect (the P-1 single-mint-site
            // pin makes it unreachable from production flow). Nothing was
            // sent; the record stays held (funds-safe) and the defect is
            // loud.
            Err(BroadcastSubmitError::PersonaMismatch { .. }) => {
                tracing::error!(
                    "bond-post dispatch DEFECT: persona mismatch at the submit choke — the \
                     P-1 single-mint-site pin should make this unreachable; record held, \
                     nothing sent"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Driver gates from `ARCHIVAL_BOND_WI3_DISPATCH.md` §5: due-check
    //! boundaries (gate 1), one-per-tick + deterministic ordering (gate 2),
    //! seal-before-send (gate 3), byte-identical resubmit (gate 4),
    //! confirmation retire + reservation release in one seal / state-agnostic
    //! confirmation (gate 5), terminal rejection removal (gate 6), and the
    //! alarm-horizon resubmit bound (§3.4).

    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use shekyl_types::TxHash;

    use super::*;

    /// One scripted submit verdict (the `BondBroadcast` return shape).
    type Verdict = Result<SubmitSuccess, BroadcastSubmitError>;
    /// The driver under test: in-memory seal store + scripted broadcast.
    type TestDriver = DispatchDriver<std::sync::Arc<MemStore>, std::sync::Arc<ScriptedBroadcast>>;

    // -- test doubles --------------------------------------------------------

    /// In-memory [`PendingSealStore`] with a save kill-switch (for the
    /// seal-failure half of gate 3).
    #[derive(Default)]
    struct MemStore {
        block: Mutex<Option<PendingPostBlock>>,
        fail_saves: AtomicBool,
        saves: Mutex<u64>,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("injected seal failure")]
    struct InjectedSealFailure;

    impl PendingSealStore for std::sync::Arc<MemStore> {
        type Error = InjectedSealFailure;

        async fn load(&self) -> Result<Option<PendingPostBlock>, Self::Error> {
            Ok(self.block.lock().expect("mem store").clone())
        }

        async fn save(&self, block: &PendingPostBlock) -> Result<(), Self::Error> {
            if self.fail_saves.load(Ordering::Relaxed) {
                return Err(InjectedSealFailure);
            }
            *self.saves.lock().expect("mem store") += 1;
            *self.block.lock().expect("mem store") = Some(block.clone());
            Ok(())
        }
    }

    /// Scripted [`BondBroadcast`]: pops the next verdict per call and records
    /// every `(persona, bytes)` it was handed.
    #[derive(Default)]
    struct ScriptedBroadcast {
        script: Mutex<VecDeque<Verdict>>,
        sent: Mutex<Vec<(PCanonicalId, Vec<u8>)>>,
    }

    impl ScriptedBroadcast {
        fn scripted(outcomes: Vec<Verdict>) -> Self {
            Self {
                script: Mutex::new(outcomes.into()),
                sent: Mutex::new(Vec::new()),
            }
        }

        fn sent(&self) -> Vec<(PCanonicalId, Vec<u8>)> {
            self.sent.lock().expect("sent").clone()
        }
    }

    impl BondBroadcast for std::sync::Arc<ScriptedBroadcast> {
        async fn submit_bound(
            &self,
            bound: PBoundBytes,
        ) -> Result<SubmitSuccess, BroadcastSubmitError> {
            self.sent
                .lock()
                .expect("sent")
                .push((*bound.persona(), bound.bytes().to_vec()));
            self.script
                .lock()
                .expect("script")
                .pop_front()
                .unwrap_or(Ok(SubmitSuccess::Broadcast {
                    hash: TxHash::from_bytes([0u8; 32]),
                }))
        }
    }

    fn persona(byte: u8) -> PCanonicalId {
        PCanonicalId::from_bytes([byte; 32])
    }

    fn post(persona_byte: u8, anchor: u64, offset: u64, gindexes: &[u64]) -> PendingBondPost {
        PendingBondPost {
            p_slot: u32::from(persona_byte),
            persona: persona(persona_byte),
            tx_bytes: vec![persona_byte, 0xBE, 0xEF],
            entry_offset_blocks: 3,
            bond_post_offset_blocks: offset,
            anchor_t0: BlockHeight::from_raw(anchor),
            funding_gindexes: gindexes.to_vec(),
            state: PendingPostState::Pending,
        }
    }

    fn test_config() -> DispatchConfig {
        DispatchConfig {
            alarm_horizon_blocks: 100,
            // No dispersal sleep in tests: the draw's decorrelation is a
            // WI-4-graded behavior, not a unit-testable invariant.
            dispersal_bound: Duration::ZERO,
        }
    }

    fn driver_with_posts(
        posts: Vec<PendingBondPost>,
        outcomes: Vec<Verdict>,
    ) -> (
        TestDriver,
        std::sync::Arc<MemStore>,
        std::sync::Arc<ScriptedBroadcast>,
    ) {
        let store = std::sync::Arc::new(MemStore::default());
        *store.block.lock().expect("mem store") = Some(PendingPostBlock::new(posts));
        let broadcast = std::sync::Arc::new(ScriptedBroadcast::scripted(outcomes));
        let driver = DispatchDriver::new(store.clone(), broadcast.clone(), test_config());
        (driver, store, broadcast)
    }

    fn sealed_state(store: &MemStore, persona: &PCanonicalId) -> Option<PendingPostState> {
        store
            .block
            .lock()
            .expect("mem store")
            .as_ref()
            .and_then(|b| b.posts().iter().find(|p| &p.persona == persona))
            .map(|p| p.state)
    }

    // The helpers return the script's slot type on purpose (a `Verdict`, not a
    // bare success): the scripted queue mixes Ok and Err entries.
    #[allow(clippy::unnecessary_wraps)]
    fn accepted() -> Verdict {
        Ok(SubmitSuccess::Broadcast {
            hash: TxHash::from_bytes([1u8; 32]),
        })
    }

    fn ambiguous() -> Verdict {
        Err(BroadcastSubmitError::Submit(SubmitterError::Ambiguous {
            kind: crate::engine::error::AmbiguousErrorKind::DaemonTimeout,
        }))
    }

    async fn tick(driver: &mut TestDriver, tip: u64) {
        driver
            .on_tick(
                BlockHeight::from_raw(tip),
                &BTreeSet::new(),
                &CancellationToken::new(),
            )
            .await
            .expect("tick");
    }

    // -- gate 1: due-check boundaries ----------------------------------------

    /// `due = anchor_t0 + offset`, boundary-exact: nothing fires at
    /// `due − 1`, the dispatch fires at `due`, and a late tick (`due + k`)
    /// still fires (late is monotone noise, §3.6).
    #[tokio::test]
    async fn due_check_boundaries() {
        // anchor 100 + offset 10 ⇒ due at 110.
        let (mut driver, _store, broadcast) = driver_with_posts(
            vec![post(1, 100, 10, &[7])],
            (0..3).map(|_| accepted()).collect(),
        );

        tick(&mut driver, 109).await;
        assert!(broadcast.sent().is_empty(), "tip = due − 1 must not fire");

        tick(&mut driver, 110).await;
        assert_eq!(broadcast.sent().len(), 1, "tip = due fires");

        // A later overdue tick would resubmit only on unknown outcome; the
        // accepted verdict holds it — covered below. Late-first-dispatch:
        let (mut late_driver, _s, late_broadcast) =
            driver_with_posts(vec![post(2, 100, 10, &[8])], vec![accepted()]);
        tick(&mut late_driver, 500).await;
        assert_eq!(
            late_broadcast.sent().len(),
            1,
            "tip = due + k fires (lateness only adds delay, never a re-draw)"
        );
    }

    // -- gate 2: one-per-tick + deterministic ordering ------------------------

    /// A catch-up backlog (every post overdue on one tick) dispatches exactly
    /// one post per tick, lowest due block first; ties break by `anchor_t0`
    /// then persona id.
    #[tokio::test]
    async fn one_per_tick_and_deterministic_ordering() {
        // due: A=130 (anchor 100), B=120 (anchor 90), C=120 (anchor 80),
        // D=120 (anchor 80, higher persona byte than C).
        let posts = vec![
            post(0xAA, 100, 30, &[1]),
            post(0xBB, 90, 30, &[2]),
            post(0xCC, 80, 40, &[3]),
            post(0xDD, 80, 40, &[4]),
        ];
        let (mut driver, _store, broadcast) =
            driver_with_posts(posts, (0..4).map(|_| accepted()).collect());

        // Every post overdue at once — the downtime catch-up shape (§3.2).
        for _ in 0..4 {
            tick(&mut driver, 1_000).await;
        }
        let sent: Vec<PCanonicalId> = broadcast.sent().iter().map(|(p, _)| *p).collect();
        assert_eq!(
            sent,
            vec![persona(0xCC), persona(0xDD), persona(0xBB), persona(0xAA)],
            "order: lowest due first (C/D/B at 120 before A at 130); the C/D tie breaks by \
             anchor_t0 (equal) then persona id (0xCC < 0xDD)"
        );

        // And strictly one per tick: 4 ticks, 4 sends.
        assert_eq!(broadcast.sent().len(), 4);
    }

    // -- gate 3: seal-before-send ---------------------------------------------

    /// The sealed state already says `Dispatched` when the send fails: a
    /// crash/failure after the seal resumes as "maybe sent", which is the
    /// recoverable direction (§3.3 step 2).
    #[tokio::test]
    async fn seal_precedes_send_failed_send_leaves_dispatched() {
        let (mut driver, store, broadcast) =
            driver_with_posts(vec![post(1, 100, 0, &[7])], vec![ambiguous()]);

        tick(&mut driver, 100).await;

        assert_eq!(broadcast.sent().len(), 1, "the send was attempted");
        match sealed_state(&store, &persona(1)) {
            Some(PendingPostState::Dispatched { at, attempts }) => {
                assert_eq!(at.to_raw(), 100, "`at` records the due-check tip");
                assert_eq!(attempts, 1);
            }
            other => panic!("sealed state must be Dispatched after a failed send, got {other:?}"),
        }
    }

    /// The reverse half: when the SEAL fails, **no send happens** (§4 row 2 —
    /// "error logged; no send happens; retried next tick").
    #[tokio::test]
    async fn failed_seal_sends_nothing() {
        let (mut driver, store, broadcast) =
            driver_with_posts(vec![post(1, 100, 0, &[7])], vec![accepted()]);
        store.fail_saves.store(true, Ordering::Relaxed);

        let result = driver
            .on_tick(
                BlockHeight::from_raw(100),
                &BTreeSet::new(),
                &CancellationToken::new(),
            )
            .await;

        assert!(result.is_err(), "the seal failure surfaces as a tick error");
        assert!(
            broadcast.sent().is_empty(),
            "nothing may reach a wire when the Dispatched transition did not seal"
        );

        // Recovery: the next tick (seal healthy again) dispatches normally.
        store.fail_saves.store(false, Ordering::Relaxed);
        tick(&mut driver, 101).await;
        assert_eq!(broadcast.sent().len(), 1, "retried next tick");
    }

    // -- gate 4 (driver half): byte-identical resubmit -------------------------

    /// An unknown-outcome dispatch resubmits on the next tick with exactly
    /// the sealed bytes (pin P-2 extended to the retry path), bumping the
    /// attempt counter; `at` stays the first-dispatch tip.
    #[tokio::test]
    async fn resubmit_sends_identical_bytes_and_bumps_attempts() {
        let (mut driver, store, broadcast) = driver_with_posts(
            vec![post(1, 100, 0, &[7])],
            vec![ambiguous(), ambiguous(), accepted()],
        );

        tick(&mut driver, 100).await;
        tick(&mut driver, 101).await;
        tick(&mut driver, 102).await;

        let sent = broadcast.sent();
        assert_eq!(sent.len(), 3, "two unknown outcomes ⇒ two resubmits");
        assert_eq!(sent[0].1, sent[1].1, "attempt 2 sends the stored bytes");
        assert_eq!(sent[1].1, sent[2].1, "attempt 3 sends the stored bytes");

        match sealed_state(&store, &persona(1)) {
            Some(PendingPostState::Dispatched { at, attempts }) => {
                assert_eq!(attempts, 3);
                assert_eq!(
                    at.to_raw(),
                    100,
                    "`at` records the FIRST due-check tip, never a resubmit's"
                );
            }
            other => panic!("expected Dispatched, got {other:?}"),
        }

        // The accepted verdict on attempt 3 holds further resubmits: the
        // record awaits pscan confirmation, resending adds nothing (F31).
        tick(&mut driver, 103).await;
        assert_eq!(
            broadcast.sent().len(),
            3,
            "a success-equivalent verdict stops the per-tick resubmit"
        );
    }

    /// A success-equivalent hold is session-scoped by design: a restarted
    /// driver re-probes once with the same bytes (safe by P-2), then holds
    /// again — the watchdog's probe discipline.
    #[tokio::test]
    async fn restart_reprobes_a_dispatched_post_once() {
        let (mut driver, store, broadcast) =
            driver_with_posts(vec![post(1, 100, 0, &[7])], vec![accepted()]);
        tick(&mut driver, 100).await;
        assert_eq!(broadcast.sent().len(), 1);

        // "Restart": a fresh driver over the same sealed store (held set empty).
        let broadcast2 = std::sync::Arc::new(ScriptedBroadcast::scripted(vec![accepted()]));
        let mut driver2 = DispatchDriver::new(store.clone(), broadcast2.clone(), test_config());
        tick(&mut driver2, 101).await;
        tick(&mut driver2, 102).await;

        let sent = broadcast2.sent();
        assert_eq!(sent.len(), 1, "one re-probe, then held again");
        assert_eq!(
            sent[0].1,
            vec![1, 0xBE, 0xEF],
            "the re-probe sends the sealed bytes"
        );
    }

    // -- gate 5: confirmation retire ------------------------------------------

    /// A pscan confirmation removes the record — bytes and derived
    /// reservation in one seal — and is state-agnostic: a `Pending` record
    /// whose persona shows a confirmed post (the seal-before-send crash
    /// case) retires identically.
    #[tokio::test]
    async fn confirmation_retires_bytes_and_reservation_in_one_seal() {
        let (mut driver, store, broadcast) = driver_with_posts(
            vec![post(1, 100, 0, &[7, 8]), post(2, 100, 500, &[9])],
            vec![accepted()],
        );
        tick(&mut driver, 100).await; // dispatch persona 1
        assert_eq!(broadcast.sent().len(), 1);

        // Confirmation for the Dispatched persona 1 AND the still-Pending
        // persona 2 (state-agnostic: prior instance sent and died pre-seal).
        let confirmed: BTreeSet<PCanonicalId> = [persona(1), persona(2)].into();
        driver
            .on_tick(
                BlockHeight::from_raw(101),
                &confirmed,
                &CancellationToken::new(),
            )
            .await
            .expect("tick");

        let block = store
            .block
            .lock()
            .expect("mem store")
            .clone()
            .expect("sealed");
        assert!(block.posts().is_empty(), "both records retired");
        assert!(
            block.reserved_gindexes().is_empty(),
            "the derived reservation released with the records — same seal, no second write"
        );
    }

    // -- gate 6: terminal rejection --------------------------------------------

    /// A terminal verify rejection removes the record (releasing bytes +
    /// reservation, R2-4) and never resends.
    #[tokio::test]
    async fn terminal_rejection_removes_and_never_resends() {
        let terminal = Err(BroadcastSubmitError::Submit(
            SubmitterError::RejectedTerminal {
                kind: crate::engine::error::TerminalErrorKind::DoubleSpend,
            },
        ));
        let (mut driver, store, broadcast) =
            driver_with_posts(vec![post(1, 100, 0, &[7, 8])], vec![terminal]);

        tick(&mut driver, 100).await;
        assert_eq!(broadcast.sent().len(), 1);

        let block = store
            .block
            .lock()
            .expect("mem store")
            .clone()
            .expect("sealed");
        assert!(
            block.posts().is_empty(),
            "terminal reject prunes the signed bytes at rest (no resurrection on restart)"
        );
        assert!(block.reserved_gindexes().is_empty(), "reservation released");

        tick(&mut driver, 101).await;
        assert_eq!(broadcast.sent().len(), 1, "never resends after terminal");
    }

    // -- §3.4 resubmit bound: the alarm horizon ---------------------------------

    /// A dispatched post unconfirmed past the alarm horizon stops
    /// resubmitting and alarms once; the record and its reservation are held
    /// (funds-safety over liveness).
    #[tokio::test]
    async fn alarm_horizon_stops_resubmits_and_holds_the_record() {
        let (mut driver, store, broadcast) = driver_with_posts(
            vec![post(1, 100, 0, &[7])],
            vec![ambiguous(), ambiguous(), ambiguous()],
        );

        tick(&mut driver, 100).await; // dispatch, at = 100
        tick(&mut driver, 150).await; // unknown outcome ⇒ resubmit
        assert_eq!(broadcast.sent().len(), 2);

        // horizon = 100 (test config): past-horizon at tip 200.
        tick(&mut driver, 200).await;
        tick(&mut driver, 201).await;
        assert_eq!(
            broadcast.sent().len(),
            2,
            "past the horizon, resubmits stop (the escalation is the alarm, not a faster loop)"
        );

        let block = store
            .block
            .lock()
            .expect("mem store")
            .clone()
            .expect("sealed");
        assert_eq!(block.posts().len(), 1, "the record is held, not removed");
        assert_eq!(
            block.reserved_gindexes(),
            [7u64].into(),
            "the funding reservation stays intact (funds-safety over liveness)"
        );
    }

    // -- selection unit coverage -------------------------------------------------

    /// The pure selector: held and alarmed personas are excluded; `Pending`
    /// posts are always candidates when due.
    #[test]
    fn selector_excludes_held_and_alarmed() {
        let posts = vec![post(1, 100, 0, &[1]), post(2, 100, 0, &[2])];
        let tip = BlockHeight::from_raw(100);

        let held: BTreeSet<PCanonicalId> = [persona(1)].into();
        let none = BTreeSet::new();
        // Pending posts ignore the held set (it only gates resubmits).
        let picked =
            select_dispatch_candidate(&posts, tip, 100, &held, &none).expect("a candidate exists");
        assert_eq!(picked.persona, persona(1), "Pending ignores held");

        let alarmed: BTreeSet<PCanonicalId> = [persona(1)].into();
        let picked = select_dispatch_candidate(&posts, tip, 100, &none, &alarmed)
            .expect("a candidate exists");
        assert_eq!(picked.persona, persona(2), "alarmed personas are excluded");
    }

    /// GF-7 emission-completeness, driver edition (§3.7 / gate 8, the
    /// stake-engine emission test's shape): every submit call site emits
    /// exactly one `BondPostDispatched` — the first send and each
    /// byte-identical resubmit (the timeline records every network
    /// exposure, which is what WI-4's correlator grades) — with the opaque
    /// slot ordinal and the due-check tip as the payload (no wall-clock,
    /// no txid, no identity). Ticks that send nothing emit nothing.
    #[cfg(feature = "gf7-hooks")]
    #[tokio::test]
    async fn gf7_emits_bond_post_dispatched_per_submit() {
        use std::sync::Arc;

        #[derive(Default)]
        struct Recorder(Arc<Mutex<Vec<TimelineEvent>>>);
        impl BroadcastTimelineObserver for Recorder {
            fn record(&mut self, event: TimelineEvent) {
                self.0.lock().expect("recorder").push(event);
            }
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        // First send lands ambiguous ⇒ the next due tick resubmits.
        let (mut driver, _store, broadcast) =
            driver_with_posts(vec![post(5, 100, 0, &[7])], vec![ambiguous(), accepted()]);
        driver.set_observer(Box::new(Recorder(events.clone())));

        // Not yet due: no send, no emission (emission is the submit call
        // site, nothing else on the tick emits).
        tick(&mut driver, 99).await;
        assert!(
            events.lock().expect("recorder").is_empty(),
            "a no-send tick must not emit"
        );

        tick(&mut driver, 100).await; // first send (ambiguous outcome)
        tick(&mut driver, 150).await; // byte-identical resubmit (accepted)
        assert_eq!(broadcast.sent().len(), 2, "two network exposures");

        let recorded = events.lock().expect("recorder").clone();
        assert_eq!(
            recorded,
            vec![
                TimelineEvent::BondPostDispatched {
                    persona: 5,
                    at: 100
                },
                TimelineEvent::BondPostDispatched {
                    persona: 5,
                    at: 150
                },
            ],
            "one emission per submit — slot ordinal + the tick's tip, and nothing besides \
             the submit call site emits"
        );
    }
}
