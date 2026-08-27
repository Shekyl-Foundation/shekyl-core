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
use std::sync::Arc;
use std::time::Duration;

use shekyl_archival_retention::ARCHIVAL_REORG_DEPTH_BLOCKS;
use shekyl_engine_state::{PendingBondPost, PendingPostBlock, PendingPostState};
use shekyl_standoff::draw::bounded_uniform;
use shekyl_types::{BlockHeight, PCanonicalId};
use tokio_util::sync::CancellationToken;

use crate::engine::stake_timing::OsRngGapAdapter;

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
/// through this handle; the lock is what makes their two cadences safe
/// against read-modify-seal races. (Same shape as `PScanStore`, plus the
/// lock, because unlike the pscan seal this one legitimately has two
/// writers.)
///
/// **The lock is per-wallet, not per-instance.** It is injected as a shared
/// [`Arc`] owned by the `Engine` (`pending_write_lock`), so the driver's
/// store and the future WI-2 assemble path — which construct *independent*
/// stateless [`PendingSealStore`] adapters over the same `.wallet.pending`
/// file — still serialize against **one** mutex. Creating the lock inside
/// `new` would give each writer its own, which is precisely the lost-update
/// this discipline exists to forbid (assemble's append and the driver's
/// transition both load, then the last save wins). Requiring the caller to
/// pass the engine-held lock makes "one mutex per wallet" a construction
/// invariant, not a convention.
pub(crate) struct PendingPostStore<S> {
    seal: S,
    write_lock: Arc<tokio::sync::Mutex<()>>,
}

impl<S: PendingSealStore> PendingPostStore<S> {
    /// Wrap the sealed-block store in the locked write path, sharing the
    /// engine-held `write_lock` (see the type docs: one mutex per wallet).
    pub(crate) fn new(seal: S, write_lock: Arc<tokio::sync::Mutex<()>>) -> Self {
        Self { seal, write_lock }
    }

    /// Read the current block under the lock (a serialized snapshot; no
    /// seal write). The WI-2 assemble path reads the derived reservation
    /// set ([`PendingPostBlock::reserved_gindexes`]) through this.
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

/// The confirmation evidence one tick reads — **one source per record kind**,
/// deliberately not one set.
///
/// The three pending kinds settle against different on-chain facts, and the
/// tempting simplification (a single "confirmed personas" set) is wrong for two
/// of them. A bond post is observed directly: the pscan matches the post itself.
/// A claim and a drain have no match set, so each is observed through the
/// funding it reserved — every input it spends leaving the accrual's live set.
///
/// Keeping them apart in the type is the point. `confirmed_posts` reads like a
/// general "these personas confirmed something" set and is nothing of the kind
/// (`confirmed_join_market_personas` filters to `BOND_POST_KIND_JOINMARKET`);
/// crossing the two would retire a live drain because its persona's *bond post*
/// confirmed — a different transaction entirely.
pub(crate) struct TickEvidence<'a> {
    /// Personas with a reorg-deep **JoinMarket bond-post** match. Retires
    /// pending posts only.
    pub(crate) confirmed_posts: &'a BTreeSet<PCanonicalId>,
    /// The accrual's live `P`-owned funding outputs, by global index. A claim or
    /// drain is settled once **every** gindex it reserved has left this set.
    ///
    /// Same provenance as `confirmed_posts` — our own verified, exhaustive scan
    /// behind the finality horizon, never a daemon claim — so releasing a seal
    /// against it is the same quality of evidence at the same reorg depth. That
    /// equivalence is why this is a second field rather than a second driver
    /// with its own notion of "confirmed".
    pub(crate) live_funding: &'a BTreeSet<shekyl_types::GlobalOutputIndex>,
}

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
        evidence: TickEvidence<'_>,
        cancel: &CancellationToken,
    ) -> impl std::future::Future<Output = Result<(), DispatchError>> + Send;
}

/// The no-dispatch no-op — for pscan loop tests that exercise the scan and
/// never the dispatch path.
impl DispatchTick for () {
    async fn on_tick(
        &mut self,
        _tip: BlockHeight,
        _evidence: TickEvidence<'_>,
        _cancel: &CancellationToken,
    ) -> Result<(), DispatchError> {
        Ok(())
    }
}

/// What one locked read-modify-seal pass decided (phase 1 of a tick).
struct TickPlan {
    /// Personas whose pending **post** was retired by confirmation this tick.
    retired: Vec<PCanonicalId>,
    /// Claims and drains retired this tick by their reservation settling.
    settled: shekyl_engine_state::pending_post_block::SettledRetirement,
    /// Dispatched-but-unsettled claims/drains newly past the alarm horizon:
    /// `(kind, persona, first-dispatch tip)`.
    reservation_alarms: Vec<(ReservationKind, PCanonicalId, BlockHeight)>,
    /// Dispatched-but-unconfirmed posts newly past the alarm horizon:
    /// `(persona, first-dispatch tip, total attempts)`.
    alarms: Vec<(PCanonicalId, BlockHeight, u32)>,
    /// The post sealed as `Dispatched` this tick (a clone of the sealed
    /// record) and its post-transition attempt count.
    dispatched: Option<(PendingBondPost, u32)>,
}

/// Which reservation-observed record a stall alarm is about. Alarms are keyed
/// by `(kind, persona)` rather than persona alone: one persona can hold a live
/// claim and a live drain at once, and a shared key would let the first alarm
/// silence the second — the alarm-once rule turning into an alarm-never.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ReservationKind {
    /// A pending emission claim.
    Claim,
    /// A pending `P`→principal drain.
    Drain,
}

impl ReservationKind {
    /// The word the operator log uses.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "emission claim",
            Self::Drain => "drain",
        }
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
    /// Claims/drains already alarmed this session, keyed by kind AND persona.
    /// Same alarm-once discipline as the post set, and the same resume
    /// behaviour: the record is held, so a restart re-raises.
    alarmed_reservations: BTreeSet<(ReservationKind, PCanonicalId)>,
    /// GF-7 timeline seam (hooks-spec §3/§4 discipline): production injects
    /// [`NoOpObserver`](shekyl_standoff::gf7::NoOpObserver); only the sim
    /// wires a recording observer.
    #[cfg(feature = "gf7-hooks")]
    observer: Box<dyn BroadcastTimelineObserver>,
}

impl<S: PendingSealStore, T: BondBroadcast> DispatchDriver<S, T> {
    /// Build the driver over the sealed-block store and the broadcast seam.
    /// `write_lock` is the engine-held, per-wallet pending-seal mutex (see
    /// [`PendingPostStore`]): the driver's store and the WI-2 assemble path
    /// share this one lock so their two write cadences cannot race.
    pub(crate) fn new(
        seal: S,
        broadcast: T,
        config: DispatchConfig,
        write_lock: Arc<tokio::sync::Mutex<()>>,
    ) -> Self {
        Self {
            store: PendingPostStore::new(seal, write_lock),
            broadcast,
            config,
            held_this_session: BTreeSet::new(),
            alarmed_this_session: BTreeSet::new(),
            alarmed_reservations: BTreeSet::new(),
            #[cfg(feature = "gf7-hooks")]
            observer: Box::new(shekyl_standoff::gf7::NoOpObserver),
        }
    }

    /// Replace the GF-7 observer (sim wiring only; hooks-spec §4).
    // In-crate callers: the gate-8 test and the WI-4 §19.8.1 sealing-run
    // seam (`spawn_pscan`'s injection arm). Both are `cfg(test)`-gated, so
    // a feature-on **non-test** build still sees no caller — the
    // `dead_code` allow covers exactly that build shape.
    #[cfg(feature = "gf7-hooks")]
    #[allow(dead_code)] // gf7-hooks lane only: the sim-facing observer injector; no default-feature caller.
    pub(crate) fn set_observer(&mut self, observer: Box<dyn BroadcastTimelineObserver>) {
        self.observer = observer;
    }

    /// The driver's locked write path (§3.3 writer discipline). The WI-2
    /// assemble path does **not** have to route through this exact handle:
    /// its store shares the same engine-held `pending_write_lock`, so an
    /// independently-constructed `PendingPostStore` over `.wallet.pending`
    /// already serializes against the driver's writes (see
    /// [`PendingPostStore`]). This accessor is kept for the in-task read of
    /// the derived reservation set and gate-11's single-write-path audit.
    // Transient — the consumer is the WI-2 Engine-side assemble orchestrator
    // (out of WI-3 scope per the design doc §1). Gate 11 enforces that when it
    // lands, it lands on the one locked seal path and not a second write.
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
    /// reserve for that reopen). The tip has **two consumers in this tick
    /// with opposite sensitivities to a lying daemon** (finding A-1,
    /// 2026-07-06): the *due-check* (`due_height(p) <= tip`), where
    /// inflation is benign-later (monotone noise, posts dispatch late);
    /// and the *alarm horizon* (`tip < at + alarm_horizon_blocks`), where
    /// inflation is **premature-alarm** — a tip reported
    /// `alarm_horizon_blocks` ahead trips the operator alarm on posts
    /// that are propagating normally. The 2d-2 clamp must therefore cover
    /// **both** tip reads, not just the due-check the invariant's
    /// monotone-noise argument was written against.
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
        evidence: TickEvidence<'_>,
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
        let reservation_alarmed = &self.alarmed_reservations;
        let horizon = self.config.alarm_horizon_blocks;
        let plan = self
            .store
            .mutate(|block| {
                let mut changed = false;

                // Confirmation retire (§3.5): state-agnostic — observed
                // reality wins, whatever the record's state arm says (the
                // `Pending`-but-confirmed arm is the seal-before-send crash
                // case). Removal is the byte-prune and the reservation
                // release in one seal (R2-4). Batched over the LIVE posts
                // (`remove_confirmed`) so the cost is bounded by in-flight
                // posts, not by the ever-growing `confirmed` set.
                let retired = block.remove_confirmed(evidence.confirmed_posts);
                if !retired.is_empty() {
                    changed = true;
                }

                // Confirmation retire for the reservation-observed kinds. Same
                // seal, same pass: a claim or drain whose inputs are gone has
                // confirmed, and its record + reservation are released together
                // (R2-4). This is what releases the one-live gates — until it
                // existed, a settled claim left `has_live_claim_for` true
                // forever (the persona silently stopped claiming) and a settled
                // drain left the lane refusing `-29511` across sessions.
                let settled = block.remove_settled(evidence.live_funding);
                if !settled.is_empty() {
                    changed = true;
                }

                // Stall alarm for the reservation-observed kinds. A claim or
                // drain that never settles holds its one-live gate shut, and
                // the failure paths that produce one are silent by nature: a
                // terminally-rejected transaction never spends its inputs, so
                // it never settles and nothing else says so. Naming it in the
                // log is the honest half-measure while terminal-reject prune
                // is a separate slice — the record is HELD, matching the bond
                // post's funds-safety-over-liveness posture.
                let mut reservation_alarms = Vec::new();
                for (kind, persona, state) in block
                    .claims()
                    .iter()
                    .map(|c| (ReservationKind::Claim, c.persona, c.state))
                    .chain(
                        block
                            .drains()
                            .iter()
                            .map(|d| (ReservationKind::Drain, d.persona, d.state)),
                    )
                {
                    if let PendingPostState::Dispatched { at, .. } = state {
                        if tip.to_raw() >= at.to_raw().saturating_add(horizon)
                            && !reservation_alarmed.contains(&(kind, persona))
                        {
                            reservation_alarms.push((kind, persona, at));
                        }
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
                    // `mark_dispatched` returns the transitioned post from the
                    // same lookup it mutates — no second scan to re-find it.
                    let (attempts, post) = block
                        .mark_dispatched(&persona, tip)
                        .expect("selected candidate is a live post by construction");
                    changed = true;
                    (post.clone(), attempts)
                });

                (
                    changed,
                    TickPlan {
                        retired,
                        settled,
                        reservation_alarms,
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
        if !plan.settled.claims.is_empty() {
            tracing::info!(
                count = plan.settled.claims.len(),
                "emission claim: reservation settled — pending claim(s) retired, fee \
                 reservation released, and the persona's epoch-dedup gate reopened"
            );
        }
        if !plan.settled.drains.is_empty() {
            tracing::info!(
                count = plan.settled.drains.len(),
                "drain: reservation settled — pending drain(s) retired, funding \
                 reservation released, and the persona's one-live-drain lane reopened"
            );
        }

        for persona in plan.settled.claims.iter().chain(plan.settled.drains.iter()) {
            self.alarmed_reservations
                .remove(&(ReservationKind::Claim, *persona));
            self.alarmed_reservations
                .remove(&(ReservationKind::Drain, *persona));
        }
        for (kind, persona, at) in &plan.reservation_alarms {
            self.alarmed_reservations.insert((*kind, *persona));
            tracing::error!(
                kind = kind.as_str(),
                persona = ?persona,
                dispatched_at = at.to_raw(),
                tip = tip.to_raw(),
                horizon_blocks = self.config.alarm_horizon_blocks,
                "reservation STALL: a dispatched {} has not settled past the alarm horizon — \
                 its inputs are still unspent, so its one-live gate stays shut and this \
                 persona cannot start another. The record and its reservation are HELD \
                 (funds-safety over liveness). A terminal rejection looks exactly like this \
                 until terminal-reject prune lands. Operator action: check daemon \
                 connectivity / chain health",
                kind.as_str()
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
            let delay_ms = bounded_uniform(&mut OsRngGapAdapter, bound_ms - 1);
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
            persona: u64::from(post.p_slot.to_raw()),
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

    use shekyl_types::{PSlot, TxHash};

    use super::*;
    use crate::engine::transaction_submitter::BroadcastKind;

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
                    kind: BroadcastKind::Accepted,
                }))
        }
    }

    fn persona(byte: u8) -> PCanonicalId {
        PCanonicalId::from_bytes([byte; 32])
    }

    fn post(persona_byte: u8, anchor: u64, offset: u64, gindexes: &[u64]) -> PendingBondPost {
        PendingBondPost {
            p_slot: PSlot::from_raw(u32::from(persona_byte)),
            persona: persona(persona_byte),
            tx_bytes: vec![persona_byte, 0xBE, 0xEF],
            bond_post_offset_blocks: offset,
            anchor_t0: BlockHeight::from_raw(anchor),
            funding_gindexes: gindexes
                .iter()
                .copied()
                .map(shekyl_types::GlobalOutputIndex::from_raw)
                .collect(),
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

    /// A fresh per-test pending-seal write lock (in production the `Engine`
    /// owns one per wallet and shares it with the WI-2 assemble path).
    fn test_lock() -> Arc<tokio::sync::Mutex<()>> {
        Arc::new(tokio::sync::Mutex::new(()))
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
        let driver =
            DispatchDriver::new(store.clone(), broadcast.clone(), test_config(), test_lock());
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
            kind: BroadcastKind::Accepted,
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
                TickEvidence {
                    confirmed_posts: &BTreeSet::new(),
                    live_funding: &BTreeSet::new(),
                },
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
                TickEvidence {
                    confirmed_posts: &BTreeSet::new(),
                    live_funding: &BTreeSet::new(),
                },
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
        let mut driver2 = DispatchDriver::new(
            store.clone(),
            broadcast2.clone(),
            test_config(),
            test_lock(),
        );
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
                TickEvidence {
                    confirmed_posts: &confirmed,
                    live_funding: &BTreeSet::new(),
                },
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

    // -- gate 5b: reservation settlement (claims + drains) ---------------------

    /// Seed a driver whose block also carries a live claim and a live drain,
    /// each reserving one funding output.
    fn driver_with_reservations() -> (TestDriver, std::sync::Arc<MemStore>) {
        use shekyl_engine_state::pending_post_block::{PendingDrain, PendingEmissionClaim};
        let mut block = PendingPostBlock::empty();
        assert!(block.push_claim(PendingEmissionClaim {
            persona: persona(1),
            tx_bytes: vec![0xCD; 8],
            fee_gindexes: vec![shekyl_types::GlobalOutputIndex::from_raw(11)],
            state: PendingPostState::Pending,
        }));
        assert!(block.push_drain(PendingDrain {
            persona: persona(2),
            tx_bytes: vec![0xEF; 8],
            funding_gindexes: vec![shekyl_types::GlobalOutputIndex::from_raw(22)],
            state: PendingPostState::Pending,
        }));
        let store = std::sync::Arc::new(MemStore::default());
        *store.block.lock().expect("mem store") = Some(block);
        let broadcast = std::sync::Arc::new(ScriptedBroadcast::scripted(vec![]));
        let driver = DispatchDriver::new(store.clone(), broadcast, test_config(), test_lock());
        (driver, store)
    }

    /// **The negative control, and it goes first.** A JoinMarket bond-post
    /// confirmation must not retire a live claim or a live drain.
    ///
    /// `confirmed_join_market_personas` reads like a general "these personas
    /// confirmed" set and is filtered to `BOND_POST_KIND_JOINMARKET` by
    /// construction. Handing it to the reservation-observed kinds would retire a
    /// drain because that persona's *bond post* confirmed — a different
    /// transaction, releasing the gate that stops a second drain racing the
    /// first's inputs. Both records here name a persona in `confirmed_posts`, so
    /// a driver that crossed the two evidence sources retires them and this test
    /// goes red.
    #[tokio::test]
    async fn a_bond_post_confirmation_never_retires_a_claim_or_drain() {
        let (mut driver, store) = driver_with_reservations();

        // Both personas confirmed a bond post; both reservations are still live.
        let confirmed: BTreeSet<PCanonicalId> = [persona(1), persona(2)].into();
        let live: BTreeSet<shekyl_types::GlobalOutputIndex> = [11, 22]
            .map(shekyl_types::GlobalOutputIndex::from_raw)
            .into();
        driver
            .on_tick(
                BlockHeight::from_raw(100),
                TickEvidence {
                    confirmed_posts: &confirmed,
                    live_funding: &live,
                },
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
        assert!(
            block.has_live_claim_for(&persona(1)),
            "a bond-post confirmation is not this claim's settlement"
        );
        assert!(
            block.has_live_drain_for(&persona(2)),
            "a bond-post confirmation is not this drain's settlement"
        );
    }

    /// The seal releases when the reservation settles — the defect this driver
    /// closes, for both kinds.
    ///
    /// Before it, a confirmed drain left `has_live_drain_for` true forever (the
    /// persona's lane refused `-29511` across sessions) and a confirmed claim
    /// left `has_live_claim_for` true forever — the worse of the two, because
    /// claims are engine-automated: the persona simply stopped claiming, with no
    /// user action to correlate the silence against.
    #[tokio::test]
    async fn a_settled_reservation_retires_the_claim_and_the_drain() {
        let (mut driver, store) = driver_with_reservations();

        // Neither reservation remains in the accrual's live funding set: both
        // transactions spent their inputs and confirmed.
        driver
            .on_tick(
                BlockHeight::from_raw(100),
                TickEvidence {
                    confirmed_posts: &BTreeSet::new(),
                    live_funding: &BTreeSet::new(),
                },
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
        assert!(
            !block.has_live_claim_for(&persona(1)),
            "claim gate reopened"
        );
        assert!(
            !block.has_live_drain_for(&persona(2)),
            "drain lane reopened"
        );
        assert!(
            block.reserved_gindexes().is_empty(),
            "records and their reservations released in the same seal (R2-4)"
        );
    }

    /// A dispatched claim and drain that never settle both alarm — and the
    /// **same persona gets both**.
    ///
    /// That is the whole reason alarms are keyed by `(kind, persona)`. Keying on
    /// persona alone would let the claim's alarm mark the persona as alarmed and
    /// silence the drain's, turning alarm-once into alarm-never for the second
    /// kind — on exactly the persona that has two things stuck at once, which is
    /// the case an operator most needs to see. Collapsing the key makes this
    /// test red.
    #[tokio::test]
    async fn a_stalled_claim_and_drain_on_one_persona_both_alarm() {
        use shekyl_engine_state::pending_post_block::{PendingDrain, PendingEmissionClaim};
        let p = persona(1);
        let mut block = PendingPostBlock::empty();
        assert!(block.push_claim(PendingEmissionClaim {
            persona: p,
            tx_bytes: vec![0xCD; 8],
            fee_gindexes: vec![shekyl_types::GlobalOutputIndex::from_raw(11)],
            state: PendingPostState::Pending,
        }));
        assert!(block.push_drain(PendingDrain {
            persona: p,
            tx_bytes: vec![0xEF; 8],
            funding_gindexes: vec![shekyl_types::GlobalOutputIndex::from_raw(22)],
            state: PendingPostState::Pending,
        }));
        let at = BlockHeight::from_raw(100);
        assert!(block.mark_claim_dispatched(&p, at).is_some());
        assert!(block.mark_drain_dispatched(&p, at).is_some());

        let store = std::sync::Arc::new(MemStore::default());
        *store.block.lock().expect("mem store") = Some(block);
        let mut driver = DispatchDriver::new(
            store.clone(),
            std::sync::Arc::new(ScriptedBroadcast::scripted(vec![])),
            test_config(),
            test_lock(),
        );

        // Well past the horizon, with both reservations still on chain.
        let live: BTreeSet<shekyl_types::GlobalOutputIndex> = [11, 22]
            .map(shekyl_types::GlobalOutputIndex::from_raw)
            .into();
        driver
            .on_tick(
                BlockHeight::from_raw(100 + test_config().alarm_horizon_blocks),
                TickEvidence {
                    confirmed_posts: &BTreeSet::new(),
                    live_funding: &live,
                },
                &CancellationToken::new(),
            )
            .await
            .expect("tick");

        assert!(
            driver
                .alarmed_reservations
                .contains(&(ReservationKind::Claim, p)),
            "the stalled claim must alarm"
        );
        assert!(
            driver
                .alarmed_reservations
                .contains(&(ReservationKind::Drain, p)),
            "the stalled drain must alarm too — one persona, two stuck records"
        );

        // Both records are HELD: the alarm names the stall, it does not resolve it.
        let block = store
            .block
            .lock()
            .expect("mem store")
            .clone()
            .expect("sealed");
        assert!(block.has_live_claim_for(&p) && block.has_live_drain_for(&p));
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
            [shekyl_types::GlobalOutputIndex::from_raw(7)].into(),
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
