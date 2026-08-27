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

        // Clear ONLY the key whose record actually settled. Clearing both for
        // any settled persona would drop a still-live sibling's marker, and the
        // marker is what makes the alarm fire once instead of once per tick —
        // so a persona whose claim settled while its drain stayed stuck would
        // re-alarm the drain on the very next sweep, forever. Alarm fatigue is
        // itself an attack surface (see the post alarm's note), and the fix is
        // the same discipline the insert side already had: the key is
        // `(kind, persona)`, so every operation on it must be too.
        for persona in &plan.settled.claims {
            self.alarmed_reservations
                .remove(&(ReservationKind::Claim, *persona));
        }
        for persona in &plan.settled.drains {
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
#[path = "dispatch_tests.rs"]
mod tests;
