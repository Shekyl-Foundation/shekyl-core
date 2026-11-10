// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bundle queue's admission, and the draws a mined block reads, on the
//! single writer (`SO-D12` increment 4c; `ARCHIVAL_SERVE_CREDIT_SPEC.md`
//! §7.5, §9.1).
//!
//! Both run here because both read `D`, and the drawable memo is this
//! actor's.
//!
//! - [`OfferBundle`] — the producer files a bundle. The queue's admission
//!   is the bundle rule run against the tip: `judge_bundles` over the
//!   store's bundle view at `h_incl = tip + 1`, in the same write that
//!   queues it. It is shaped like offering an alternative block: the
//!   offer is judged, and the verdict is the reply.
//! - [`LearnDraws`] — the producer mined `h` and asks for its draws, which
//!   the verifier's own selection derives (`draw_targets`) on a committed
//!   snapshot, with the endpoint each persona's bond record carries. A
//!   quiet derivation writes nothing. A corrupt read arms the shared halt
//!   through a batch that commits nothing.
//! - **Upkeep**, after every write that moves the tip, classified on one
//!   snapshot. An entry whose window closed leaves. An entry whose
//!   admitting tip is no longer on the chain is judged again: kept by
//!   rewriting that tip ([`WriteBatch::retip_bundle`]), or removed if
//!   refused. An entry above the tip waits. A queue that does not change
//!   is not written.
//! - **Reconcile**, at start: the store drops a body no entry names and an
//!   entry whose body is gone (SI-41), and this actor logs what went.
//!
//! The queue is not the connect path. No block carries a reference until
//! 4b, so nothing the queue admits is ever connected from it here.

use kameo::message::{Context, Message};
use shekyl_archival_retention::{
    bundle_root, constants::W2_MAX_DEFENSIBLE_BLOCKS, BundleBody, BundleRef, PassStream,
};
use shekyl_bundle_producer::{DrawTarget, Targets};
use shekyl_chain_rules::{
    draw_targets, judge_bundles, remember_window_epochs, AdmissionFault, AtHeight, BundleInvalid,
    BundleRefused, CenRow, ChainView, DrawableMemo, HeaderView, RuleSet, ViewRead,
};
use shekyl_chain_store::store::{
    ChainStore, QueueCannot, ReadSnapshot, SnapshotView, StoreBundleView, StoreCannot, StoreError,
    WriteBatch,
};
use shekyl_network::NetworkId;
use shekyl_types::{BlockCount, BlockHash, BlockHeight};
use zeroize::Zeroizing;

use super::{Connector, RunFault};
use crate::schedule::ChainRules;

/// File a bundle with the queue.
pub struct OfferBundle {
    /// The reference: what a block will carry when references travel.
    pub reference: BundleRef,
    /// The body it names.
    pub body: BundleBody,
}

/// A bundle this node filed and the queue admitted: what the sync owner
/// relays to its peers (§7.5, `SCS-P25`). A peer's bundle is relayed by the
/// owner from its own offer's reply and does not pass through here.
#[derive(Clone, Debug)]
pub struct FiledBundle {
    /// The reference the queue holds.
    pub reference: BundleRef,
    /// The body it names.
    pub body: BundleBody,
}

/// How many filed bundles the relay feed holds for a receiver that has
/// not read them: the queue's own bound. The queue holds at most `W₂`
/// entries and `W₂` is at most [`W2_MAX_DEFENSIBLE_BLOCKS`] on every rule
/// set `ArchivalParams::validate` admits, so a feed this long holds every
/// bundle the queue can hold at once. A receiver further behind has
/// missed a bundle whose window has already closed.
// CLIPPY: cast_possible_truncation — W₂'s ruled upper edge is 500.
#[allow(clippy::cast_possible_truncation)]
pub const FILED_FEED_CAPACITY: usize = W2_MAX_DEFENSIBLE_BLOCKS as usize;

/// Why an offer through the door got no answer.
#[derive(Debug, thiserror::Error)]
pub enum OfferFault {
    /// The connector answered with a fault of its own.
    #[error("the connector faulted: {0}")]
    Connector(RunFault),
    /// The connector has stopped.
    #[error("the connector has stopped")]
    Stopped,
}

/// File a bundle this node produced: offer it to the queue, and when the
/// queue admits it, publish it on `filed` for the sync owner to relay
/// (`SCS-P25`). The one filing path: the producer's task and the door's
/// [`file_bundle`](crate::service::Door::file_bundle) both call it.
///
/// # Errors
///
/// [`OfferFault`] when the connector faulted or has stopped.
pub async fn file_bundle(
    connector: &kameo::actor::ActorRef<Connector>,
    filed: &tokio::sync::broadcast::Sender<FiledBundle>,
    reference: BundleRef,
    body: BundleBody,
) -> Result<BundleOffered, OfferFault> {
    let filing = FiledBundle {
        reference: reference.clone(),
        body: body.clone(),
    };
    let offered = match connector.ask(OfferBundle { reference, body }).await {
        Ok(offered) => offered,
        Err(kameo::error::SendError::HandlerError(fault)) => {
            return Err(OfferFault::Connector(fault))
        }
        Err(_) => return Err(OfferFault::Stopped),
    };
    if matches!(offered, BundleOffered::Queued { .. }) {
        // No receiver is a node with no sync owner yet: the bundle stays
        // queued, and nothing else is lost.
        let _relayed = filed.send(filing);
    }
    Ok(offered)
}

/// What the queue did with an offer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundleOffered {
    /// Admitted against the tip at `tip_height`, and queued.
    Queued {
        /// The bundle's block.
        h: BlockHeight,
        /// The tip it was judged against.
        tip_height: BlockHeight,
    },
    /// A bundle for `h` is already admitted on this chain. Another bundle
    /// for `h` won; nothing is wrong with this one.
    AlreadyRevealed {
        /// The bundle's block.
        h: BlockHeight,
    },
    /// The queue already holds a bundle for `h`.
    AlreadyQueued {
        /// The bundle's block.
        h: BlockHeight,
    },
    /// The rule refused it. For this daemon's own bundle that is a
    /// producer defect: the producer logs it with the row and reports it.
    Refused {
        /// The bundle's block.
        h: BlockHeight,
        /// The census row the refusal is a verdict under, when it is one.
        row: Option<CenRow>,
        /// What refused it, for the log.
        why: String,
    },
}

/// Derive the draws of a block this daemon mined.
pub struct LearnDraws {
    /// The block.
    pub h: BlockHeight,
    /// Its hash when the producer claimed it.
    pub hash: BlockHash,
    /// The seed it drew. Wiped when this message drops.
    pub seed: Zeroizing<[u8; 32]>,
}

/// What [`LearnDraws`] found.
#[derive(Debug)]
pub enum Learned {
    /// The draws, with each persona's endpoint.
    Targets(Targets),
    /// The block at `h` is not the one claimed: it was popped, or replaced.
    NotOnChain,
    /// The view could not answer for a block it holds; the producer asks
    /// again on the next tip.
    Unanswered(String),
}

/// What the start's reconcile dropped (SI-41), for the log.
pub(crate) fn log_reconciled(report: &shekyl_chain_store::store::QueueReconciled) {
    if report.is_clean() {
        return;
    }
    for h in &report.entries_without_body {
        tracing::warn!(
            h = h.to_raw(),
            "bundle queue: dropped the entry for height {} at open; its body was not stored",
            h.to_raw()
        );
    }
    if !report.bodies_without_holder.is_empty() {
        tracing::warn!(
            count = report.bodies_without_holder.len(),
            "bundle queue: dropped {} stored bodies at open that no entry held",
            report.bodies_without_holder.len()
        );
    }
}

impl Message<OfferBundle> for Connector {
    type Reply = Result<BundleOffered, RunFault>;

    async fn handle(
        &mut self,
        msg: OfferBundle,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let rules = self.rules;
        let memo = &mut self.memo;
        // Judged on a snapshot: a bundle the queue does not take opens no
        // write, so a peer's refused bundle costs no commit. This actor is
        // the store's single writer, so the snapshot's tip is the tip the
        // batch below queues against.
        let judged = self.writer.with_store(|store| {
            let snapshot = store.begin_read().map_err(RunFault::Store)?;
            judge_offer(store, &snapshot, rules, memo, &msg.reference, &msg.body)
        })?;
        match judged {
            Offer::Decided(offered) => Ok(offered),
            Offer::Admit {
                tip_height,
                tip_hash,
                capacity,
            } => self.writer.write(|batch| {
                queue(
                    batch,
                    &msg.reference,
                    &msg.body,
                    tip_height,
                    tip_hash,
                    capacity,
                )
            }),
        }
    }
}

impl Message<LearnDraws> for Connector {
    type Reply = Result<Learned, RunFault>;

    async fn handle(
        &mut self,
        msg: LearnDraws,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let rules = self.rules;
        let memo = &mut self.memo;
        // A snapshot. A quiet derivation opens no batch. A corrupt read
        // arms the shared halt through a batch that commits nothing.
        self.writer.with_store(|store| {
            let snapshot = store.begin_read().map_err(RunFault::Store)?;
            learn(store, &snapshot, rules, memo, msg.h, msg.hash, &msg.seed)
        })
    }
}

impl Connector {
    /// The tip moved in a committed write: keep the bundle queue to it,
    /// then publish it. A queue upkeep that faults is logged here and has
    /// already latched the writer if it was terminal; the next write meets
    /// the halt, and the tip the committed write left is published.
    pub(crate) fn tip_moved(&mut self) {
        if let Err(fault) = self.upkeep_queue() {
            tracing::error!("the bundle queue's upkeep faulted: {fault}");
        }
        self.publish_tip();
    }

    /// The queue's upkeep after a write that moved the tip (module docs).
    /// The classification reads one snapshot. A queue that does not change
    /// writes nothing.
    pub(crate) fn upkeep_queue(&mut self) -> Result<(), RunFault> {
        let rules = self.rules;
        let memo = &mut self.memo;
        let plan = self.writer.with_store(|store| {
            let snapshot = store.begin_read().map_err(RunFault::Store)?;
            classify(store, &snapshot, rules, memo)
        })?;
        if plan.is_quiet() {
            return Ok(());
        }
        self.writer.write(|batch| commit_upkeep(batch, &plan))?;
        for departure in &plan.departures {
            match &departure.why {
                Departed::WindowClosed => tracing::info!(
                    h = departure.h.to_raw(),
                    "bundle queue: the window for height {} closed",
                    departure.h.to_raw()
                ),
                Departed::Refused(why) => tracing::info!(
                    h = departure.h.to_raw(),
                    "bundle queue: the entry for height {} left after a reorg: {why}",
                    departure.h.to_raw()
                ),
            }
        }
        Ok(())
    }

    /// The open's reconcile of the queue and the body store (SI-41).
    pub(crate) fn reconcile_queue(&mut self) -> Result<(), RunFault> {
        let report = self
            .writer
            .write(|batch| batch.reconcile_bundle_queue().map_err(RunFault::Store))?;
        log_reconciled(&report);
        Ok(())
    }
}

/// A view read's fault, as the count raises it: a `Corrupt` halts the
/// writer, a store fault is the store's. Only the staged admitting door
/// reads on a batch.
#[cfg(test)]
fn view_fault(batch: &WriteBatch<'_, '_>, fault: ViewRead<StoreError>) -> RunFault {
    match fault {
        ViewRead::View(error) => RunFault::Store(error),
        ViewRead::Corrupt(corrupt) => RunFault::Store(batch.refuse_corrupt(corrupt)),
    }
}

/// Why the rule refused a bundle, as the queue reports it.
enum Refusal {
    /// A bundle for `h` is already admitted on this chain.
    AlreadyRevealed,
    /// Any other refusal: its census row when it is a verdict, and what it
    /// says.
    Rule { row: Option<CenRow>, why: String },
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyRevealed => f.write_str("a bundle for this block is already admitted"),
            Self::Rule { why, .. } => f.write_str(why),
        }
    }
}

/// A snapshot read's fault. A `Corrupt` arms the shared halt through
/// [`halt_on_corrupt`](super::halt_on_corrupt): the batch commits nothing.
/// A view fault is the store's error, and the caller latches. A quiet
/// read never reaches this.
fn snapshot_view_fault(store: &ChainStore, fault: ViewRead<StoreError>) -> RunFault {
    match fault {
        ViewRead::View(error) => RunFault::Store(error),
        ViewRead::Corrupt(corrupt) => super::halt_on_corrupt(store, corrupt),
    }
}

/// The pass stream, in the words an unanswered read logs.
fn stream_word(stream: PassStream) -> &'static str {
    match stream {
        PassStream::Economy => "economy",
        PassStream::Support => "support",
    }
}

/// Why the rule refused, as [`Refusal`], or the view fault as the writer's.
fn refusal_of(fault: AdmissionFault<StoreError>) -> Result<Refusal, RunFault> {
    let row = fault.row();
    match fault {
        AdmissionFault::View(error)
        | AdmissionFault::Bundle {
            refused: BundleRefused::View(error),
            ..
        } => Err(RunFault::Store(error)),
        AdmissionFault::Bundle {
            refused: BundleRefused::Invalid(BundleInvalid::AlreadyRevealed),
            ..
        } => Ok(Refusal::AlreadyRevealed),
        AdmissionFault::Bundle { refused, .. } => Ok(Refusal::Rule {
            row,
            why: refused.to_string(),
        }),
        AdmissionFault::Section(refused) => Ok(Refusal::Rule {
            row,
            why: refused.to_string(),
        }),
        AdmissionFault::Awaiting => Ok(Refusal::Rule {
            row,
            why: "a drawable epoch the section names is not on this chain".into(),
        }),
    }
}

/// `judge_bundles` for one reference, as a refusal. The caller has filled
/// the memo and built the view. `None` admitted. A view fault is the writer's.
fn judge_section(
    judged: Result<Vec<shekyl_chain_rules::Admitted>, AdmissionFault<StoreError>>,
) -> Result<Option<Refusal>, RunFault> {
    match judged {
        Ok(_) => Ok(None),
        Err(fault) => refusal_of(fault).map(Some),
    }
}

/// The root of a section of one reference.
///
/// The root counts its references in four bytes. One reference is a count
/// that fits, so this section has a root.
fn root_of_one(reference: &BundleRef) -> [u8; 32] {
    let refs = std::slice::from_ref(reference);
    match bundle_root(refs) {
        Ok(root) => root,
        Err(_) => unreachable!("one reference is a section count that fits"),
    }
}

/// What one bundle is judged against: the height it would be included
/// at, the rule set in force there, and the network whose id its witness
/// signature is checked under.
#[derive(Clone, Copy)]
struct Judging<'a> {
    h_incl: BlockHeight,
    rule_set: &'a RuleSet,
    network_id: &'a NetworkId,
}

/// Judge one reference on a view the caller already filled.
///
/// `V` is named by its path. Importing [`BundleRows`](shekyl_chain_store::store::BundleRows)
/// would put its row reads beside [`HeaderView`] on a concrete view, and
/// `header_at` would no longer resolve.
fn judge_prepared<V>(
    bundle_view: &StoreBundleView<'_, V>,
    judging: Judging<'_>,
    reference: &BundleRef,
    body: &BundleBody,
) -> Result<Option<Refusal>, RunFault>
where
    V: shekyl_chain_store::store::BundleRows,
{
    let refs = std::slice::from_ref(reference);
    let root = root_of_one(reference);
    judge_section(judge_bundles(
        refs,
        std::slice::from_ref(body),
        &root,
        judging.h_incl,
        bundle_view,
        judging.rule_set,
        judging.network_id,
    ))
}

/// Judge one bundle against the tip, on a snapshot. A `Corrupt` latches
/// and does not open a batch.
fn judge_snapshot(
    store: &ChainStore,
    view: &SnapshotView<'_>,
    memo: &mut DrawableMemo,
    judging: Judging<'_>,
    reference: &BundleRef,
    body: &BundleBody,
) -> Result<Option<Refusal>, RunFault> {
    let Judging {
        h_incl, rule_set, ..
    } = judging;
    remember_window_epochs(view, h_incl, rule_set, memo)
        .map_err(|fault| snapshot_view_fault(store, fault))?;
    let bundle_view = StoreBundleView::new(view, memo, h_incl, rule_set.settlement_schedule());
    judge_prepared(&bundle_view, judging, reference, body)
}

/// What judging an offer on a snapshot decided.
enum Offer {
    /// The queue does not take it, and why.
    Decided(BundleOffered),
    /// The rule admits it against the tip: queue it there.
    Admit {
        tip_height: BlockHeight,
        tip_hash: BlockHash,
        capacity: u64,
    },
}

/// Judge an offered bundle against the tip, on a snapshot.
fn judge_offer(
    store: &ChainStore,
    snapshot: &ReadSnapshot<'_>,
    rules: ChainRules,
    memo: &mut DrawableMemo,
    reference: &BundleRef,
    body: &BundleBody,
) -> Result<Offer, RunFault> {
    let h = reference.h();
    // One per `h`, the first valid one wins (§7.5): a node that holds
    // `h`'s bundle drops another before any signature is checked (§9.1).
    // A relayed bundle reaches a node from several peers, so this is the
    // common case once bundles travel.
    if snapshot.bundle_queued(h).map_err(RunFault::Store)? {
        return Ok(Offer::Decided(BundleOffered::AlreadyQueued { h }));
    }
    let view = SnapshotView::new(snapshot);
    let Some(tip) = view.tip()? else {
        return Ok(Offer::Decided(BundleOffered::Refused {
            h,
            row: None,
            why: "the chain is empty".into(),
        }));
    };
    let h_incl = tip
        .height
        .checked_add(BlockCount::ONE)
        .ok_or(RunFault::NoNextHeight { tip: tip.height })?;
    let rule_set = rules.in_force(h_incl);
    let network_id = rules.trust().network_id();
    let judging = Judging {
        h_incl,
        rule_set: &rule_set,
        network_id: &network_id,
    };
    match judge_snapshot(store, &view, memo, judging, reference, body)? {
        None => {}
        Some(Refusal::AlreadyRevealed) => {
            return Ok(Offer::Decided(BundleOffered::AlreadyRevealed { h }))
        }
        Some(Refusal::Rule { row, why }) => {
            return Ok(Offer::Decided(BundleOffered::Refused { h, row, why }))
        }
    }
    let capacity = rule_set
        .settlement_schedule()
        .challenge_response_blocks()
        .map_or(0, core::num::NonZeroU64::get);
    Ok(Offer::Admit {
        tip_height: tip.height,
        tip_hash: tip.hash,
        capacity,
    })
}

/// Queue a bundle the rule admitted against `(tip_height, tip_hash)`.
fn queue(
    batch: &WriteBatch<'_, '_>,
    reference: &BundleRef,
    body: &BundleBody,
    tip_height: BlockHeight,
    tip_hash: BlockHash,
    capacity: u64,
) -> Result<BundleOffered, RunFault> {
    let h = reference.h();
    match batch.queue_bundle(reference, body, tip_height, tip_hash, capacity) {
        Ok(()) => Ok(BundleOffered::Queued { h, tip_height }),
        Err(StoreError::Cannot(StoreCannot::Queue(QueueCannot::Held { h }))) => {
            Ok(BundleOffered::AlreadyQueued { h })
        }
        Err(StoreError::Cannot(StoreCannot::Queue(cannot))) => Ok(BundleOffered::Refused {
            h,
            row: None,
            why: cannot.to_string(),
        }),
        Err(error) => Err(RunFault::Store(error)),
    }
}

fn learn(
    store: &ChainStore,
    snapshot: &ReadSnapshot<'_>,
    rules: ChainRules,
    memo: &mut DrawableMemo,
    h: BlockHeight,
    hash: BlockHash,
    seed: &[u8; 32],
) -> Result<Learned, RunFault> {
    let view = SnapshotView::new(snapshot);
    let Some(tip) = view.tip()? else {
        return Ok(Learned::NotOnChain);
    };
    let h_incl = tip
        .height
        .checked_add(BlockCount::ONE)
        .ok_or(RunFault::NoNextHeight { tip: tip.height })?;
    let rule_set = rules.in_force(h_incl);
    match view.header_at(h)? {
        AtHeight::Recorded(header) if header.hash == hash => {}
        _ => return Ok(Learned::NotOnChain),
    }
    remember_window_epochs(&view, h_incl, &rule_set, memo)
        .map_err(|fault| snapshot_view_fault(store, fault))?;
    let bundle_view = StoreBundleView::new(&view, memo, h_incl, rule_set.settlement_schedule());
    let derived = match draw_targets(&bundle_view, h, seed, &rule_set) {
        Ok(derived) => derived,
        Err(BundleRefused::View(error)) => return Err(RunFault::Store(error)),
        Err(other) => return Ok(Learned::Unanswered(other.to_string())),
    };
    let mut targets = Targets::default();
    for drawn in derived.draws {
        let Some(record) = view.bond_record(&drawn.persona)? else {
            return Ok(Learned::Unanswered(format!(
                "{} draw {} names a persona with no bond record",
                stream_word(drawn.stream()),
                drawn.draw
            )));
        };
        targets.draws.push(DrawTarget {
            stream: drawn.stream(),
            draw: drawn.draw,
            persona: drawn.persona,
            shard: drawn.shard,
            receipt_key: drawn.receipt_key,
            endpoint: record.endpoint,
        });
    }
    Ok(Learned::Targets(targets))
}

/// One entry the next write removes, and why. Logged only after that write
/// commits.
struct Departure {
    h: BlockHeight,
    why: Departed,
}

enum Departed {
    WindowClosed,
    Refused(String),
}

/// One entry whose admitting tip left the chain and which the rule still
/// admits, rewritten onto the tip the classification read.
struct Retip {
    h: BlockHeight,
    tip_height: BlockHeight,
    tip_hash: BlockHash,
}

/// What upkeep will write. Quiet means the queue does not change.
struct Upkeep {
    departures: Vec<Departure>,
    retips: Vec<Retip>,
}

impl Upkeep {
    fn quiet() -> Self {
        Self {
            departures: Vec::new(),
            retips: Vec::new(),
        }
    }

    fn is_quiet(&self) -> bool {
        self.departures.is_empty() && self.retips.is_empty()
    }
}

/// Classify the queue on one snapshot. A view fault is the writer's and
/// writes nothing. An entry at or above the tip waits. A closed window
/// leaves without being judged. An admitting tip still on the chain is
/// kept as it stands.
fn classify(
    store: &ChainStore,
    snapshot: &ReadSnapshot<'_>,
    rules: ChainRules,
    memo: &mut DrawableMemo,
) -> Result<Upkeep, RunFault> {
    let entries = snapshot.queued_bundles().map_err(RunFault::Store)?;
    if entries.is_empty() {
        return Ok(Upkeep::quiet());
    }
    let view = SnapshotView::new(snapshot);
    let Some(tip) = view.tip()? else {
        return Ok(Upkeep::quiet());
    };
    let h_incl = tip
        .height
        .checked_add(BlockCount::ONE)
        .ok_or(RunFault::NoNextHeight { tip: tip.height })?;
    let rule_set = rules.in_force(h_incl);
    let window = rule_set
        .settlement_schedule()
        .challenge_response_blocks()
        .map_or(BlockCount::ZERO, |w| BlockCount::from_raw(w.get()));
    let network_id = rules.trust().network_id();
    let mut plan = Upkeep::quiet();
    for entry in entries {
        let h = entry.h;
        if h >= h_incl {
            // Popped and not reconnected: the window cannot have closed,
            // and there is nothing to judge until the block is back.
            continue;
        }
        if h_incl > h.saturating_add(window) {
            plan.departures.push(Departure {
                h,
                why: Departed::WindowClosed,
            });
            continue;
        }
        let admitted_on_chain = match view.header_at(entry.queued.tip_height)? {
            AtHeight::Recorded(header) => header.hash == entry.queued.tip_hash,
            AtHeight::AboveTip => false,
        };
        if admitted_on_chain {
            continue;
        }
        match judge_snapshot(
            store,
            &view,
            memo,
            Judging {
                h_incl,
                rule_set: &rule_set,
                network_id: &network_id,
            },
            &entry.queued.reference,
            &entry.body,
        )? {
            None => plan.retips.push(Retip {
                h,
                tip_height: tip.height,
                tip_hash: tip.hash,
            }),
            Some(refused) => plan.departures.push(Departure {
                h,
                why: Departed::Refused(refused.to_string()),
            }),
        }
    }
    Ok(plan)
}

/// Apply a classification. The caller logs departures after this commits.
fn commit_upkeep(batch: &WriteBatch<'_, '_>, plan: &Upkeep) -> Result<(), RunFault> {
    for departure in &plan.departures {
        batch.unqueue_bundle(departure.h)?;
    }
    for retip in &plan.retips {
        batch.retip_bundle(retip.h, retip.tip_height, retip.tip_hash)?;
    }
    Ok(())
}

/// Test only: apply one block through the connector's own judge and
/// connect, and report what its section admitted — the verdict's
/// admissions — then take those entries out of the queue. The block
/// carries the section ([`Scenario::mine_admitting`](crate::scenario::Scenario::mine_admitting)),
/// and `validate` admits it as it admits any block's.
#[cfg(test)]
pub(crate) struct ApplyAdmitting {
    /// The height the source claims for the block.
    pub(crate) height: BlockHeight,
    /// The formed block.
    pub(crate) formed: shekyl_chain_rules::Verdict<shekyl_chain_rules::StructurallyValid>,
}

/// What [`ApplyAdmitting`] did: the block, and what its section admitted.
#[cfg(test)]
pub(crate) struct AppliedAdmitting {
    pub(crate) applied: super::Applied,
    pub(crate) admitted: Vec<shekyl_chain_rules::Admitted>,
}

#[cfg(test)]
impl Message<ApplyAdmitting> for Connector {
    type Reply = Result<AppliedAdmitting, RunFault>;

    async fn handle(
        &mut self,
        msg: ApplyAdmitting,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let rules = self.rules;
        let trust = self.rules.trust();
        let memo = &mut self.memo;
        let out = self.writer.write(|batch| {
            let mut applied = super::Applied::default();
            let Some(judged) = super::connect_step::judge_connecting(
                &mut applied,
                batch,
                rules,
                &trust,
                memo,
                msg.height,
                msg.formed,
            )?
            else {
                return Ok(AppliedAdmitting {
                    applied,
                    admitted: Vec::new(),
                });
            };
            let height = judged.height;
            let in_force = judged.rule_set;
            let admitted = judged.valid.block().admitted().to_vec();
            applied.exercised.extend(judged.exercised());
            batch.connect(judged.valid, in_force)?;
            for bundle in &admitted {
                batch.unqueue_bundle(bundle.kept.h)?;
            }
            super::connect_step::record_connected(&mut applied, height, judged.facts);
            Ok(AppliedAdmitting { applied, admitted })
        })?;
        if !out.applied.connected.is_empty() {
            self.tip_moved();
        }
        Ok(out)
    }
}
